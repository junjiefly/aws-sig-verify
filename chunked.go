// Copyright 2026 junjiefly
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awsverify

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

const (
	chunkSignatureMarker    = ";chunk-signature="
	defaultMaxChunkSize     = int64(16 << 20)
	maxChunkHeaderSize      = 16 * 1024
	chunkedPayloadAlgorithm = "AWS4-HMAC-SHA256-PAYLOAD"
	chunkedTrailerAlgorithm = "AWS4-HMAC-SHA256-TRAILER"
	trailerSignatureHeader  = "x-amz-trailer-signature"
	maxTrailerBlockSize     = 64 * 1024
	maxTrailerLineCount     = 128
)

type ChunkedReaderOptions struct {
	// MaxChunkSize limits a single decoded chunk. AWS SDKs normally use much
	// smaller chunks; the default is 16 MiB.
	MaxChunkSize int64
}

// ChunkedReader returns the decoded body for an already verified AWS SigV4
// streaming request. The returned reader must be closed by the caller. After
// reading to EOF, Trailer returns the trailers parsed from the stream.
func (v *Verifier) ChunkedReader(req *http.Request, result *Result, options ChunkedReaderOptions) (*ChunkedReader, error) {
	if req == nil || req.Body == nil {
		return nil, ErrNilRequest
	}
	if result == nil {
		return nil, ErrUnsupportedStreamingPayload
	}
	maxChunkSize := options.MaxChunkSize
	if maxChunkSize <= 0 {
		maxChunkSize = defaultMaxChunkSize
	}

	base := io.ReadCloser(req.Body)
	switch result.PayloadHash {
	case streamingPayload:
		if result.credentials.SecretAccessKey == "" {
			return nil, ErrCredentialLookupRequired
		}
		date := result.SigningTime.UTC().Format("20060102")
		return &ChunkedReader{
			body:              base,
			reader:            bufio.NewReaderSize(base, 64*1024),
			signed:            true,
			signingKey:        deriveSigningKey(result.credentials.SecretAccessKey, date, result.Region, result.Service),
			scope:             fmt.Sprintf("%s/%s/%s/aws4_request", date, result.Region, result.Service),
			signingTime:       result.SigningTime,
			previousSignature: result.Signature,
			maxChunkSize:      maxChunkSize,
		}, nil
	case unsignedStreamingPayload:
		return &ChunkedReader{
			body:         base,
			reader:       bufio.NewReaderSize(base, 64*1024),
			trailer:      true,
			maxChunkSize: maxChunkSize,
		}, nil
	case streamingPayloadTrailer:
		if result.credentials.SecretAccessKey == "" {
			return nil, ErrCredentialLookupRequired
		}
		expectedTrailers := parseTrailerNames(req.Header.Values("X-Amz-Trailer"))
		if len(expectedTrailers) == 0 {
			return nil, ErrMalformedChunk
		}
		date := result.SigningTime.UTC().Format("20060102")
		return &ChunkedReader{
			body:              base,
			reader:            bufio.NewReaderSize(base, 64*1024),
			signed:            true,
			trailer:           true,
			expectedTrailers:  expectedTrailers,
			signingKey:        deriveSigningKey(result.credentials.SecretAccessKey, date, result.Region, result.Service),
			scope:             fmt.Sprintf("%s/%s/%s/aws4_request", date, result.Region, result.Service),
			signingTime:       result.SigningTime,
			previousSignature: result.Signature,
			maxChunkSize:      maxChunkSize,
		}, nil
	default:
		return nil, ErrUnsupportedStreamingPayload
	}
}

type ChunkedReader struct {
	body              io.ReadCloser
	reader            *bufio.Reader
	signed            bool
	signingKey        []byte
	scope             string
	signingTime       time.Time
	previousSignature string
	pending           []byte
	pendingOffset     int
	done              bool
	maxChunkSize      int64
	trailer           bool
	expectedTrailers  []string
	trailers          http.Header
	err               error
}

func (reader *ChunkedReader) Trailers() http.Header {
	if reader.trailers == nil {
		return http.Header{}
	}
	trailers := make(http.Header, len(reader.trailers))
	for name, values := range reader.trailers {
		trailers[name] = append([]string(nil), values...)
	}
	return trailers
}

func (reader *ChunkedReader) Read(output []byte) (int, error) {
	if reader.err != nil {
		return 0, reader.err
	}
	if len(reader.pending) > 0 {
		copied := copy(output, reader.pending[reader.pendingOffset:])
		reader.pendingOffset += copied
		if reader.pendingOffset == len(reader.pending) {
			reader.pending = nil
			reader.pendingOffset = 0
		}
		return copied, nil
	}
	if reader.done {
		return 0, io.EOF
	}
	if len(output) == 0 {
		return 0, nil
	}
	if err := reader.nextChunk(); err != nil {
		reader.err = err
		return 0, err
	}
	return reader.Read(output)
}

func (reader *ChunkedReader) Close() error {
	err := reader.body.Close()
	if reader.err == nil {
		reader.err = io.EOF
	}
	return err
}

func (reader *ChunkedReader) nextChunk() error {
	line, err := readCRLFLineLimited(reader.reader, maxChunkHeaderSize)
	if err != nil {
		return err
	}
	sizeText := line
	signatureText := ""
	if reader.signed {
		var found bool
		sizeText, signatureText, found = strings.Cut(line, chunkSignatureMarker)
		if !found || !validChunkSignature(signatureText) {
			return ErrMalformedChunk
		}
	} else if strings.Contains(line, chunkSignatureMarker) {
		return ErrMalformedChunk
	}

	size, err := parseChunkSize(sizeText)
	if err != nil {
		return err
	}
	if size > reader.maxChunkSize {
		return ErrChunkSizeTooLarge
	}

	if size == 0 {
		if reader.signed {
			if err := reader.verifyChunk(nil, signatureText); err != nil {
				return err
			}
		}
		if reader.signed {
			expectOptionalCRLF(reader.reader)
		} else {
			if reader.trailer {
				if err := reader.readTrailers(); err != nil {
					return err
				}
			}
		}
		if reader.signed && reader.trailer {
			if err := reader.readTrailers(); err != nil {
				return err
			}
		}
		reader.done = true
		return nil
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(reader.reader, data); err != nil {
		return fmt.Errorf("%w: truncated chunk data", ErrMalformedChunk)
	}
	if err := expectCRLF(reader.reader); err != nil {
		return err
	}
	if reader.signed {
		if err := reader.verifyChunk(data, signatureText); err != nil {
			return err
		}
	}
	reader.pending = data
	return nil
}

func (reader *ChunkedReader) verifyChunk(data []byte, presented string) error {
	chunkHash := sha256.Sum256(data)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		reader.signingTime.UTC().Format("20060102T150405Z"),
		reader.scope,
		reader.previousSignature,
		emptyPayloadHash,
		hex.EncodeToString(chunkHash[:]),
	}, "\n")
	expected := hex.EncodeToString(hmacSHA256(reader.signingKey, []byte(stringToSign)))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
		return ErrChunkSignatureMismatch
	}
	reader.previousSignature = expected
	return nil
}

func (reader *ChunkedReader) readTrailers() error {
	lines, err := readTrailerBlock(reader.reader, maxTrailerBlockSize)
	if err != nil {
		return err
	}
	if reader.signed && len(lines) == 0 {
		return ErrMalformedChunk
	}

	presented := ""
	if reader.signed {
		// The trailer signature follows the blank line that ends the block.
		line, err := readCRLFLineLimited(reader.reader, maxChunkHeaderSize)
		if err != nil {
			return err
		}
		name, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), trailerSignatureHeader) ||
			!validChunkSignature(strings.TrimSpace(value)) {
			return ErrMalformedChunk
		}
		presented = strings.TrimSpace(value)
	}

	var raw []byte
	for _, line := range lines {
		raw = append(raw, line.raw...)
	}

	parsed, err := parseTrailers(raw, reader.expectedTrailers)
	if err != nil {
		return err
	}
	if err := validateTrailerPresence(parsed, reader.expectedTrailers); err != nil {
		return err
	}
	if reader.signed {
		trailerHash := sha256.Sum256(raw)
		stringToSign := strings.Join([]string{
			chunkedTrailerAlgorithm,
			reader.signingTime.UTC().Format("20060102T150405Z"),
			reader.scope,
			reader.previousSignature,
			hex.EncodeToString(trailerHash[:]),
		}, "\n")
		expected := hex.EncodeToString(hmacSHA256(reader.signingKey, []byte(stringToSign)))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
			return ErrChunkSignatureMismatch
		}
	}
	reader.trailers = parsed
	return nil
}

// trailerLine keeps both the decoded text and the transmitted bytes. The
// trailer signature covers the block verbatim, so a client that terminates
// lines with LF and one that uses CRLF cannot be verified with the same hash
// unless the original framing is preserved.
type trailerLine struct {
	text string
	raw  []byte
}

// readTrailerBlock reads trailer lines up to the blank line that ends them.
func readTrailerBlock(reader *bufio.Reader, max int) ([]trailerLine, error) {
	lines := make([]trailerLine, 0, 4)
	total := 0
	for {
		raw, err := readRawLineLimited(reader, max)
		if err != nil {
			return nil, err
		}
		if strings.TrimRight(raw, "\r\n") == "" {
			return lines, nil
		}
		if len(lines) >= maxTrailerLineCount || total+len(raw) > max {
			return nil, ErrChunkHeaderTooLong
		}
		lines = append(lines, trailerLine{
			text: strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r"),
			raw:  []byte(raw),
		})
		total += len(raw)
	}
}

func parseTrailerNames(values []string) []string {
	var names []string
	seen := make(map[string]struct{})
	for _, list := range values {
		for _, name := range strings.Split(list, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

func parseTrailers(raw []byte, expected []string) (http.Header, error) {
	trailers := make(http.Header)
	lines := strings.Split(string(raw), "\n")
	if len(lines) > maxTrailerLineCount {
		return nil, ErrMalformedChunk
	}
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, ErrMalformedChunk
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "" || name == trailerSignatureHeader {
			return nil, ErrMalformedChunk
		}
		if len(expected) > 0 && !containsString(expected, name) {
			return nil, ErrMalformedChunk
		}
		trailers.Add(textproto.CanonicalMIMEHeaderKey(name), value)
	}
	return trailers, nil
}

func validateTrailerPresence(trailers http.Header, expected []string) error {
	for _, name := range expected {
		if _, ok := trailers[textproto.CanonicalMIMEHeaderKey(name)]; !ok {
			return ErrMalformedChunk
		}
	}
	return nil
}

func validChunkSignature(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// parseChunkSize accepts only the plain hexadecimal size AWS signers write.
// strconv.ParseInt would also accept "+5", and a size too wide for int64 is
// reported as too large rather than malformed.
func parseChunkSize(sizeText string) (int64, error) {
	if sizeText == "" {
		return 0, ErrMalformedChunk
	}
	for i := 0; i < len(sizeText); i++ {
		c := sizeText[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return 0, ErrMalformedChunk
		}
	}
	size, err := strconv.ParseInt(sizeText, 16, 63)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, ErrChunkSizeTooLarge
		}
		return 0, ErrMalformedChunk
	}
	return size, nil
}

// readCRLFLineLimited reads a framing line. Chunk headers and the trailer
// signature belong to the AWS chunked-transfer framing, which ends every line
// with CRLF. The trailer block is the exception and stays LF-tolerant because
// clients transmit those bytes verbatim.
func readCRLFLineLimited(reader *bufio.Reader, max int) (string, error) {
	raw, err := readRawLineLimited(reader, max)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(raw, "\r\n") {
		return "", ErrMalformedChunk
	}
	return strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r"), nil
}

// readRawLineLimited reads one line including its terminator. An absent
// terminator means the stream ended inside the line, which callers treat as
// truncation rather than a complete line.
func readRawLineLimited(reader *bufio.Reader, max int) (string, error) {
	var line bytes.Buffer
	for {
		piece, err := reader.ReadSlice('\n')
		if line.Len()+len(piece) > max {
			return "", ErrChunkHeaderTooLong
		}
		line.Write(piece)
		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	return line.String(), nil
}

func expectCRLF(reader *bufio.Reader) error {
	var terminator [2]byte
	if _, err := io.ReadFull(reader, terminator[:]); err != nil {
		return fmt.Errorf("%w: missing chunk CRLF", ErrMalformedChunk)
	}
	if terminator[0] != '\r' || terminator[1] != '\n' {
		return ErrMalformedChunk
	}
	return nil
}

func expectOptionalCRLF(reader *bufio.Reader) {
	pending, err := reader.Peek(2)
	if err != nil || len(pending) != 2 || pending[0] != '\r' || pending[1] != '\n' {
		return
	}
	if _, err := reader.Discard(2); err != nil {
		return
	}
}
