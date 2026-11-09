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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const fuzzScope = "20260101/us-east-1/s3/aws4_request"

// fuzzStreamBody returns a valid signed stream for the given chunk payloads.
func fuzzStreamBody(payloads ...string) string {
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := fuzzStreamingRequest()
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	previous := signV4Header(req, fuzzScope, headers, streamingPayload, testTime)

	var out strings.Builder
	for _, payload := range payloads {
		previous = expectedChunkSignature(signingKey, testTime, fuzzScope, previous, []byte(payload))
		fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n%s\r\n", len(payload), previous, payload)
	}
	previous = expectedChunkSignature(signingKey, testTime, fuzzScope, previous, nil)
	fmt.Fprintf(&out, "0;chunk-signature=%s\r\n\r\n", previous)
	return out.String()
}

func fuzzStreamingRequest() *http.Request {
	req := httptest.NewRequest("PUT", "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	return req
}

// FuzzChunkedReader feeds arbitrary bytes to the streaming framer. The
// invariant is that no input panics and that a rejected stream is reported as
// an error instead of ending the read quietly.
func FuzzChunkedReader(fuzz *testing.F) {
	fuzz.Add([]byte(fuzzStreamBody("hello")))
	fuzz.Add([]byte(fuzzStreamBody("hello", "world")))
	fuzz.Add([]byte("0;chunk-signature=" + strings.Repeat("a", 64) + "\r\n\r\n"))
	fuzz.Add([]byte("fff;chunk-signature=" + strings.Repeat("a", 64) + "\r\nshort\r\n"))
	fuzz.Add([]byte("0\r\n\r\n"))
	fuzz.Add([]byte("\r\n"))
	fuzz.Add([]byte(""))

	verifier := staticTestVerifier()
	fuzz.Fuzz(func(t *testing.T, stream []byte) {
		req := fuzzStreamingRequest()
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
		seed := signV4Header(req, fuzzScope, headers, streamingPayload, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(fuzzScope, seed, headers))
		req.Body = io.NopCloser(bytes.NewReader(stream))

		result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{MaxChunkSize: 1 << 20})
		if err != nil {
			t.Fatalf("ChunkedReader() error = %v", err)
		}
		defer reader.Close()

		decoded, err := io.ReadAll(reader)
		if err != nil {
			// Rejection is a valid outcome; the invariant is only that it is
			// reported instead of ending the read silently.
			return
		}
		// An accepted stream must reproduce exactly the framed payloads, so a
		// parser bug cannot drop or duplicate bytes without failing here.
		if got, want := decoded, fuzzFramePayloads(t, stream); !bytes.Equal(got, want) {
			t.Fatalf("decoded %d bytes, the frames carry %d", len(got), len(want))
		}
	})
}

// parseFuzzChunkSize reads the hex size in front of an optional
// ;chunk-signature= parameter, mirroring the reader's own limit so that an
// oversized chunk never wraps the arithmetic below.
func parseFuzzChunkSize(header []byte) (int, error) {
	text := string(header)
	if marker := strings.Index(text, ";chunk-signature="); marker >= 0 {
		text = text[:marker]
	}
	parsed, err := strconv.ParseInt(text, 16, 63)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("bad chunk header %q", string(header))
	}
	if parsed > 1<<20 {
		return 0, fmt.Errorf("chunk size %d exceeds the fuzz limit", parsed)
	}
	return int(parsed), nil
}

// fuzzFramePayloads re-parses the chunk frames independently of the reader, so
// an accepted stream can be compared against what the bytes really carry.
func fuzzFramePayloads(t *testing.T, stream []byte) []byte {
	t.Helper()
	var expected bytes.Buffer
	rest := stream
	for len(rest) > 0 {
		headerEnd := bytes.Index(rest, []byte("\r\n"))
		if headerEnd < 0 {
			t.Fatalf("accepted a stream with no chunk header terminator")
		}
		size, err := parseFuzzChunkSize(rest[:headerEnd])
		if err != nil {
			t.Fatalf("accepted a stream with an unparsable chunk header: %v", err)
		}
		if size == 0 {
			break
		}
		frame := rest[headerEnd+2:]
		if len(frame) < size+2 || frame[size] != '\r' || frame[size+1] != '\n' {
			t.Fatalf("accepted a chunk with no terminator after %d payload bytes", size)
		}
		expected.Write(frame[:size])
		rest = frame[size+2:]
	}
	return expected.Bytes()
}

const fuzzTrailerName = "x-amz-checksum-crc32"

func fuzzTrailerRequest() *http.Request {
	req := fuzzStreamingRequest()
	req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
	req.Header.Set("X-Amz-Trailer", "X-Amz-Checksum-CRC32")
	return req
}

// fuzzTrailerBody frames a signed-trailer stream around a caller-supplied
// trailer block, so the fuzzer can mutate the block while the chunk chain stays
// valid.
func fuzzTrailerBody(payloads []string, trailerBlock string) string {
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := fuzzTrailerRequest()
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-trailer"}
	previous := signV4Header(req, fuzzScope, headers, streamingPayloadTrailer, testTime)

	var out strings.Builder
	for _, payload := range payloads {
		previous = expectedChunkSignature(signingKey, testTime, fuzzScope, previous, []byte(payload))
		fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n%s\r\n", len(payload), previous, payload)
	}
	previous = expectedChunkSignature(signingKey, testTime, fuzzScope, previous, nil)
	fmt.Fprintf(&out, "0;chunk-signature=%s\r\n", previous)
	out.WriteString(trailerBlock + "\r\n")
	trailerSignature := expectedTrailerSignature(signingKey, testTime, fuzzScope, previous, []byte(trailerBlock))
	fmt.Fprintf(&out, "%s:%s\r\n\r\n", trailerSignatureHeader, trailerSignature)
	return out.String()
}

// FuzzTrailerBlock attacks the trailer parser, the code that produced the one
// real streaming bug this package had. Invariants: no panic, the decoded body
// still matches the chunk frames, and any trailer reported by Trailer() is a
// declared trailer whose value is literally present in the input.
func FuzzTrailerBlock(fuzz *testing.F) {
	fuzz.Add([]byte(fuzzTrailerBody([]string{"hello"}, fuzzTrailerName+":AAAAAA==\n")))
	fuzz.Add([]byte(fuzzTrailerBody([]string{"hello", "world"}, fuzzTrailerName+":AQID\n")))
	fuzz.Add([]byte(fuzzTrailerBody(nil, fuzzTrailerName+":\n")))
	fuzz.Add([]byte(fuzzTrailerBody([]string{"hello"}, "x-amz-meta-other:1\n")))
	fuzz.Add([]byte(fuzzTrailerBody([]string{"hello"}, fuzzTrailerName+":AAAA==\nx-amz-checksum-crc32c:BBBB==\n")))
	fuzz.Add([]byte(fuzzTrailerBody([]string{"hello"}, strings.Repeat(fuzzTrailerName+":A\n", 200))))

	verifier := staticTestVerifier()
	fuzz.Fuzz(func(t *testing.T, stream []byte) {
		req := fuzzTrailerRequest()
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-trailer"}
		seed := signV4Header(req, fuzzScope, headers, streamingPayloadTrailer, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(fuzzScope, seed, headers))
		req.Body = io.NopCloser(bytes.NewReader(stream))

		result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{MaxChunkSize: 1 << 20})
		if err != nil {
			t.Fatalf("ChunkedReader() error = %v", err)
		}
		defer reader.Close()

		decoded, err := io.ReadAll(reader)
		if err != nil {
			return
		}
		if got, want := decoded, fuzzFramePayloads(t, stream); !bytes.Equal(got, want) {
			t.Fatalf("decoded %d bytes, the frames carry %d", len(got), len(want))
		}
		trailers := reader.Trailers()
		if len(trailers) == 0 {
			t.Fatalf("accepted a signed-trailer stream that reported no trailers")
		}
		for name, values := range trailers {
			if !strings.EqualFold(name, fuzzTrailerName) {
				t.Fatalf("reported undeclared trailer %q", name)
			}
			for _, value := range values {
				if !bytes.Contains(stream, []byte(fuzzTrailerName+":"+value)) {
					t.Fatalf("trailer value %q is not in the input", value)
				}
			}
		}
	})
}
