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

package interop

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7/pkg/signer"
)

const (
	streamingPayload        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingTrailerPayload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	unsignedTrailerPayload  = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	clientChunkSize         = 64 * 1024
)

// encodeStream materialises the framed body an AWS client puts on the wire.
func encodeStream(t *testing.T, req *http.Request) []byte {
	t.Helper()
	encoded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read signed stream: %v", err)
	}
	return encoded
}

// framedRequest rebuilds the request so its body is an already signed stream.
func framedRequest(t *testing.T, signed *http.Request, encoded []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(signed.Method, signed.URL.String(), bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = signed.Host
	req.Header = signed.Header.Clone()
	req.ContentLength = int64(len(encoded))
	return req
}

func signStream(t *testing.T, body []byte, token, expectedAlgorithm string, trailers http.Header) (*http.Request, []byte) {
	t.Helper()
	req := buildRequest(t, http.MethodPut, "/bucket/stream.bin", body)
	req.ContentLength = int64(len(body))
	if trailers != nil {
		req.Trailer = trailers.Clone()
		req.Header.Set("X-Amz-Content-Sha256", expectedAlgorithm)
	}
	signed := signer.StreamingSignV4(req, accessKeyID, secretAccessKey, token, region,
		int64(len(body)), fixedStreamingTime, newHasher())
	if got := signed.Header.Get("X-Amz-Content-Sha256"); got != expectedAlgorithm {
		t.Fatalf("X-Amz-Content-Sha256 = %q, want %q", got, expectedAlgorithm)
	}
	return signed, encodeStream(t, signed)
}

func streamVerifier() *awsverify.Verifier {
	return newVerifier(func() time.Time { return fixedStreamingTime })
}

func openStream(t *testing.T, req *http.Request) (*awsverify.ChunkedReader, *awsverify.Result) {
	t.Helper()
	verifier := streamVerifier()
	result := mustVerify(t, verifier, req, verifyOptions())
	reader, err := verifier.ChunkedReader(req, result, awsverify.ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	return reader, result
}

// chunkFrame is one signed chunk: header line plus CRLF, then data plus CRLF.
type chunkFrame struct {
	header []byte
	data   []byte
}

func (frame chunkFrame) bytes() []byte {
	return append(append([]byte(nil), frame.header...), frame.data...)
}

// parseFrames splits a signed stream into frames, keeping the framing bytes.
func parseFrames(t *testing.T, encoded []byte) []chunkFrame {
	t.Helper()
	var frames []chunkFrame
	rest := encoded
	for len(rest) > 0 {
		end := bytes.Index(rest, []byte("\r\n"))
		if end < 0 {
			t.Fatalf("stream has no chunk header terminator")
		}
		header := rest[:end+2]
		rest = rest[end+2:]
		sizeText := string(header)
		if marker := bytes.Index(header, []byte(";")); marker >= 0 {
			sizeText = string(header[:marker])
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil {
			t.Fatalf("bad chunk header %q: %v", header, err)
		}
		if size == 0 {
			// The terminator chunk plus whatever follows (trailer block).
			frames = append(frames, chunkFrame{header: header, data: rest})
			return frames
		}
		if int64(len(rest)) < size+2 {
			t.Fatalf("stream ends inside a chunk")
		}
		frames = append(frames, chunkFrame{header: header, data: rest[:size+2]})
		rest = rest[size+2:]
	}
	return frames
}

func reassemble(frames []chunkFrame) []byte {
	var out bytes.Buffer
	for _, frame := range frames {
		out.Write(frame.bytes())
	}
	return out.Bytes()
}

func TestSigV4StreamingChunksInterop(t *testing.T) {
	for _, size := range []int{1, 17, 4095, clientChunkSize - 1, clientChunkSize, clientChunkSize + 1, 5 * clientChunkSize, 1 << 20} {
		size := size
		t.Run("size="+strconv.Itoa(size), func(t *testing.T) {
			body := patternBytes(size)
			signed, encoded := signStream(t, body, "", streamingPayload, nil)
			if int64(len(encoded)) != signed.ContentLength {
				t.Fatalf("stream is %d bytes, request declares Content-Length %d", len(encoded), signed.ContentLength)
			}
			reader, result := openStream(t, framedRequest(t, signed, encoded))
			if result.PayloadHash != streamingPayload {
				t.Fatalf("PayloadHash = %q, want %q", result.PayloadHash, streamingPayload)
			}
			decoded, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("decoding the stream: %v", err)
			}
			if !bytes.Equal(decoded, body) {
				t.Fatalf("decoded %d bytes, want the %d original bytes", len(decoded), len(body))
			}
			if len(reader.Trailers()) != 0 {
				t.Fatalf("unexpected trailers %+v", reader.Trailers())
			}
		})
	}
}

func TestSigV4StreamingEmptyBody(t *testing.T) {
	signed, encoded := signStream(t, []byte{}, "", streamingPayload, nil)
	t.Logf("empty-body stream is %d bytes, Content-Length %d: %q", len(encoded), signed.ContentLength, encoded)
	reader, _ := openStream(t, framedRequest(t, signed, encoded))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decoding the empty stream: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("decoded %d bytes, want none", len(decoded))
	}
}

func TestSigV4StreamingRejectsTampering(t *testing.T) {
	body := patternBytes(3 * clientChunkSize)
	signed, encoded := signStream(t, body, "", streamingPayload, nil)
	frames := parseFrames(t, encoded)
	if len(frames) != 4 {
		t.Fatalf("expected 3 data chunks plus the terminator, got %d frames", len(frames))
	}

	mutations := []struct {
		name     string
		want     error
		tampered []byte
	}{
		{
			name:     "one byte changed inside the first chunk",
			want:     awsverify.ErrChunkSignatureMismatch,
			tampered: flipByteInFrameData(frames, 0),
		},
		{
			name:     "chunk signature changed",
			want:     awsverify.ErrChunkSignatureMismatch,
			tampered: flipSignatureHex(frames, 0),
		},
		{
			name:     "first two chunks swapped",
			want:     awsverify.ErrChunkSignatureMismatch,
			tampered: reassemble([]chunkFrame{frames[1], frames[0], frames[2], frames[3]}),
		},
		{
			name:     "last data chunk replaced by an earlier one",
			want:     awsverify.ErrChunkSignatureMismatch,
			tampered: reassemble([]chunkFrame{frames[0], frames[1], frames[0], frames[3]}),
		},
		{
			name:     "terminator chunk removed",
			want:     nil,
			tampered: reassemble(frames[:3]),
		},
		{
			name:     "stream cut in the middle of a chunk",
			want:     nil,
			tampered: append(append([]byte(nil), frames[0].bytes()...), frames[1].header...),
		},
		{
			name:     "chunk size inflated beyond the framed data",
			want:     nil,
			tampered: reassemble([]chunkFrame{{header: bytes.Replace(frames[0].header, []byte(strconv.FormatInt(int64(clientChunkSize), 16)), []byte(strconv.FormatInt(int64(clientChunkSize)+1, 16)), 1), data: frames[0].data}, frames[1], frames[2], frames[3]}),
		},
	}

	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			req := framedRequest(t, signed, mutation.tampered)
			reader, _ := openStream(t, req)
			_, readErr := io.ReadAll(reader)
			if readErr == nil {
				t.Fatalf("the tampered stream decoded without an error")
			}
			if mutation.want != nil && !errors.Is(readErr, mutation.want) {
				t.Fatalf("error = %v, want %v", readErr, mutation.want)
			}
			t.Logf("rejected with %v", readErr)
		})
	}

	t.Run("prefix released before the failure is authentic", func(t *testing.T) {
		tampered := flipByteInFrameData(frames, 1)
		reader, _ := openStream(t, framedRequest(t, signed, tampered))
		collected, readErr := io.ReadAll(reader)
		if readErr == nil {
			t.Fatal("tampered stream accepted")
		}
		if !bytes.Equal(collected, body[:2*clientChunkSize][:clientChunkSize]) {
			t.Fatalf("released %d bytes before failing, want the first chunk only", len(collected))
		}
	})

	t.Run("declared decoded length is tampered", func(t *testing.T) {
		req := framedRequest(t, signed, encoded)
		req.Header.Set("x-amz-decoded-content-length", "1")
		mustReject(t, streamVerifier(), req, verifyOptions(), "tampered x-amz-decoded-content-length")
	})
}

func flipByteInFrameData(frames []chunkFrame, index int) []byte {
	clone := append([]chunkFrame(nil), frames...)
	data := append([]byte(nil), clone[index].data...)
	data[10] ^= 0x20
	clone[index].data = data
	return reassemble(clone)
}

func flipSignatureHex(frames []chunkFrame, index int) []byte {
	clone := append([]chunkFrame(nil), frames...)
	header := append([]byte(nil), clone[index].header...)
	marker := bytes.Index(header, []byte(";chunk-signature="))
	position := marker + len(";chunk-signature=") + 5
	if header[position] == 'a' {
		header[position] = 'b'
	} else {
		header[position] = 'a'
	}
	clone[index].header = header
	return reassemble(clone)
}

func TestSigV4StreamingLimits(t *testing.T) {
	body := patternBytes(2 * clientChunkSize)
	signed, encoded := signStream(t, body, "", streamingPayload, nil)

	t.Run("chunk larger than the configured maximum", func(t *testing.T) {
		req := framedRequest(t, signed, encoded)
		verifier := streamVerifier()
		result := mustVerify(t, verifier, req, verifyOptions())
		reader, err := verifier.ChunkedReader(req, result, awsverify.ChunkedReaderOptions{MaxChunkSize: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(reader); !errors.Is(err, awsverify.ErrChunkSizeTooLarge) {
			t.Fatalf("error = %v, want ErrChunkSizeTooLarge", err)
		}
	})

	t.Run("temporary credential requires the session token", func(t *testing.T) {
		req := buildRequest(t, http.MethodPut, "/bucket/stream.bin", body)
		req.ContentLength = int64(len(body))
		stsSigned := signer.StreamingSignV4(req, accessKeyID, secretAccessKey, sessionToken, region,
			int64(len(body)), fixedStreamingTime, newHasher())
		stream := framedRequest(t, stsSigned, encodeStream(t, stsSigned))
		store := newSessionVerifier(func() time.Time { return fixedStreamingTime }, sessionToken)

		result := mustVerify(t, store, stream, verifyOptions())
		reader, err := store.ChunkedReader(stream, result, awsverify.ChunkedReaderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err := io.ReadAll(reader); err != nil || !bytes.Equal(decoded, body) {
			t.Fatalf("decoded %d bytes, err %v", len(decoded), err)
		}

		withoutToken := framedRequest(t, stsSigned, encodeStream(t, stsSigned))
		withoutToken.Header.Del("X-Amz-Security-Token")
		if _, err := store.Verify(withoutToken, verifyOptions()); !errors.Is(err, awsverify.ErrSessionTokenMismatch) {
			t.Fatalf("error = %v, want ErrSessionTokenMismatch", err)
		}
	})
}

func patternBytes(size int) []byte {
	out := make([]byte, size)
	for index := range out {
		out[index] = byte('a' + index%26)
	}
	return out
}

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
