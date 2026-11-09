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
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7/pkg/signer"
)

func TestSigV4StreamingSignedTrailerInterop(t *testing.T) {
	body := patternBytes(clientChunkSize + 5)
	trailers := http.Header{"X-Amz-Checksum-Crc32c": {"OQ=="}, "X-Amz-Meta-Trail": {"tail-value"}}
	signed, encoded := signStream(t, body, "", streamingTrailerPayload, trailers)

	if signed.Header.Get("X-Amz-Trailer") == "" {
		t.Fatal("the client did not declare X-Amz-Trailer")
	}
	reader, result := openStream(t, framedRequest(t, signed, encoded))
	if result.PayloadHash != streamingTrailerPayload {
		t.Fatalf("PayloadHash = %q, want %q", result.PayloadHash, streamingTrailerPayload)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decoding the signed-trailer stream: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("decoded %d bytes, want %d", len(decoded), len(body))
	}
	for name, values := range trailers {
		if got := reader.Trailers().Get(name); got != values[0] {
			t.Errorf("trailer %s = %q, want %q", name, got, values[0])
		}
	}

	t.Run("trailer value changed", func(t *testing.T) {
		tampered := append([]byte(nil), encoded...)
		index := bytes.Index(tampered, []byte("x-amz-checksum-crc32c:"))
		if index < 0 {
			t.Fatalf("trailer block not found in %q", tailOf(encoded))
		}
		position := index + len("x-amz-checksum-crc32c:")
		tampered[position+1] ^= 0x20
		reader, _ := openStream(t, framedRequest(t, signed, tampered))
		if _, err := io.ReadAll(reader); !errors.Is(err, awsverify.ErrChunkSignatureMismatch) {
			t.Fatalf("error = %v, want ErrChunkSignatureMismatch", err)
		}
	})

	t.Run("trailer declared but missing", func(t *testing.T) {
		frames := parseFrames(t, encoded)
		// Drop everything after the terminator chunk header.
		last := frames[len(frames)-1]
		trimmed := reassemble(frames[:len(frames)-1])
		trimmed = append(trimmed, last.header...)
		reader, _ := openStream(t, framedRequest(t, signed, trimmed))
		if _, err := io.ReadAll(reader); err == nil {
			t.Fatal("a stream without its declared trailers was accepted")
		}
	})

	t.Run("unsigned trailer request keeps its framing", func(t *testing.T) {
		req := framedRequest(t, signed, encoded)
		req.Header.Del("X-Amz-Trailer")
		mustReject(t, streamVerifier(), req, verifyOptions(), "X-Amz-Trailer removed from a signed-trailer request")
	})
}

func TestSigV4StreamingUnsignedTrailerInterop(t *testing.T) {
	body := patternBytes(1500)
	req := buildRequest(t, http.MethodPut, "/bucket/stream.bin", body)
	req.Header.Set("X-Amz-Content-Sha256", unsignedTrailerPayload)
	trailers := http.Header{"X-Amz-Checksum-Crc32": {"abcd=="}}

	// The independent client signs the seed request with time.Now, so the
	// verifier uses the real clock here.
	signed := signer.SignV4Trailer(*req, accessKeyID, secretAccessKey, "", region, trailers)
	encoded := encodeStream(t, signed)
	if got := signed.Header.Get("X-Amz-Content-Sha256"); got != unsignedTrailerPayload {
		t.Fatalf("X-Amz-Content-Sha256 = %q, want %q", got, unsignedTrailerPayload)
	}

	verifier := newVerifier(time.Now)
	result := mustVerify(t, verifier, framedRequest(t, signed, encoded), verifyOptions())
	if result.PayloadHash != unsignedTrailerPayload {
		t.Fatalf("PayloadHash = %q, want %q", result.PayloadHash, unsignedTrailerPayload)
	}
	reader, err := verifier.ChunkedReader(framedRequest(t, signed, encoded), result, awsverify.ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("decoding the unsigned-trailer stream: %v", err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("decoded %d bytes, want %d", len(decoded), len(body))
	}
	if got := reader.Trailers().Get("X-Amz-Checksum-Crc32"); got != "abcd==" {
		t.Fatalf("trailer = %q, want %q", got, "abcd==")
	}

	// Documented gap: the trailer block is not signed in this mode, so a changed
	// trailer value still decodes. Callers must validate checksum trailers
	// against the stored object themselves.
	t.Run("trailer payload is not integrity protected", func(t *testing.T) {
		tampered := append([]byte(nil), encoded...)
		index := bytes.Index(tampered, []byte("x-amz-checksum-crc32:"))
		if index < 0 {
			t.Fatalf("trailer block not found in %q", tailOf(encoded))
		}
		position := index + len("x-amz-checksum-crc32:")
		tampered[position+1] ^= 0x20
		reader, _ := openStreamUnsigned(t, signed, tampered)
		if _, err := io.ReadAll(reader); err != nil {
			t.Fatalf("unsigned trailer stream failed after a trailer edit: %v", err)
		}
		t.Logf("accepted with the trailer changed: expected in unsigned mode")
	})
}

func openStreamUnsigned(t *testing.T, signed *http.Request, encoded []byte) (*awsverify.ChunkedReader, *awsverify.Result) {
	t.Helper()
	verifier := newVerifier(time.Now)
	req := framedRequest(t, signed, encoded)
	result := mustVerify(t, verifier, req, verifyOptions())
	reader, err := verifier.ChunkedReader(req, result, awsverify.ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	return reader, result
}

// tailOf returns the last bytes of a stream, enough to see the trailer block.
func tailOf(encoded []byte) []byte {
	if len(encoded) > 200 {
		return encoded[len(encoded)-200:]
	}
	return encoded
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
