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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// signedTrailerRequest builds a STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER PUT
// whose single "hello" chunk is correctly signed and whose trailer signature
// covers signedOver, which may differ from the bytes put on the wire.
func signedTrailerRequest(t *testing.T, declared, block, signedOver string) *http.Request {
	t.Helper()
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")

	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	req.Header.Set("X-Amz-Trailer", declared)
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-trailer"}
	seed := signV4Header(req, scope, headers, streamingPayloadTrailer, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	chunkSignature := expectedChunkSignature(signingKey, testTime, scope, seed, []byte("hello"))
	finalChunkSignature := expectedChunkSignature(signingKey, testTime, scope, chunkSignature, nil)
	trailerSignature := expectedTrailerSignature(signingKey, testTime, scope, finalChunkSignature, []byte(signedOver))
	req.Body = io.NopCloser(strings.NewReader(strings.Join([]string{
		"5;chunk-signature=" + chunkSignature + "\r\nhello\r\n",
		"0;chunk-signature=" + finalChunkSignature + "\r\n",
		block + "\r\n",
		"x-amz-trailer-signature:" + trailerSignature + "\r\n\r\n",
	}, "")))
	return req
}

func readSignedTrailer(t *testing.T, req *http.Request) ([]byte, http.Header, error) {
	t.Helper()
	verifier := testVerifier(t)
	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		return nil, nil, err
	}
	reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}
	return decoded, reader.Trailers(), nil
}

// The trailer hash covers the transmitted block bytes, so a client that frames
// trailer lines with CRLF verifies as long as it signs those exact bytes.
func TestSignedTrailerChunkedReaderAcceptsCRLFTerminatedBlock(t *testing.T) {
	decoded, trailers, err := readSignedTrailer(t, signedTrailerRequest(t,
		"X-Amz-Checksum-CRC32", "x-amz-checksum-crc32:AAAAAA==\r\n", "x-amz-checksum-crc32:AAAAAA==\r\n"))
	if err != nil {
		t.Fatalf("read error = %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded body = %q", decoded)
	}
	if got := trailers.Get("X-Amz-Checksum-Crc32"); got != "AAAAAA==" {
		t.Fatalf("checksum trailer = %q, trailers = %v", got, trailers)
	}
}

// A client that signs the LF-normalized block but transmits CRLF cannot be
// verified without hashing bytes that were never sent; MinIO's server does
// exactly that and accepts the stream, this package rejects it.
func TestSignedTrailerChunkedReaderRejectsReframedBlock(t *testing.T) {
	_, _, err := readSignedTrailer(t, signedTrailerRequest(t,
		"X-Amz-Checksum-CRC32", "x-amz-checksum-crc32:AAAAAA==\r\n", "x-amz-checksum-crc32:AAAAAA==\n"))
	if !errors.Is(err, ErrChunkSignatureMismatch) {
		t.Fatalf("read error = %v, want %v", err, ErrChunkSignatureMismatch)
	}
}

// MinIO's server also tolerates a trailer line that ends the block with its own
// CRLF instead of a following blank line, reading the signature line only after
// that. Without the blank line the block has no terminator here.
func TestSignedTrailerChunkedReaderRequiresBlockTerminator(t *testing.T) {
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	req.Header.Set("X-Amz-Trailer", "X-Amz-Checksum-CRC32")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-trailer"}
	seed := signV4Header(req, scope, headers, streamingPayloadTrailer, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	chunkSignature := expectedChunkSignature(signingKey, testTime, scope, seed, []byte("hello"))
	finalChunkSignature := expectedChunkSignature(signingKey, testTime, scope, chunkSignature, nil)
	trailerSignature := expectedTrailerSignature(signingKey, testTime, scope, finalChunkSignature, []byte("x-amz-checksum-crc32:AAAAAA==\n"))
	req.Body = io.NopCloser(strings.NewReader("5;chunk-signature=" + chunkSignature + "\r\nhello\r\n0;chunk-signature=" +
		finalChunkSignature + "\r\nx-amz-checksum-crc32:AAAAAA==\r\nx-amz-trailer-signature:" + trailerSignature + "\r\n\r\n"))

	_, _, err := readSignedTrailer(t, req)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v, want a malformed stream", err)
	}
}

// Trailer names are HTTP header names, so they match case-insensitively. MinIO's
// server compares the declared names after lowering them but looks the received
// name up unchanged, so it rejects a capitalized trailer line.
func TestSignedTrailerChunkedReaderAcceptsMixedCaseTrailerName(t *testing.T) {
	decoded, trailers, err := readSignedTrailer(t, signedTrailerRequest(t,
		"x-amz-checksum-crc32", "X-Amz-Checksum-Crc32:AAAAAA==\n", "X-Amz-Checksum-Crc32:AAAAAA==\n"))
	if err != nil {
		t.Fatalf("read error = %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded body = %q", decoded)
	}
	if got := trailers.Get("X-Amz-Checksum-Crc32"); got != "AAAAAA==" {
		t.Fatalf("checksum trailer = %q, trailers = %v", got, trailers)
	}
}
