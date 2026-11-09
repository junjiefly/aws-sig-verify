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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignedTrailerChunkedReader(t *testing.T) {
	verifier := testVerifier(t)
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
	trailerValue := "x-amz-checksum-crc32:AAAAAA==\n"
	trailerSignature := expectedTrailerSignature(signingKey, testTime, scope, finalChunkSignature, []byte(trailerValue))
	body := strings.Join([]string{
		"5;chunk-signature=" + chunkSignature + "\r\nhello\r\n",
		"0;chunk-signature=" + finalChunkSignature + "\r\n",
		trailerValue + "\r\n",
		"x-amz-trailer-signature:" + trailerSignature + "\r\n\r\n",
	}, "")
	req.Body = io.NopCloser(strings.NewReader(body))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded body = %q", decoded)
	}
	trailers := reader.Trailers()
	if got := trailers.Get("X-Amz-Checksum-Crc32"); got != "AAAAAA==" {
		t.Fatalf("checksum trailer = %q, trailers = %v", got, trailers)
	}
}

func TestSignedTrailerChunkedReaderRejectsBadSignature(t *testing.T) {
	verifier := testVerifier(t)
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
	trailerValue := "x-amz-checksum-crc32:AAAAAA==\n"
	trailerSignature := expectedTrailerSignature(signingKey, testTime, scope, finalChunkSignature, []byte("x-amz-checksum-crc32:BBBBBB==\n"))
	body := strings.Join([]string{
		"5;chunk-signature=" + chunkSignature + "\r\nhello\r\n",
		"0;chunk-signature=" + finalChunkSignature + "\r\n",
		trailerValue + "\r\n",
		"x-amz-trailer-signature:" + trailerSignature + "\r\n\r\n",
	}, "")
	req.Body = io.NopCloser(strings.NewReader(body))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	defer reader.Close()
	_, err = io.ReadAll(reader)
	if err == nil || !strings.Contains(err.Error(), ErrChunkSignatureMismatch.Error()) {
		t.Fatalf("ReadAll() error = %v, want trailer signature mismatch", err)
	}
}

func TestSignedTrailerChunkedReaderWithMultipleTrailers(t *testing.T) {
	verifier := testVerifier(t)
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")

	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	req.Header.Set("X-Amz-Trailer", "X-Amz-Checksum-CRC32,X-Amz-Checksum-CRC32C")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-trailer"}
	seed := signV4Header(req, scope, headers, streamingPayloadTrailer, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	chunkSignature := expectedChunkSignature(signingKey, testTime, scope, seed, []byte("hello"))
	finalChunkSignature := expectedChunkSignature(signingKey, testTime, scope, chunkSignature, nil)
	trailerBlock := "x-amz-checksum-crc32:AAAAAA==\nx-amz-checksum-crc32c:BBBBAA==\n"
	trailerSignature := expectedTrailerSignature(signingKey, testTime, scope, finalChunkSignature, []byte(trailerBlock))
	body := strings.Join([]string{
		"5;chunk-signature=" + chunkSignature + "\r\nhello\r\n",
		"0;chunk-signature=" + finalChunkSignature + "\r\n",
		trailerBlock + "\r\n",
		"x-amz-trailer-signature:" + trailerSignature + "\r\n\r\n",
	}, "")
	req.Body = io.NopCloser(strings.NewReader(body))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded body = %q", decoded)
	}
	trailers := reader.Trailers()
	if got := trailers.Get("X-Amz-Checksum-Crc32"); got != "AAAAAA==" {
		t.Fatalf("crc32 trailer = %q, trailers = %v", got, trailers)
	}
	if got := trailers.Get("X-Amz-Checksum-Crc32c"); got != "BBBBAA==" {
		t.Fatalf("crc32c trailer = %q, trailers = %v", got, trailers)
	}
}
