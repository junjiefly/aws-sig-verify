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

func TestChunkedReaderVerifiesSignedChunks(t *testing.T) {
	verifier := testVerifier(t)
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")

	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, scope, headers, streamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	previous := seed
	first := expectedChunkSignature(signingKey, testTime, scope, previous, []byte("hello"))
	previous = first
	second := expectedChunkSignature(signingKey, testTime, scope, previous, []byte("world"))
	previous = second
	final := expectedChunkSignature(signingKey, testTime, scope, previous, nil)
	body := strings.Join([]string{
		"5;chunk-signature=" + first + "\r\nhello\r\n",
		"5;chunk-signature=" + second + "\r\nworld\r\n",
		"0;chunk-signature=" + final + "\r\n\r\n",
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
	if string(decoded) != "helloworld" {
		t.Fatalf("decoded body = %q", decoded)
	}
}

func TestChunkedReaderRejectsChangedChunk(t *testing.T) {
	verifier := testVerifier(t)
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, scope, headers, streamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	first := expectedChunkSignature(signingKey, testTime, scope, seed, []byte("hello"))
	final := expectedChunkSignature(signingKey, testTime, scope, first, nil)
	body := "5;chunk-signature=" + first + "\r\nHELLO\r\n0;chunk-signature=" + final + "\r\n\r\n"
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
		t.Fatalf("ReadAll() error = %v, want chunk mismatch", err)
	}
}

func TestChunkedReaderReadsUnsignedTrailerStream(t *testing.T) {
	verifier := testVerifier(t)
	scope := "20260101/us-east-1/s3/aws4_request"
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", unsignedStreamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, scope, headers, unsignedStreamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))
	req.Body = io.NopCloser(strings.NewReader("5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAA\r\n\r\n"))

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
}

// Found by fuzzing: every chunk signature can be correct while the framing is
// not what AWS clients send, so the header terminator is verified too.
func TestChunkedReaderRejectsLFTerminatedChunkHeader(t *testing.T) {
	verifier := testVerifier(t)
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, scope, headers, streamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	first := expectedChunkSignature(signingKey, testTime, scope, seed, []byte("hello"))
	final := expectedChunkSignature(signingKey, testTime, scope, first, nil)
	req.Body = io.NopCloser(strings.NewReader(
		"5;chunk-signature=" + first + "\nhello\r\n0;chunk-signature=" + final + "\r\n\r\n"))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	defer reader.Close()
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrMalformedChunk) {
		t.Fatalf("ReadAll() error = %v, want malformed streaming payload", err)
	}
}

// The size field is a plain hexadecimal number. strconv.ParseInt also accepts a
// sign, and a value too wide for int64 only fails after parsing, so both shapes
// are pinned. MinIO's server rejects a signed size and reports an over-wide one
// as too large, which is what this package does.
func TestChunkedReaderChunkSizeSyntax(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		size    string
		payload string
		wantErr error
	}{
		{name: "lowercase", size: "5", payload: "hello"},
		{name: "uppercase", size: "A", payload: "helloworld"},
		{name: "leading zeros", size: "0005", payload: "hello"},
		{name: "signed", size: "+5", payload: "hello", wantErr: ErrMalformedChunk},
		{name: "prefixed", size: "0x5", payload: "hello", wantErr: ErrMalformedChunk},
		{name: "wider than int64", size: "ffffffffffffffffff", payload: "hello", wantErr: ErrChunkSizeTooLarge},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := signedSingleChunkStream(t, testCase.size, []byte(testCase.payload))
			reader := openSignedChunkedReader(t, req)
			defer reader.Close()
			decoded, err := io.ReadAll(reader)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("ReadAll() error = %v, want %v", err, testCase.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			if string(decoded) != testCase.payload {
				t.Fatalf("decoded = %q, want %q", decoded, testCase.payload)
			}
		})
	}
}

// signedSingleChunkStream signs one chunk of payload plus the final zero chunk,
// writing the given text as the size field of the first chunk header.
func signedSingleChunkStream(t *testing.T, sizeText string, payload []byte) *http.Request {
	t.Helper()
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, scope, headers, streamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	first := expectedChunkSignature(signingKey, testTime, scope, seed, payload)
	final := expectedChunkSignature(signingKey, testTime, scope, first, nil)
	req.Body = io.NopCloser(strings.NewReader(sizeText + ";chunk-signature=" + first + "\r\n" +
		string(payload) + "\r\n0;chunk-signature=" + final + "\r\n\r\n"))
	return req
}

func openSignedChunkedReader(t *testing.T, req *http.Request) *ChunkedReader {
	t.Helper()
	verifier := testVerifier(t)
	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
	if err != nil {
		t.Fatalf("ChunkedReader() error = %v", err)
	}
	return reader
}

// The live service stores a stream that stops after the last data chunk, with no
// terminator chunk at all. This package's reader requires one, so the same stream
// ends as a truncation here; that asymmetry is recorded in docs/VERIFICATION.md.
func TestChunkedReaderRequiresTerminatorChunk(t *testing.T) {
	scope := "20260101/us-east-1/s3/aws4_request"
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, scope, headers, streamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))

	first := expectedChunkSignature(signingKey, testTime, scope, seed, []byte("first-"))
	second := expectedChunkSignature(signingKey, testTime, scope, first, []byte("second-"))
	req.Body = io.NopCloser(strings.NewReader(
		"6;chunk-signature=" + first + "\r\nfirst-\r\n" +
			"7;chunk-signature=" + second + "\r\nsecond-\r\n"))

	decoded, err := io.ReadAll(openSignedChunkedReader(t, req))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if string(decoded) != "first-second-" {
		t.Fatalf("decoded = %q before the stream was reported truncated", decoded)
	}
}
