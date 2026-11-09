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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func signedPutRequest(t *testing.T, body []byte, declaredHash string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", bytes.NewReader(body))
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", declaredHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	scope := "20260101/us-east-1/s3/aws4_request"
	signature := signV4Header(req, scope, headers, declaredHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))
	return req
}

func TestPayloadHashReaderAcceptsSignedBody(t *testing.T) {
	body := []byte("the object the client signed")
	digest := sha256.Sum256(body)
	declared := hex.EncodeToString(digest[:])

	req := signedPutRequest(t, body, declared)
	result, err := testVerifier(t).Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.PayloadHash != declared {
		t.Fatalf("PayloadHash = %q, want %q", result.PayloadHash, declared)
	}

	reader, err := NewPayloadHashReader(req.Body, result.PayloadHash)
	if err != nil {
		t.Fatalf("NewPayloadHashReader() error = %v", err)
	}
	if !reader.Checked() {
		t.Fatal("Checked() = false for a request that declares a SHA-256")
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body = %q, want %q", got, body)
	}
	if err := reader.Err(); err != nil {
		t.Fatalf("Err() = %v after a matching body", err)
	}
}

func TestPayloadHashReaderRejectsSubstitutedBody(t *testing.T) {
	// The signature is over the declared hash, not the bytes. Swapping the body
	// while keeping the signed request intact is exactly what this reader
	// catches, and nothing else in the verifier does.
	signedBody := []byte("the object the client signed")
	digest := sha256.Sum256(signedBody)
	declared := hex.EncodeToString(digest[:])

	req := signedPutRequest(t, signedBody, declared)
	result, err := testVerifier(t).Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	reader, err := NewPayloadHashReader(strings.NewReader("a different object"), result.PayloadHash)
	if err != nil {
		t.Fatalf("NewPayloadHashReader() error = %v", err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrPayloadHashMismatch) {
		t.Fatalf("ReadAll() error = %v, want ErrPayloadHashMismatch", err)
	}
	if err := reader.Err(); !errors.Is(err, ErrPayloadHashMismatch) {
		t.Fatalf("Err() = %v, want ErrPayloadHashMismatch", err)
	}
}

func TestPayloadHashReaderEmptyBody(t *testing.T) {
	req := signedPutRequest(t, nil, EmptyPayloadSHA256)
	result, err := testVerifier(t).Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := NewPayloadHashReader(req.Body, result.PayloadHash)
	if err != nil {
		t.Fatalf("NewPayloadHashReader() error = %v", err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
}

func TestPayloadHashReaderPassesThroughUnhashedPayloads(t *testing.T) {
	body := []byte("payload bytes")
	for _, declared := range []string{
		unsignedPayloadHash,
		streamingPayload,
		streamingPayloadTrailer,
		unsignedStreamingPayload,
	} {
		t.Run(declared, func(t *testing.T) {
			reader, err := NewPayloadHashReader(bytes.NewReader(body), declared)
			if err != nil {
				t.Fatalf("NewPayloadHashReader() error = %v", err)
			}
			if reader.Checked() {
				t.Fatal("Checked() = true for a payload hash that carries no hash")
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("body = %q, want %q", got, body)
			}
			if err := reader.Err(); err != nil {
				t.Fatalf("Err() = %v, want nil", err)
			}
		})
	}
}

func TestPayloadHashReaderRejectsUnusableDeclaredHash(t *testing.T) {
	for _, declared := range []string{
		"",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
		"not-a-hex-digest-not-a-hex-digest-not-a-hex-digest-not-a-hex-digest-",
		"STREAMING-UNSIGNED-PAYLOAD",
	} {
		t.Run(declared, func(t *testing.T) {
			reader, err := NewPayloadHashReader(bytes.NewReader([]byte("x")), declared)
			if reader != nil {
				t.Fatalf("reader = %v, want nil", reader)
			}
			if !errors.Is(err, ErrMalformedAuthorization) {
				t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
			}
		})
	}
}

func TestPayloadHashReaderAcceptsUppercaseDigest(t *testing.T) {
	body := []byte("the object the client signed")
	digest := sha256.Sum256(body)
	reader, err := NewPayloadHashReader(bytes.NewReader(body), strings.ToUpper(hex.EncodeToString(digest[:])))
	if err != nil {
		t.Fatalf("NewPayloadHashReader() error = %v", err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
}
