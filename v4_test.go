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
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDeriveSigningKeyAWSVector(t *testing.T) {
	got := hexString(deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam"))
	want := "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
	if got != want {
		t.Fatalf("signing key mismatch\n got %s\nwant %s", got, want)
	}
}

func TestVerifyV4Header(t *testing.T) {
	verifier := testVerifier(t)
	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt?foo=bar&foo=baz&empty", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("Range", "bytes=0-9")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")

	scope := "20260101/us-east-1/s3/aws4_request"
	signedHeaders := []string{"host", "range", "x-amz-content-sha256", "x-amz-date"}
	signature := signV4Header(req, scope, signedHeaders, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, signedHeaders))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Version != SigV4 || result.AccessKeyID != testAccessKey || result.Service != "s3" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.PayloadHash != emptyPayloadHash {
		t.Fatalf("payload hash = %q", result.PayloadHash)
	}
}

func TestVerifyV4HeaderRejectsBadSignature(t *testing.T) {
	verifier := testVerifier(t)
	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	scope := "20260101/us-east-1/s3/aws4_request"
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	signature := signV4Header(req, scope, signedHeaders, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, strings.Repeat("0", 64), signedHeaders))
	if signature == strings.Repeat("0", 64) {
		t.Fatal("expected signature unexpectedly zero")
	}
	_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerifyV4Presigned(t *testing.T) {
	verifier := testVerifier(t)
	target, err := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/path with plus+and unicode.txt?plain=value")
	if err != nil {
		t.Fatal(err)
	}
	scope := "20260101/us-east-1/s3/aws4_request"
	addV4PresignedParameters(target, scope, "300", testTime)
	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = target.Host
	signature := signV4Presigned(req, scope, []string{"host"}, unsignedPayloadHash, testTime)
	signed := completeV4PresignedURL(target, signature)

	result, err := verifier.Verify(signed, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.ExpiresAt.IsZero() {
		t.Fatal("presigned result has no expiration")
	}
}

func TestVerifyV4PresignedRejectsExpired(t *testing.T) {
	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		}),
		Clock: func() time.Time { return testTime.Add(2 * time.Second) },
	})
	target, _ := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
	scope := "20260101/us-east-1/s3/aws4_request"
	addV4PresignedParameters(target, scope, "1", testTime)
	req, _ := http.NewRequest(http.MethodGet, target.String(), nil)
	req.Host = target.Host
	signature := signV4Presigned(req, scope, []string{"host"}, unsignedPayloadHash, testTime)
	signed := completeV4PresignedURL(target, signature)
	_, err := verifier.Verify(signed, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if !errors.Is(err, ErrExpiredSignature) {
		t.Fatalf("error = %v, want ErrExpiredSignature", err)
	}
}

func TestCanonicalURIEncodesS3Path(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://bucket.example.com/root", nil)
	req.URL.Path = "/a b/c+d/unicode.txt"
	req.Host = "bucket.example.com"
	got := canonicalURI(req, true)
	want := "/a%20b/c%2Bd/unicode.txt"
	if got != want {
		t.Fatalf("canonical URI = %q, want %q", got, want)
	}
}

func TestCanonicalURIPreservesEncodedSlash(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://bucket.example.com/a%2Fb%20c+d%7E", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := canonicalURI(req, true)
	want := "/a%2Fb%20c%2Bd~"
	if got != want {
		t.Fatalf("canonical URI = %q, want %q", got, want)
	}
}

func TestMissingPayloadHashUsesConfiguredDefault(t *testing.T) {
	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		}),
		Clock:              func() time.Time { return testTime },
		DefaultPayloadHash: emptyPayloadHash,
	})
	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	scope := "20260101/us-east-1/s3/aws4_request"
	headers := []string{"host", "x-amz-date"}
	signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.PayloadHash != emptyPayloadHash {
		t.Fatalf("payload hash = %q", result.PayloadHash)
	}
}

func TestTemporaryCredentialRequiresMatchingToken(t *testing.T) {
	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {
				AccessKeyID:     testAccessKey,
				SecretAccessKey: testSecretKey,
				SessionToken:    "temporary-token",
			},
		}),
		Clock: func() time.Time { return testTime },
	})
	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	scope := "20260101/us-east-1/s3/aws4_request"
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

	_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if !errors.Is(err, ErrSessionTokenMismatch) {
		t.Fatalf("error = %v, want ErrSessionTokenMismatch", err)
	}
}

func TestV4SignatureIsConstant(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Host = "examplebucket.s3.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	scope := "20260101/us-east-1/s3/aws4_request"
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	first := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
	second := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
	if first != second {
		t.Fatal("signature calculation is not deterministic")
	}
	if !validHexSignature(first) {
		t.Fatalf("invalid signature %q", first)
	}
}

// TestVerifyRequiresPinnedScope covers the three SigV4 shapes and the two SigV2
// ones: a SigV4 request is only verified against a scope the caller named, while
// SigV2 carries no scope to pin.
func TestVerifyRequiresPinnedScope(t *testing.T) {
	verifier := testVerifier(t)
	scope := "20260101/us-east-1/s3/aws4_request"

	v4PostForm := func() url.Values {
		document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[]}`
		encoded := base64.StdEncoding.EncodeToString([]byte(document))
		key := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
		form := url.Values{}
		form.Set("policy", encoded)
		form.Set("x-amz-algorithm", v4Algorithm)
		form.Set("x-amz-credential", testAccessKey+"/"+scope)
		form.Set("x-amz-date", "20260101T000000Z")
		form.Set("x-amz-signature", hexString(hmacSHA256(key, []byte(encoded))))
		return form
	}
	shapes := []struct {
		name   string
		verify func(VerifyOptions) error
	}{
		{
			name: "header",
			verify: func(options VerifyOptions) error {
				req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
				req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
				req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
				req.Header.Set("X-Amz-Date", "20260101T000000Z")
				headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
				req.Header.Set("Authorization", v4AuthorizationHeader(scope,
					signV4Header(req, scope, headers, emptyPayloadHash, testTime), headers))
				_, err := verifier.Verify(req, options)
				return err
			},
		},
		{
			name: "presigned",
			verify: func(options VerifyOptions) error {
				target, err := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
				if err != nil {
					t.Fatal(err)
				}
				addV4PresignedParameters(target, scope, "900", testTime)
				req, err := http.NewRequest(http.MethodGet, target.String(), nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = target.Host
				signed := completeV4PresignedURL(target,
					signV4Presigned(req, scope, []string{"host"}, unsignedPayloadHash, testTime))
				_, err = verifier.Verify(signed, options)
				return err
			},
		},
		{
			name: "post policy",
			verify: func(options VerifyOptions) error {
				_, err := verifier.VerifyPostPolicy(v4PostForm(), options)
				return err
			},
		},
	}

	for _, shape := range shapes {
		for _, test := range []struct {
			name    string
			options VerifyOptions
			want    error
		}{
			{"neither field set", VerifyOptions{}, ErrScopeRequired},
			{"service only", VerifyOptions{Service: "s3"}, ErrScopeRequired},
			{"region only", VerifyOptions{Region: "us-east-1"}, ErrScopeRequired},
			{"scope pinned", VerifyOptions{Service: "s3", Region: "us-east-1"}, nil},
			{"another region pinned", VerifyOptions{Service: "s3", Region: "eu-west-1"}, ErrMalformedCredential},
			{"another service pinned", VerifyOptions{Service: "execute-api", Region: "us-east-1"}, ErrMalformedCredential},
		} {
			t.Run(shape.name+" "+test.name, func(t *testing.T) {
				err := shape.verify(test.options)
				if test.want == nil {
					if err != nil {
						t.Fatalf("Verify() error = %v", err)
					}
					return
				}
				if !errors.Is(err, test.want) {
					t.Fatalf("error = %v, want %v", err, test.want)
				}
			})
		}
	}

	t.Run("sigv2 header needs no scope", func(t *testing.T) {
		legacy := awsDocsVerifier(v2SigningTime)
		bucket := VerifyOptions{S3Bucket: "johnsmith"}
		req := httptest.NewRequest(http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg", nil)
		req.Host = "johnsmith.s3.amazonaws.com"
		req.Header.Set("Date", v2DateHeader)
		req.Header.Set("Authorization", "AWS "+testAccessKey+":"+SignV2Request(testSecretKey, req, bucket))
		if _, err := legacy.Verify(req, bucket); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("sigv2 post policy needs no scope", func(t *testing.T) {
		document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[]}`
		encoded := base64.StdEncoding.EncodeToString([]byte(document))
		form := url.Values{}
		form.Set("policy", encoded)
		form.Set("AWSAccessKeyId", testAccessKey)
		form.Set("Signature", SignV2(testSecretKey, encoded))
		if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); err != nil {
			t.Fatalf("VerifyPostPolicy() error = %v", err)
		}
	})
}
