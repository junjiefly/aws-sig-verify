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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func requestWithURL(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	return req
}

func TestRequestAuthTypeMatchesOSSEntryPoints(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want AuthType
	}{
		{
			name: "sigv4 header",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodGet, "https://bucket.example.com/object")
				req.Header.Set("Authorization", v4AuthorizationHeader(
					"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host"},
				))
				return req
			}(),
			want: AuthTypeSigV4Header,
		},
		{
			name: "sigv4 streaming",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPut, "https://bucket.example.com/object")
				req.Header.Set("Authorization", v4AuthorizationHeader(
					"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host"},
				))
				req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
				return req
			}(),
			want: AuthTypeStreamingV4,
		},
		{
			name: "sigv4 streaming trailer",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPut, "https://bucket.example.com/object")
				req.Header.Set("Authorization", v4AuthorizationHeader(
					"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host"},
				))
				req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
				return req
			}(),
			want: AuthTypeStreamingV4Tr,
		},
		{
			name: "unsigned streaming trailer without seed signature",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPut, "https://bucket.example.com/object")
				req.Header.Set("X-Amz-Content-Sha256", unsignedStreamingPayload)
				return req
			}(),
			want: AuthTypeUnsignedTr,
		},
		{
			name: "sigv4 presign",
			req: requestWithURL(t, http.MethodGet,
				"https://bucket.example.com/object?X-Amz-Algorithm="+v4Algorithm),
			want: AuthTypeSigV4Presign,
		},
		{
			name: "sigv2 presign",
			req: requestWithURL(t, http.MethodGet,
				"https://bucket.example.com/object?AWSAccessKeyId=AKIA&Signature=c2ln&Expires=1"),
			want: AuthTypeSigV2Presign,
		},
		{
			name: "sigv2 header",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodGet, "https://bucket.example.com/object")
				req.Header.Set("Authorization", "AWS AKIA:c2ln")
				return req
			}(),
			want: AuthTypeSigV2Header,
		},
		{
			name: "sigv2 post policy",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPost, "https://bucket.example.com/")
				req.Header.Set("Content-Type", "multipart/form-data; boundary=example")
				return req
			}(),
			want: AuthTypeSigV2Post,
		},
		{
			name: "sigv4 post policy",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPost,
					"https://bucket.example.com/?x-amz-credential="+url.QueryEscape(testAccessKey+"/20260101/us-east-1/s3/aws4_request"))
				req.Header.Set("Content-Type", "multipart/form-data; boundary=example")
				return req
			}(),
			want: AuthTypeSigV4Post,
		},
		{
			name: "anonymous",
			req:  requestWithURL(t, http.MethodGet, "https://bucket.example.com/object"),
			want: AuthTypeAnonymous,
		},
		{
			name: "jwt is not an AWS signature type",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodGet, "https://bucket.example.com/object")
				req.Header.Set("Authorization", "Bearer token")
				return req
			}(),
			want: AuthTypeUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := RequestAuthType(test.req)
			if !ok || got != test.want {
				t.Fatalf("RequestAuthType() = %q, %v; want %q, true", got, ok, test.want)
			}
		})
	}
}

func TestRequestAccessKeyIDMatchesOSSEntryPoints(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "sigv2 header",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodGet, "https://bucket.example.com/object")
				req.Header.Set("Authorization", "AWS "+testAccessKey+":c2ln")
				return req
			}(),
			want: testAccessKey,
		},
		{
			name: "sigv4 header",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodGet, "https://bucket.example.com/object")
				req.Header.Set("Authorization", v4AuthorizationHeader(
					"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host"},
				))
				return req
			}(),
			want: testAccessKey,
		},
		{
			name: "sigv4 streaming",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPut, "https://bucket.example.com/object")
				req.Header.Set("Authorization", v4AuthorizationHeader(
					"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host"},
				))
				req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
				return req
			}(),
			want: testAccessKey,
		},
		{
			name: "sigv4 streaming trailer",
			req: func() *http.Request {
				req := requestWithURL(t, http.MethodPut, "https://bucket.example.com/object")
				req.Header.Set("Authorization", v4AuthorizationHeader(
					"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host"},
				))
				req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
				return req
			}(),
			want: testAccessKey,
		},
		{
			name: "sigv4 presign",
			req: requestWithURL(t, http.MethodGet,
				"https://bucket.example.com/object?X-Amz-Credential="+url.QueryEscape(
					testAccessKey+"/20260101/us-east-1/s3/aws4_request",
				)),
			want: testAccessKey,
		},
		{
			name: "sigv2 presign",
			req: requestWithURL(t, http.MethodGet,
				"https://bucket.example.com/object?AWSAccessKeyId="+url.QueryEscape(testAccessKey)),
			want: testAccessKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, authType, ok := RequestAccessKeyID(test.req)
			if !ok || got != test.want || authType == AuthTypeUnknown {
				t.Fatalf("RequestAccessKeyID() = %q, %q, %v; want %q", got, authType, ok, test.want)
			}
		})
	}

	invalid := requestWithURL(t, http.MethodGet,
		"https://bucket.example.com/object?X-Amz-Credential=invalid")
	if got, _, ok := RequestAccessKeyID(invalid); ok || got != "" {
		t.Fatalf("RequestAccessKeyID() invalid credential = %q, %v", got, ok)
	}
}

func TestSignV2HelpersMatchAWSVectorAndVerifier(t *testing.T) {
	date := "Tue, 27 Mar 2007 19:36:42 +0000"
	req := requestWithURL(t, http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg")
	req.Header.Set("Date", date)

	stringToSign := "GET\n\n\n" + date + "\n/johnsmith/photos/puppy.jpg"
	if got, want := SignV2(testSecretKey, stringToSign), "bWq2s1WEIj+Ydj0vQ697zp+IXMU="; got != want {
		t.Fatalf("SignV2() = %q, want %q", got, want)
	}

	signature := SignV2Request(testSecretKey, req, VerifyOptions{S3Bucket: "johnsmith"})
	req.Header.Set("Authorization", "AWS "+testAccessKey+":"+signature)
	result, err := awsDocsVerifier(time.Date(2007, 3, 27, 19, 36, 42, 0, time.UTC)).
		Verify(req, VerifyOptions{S3Bucket: "johnsmith"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Version != SigV2 || result.AccessKeyID != testAccessKey {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got := result.Credentials().SecretAccessKey; got != testSecretKey {
		t.Fatalf("result credential secret = %q", got)
	}
}

func TestSignV2PresignAndVerify(t *testing.T) {
	verifier := awsDocsVerifier(testTime)
	req := requestWithURL(t, http.MethodGet,
		"https://johnsmith.s3.amazonaws.com/photos/puppy.jpg?response-content-type=image/jpeg")
	expires := strconv.FormatInt(testTime.Add(10*time.Minute).Unix(), 10)

	signature := SignV2Presign(testSecretKey, req, expires, VerifyOptions{S3Bucket: "johnsmith"})
	query := req.URL.Query()
	query.Set("AWSAccessKeyId", testAccessKey)
	query.Set("Expires", expires)
	query.Set("Signature", signature)
	req.URL.RawQuery = query.Encode()

	result, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Version != SigV2 || result.ExpiresAt.IsZero() {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestV2HeaderCompatibility(t *testing.T) {
	t.Run("x-amz-date and canonical amz headers", func(t *testing.T) {
		verifier := awsDocsVerifier(testTime)
		req := requestWithURL(t, http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg")
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		req.Header.Set("X-Amz-Meta-Owner", "jun jie")
		signature := SignV2Request(testSecretKey, req, VerifyOptions{S3Bucket: "johnsmith"})
		req.Header.Set("Authorization", "AWS "+testAccessKey+":"+signature)

		if _, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"}); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("clock skew", func(t *testing.T) {
		verifier := awsDocsVerifier(testTime.Add(16 * time.Minute))
		req := requestWithURL(t, http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg")
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		signature := SignV2Request(testSecretKey, req, VerifyOptions{S3Bucket: "johnsmith"})
		req.Header.Set("Authorization", "AWS "+testAccessKey+":"+signature)

		_, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"})
		if !errors.Is(err, ErrClockSkew) {
			t.Fatalf("error = %v, want ErrClockSkew", err)
		}
	})

	t.Run("bad presign signature", func(t *testing.T) {
		verifier := awsDocsVerifier(testTime)
		req := requestWithURL(t, http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg")
		expires := strconv.FormatInt(testTime.Add(time.Minute).Unix(), 10)
		query := req.URL.Query()
		query.Set("AWSAccessKeyId", testAccessKey)
		query.Set("Expires", expires)
		query.Set("Signature", base64.StdEncoding.EncodeToString([]byte("bad")))
		req.URL.RawQuery = query.Encode()

		_, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"})
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("error = %v, want ErrSignatureMismatch", err)
		}
	})
}

func TestV4HeaderCompatibility(t *testing.T) {
	t.Run("headers stripped by Go server", func(t *testing.T) {
		verifier := testVerifier(t)
		req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
		req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
		req.ContentLength = 5
		req.TransferEncoding = []string{"chunked"}
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		headers := []string{
			"content-length", "expect", "host", "transfer-encoding",
			"x-amz-content-sha256", "x-amz-date",
		}
		scope := "20260101/us-east-1/s3/aws4_request"
		signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

		if _, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"}); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("unsigned x-amz header", func(t *testing.T) {
		verifier := testVerifier(t)
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test", nil)
		req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		req.Header.Set("X-Amz-Meta-Unsigned", "yes")
		scope := "20260101/us-east-1/s3/aws4_request"
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
		signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

		_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if !errors.Is(err, ErrMissingSignedHeader) {
			t.Fatalf("error = %v, want ErrMissingSignedHeader", err)
		}
	})

	t.Run("region mismatch", func(t *testing.T) {
		verifier := testVerifier(t)
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.eu-west-1.amazonaws.com/test", nil)
		req.Host = "examplebucket.s3.eu-west-1.amazonaws.com"
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		scope := "20260101/eu-west-1/s3/aws4_request"
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
		signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

		_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if !errors.Is(err, ErrMalformedCredential) {
			t.Fatalf("error = %v, want ErrMalformedCredential", err)
		}
	})

	t.Run("missing payload hash", func(t *testing.T) {
		verifier := testVerifier(t)
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test", nil)
		req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		scope := "20260101/us-east-1/s3/aws4_request"
		headers := []string{"host", "x-amz-date"}
		signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

		_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if !errors.Is(err, ErrPayloadHashRequired) {
			t.Fatalf("error = %v, want ErrPayloadHashRequired", err)
		}
	})
}

func TestV4PresignedCompatibility(t *testing.T) {
	t.Run("credential-only entry point still reports missing algorithm", func(t *testing.T) {
		verifier := testVerifier(t)
		req := requestWithURL(t, http.MethodGet,
			"https://examplebucket.s3.us-east-1.amazonaws.com/test.txt?X-Amz-Credential="+
				url.QueryEscape(testAccessKey+"/20260101/us-east-1/s3/aws4_request"))
		_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if !errors.Is(err, ErrUnsupportedSignatureVersion) {
			t.Fatalf("error = %v, want ErrUnsupportedSignatureVersion", err)
		}
	})

	tests := []struct {
		name        string
		scope       string
		expires     string
		signingTime time.Time
		want        error
	}{
		{name: "invalid expires", scope: "20260101/us-east-1/s3/aws4_request", expires: "bad", signingTime: testTime, want: ErrMalformedAuthorization},
		{name: "zero expires", scope: "20260101/us-east-1/s3/aws4_request", expires: "0", signingTime: testTime, want: ErrMalformedAuthorization},
		{name: "expires too long", scope: "20260101/us-east-1/s3/aws4_request", expires: "604801", signingTime: testTime, want: ErrPresignExpiryTooLong},
		{name: "region mismatch", scope: "20260101/eu-west-1/s3/aws4_request", expires: "300", signingTime: testTime, want: ErrMalformedCredential},
		{name: "future signing time", scope: "20260101/us-east-1/s3/aws4_request", expires: "300", signingTime: testTime.Add(16 * time.Minute), want: ErrClockSkew},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := testVerifier(t)
			target, err := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
			if err != nil {
				t.Fatal(err)
			}
			addV4PresignedParameters(target, test.scope, test.expires, test.signingTime)
			req, err := http.NewRequest(http.MethodGet, target.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = target.Host
			signature := signV4Presigned(req, test.scope, []string{"host"}, unsignedPayloadHash, test.signingTime)
			signed := completeV4PresignedURL(target, signature)

			_, err = verifier.Verify(signed, VerifyOptions{Service: "s3", Region: "us-east-1"})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	t.Run("missing expires", func(t *testing.T) {
		// A presigned URL without X-Amz-Expires has no stated lifetime. MinIO
		// lists the parameter as mandatory, so this verifier rejects the request
		// instead of inventing a default.
		verifier := testVerifier(t)
		target, err := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
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

		query := signed.URL.Query()
		query.Del("X-Amz-Expires")
		signed.URL.RawQuery = query.Encode()

		if _, err := verifier.Verify(signed, VerifyOptions{Service: "s3", Region: "us-east-1"}); !errors.Is(err, ErrMalformedAuthorization) {
			t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
		}
	})
}

func TestPostPolicyCompatibility(t *testing.T) {
	const policy = `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"bucket":"examplebucket"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(policy))

	t.Run("capital Signature field", func(t *testing.T) {
		verifier := testVerifier(t)
		form := url.Values{}
		form.Set("AWSAccessKeyId", testAccessKey)
		form.Set("policy", encoded)
		form.Set("bucket", "examplebucket")
		form.Set("Signature", SignV2(testSecretKey, encoded))
		result, err := verifier.VerifyPostPolicy(form, VerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyPostPolicy() error = %v", err)
		}
		if result.Version != SigV2 || string(result.Policy) != policy {
			t.Fatalf("unexpected result: %+v", result)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		verifier := testVerifier(t)
		form := url.Values{}
		form.Set("AWSAccessKeyId", testAccessKey)
		form.Set("policy", encoded)
		form.Set("Signature", SignV2(testSecretKey, "other policy"))
		if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("error = %v, want ErrSignatureMismatch", err)
		}
	})

	t.Run("expired policy", func(t *testing.T) {
		verifier := testVerifier(t)
		expired := `{"expiration":"2025-01-01T00:00:00Z","conditions":[]}`
		form := url.Values{}
		form.Set("AWSAccessKeyId", testAccessKey)
		form.Set("policy", base64.StdEncoding.EncodeToString([]byte(expired)))
		form.Set("Signature", SignV2(testSecretKey, base64.StdEncoding.EncodeToString([]byte(expired))))
		if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrExpiredSignature) {
			t.Fatalf("error = %v, want ErrExpiredSignature", err)
		}
	})

	t.Run("session token mismatch", func(t *testing.T) {
		verifier := NewVerifier(Config{
			Credentials: StaticCredentials(map[string]Credentials{
				testAccessKey: {
					AccessKeyID:     testAccessKey,
					SecretAccessKey: testSecretKey,
					SessionToken:    "expected-token",
				},
			}),
			Clock: func() time.Time { return testTime },
		})
		scope := "20260101/us-east-1/s3/aws4_request"
		key := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
		form := url.Values{}
		form.Set("policy", encoded)
		form.Set("x-amz-algorithm", v4Algorithm)
		form.Set("x-amz-credential", testAccessKey+"/"+scope)
		form.Set("x-amz-date", "20260101T000000Z")
		form.Set("x-amz-signature", hexString(hmacSHA256(key, []byte(encoded))))
		form.Set("x-amz-security-token", "wrong-token")
		if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{Service: "s3", Region: "us-east-1"}); !errors.Is(err, ErrSessionTokenMismatch) {
			t.Fatalf("error = %v, want ErrSessionTokenMismatch", err)
		}
	})

	t.Run("access key extraction", func(t *testing.T) {
		form := url.Values{}
		form.Set("x-amz-credential", testAccessKey+"/20260101/us-east-1/s3/aws4_request")
		accessKeyID, authType, ok := RequestPostPolicyAccessKeyID(form)
		if !ok || accessKeyID != testAccessKey || authType != AuthTypeSigV4Post {
			t.Fatalf("got %q, %q, %v", accessKeyID, authType, ok)
		}
	})
}

func TestStreamingCompatibility(t *testing.T) {
	t.Run("unsigned trailer exposes trailers", func(t *testing.T) {
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
		if _, err := io.ReadAll(reader); err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if got := reader.Trailers().Get("X-Amz-Checksum-Crc32"); got != "AAAA" {
			t.Fatalf("trailer = %q", got)
		}
	})

	t.Run("chunk too large", func(t *testing.T) {
		verifier := testVerifier(t)
		scope := "20260101/us-east-1/s3/aws4_request"
		req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
		req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
		req.Header.Set("X-Amz-Content-Sha256", streamingPayload)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
		seed := signV4Header(req, scope, headers, streamingPayload, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))
		req.Body = io.NopCloser(strings.NewReader("2;chunk-signature=" + strings.Repeat("a", 64) + "\r\nab\r\n0\r\n\r\n"))

		result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{MaxChunkSize: 1})
		if err != nil {
			t.Fatalf("ChunkedReader() error = %v", err)
		}
		defer reader.Close()
		if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkSizeTooLarge) {
			t.Fatalf("ReadAll() error = %v, want ErrChunkSizeTooLarge", err)
		}
	})

	t.Run("signed trailer requires trailer", func(t *testing.T) {
		verifier := testVerifier(t)
		scope := "20260101/us-east-1/s3/aws4_request"
		req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", nil)
		req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
		req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		req.Header.Set("X-Amz-Trailer", "X-Amz-Checksum-CRC32")
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-trailer"}
		seed := signV4Header(req, scope, headers, streamingPayloadTrailer, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, seed, headers))
		req.Body = io.NopCloser(strings.NewReader("0;chunk-signature=" + strings.Repeat("a", 64) + "\r\n"))

		result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
		if err != nil {
			t.Fatalf("ChunkedReader() error = %v", err)
		}
		defer reader.Close()
		if _, err := io.ReadAll(reader); err == nil {
			t.Fatal("ReadAll() unexpectedly succeeded")
		}
	})

	t.Run("non-streaming result", func(t *testing.T) {
		verifier := testVerifier(t)
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test", nil)
		req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		scope := "20260101/us-east-1/s3/aws4_request"
		headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
		signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

		result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if _, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{}); !errors.Is(err, ErrUnsupportedStreamingPayload) {
			t.Fatalf("error = %v, want ErrUnsupportedStreamingPayload", err)
		}
	})
}

func TestCanonicalQueryCompatibility(t *testing.T) {
	req := requestWithURL(t, http.MethodGet,
		"https://examplebucket.s3.amazonaws.com/test?b=2&a=%20&a=1&empty")
	got := canonicalQuery(req.URL.Query(), "")
	want := "a=%20&a=1&b=2&empty="
	if got != want {
		t.Fatalf("canonical query = %q, want %q", got, want)
	}
}
