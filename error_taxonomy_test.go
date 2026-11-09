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
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// taxonomyScope is the pinned scope every taxonomy case signs with.
const taxonomyScope = "20260101/us-east-1/s3/aws4_request"

var taxonomyHeaders = []string{"host", "x-amz-content-sha256", "x-amz-date"}

// taxonomyRequest returns a correctly signed V4 header request over the empty
// payload. Cases mutate it to aim at one specific failure.
func taxonomyRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, "https://s3.example.com/taxonomy", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "s3.example.com"
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	signature := signV4Header(req, taxonomyScope, taxonomyHeaders, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(taxonomyScope, signature, taxonomyHeaders))
	return req
}

func verifyTaxonomyRequest(verifier *Verifier, req *http.Request) error {
	_, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	return err
}

func TestErrorTaxonomy(t *testing.T) {
	verifier := testVerifier(t)

	cases := []struct {
		name  string
		build func(t *testing.T) (*Verifier, func() error, error)
	}{
		{
			name: "nil request",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				return verifier, func() error {
					_, err := verifier.Verify(nil, VerifyOptions{Service: "s3", Region: "us-east-1"})
					return err
				}, ErrNilRequest
			},
		},
		{
			name: "no credential lookup",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				blank := NewVerifier(Config{Clock: func() time.Time { return testTime }})
				return blank, func() error {
					return verifyTaxonomyRequest(blank, taxonomyRequest(t))
				}, ErrCredentialLookupRequired
			},
		},
		{
			name: "request carries no signature",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req, err := http.NewRequest(http.MethodGet, "https://s3.example.com/plain", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "s3.example.com"
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrUnsupportedSignatureVersion
			},
		},
		{
			name: "scope not pinned by the caller",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				return verifier, func() error {
					_, err := verifier.Verify(taxonomyRequest(t), VerifyOptions{})
					return err
				}, ErrScopeRequired
			},
		},
		{
			name: "credential scope is truncated",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential="+testAccessKey+"/20260101,SignedHeaders=host,Signature="+strings.Repeat("a", 64))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMalformedCredential
			},
		},
		{
			name: "credential scope has the wrong terminal",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential="+testAccessKey+"/"+taxonomyScope[:len(taxonomyScope)-len("/aws4_request")]+"/aws4_wrong,SignedHeaders=host,Signature="+strings.Repeat("a", 64))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMalformedCredential
			},
		},
		{
			name: "signature is not 64 hex characters",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential="+testAccessKey+"/"+taxonomyScope+",SignedHeaders=host,Signature=short")
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMalformedSignature
			},
		},
		{
			name: "signed header list is not sorted",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential="+testAccessKey+"/"+taxonomyScope+",SignedHeaders=x-amz-date;host,Signature="+strings.Repeat("a", 64))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMalformedAuthorization
			},
		},
		{
			name: "signed header list omits host",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential="+testAccessKey+"/"+taxonomyScope+",SignedHeaders=x-amz-date,Signature="+strings.Repeat("a", 64))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMissingSignedHeader
			},
		},
		{
			name: "request header outside the signed list",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Add("X-Amz-Meta-Extra", "unsigned")
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMissingSignedHeader
			},
		},
		{
			name: "signing date is unparseable",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Set("X-Amz-Date", "not-a-date")
				req.Header.Set("Authorization",
					"AWS4-HMAC-SHA256 Credential="+testAccessKey+"/"+taxonomyScope+",SignedHeaders=host;"+strings.Join(taxonomyHeaders[0:1], ";")+",Signature="+strings.Repeat("a", 64))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrMalformedAuthorization
			},
		},
		{
			name: "signing time outside clock skew",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				future := testTime.Add(time.Hour)
				req, err := http.NewRequest(http.MethodPut, "https://s3.example.com/taxonomy", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "s3.example.com"
				req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
				req.Header.Set("X-Amz-Date", "20260101T010000Z")
				_ = future
				headers := taxonomyHeaders
				signature := signV4Header(req, taxonomyScope, headers, emptyPayloadHash, time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC))
				req.Header.Set("Authorization", v4AuthorizationHeader(taxonomyScope, signature, headers))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrClockSkew
			},
		},
		{
			name: "payload hash missing and no default",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Del("X-Amz-Content-Sha256")
				req.Header.Set("Authorization", "")
				headers := []string{"host", "x-amz-date"}
				signature := signV4Header(req, taxonomyScope, headers, "", testTime)
				req.Header.Set("Authorization", v4AuthorizationHeader(taxonomyScope, signature, headers))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrPayloadHashRequired
			},
		},
		{
			name: "unknown access key",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				auth := req.Header.Get("Authorization")
				req.Header.Set("Authorization",
					strings.Replace(auth, "Credential="+testAccessKey+"/", "Credential=AKIANOTAREALKEY/", 1))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrUnknownAccessKey
			},
		},
		{
			name: "signature computed with another secret",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				signature := signV4HeaderWithSecret("not-the-test-secret", req, taxonomyScope, taxonomyHeaders, emptyPayloadHash, testTime)
				req.Header.Set("Authorization", v4AuthorizationHeader(taxonomyScope, signature, taxonomyHeaders))
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrSignatureMismatch
			},
		},
		{
			name: "session token mismatch",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				session := NewVerifier(Config{
					Credentials: func(_ context.Context, _ string) (Credentials, error) {
						return Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey, SessionToken: "tok"}, nil
					},
					Clock: func() time.Time { return testTime },
				})
				return session, func() error {
					return verifyTaxonomyRequest(session, taxonomyRequest(t))
				}, ErrSessionTokenMismatch
			},
		},
		{
			name: "presign expired",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req, err := taxonomyPresign(t, "/presigned", "3600", "20251231T000000Z", time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), "20251231/us-east-1/s3/aws4_request")
				if err != nil {
					t.Fatal(err)
				}
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrExpiredSignature
			},
		},
		{
			name: "presign expiry longer than the maximum",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req, err := taxonomyPresign(t, "/presigned", "604801", "20260101T000000Z", testTime, taxonomyScope)
				if err != nil {
					t.Fatal(err)
				}
				return verifier, func() error {
					return verifyTaxonomyRequest(verifier, req)
				}, ErrPresignExpiryTooLong
			},
		},
		{
			name: "V2 header signature is not base64",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Del("X-Amz-Content-Sha256")
				req.Header.Set("Date", "Thu, 01 Jan 2026 00:00:00 GMT")
				req.Header.Set("Authorization", "AWS "+testAccessKey+":%%not-base64%%")
				return verifier, func() error {
					_, err := verifier.Verify(req, VerifyOptions{})
					return err
				}, ErrMalformedSignature
			},
		},
		{
			name: "V2 header without a date",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Header.Del("X-Amz-Content-Sha256")
				req.Header.Del("X-Amz-Date")
				req.Header.Set("Authorization", "AWS "+testAccessKey+":"+base64SHA1(testSecretKey, "x"))
				return verifier, func() error {
					_, err := verifier.Verify(req, VerifyOptions{})
					return err
				}, ErrMalformedAuthorization
			},
		},
		{
			name: "V2 presign expiry longer than the maximum",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				target, err := url.Parse("https://s3.example.com/v2-object")
				if err != nil {
					t.Fatal(err)
				}
				query := target.Query()
				query.Set("AWSAccessKeyId", testAccessKey)
				query.Set("Expires", "32503680000")
				query.Set("Signature", base64SHA1(testSecretKey, "x"))
				target.RawQuery = query.Encode()
				req, err := http.NewRequest(http.MethodGet, target.String(), nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "s3.example.com"
				return verifier, func() error {
					_, err := verifier.Verify(req, VerifyOptions{})
					return err
				}, ErrPresignExpiryTooLong
			},
		},
		{
			name: "POST policy document missing",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				return verifier, func() error {
					_, err := verifier.VerifyPostPolicy(url.Values{}, VerifyOptions{Service: "s3", Region: "us-east-1"})
					return err
				}, ErrPostPolicyRequired
			},
		},
		{
			name: "POST policy document is not base64",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				return verifier, func() error {
					_, err := verifier.VerifyPostPolicy(url.Values{"policy": {"!!"}}, VerifyOptions{Service: "s3", Region: "us-east-1"})
					return err
				}, ErrMalformedPostPolicy
			},
		},
		{
			name: "POST policy condition uses an unknown operator",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				policy := taxonomyPostPolicy(t, `{"expiration":"2026-01-01T01:00:00Z","conditions":[["nope","$key","x"]]}`)
				form := taxonomyPostForm(t, policy)
				return verifier, func() error {
					_, err := verifier.VerifyPostPolicy(form, VerifyOptions{Service: "s3", Region: "us-east-1"})
					return err
				}, ErrUnsupportedPostPolicyCondition
			},
		},
		{
			name: "POST policy exact-match condition fails",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				policy := taxonomyPostPolicy(t, `{"expiration":"2026-01-01T01:00:00Z","conditions":[{"key":"other.txt"}]}`)
				form := taxonomyPostForm(t, policy)
				return verifier, func() error {
					_, err := verifier.VerifyPostPolicy(form, VerifyOptions{Service: "s3", Region: "us-east-1"})
					return err
				}, ErrPostPolicyConditionFailed
			},
		},
		{
			name: "streaming reader fed a non-streaming result",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				req := taxonomyRequest(t)
				req.Body = io.NopCloser(strings.NewReader("ignored"))
				return verifier, func() error {
					_, err := verifier.ChunkedReader(req, &Result{PayloadHash: emptyPayloadHash}, ChunkedReaderOptions{})
					return err
				}, ErrUnsupportedStreamingPayload
			},
		},
		{
			name: "streaming chunk size above the limit",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				return verifier, func() error {
					return readStreamingError(t, fuzzStreamBody("1234567890"), ChunkedReaderOptions{MaxChunkSize: 8})
				}, ErrChunkSizeTooLarge
			},
		},
		{
			name: "streaming chunk signature does not match",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				stream := flipFirstChunkSignature(fuzzStreamBody("hello", "world"))
				return verifier, func() error {
					return readStreamingError(t, stream, ChunkedReaderOptions{})
				}, ErrChunkSignatureMismatch
			},
		},
		{
			name: "streaming chunk header is too long",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				stream := "ffffffff;" + strings.Repeat("a", maxChunkHeaderSize+8) + "\r\n"
				return verifier, func() error {
					return readStreamingError(t, stream, ChunkedReaderOptions{})
				}, ErrChunkHeaderTooLong
			},
		},
		{
			name: "streaming chunk size is not hexadecimal",
			build: func(t *testing.T) (*Verifier, func() error, error) {
				return verifier, func() error {
					return readStreamingError(t, "zz;chunk-signature="+strings.Repeat("a", 64)+"\r\n", ChunkedReaderOptions{})
				}, ErrMalformedChunk
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, action, want := testCase.build(t)
			err := action()
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
}

// flipFirstChunkSignature corrupts one character of the first chunk signature
// while keeping it a valid 64-character hex string.
func flipFirstChunkSignature(stream string) string {
	marker := ";chunk-signature="
	at := strings.Index(stream, marker)
	if at < 0 {
		return stream
	}
	start := at + len(marker)
	if start >= len(stream) {
		return stream
	}
	replacement := byte('0')
	if stream[start] == '0' {
		replacement = '1'
	}
	return stream[:start] + string(replacement) + stream[start+1:]
}

// taxonomyPresign returns a fully signed presigned GET request for keyPath.
func taxonomyPresign(t *testing.T, keyPath, expires, amzDate string, signingTime time.Time, scope string) (*http.Request, error) {
	t.Helper()
	target, err := url.Parse("https://s3.example.com" + keyPath)
	if err != nil {
		return nil, err
	}
	query := target.Query()
	query.Set("X-Amz-Algorithm", v4Algorithm)
	query.Set("X-Amz-Credential", testAccessKey+"/"+scope)
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", expires)
	query.Set("X-Amz-SignedHeaders", "host")
	target.RawQuery = query.Encode()
	request, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Host = "s3.example.com"
	signature := signV4Presigned(request, scope, []string{"host"}, unsignedPayloadHash, signingTime)
	return completeV4PresignedURL(target, signature), nil
}

func taxonomyPostPolicy(t *testing.T, document string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(document))
}

// signedPostForm encodes the policy document and signs the form with the test
// credentials, so condition-level failures are not masked by an invalid signature.
func signedPostForm(t *testing.T, document string) url.Values {
	t.Helper()
	return taxonomyPostForm(t, taxonomyPostPolicy(t, document))
}

func taxonomyPostForm(t *testing.T, policy string) url.Values {
	t.Helper()
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	return url.Values{
		"key":              {"uploads/notes.txt"},
		"bucket":           {"bucket"},
		"policy":           {policy},
		"x-amz-algorithm":  {v4Algorithm},
		"x-amz-credential": {testAccessKey + "/" + taxonomyScope},
		"x-amz-date":       {"20260101T000000Z"},
		"x-amz-signature":  {hexString(hmacSHA256(signingKey, []byte(policy)))},
	}
}

// readStreamingError verifies a streaming request and drains its decoded body,
// returning the first read error.
func readStreamingError(t *testing.T, stream string, options ChunkedReaderOptions) error {
	t.Helper()
	verifier := testVerifier(t)
	req := fuzzStreamingRequest()
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	seed := signV4Header(req, fuzzScope, headers, streamingPayload, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(fuzzScope, seed, headers))
	req.Body = io.NopCloser(strings.NewReader(stream))
	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	reader, err := verifier.ChunkedReader(req, result, options)
	if err != nil {
		return err
	}
	defer reader.Close()
	_, err = io.ReadAll(reader)
	return err
}
