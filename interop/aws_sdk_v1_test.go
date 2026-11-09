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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/junjiefly/aws-sig-verify"
)

// This file uses the official AWS SDK for Go v1 signer as a second, independent
// implementation. minio-go is one opinion about the specification; aws-sdk-go is
// AWS's own code. Agreement between three sources (recorded vectors, minio-go,
// AWS SDK) is much stronger evidence than agreement with either client alone.
//
// The SDK is usable here because buildBodyDigest keeps an X-Amz-Content-Sha256
// that the caller already set, which is how the streaming sentinels get signed,
// and because its StreamSigner's string-to-sign reduces exactly to the S3
// payload-chunk shape when the per-chunk header block is empty.

// awsSDKLargeChunkSize is the payload size of the large streaming case.
const awsSDKLargeChunkSize = 1 << 20

// flipLastCharacter changes the final character so a signature mutation cannot
// silently become a no-op by landing on the hex digit already there.
func flipLastCharacter(value string) string {
	if value[len(value)-1] == 'f' {
		return value[:len(value)-1] + "e"
	}
	return value[:len(value)-1] + "f"
}

func sdkCredentials(token string) *credentials.Credentials {
	return credentials.NewStaticCredentials(accessKeyID, secretAccessKey, token)
}

// sdkNewRequest builds a request whose payload commitment is already fixed, so
// the SDK signs the framing this package is meant to verify.
func sdkNewRequest(t *testing.T, method, target, payloadHash string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = parsed.Host
	req.Body = io.NopCloser(bytes.NewReader(nil))
	if payloadHash != "" {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return req
}

func sdkHeaderCases() []struct {
	name        string
	method      string
	target      string
	payloadHash func() string
	headers     map[string]string
	token       string
} {
	return []struct {
		name        string
		method      string
		target      string
		payloadHash func() string
		headers     map[string]string
		token       string
	}{
		{
			name: "get_object", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
		},
		{
			name: "put_object_body_hash", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { sum := sha256.Sum256([]byte("hello world")); return hex.EncodeToString(sum[:]) },
		},
		{
			name: "put_unsigned_payload", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { return "UNSIGNED-PAYLOAD" },
		},
		{
			name: "put_streaming_sentinel", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { return streamingPayload },
		},
		{
			name: "content_type_and_md5", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { sum := sha256.Sum256([]byte("data")); return hex.EncodeToString(sum[:]) },
			headers:     map[string]string{"Content-Type": "application/octet-stream", "Content-MD5": "1B2M2Y8AsgTpgAmY7PhCfg=="},
		},
		{
			name: "user_metadata", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
			headers:     map[string]string{"X-Amz-Meta-Alpha": "one", "X-Amz-Meta-Beta": "two"},
		},
		{
			name: "query_duplicate_keys", method: http.MethodGet, target: "https://examplebucket.s3.example.com/?marker=a&marker=b&prefix=x%20y",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
		},
		{
			name: "percent_encoded_key", method: http.MethodGet, target: "https://examplebucket.s3.example.com/my%20file%20%C3%A9.txt",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
		},
		{
			// An encoded slash inside an object name: the AWS rule is to keep it
			// as one path segment.
			name: "encoded_slash_key", method: http.MethodGet, target: "https://examplebucket.s3.example.com/dir%2Fnested/key",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
		},
		{
			name: "version_subresource", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key?versionId=3",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
		},
		{
			name: "acl_subresource", method: http.MethodGet, target: "https://examplebucket.s3.example.com/?acl",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
		},
		{
			name: "delete_with_body", method: http.MethodPost, target: "https://examplebucket.s3.example.com/?delete",
			payloadHash: func() string {
				sum := sha256.Sum256([]byte("<Delete><Object><Key>k</Key></Object></Delete>"))
				return hex.EncodeToString(sum[:])
			},
			headers: map[string]string{"Content-Type": "application/xml"},
		},
		{
			name: "temporary_credential", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key",
			payloadHash: func() string { return awsverify.EmptyPayloadSHA256 },
			token:       sessionToken,
		},
	}
}

func TestAWSSDKV1HeaderInterop(t *testing.T) {
	for _, testCase := range sdkHeaderCases() {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, testCase.method, testCase.target, testCase.payloadHash(), testCase.headers)
			if _, err := sdkSignerFor(testCase.token).Sign(req, nil, service, region, fixedStreamingTime); err != nil {
				t.Fatalf("official signer failed: %v", err)
			}
			verifier := newSessionVerifier(func() time.Time { return fixedStreamingTime }, testCase.token)
			mustVerify(t, verifier, req, verifyOptions())
		})
	}
}

func sdkSignerFor(token string) *v4.Signer {
	signer := v4.NewSigner(sdkCredentials(token))
	// AWS's own client disables URI path escaping for S3: "S3 service should not
	// have any escaping applied" (aws-sdk-go v1.55.8, aws/signer/v4/v4.go:471).
	// That is the rule this package follows too, so sign the way the SDK signs
	// when it really talks to S3 instead of the generic rest-JSON default.
	signer.DisableURIPathEscaping = service == "s3"
	return signer
}

func TestAWSSDKV1HeaderRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"changed object key", func(req *http.Request) { req.URL.Path = "/key-2" }},
		{"changed query value", func(req *http.Request) { req.URL.RawQuery = "versionId=4" }},
		{"added unsigned header", func(req *http.Request) { req.Header.Set("X-Amz-Meta-Added", "surprise") }},
		{"changed content type", func(req *http.Request) { req.Header.Set("Content-Type", "text/plain") }},
		{"swapped region in scope", func(req *http.Request) {
			req.Header.Set("Authorization", strings.Replace(req.Header.Get("Authorization"), "/s3/", "/sqs/", 1))
		}},
		{"changed signature", func(req *http.Request) {
			auth := req.Header.Get("Authorization")
			req.Header.Set("Authorization", flipLastCharacter(auth))
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/key?versionId=3", awsverify.EmptyPayloadSHA256, map[string]string{"Content-Type": "application/octet-stream"})
			if _, err := sdkSignerFor("").Sign(req, nil, service, region, fixedStreamingTime); err != nil {
				t.Fatalf("official signer failed: %v", err)
			}
			testCase.mutate(req)
			verifier := newVerifier(func() time.Time { return fixedStreamingTime })
			mustReject(t, verifier, req, verifyOptions(), testCase.name)
		})
	}
}

func TestAWSSDKV1PresignInterop(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		target      string
		expires     time.Duration
		headers     map[string]string
		token       string
		payloadHash string
	}{
		{name: "get_object", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key", expires: time.Hour},
		{name: "response_overrides", method: http.MethodGet,
			target:  "https://examplebucket.s3.example.com/key?response-content-disposition=attachment%3B%20filename%3D%22a.txt%22&response-content-type=text%2Fplain",
			expires: time.Hour},
		{name: "put_object", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key", expires: 15 * time.Minute},
		{name: "list_objects", method: http.MethodGet, target: "https://examplebucket.s3.example.com/?list-type=2&prefix=a%2Fb", expires: 24 * time.Hour},
		{name: "temporary_credential", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key", expires: time.Hour, token: sessionToken},
		{name: "encoded_slash_key", method: http.MethodGet, target: "https://examplebucket.s3.example.com/dir%2Fnested/key", expires: time.Hour},
		{name: "percent_encoded_key", method: http.MethodGet, target: "https://examplebucket.s3.example.com/my%20file%20%C3%A9.txt", expires: time.Hour},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, testCase.method, testCase.target, testCase.payloadHash, testCase.headers)
			if _, err := sdkSignerFor(testCase.token).Presign(req, nil, service, region, testCase.expires, fixedStreamingTime); err != nil {
				t.Fatalf("official presigner failed: %v", err)
			}
			verifier := newSessionVerifier(func() time.Time { return fixedStreamingTime }, testCase.token)
			mustVerify(t, verifier, req, verifyOptions())
		})
	}
}

func TestAWSSDKV1PresignRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"changed key", func(req *http.Request) { req.URL.Path = "/other" }},
		{"changed expiry", func(req *http.Request) {
			req.URL.RawQuery = strings.Replace(req.URL.RawQuery, "X-Amz-Expires=3600", "X-Amz-Expires=7200", 1)
		}},
		{"added query parameter", func(req *http.Request) { req.URL.RawQuery += "&acl" }},
		{"changed signature", func(req *http.Request) {
			req.URL.RawQuery = flipLastCharacter(req.URL.RawQuery)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/key", "", nil)
			if _, err := sdkSignerFor("").Presign(req, nil, service, region, time.Hour, fixedStreamingTime); err != nil {
				t.Fatalf("official presigner failed: %v", err)
			}
			testCase.mutate(req)
			verifier := newVerifier(func() time.Time { return fixedStreamingTime })
			mustReject(t, verifier, req, verifyOptions(), testCase.name)
		})
	}
}

func TestAWSSDKV1PresignExpiryWindow(t *testing.T) {
	req := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/key", "", nil)
	if _, err := sdkSignerFor("").Presign(req, nil, service, region, time.Hour, fixedStreamingTime); err != nil {
		t.Fatalf("official presigner failed: %v", err)
	}
	late := newVerifier(func() time.Time { return fixedStreamingTime.Add(2 * time.Hour) })
	if _, err := late.Verify(req, verifyOptions()); !errors.Is(err, awsverify.ErrExpiredSignature) {
		t.Fatalf("Verify() error = %v, want expired signature", err)
	}
}

// sdkSignedStream signs the streaming request with the official SDK and frames
// the chunks with the official chunk signer, so no code in this repository
// produces the expected signatures.
func sdkSignedStream(t *testing.T, payloads []string) (*http.Request, []string) {
	t.Helper()
	req := sdkNewRequest(t, http.MethodPut, "https://examplebucket.s3.example.com/key", streamingPayload, nil)
	if _, err := sdkSignerFor("").Sign(req, nil, service, region, fixedStreamingTime); err != nil {
		t.Fatalf("official signer failed: %v", err)
	}
	seed, err := v4.GetSignedRequestSignature(req)
	if err != nil {
		t.Fatalf("GetSignedRequestSignature: %v", err)
	}
	chunks := v4.NewStreamSigner(region, service, seed, sdkCredentials(""))

	frames := make([]string, 0, len(payloads)+1)
	for _, payload := range payloads {
		signature, err := chunks.GetSignature(nil, []byte(payload), fixedStreamingTime)
		if err != nil {
			t.Fatalf("official chunk signer failed: %v", err)
		}
		frames = append(frames, fmt.Sprintf("%x;chunk-signature=%s\r\n%s\r\n", len(payload), hex.EncodeToString(signature), payload))
	}
	final, err := chunks.GetSignature(nil, nil, fixedStreamingTime)
	if err != nil {
		t.Fatalf("official chunk signer failed: %v", err)
	}
	frames = append(frames, fmt.Sprintf("0;chunk-signature=%s\r\n\r\n", hex.EncodeToString(final)))
	return req, frames
}

func TestAWSSDKV1StreamingChunkChain(t *testing.T) {
	cases := []struct {
		name     string
		payloads []string
	}{
		{name: "single_chunk", payloads: []string{"hello"}},
		{name: "two_chunks", payloads: []string{"hello", "world"}},
		{name: "only_final_chunk", payloads: nil},
		{name: "one_mebibyte_chunk", payloads: []string{strings.Repeat("x", awsSDKLargeChunkSize)}},
		{name: "binary_payload", payloads: []string{"\x00\x01\xff\xfe"}},
		{name: "many_chunks", payloads: []string{"a", "bb", "ccc", "dddd", "eeeee"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req, frames := sdkSignedStream(t, testCase.payloads)
			req.Body = io.NopCloser(strings.NewReader(strings.Join(frames, "")))
			verifier := newVerifier(func() time.Time { return fixedStreamingTime })
			result := mustVerify(t, verifier, req, verifyOptions())
			reader, err := verifier.ChunkedReader(req, result, awsverify.ChunkedReaderOptions{})
			if err != nil {
				t.Fatalf("ChunkedReader() error = %v", err)
			}
			defer reader.Close()
			decoded, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			if want := strings.Join(testCase.payloads, ""); string(decoded) != want {
				t.Fatalf("decoded %d bytes, want %d", len(decoded), len(want))
			}
		})
	}
}

func TestAWSSDKV1StreamingRejectsTampering(t *testing.T) {
	req, frames := sdkSignedStream(t, []string{"hello", "world"})
	stream := strings.Join(frames, "")

	cases := []struct {
		name string
		body func() string
	}{
		{
			name: "changed chunk byte",
			body: func() string { return strings.Replace(stream, "hello", "jello", 1) },
		},
		{
			name: "swapped chunk order",
			body: func() string { return frames[1] + frames[0] + frames[2] },
		},
		{
			name: "declared size larger than payload",
			body: func() string { return strings.Replace(stream, "5;chunk-signature", "6;chunk-signature", 1) },
		},
		{
			name: "missing final chunk",
			body: func() string { return strings.TrimSuffix(stream, frames[2]) },
		},
		{
			name: "chunk signature replaced",
			body: func() string {
				start := strings.Index(stream, "chunk-signature=") + len("chunk-signature=")
				return stream[:start] + strings.Repeat("0", 64) + stream[start+64:]
			},
		},
		{
			name: "lf terminated chunk header",
			body: func() string { return strings.Replace(stream, "\r\nhello", "\nhello", 1) },
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := forkRequest(t, req, []byte(testCase.body()))
			verifier := newVerifier(func() time.Time { return fixedStreamingTime })
			result, err := verifier.Verify(mutated, verifyOptions())
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			reader, err := verifier.ChunkedReader(mutated, result, awsverify.ChunkedReaderOptions{})
			if err != nil {
				t.Fatalf("ChunkedReader() error = %v", err)
			}
			defer reader.Close()
			if _, err := io.ReadAll(reader); err == nil {
				t.Fatalf("accepted a stream it must reject: %s", testCase.name)
			}
		})
	}
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
