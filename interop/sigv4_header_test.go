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
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// signWithV4 signs a request using the independent client implementation.
func signWithV4(t *testing.T, req *http.Request, body []byte) *http.Request {
	t.Helper()
	req.Header.Set("X-Amz-Content-Sha256", payloadHashOf(body))
	return signer.SignV4(*req, accessKeyID, secretAccessKey, "", region)
}

func TestSigV4HeaderInterop(t *testing.T) {
	verifier := newVerifier(time.Now)
	for _, testCase := range []struct {
		name    string
		method  string
		path    string
		query   string
		body    []byte
		headers map[string]string
	}{
		{name: "get_object", method: http.MethodGet, path: "/bucket/key"},
		{name: "head_object", method: http.MethodHead, path: "/bucket/key"},
		{name: "put_small_body", method: http.MethodPut, path: "/bucket/key", body: []byte("hello aws")},
		{name: "put_empty_body", method: http.MethodPut, path: "/bucket/key", body: []byte("")},
		{name: "post_form_urlencoded", method: http.MethodPost, path: "/bucket", body: []byte("Param1=value1"),
			headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}},
		{name: "delete_with_version", method: http.MethodDelete, path: "/bucket/key", query: "versionId=3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo"},
		{name: "unicode_object_key", method: http.MethodGet, path: "/bucket/%E9%81%A0%E6%96%B9%20key+plus"},
		{name: "double_slash_object_key", method: http.MethodGet, path: "/bucket//nested//key"},
		{name: "dot_segments_object_key", method: http.MethodGet, path: "/bucket/a/../b/./c"},
		{name: "utf8_query", method: http.MethodGet, path: "/bucket", query: "tag=%E4%B8%AD%E6%96%87&v=a%20b"},
		{name: "list_parts", method: http.MethodGet, path: "/bucket/key", query: "uploadId=7fdy1d92d&part-number-marker=1"},
		{name: "subresource_query", method: http.MethodPut, path: "/bucket/key", query: "acl", body: []byte("<AccessControlPolicy/>")},
		{name: "with_metadata", method: http.MethodPut, path: "/bucket/key", body: []byte("payload"),
			headers: map[string]string{"X-Amz-Meta-Test": "value", "Content-Type": "text/plain"}},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := buildRequest(t, testCase.method, testCase.path, testCase.body)
			if testCase.query != "" {
				req.URL.RawQuery = testCase.query
			}
			for name, value := range testCase.headers {
				req.Header.Set(name, value)
			}
			signed := signWithV4(t, req, testCase.body)
			mustVerify(t, verifier, signed, verifyOptions())
		})
	}
}

func TestSigV4HeaderRejectsTampering(t *testing.T) {
	body := []byte("hello aws")
	sign := func(t *testing.T) *http.Request {
		req := buildRequest(t, http.MethodPut, "/bucket/key", body)
		req.Header.Set("Content-Type", "text/plain")
		return signWithV4(t, req, body)
	}

	t.Run("baseline", func(t *testing.T) {
		mustVerify(t, newVerifier(time.Now), sign(t), verifyOptions())
	})

	for _, testCase := range []struct {
		name   string
		mutate func(req *http.Request)
	}{
		{"flipped signature character", func(req *http.Request) {
			auth := req.Header.Get("Authorization")
			if auth[len(auth)-1] == 'a' {
				req.Header.Set("Authorization", auth[:len(auth)-1]+"b")
			} else {
				req.Header.Set("Authorization", auth[:len(auth)-1]+"a")
			}
		}},
		{"unsigned x-amz header", func(req *http.Request) { req.Header.Set("X-Amz-Meta-Later", "injected") }},
		{"changed signed header value", func(req *http.Request) { req.Header.Set("Content-Type", "application/octet-stream") }},
		{"changed host", func(req *http.Request) { req.Host = "evil.example.com" }},
		{"changed object key", func(req *http.Request) { req.URL.Path = "/bucket/other" }},
		{"changed query", func(req *http.Request) { req.URL.RawQuery = "versionId=2" }},
		{"payload hash swapped to empty", func(req *http.Request) { req.Header.Set("X-Amz-Content-Sha256", awsverify.EmptyPayloadSHA256) }},
		{"dropped host from signed headers", func(req *http.Request) {
			req.Header.Set("Authorization", withoutHostInSignedHeaders(req.Header.Get("Authorization")))
		}},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := sign(t)
			testCase.mutate(req)
			mustReject(t, newVerifier(time.Now), req, verifyOptions(), testCase.name)
		})
	}

	t.Run("wrong region option", func(t *testing.T) {
		req := sign(t)
		options := verifyOptions()
		options.Region = "eu-west-1"
		mustReject(t, newVerifier(time.Now), req, options, "region mismatch")
	})

	t.Run("wrong service option", func(t *testing.T) {
		req := sign(t)
		options := verifyOptions()
		options.Service = "sqs"
		mustReject(t, newVerifier(time.Now), req, options, "service mismatch")
	})

	t.Run("clock skew beyond tolerance", func(t *testing.T) {
		req := sign(t)
		verifier := newVerifier(func() time.Time { return time.Now().Add(2 * time.Hour) })
		mustReject(t, verifier, req, verifyOptions(), "signing time two hours from server clock")
	})

	t.Run("unknown access key", func(t *testing.T) {
		req := buildRequest(t, http.MethodGet, "/bucket/key", nil)
		req.Header.Set("X-Amz-Content-Sha256", awsverify.EmptyPayloadSHA256)
		signed := signer.SignV4(*req, "AKIAUNKNOWNKEY", secretAccessKey, "", region)
		_, err := newVerifier(time.Now).Verify(signed, verifyOptions())
		if !errors.Is(err, awsverify.ErrUnknownAccessKey) {
			t.Fatalf("error = %v, want ErrUnknownAccessKey", err)
		}
	})
}

// withoutHostInSignedHeaders removes host from the signed header list.
func withoutHostInSignedHeaders(authorization string) string {
	start := strings.Index(authorization, "SignedHeaders=")
	if start < 0 {
		return authorization
	}
	rest := authorization[start+len("SignedHeaders="):]
	end := strings.Index(rest, ",")
	if end < 0 {
		return authorization
	}
	names := strings.Split(rest[:end], ";")
	kept := make([]string, 0, len(names))
	for _, name := range names {
		if name != "host" {
			kept = append(kept, name)
		}
	}
	return authorization[:start] + "SignedHeaders=" + strings.Join(kept, ";") + rest[end:]
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
