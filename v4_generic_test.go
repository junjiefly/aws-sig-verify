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
	"net/http"
	"testing"
)

func TestVerifyNonS3Service(t *testing.T) {
	verifier := testVerifier(t)
	req := requestWithURL(t, http.MethodGet, "https://api.example.com/prod/resources/id")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")

	scope := "20260101/eu-central-1/execute-api/aws4_request"
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

	result, err := verifier.Verify(req, VerifyOptions{
		Service: "execute-api",
		Region:  "eu-central-1",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Service != "execute-api" || result.Region != "eu-central-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestCanonicalURINonS3UsesEscapedPath(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/path%20with%20space/value", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := canonicalURI(req, false), "/path%20with%20space/value"; got != want {
		t.Fatalf("canonical URI = %q, want %q", got, want)
	}
}

func TestCanonicalURINonS3NormalizesPath(t *testing.T) {
	for _, testCase := range []struct{ rawPath, want string }{
		{"/", "/"},
		{"//", "/"},
		{"///", "/"},
		{"//example//", "/example/"},
		{"/./", "/"},
		{"/./example", "/example"},
		{"/example/..", "/"},
		{"/example/../..", "/"},
		{"/a/../../b", "/b"},
		{"/foo/bar/", "/foo/bar/"},
		{"/foo//bar", "/foo/bar"},
		{"/foo/./bar/./", "/foo/bar/"},
		{"/%2Fa", "/%2Fa"},
		{"/a%20b//c", "/a%20b/c"},
	} {
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com"+testCase.rawPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := canonicalURI(req, false); got != testCase.want {
			t.Errorf("canonical URI for %q = %q, want %q", testCase.rawPath, got, testCase.want)
		}
	}
}
