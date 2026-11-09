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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestAccessKeyID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://bucket.example.com/object", nil)
	req.Header.Set("Authorization", "AWS "+testAccessKey+":bm9wcw==")
	accessKeyID, authType, ok := RequestAccessKeyID(req)
	if !ok || accessKeyID != testAccessKey || authType != AuthTypeSigV2Header {
		t.Fatalf("got %q %q %v", accessKeyID, authType, ok)
	}
}

func TestRequestAccessKeyIDSigV4Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://bucket.example.com/object", nil)
	req.Header.Set("Authorization", v4AuthorizationHeader(
		"20260101/us-east-1/s3/aws4_request",
		strings.Repeat("a", 64),
		[]string{"host"},
	))
	accessKeyID, authType, ok := RequestAccessKeyID(req)
	if !ok || accessKeyID != testAccessKey || authType != AuthTypeSigV4Header {
		t.Fatalf("got %q %q %v", accessKeyID, authType, ok)
	}
}

func TestRequestBucketFromHost(t *testing.T) {
	tests := []struct {
		host    string
		want    string
		domains []string
	}{
		{"bucket.s3.example.com", "bucket", []string{"s3.example.com"}},
		{"bucket.sub.s3.example.com", "bucket", []string{"s3.example.com", "sub.s3.example.com"}},
		{"BUCKET.S3.Example.COM:8443", "bucket", []string{"s3.example.com"}},
		{"notbucket.example.com", "", []string{"s3.example.com"}},
	}
	for _, test := range tests {
		if got := RequestBucketFromHost(test.host, test.domains); got != test.want {
			t.Errorf("RequestBucketFromHost(%q) = %q, want %q", test.host, got, test.want)
		}
	}
}

func TestRequestPostPolicyAccessKeyID(t *testing.T) {
	form := url.Values{}
	form.Set("AWSAccessKeyId", testAccessKey)
	accessKeyID, authType, ok := RequestPostPolicyAccessKeyID(form)
	if !ok || accessKeyID != testAccessKey || authType != AuthTypeSigV2Post {
		t.Fatalf("got %q %q %v", accessKeyID, authType, ok)
	}
}
