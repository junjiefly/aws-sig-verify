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
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCanonicalURIGenericService(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/a/./b/../c/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.example.com"
	if got, want := canonicalURI(req, false), "/a/c/"; got != want {
		t.Fatalf("canonicalURI() = %q, want %q", got, want)
	}

	root, err := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	root.Host = "api.example.com"
	if got := canonicalURI(root, false); got != "/" {
		t.Fatalf("canonicalURI() on the empty path = %q, want %q", got, "/")
	}
}

func TestCanonicalURIS3Escaping(t *testing.T) {
	cases := []struct{ escaped, want string }{
		{"/a%2fb", "/a%2Fb"},   // encoded slash stays one segment
		{"/a%62c", "/abc"},     // unreserved byte is decoded
		{"/a%zz", "/a%25zz"},   // invalid escape is re-encoded
		{"/a b/c", "/a%20b/c"}, // raw space is encoded
		{"/a+b", "/a%2Bb"},     // plus is percent-encoded in S3 paths
		{"/%C3%A9", "/%C3%A9"}, // multibyte stays uppercase hex
	}
	for _, testCase := range cases {
		if got := canonicalS3EscapedPath(testCase.escaped); got != testCase.want {
			t.Errorf("canonicalS3EscapedPath(%q) = %q, want %q", testCase.escaped, got, testCase.want)
		}
	}
}

func TestCanonicalURIS3EscapedPathThroughRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://s3.example.com/a%2fb", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "s3.example.com"
	if got := canonicalURI(req, true); got != "/a%2Fb" {
		t.Fatalf("canonicalURI() = %q, want %q", got, "/a%2Fb")
	}
}

func TestHeaderValues(t *testing.T) {
	header := http.Header{}
	if values := headerValues(header, "host"); values != nil {
		t.Fatalf("host without Host = %v, want nil", values)
	}

	header["Host"] = []string{"s3.example.com", "s3.example.com."}
	values := headerValues(header, "host")
	if len(values) != 2 || values[0] != "s3.example.com" {
		t.Fatalf("raw Host map values = %v", values)
	}

	header = http.Header{"X-Amz-Meta-Both": {"first", "second"}}
	if got := headerValues(header, "x-amz-meta-both"); len(got) != 2 {
		t.Fatalf("multi-value header = %v", got)
	}
	if got := headerValues(header, "X-Amz-Meta-Both"); len(got) != 2 {
		t.Fatalf("mixed-case lookup through Values() = %v", got)
	}
}

func TestRequestHeaderValuesFallbacks(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "https://s3.example.com/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "s3.example.com"
	req.ContentLength = 4096
	req.TransferEncoding = []string{"chunked"}
	req.ProtoAtLeast(1, 1)

	if got := requestHeaderValues(req, "content-length"); len(got) != 1 || got[0] != "4096" {
		t.Fatalf("content-length fallback = %v", got)
	}
	if got := requestHeaderValues(req, "transfer-encoding"); len(got) != 1 || got[0] != "chunked" {
		t.Fatalf("transfer-encoding fallback = %v", got)
	}
	if got := requestHeaderValues(req, "expect"); len(got) != 1 || got[0] != "100-continue" {
		t.Fatalf("expect fallback = %v", got)
	}
	if got := requestHeaderValues(req, "x-amz-nothing"); got != nil {
		t.Fatalf("missing header = %v, want nil", got)
	}
}

func TestParseV4CredentialRejectsMalformedScopes(t *testing.T) {
	signature := strings.Repeat("a", 64)
	cases := []struct{ credential string }{
		{testAccessKey + "/20260101/us-east-1/s3"},            // four segments
		{"/20260101/us-east-1/s3/aws4_request"},               // empty access key
		{testAccessKey + "/20260101/us-east-1/s3/aws4_wrong"}, // wrong terminal
		{testAccessKey + "//us-east-1/s3/aws4_request"},       // empty date
		{testAccessKey + "/20260101//s3/aws4_request"},        // empty region
		{testAccessKey + "/20260101/us-east-1//aws4_request"}, // empty service
	}
	for _, testCase := range cases {
		if _, err := parseV4Credential(testCase.credential, signature); !errors.Is(err, ErrMalformedCredential) {
			t.Errorf("parseV4Credential(%q) error = %v, want ErrMalformedCredential", testCase.credential, err)
		}
	}

	badSignatures := []string{
		strings.Repeat("a", 63), // too short
		strings.Repeat("a", 65), // too long
		strings.Repeat("g", 64), // not hex
	}
	for _, bad := range badSignatures {
		if _, err := parseV4Credential(testAccessKey+"/"+taxonomyScope, bad); !errors.Is(err, ErrMalformedSignature) {
			t.Errorf("parseV4Credential signature %q error = %v, want ErrMalformedSignature", bad, err)
		}
	}
}

func TestValidateSignedHeadersRejectsMalformedLists(t *testing.T) {
	cases := []struct {
		names []string
		want  error
	}{
		{nil, ErrMalformedAuthorization},
		{[]string{"host", "host"}, ErrMalformedAuthorization},
		{[]string{"x-amz-date", "host"}, ErrMalformedAuthorization},
		{[]string{"Host"}, ErrMalformedAuthorization},
		{[]string{"host", ""}, ErrMalformedAuthorization},
		{[]string{"x-amz-date"}, ErrMissingSignedHeader},
	}
	for _, testCase := range cases {
		err := validateSignedHeaders(testCase.names, true)
		if !errors.Is(err, testCase.want) {
			t.Errorf("validateSignedHeaders(%v) error = %v, want %v", testCase.names, err, testCase.want)
		}
	}
	if err := validateSignedHeaders([]string{"x-amz-date"}, false); err != nil {
		t.Errorf("host not required but rejected: %v", err)
	}
}

func TestV4PresignedPayloadHashSelection(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://s3.example.com/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "s3.example.com"
	query := url.Values{"X-Amz-Content-Sha256": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}

	declared := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	got, err := v4PresignedPayloadHash(req, query, VerifyOptions{PayloadHash: declared}, true)
	if err != nil || got != declared {
		t.Fatalf("options override = (%q, %v)", got, err)
	}

	got, err = v4PresignedPayloadHash(req, query, VerifyOptions{}, true)
	if err != nil || got != query.Get("X-Amz-Content-Sha256") {
		t.Fatalf("query hash = (%q, %v)", got, err)
	}

	got, err = v4PresignedPayloadHash(req, url.Values{}, VerifyOptions{}, true)
	if err != nil || got != unsignedPayloadHash {
		t.Fatalf("s3 default = (%q, %v)", got, err)
	}

	if _, err := v4PresignedPayloadHash(req, url.Values{}, VerifyOptions{}, false); !errors.Is(err, ErrPayloadHashRequired) {
		t.Fatalf("non-s3 without hash error = %v, want ErrPayloadHashRequired", err)
	}
}

func TestV2HeaderDateHandling(t *testing.T) {
	verifier := testVerifier(t)
	options := VerifyOptions{}

	build := func(dateHeader, amzDate string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "https://s3.example.com/v2", nil)
		req.Host = "s3.example.com"
		if dateHeader != "" {
			req.Header.Set("Date", dateHeader)
		}
		if amzDate != "" {
			req.Header.Set("X-Amz-Date", amzDate)
		}
		return req
	}

	request := build("", "Thu, 01 Jan 2026 00:00:00 GMT")
	request.Header.Set("Authorization", "AWS "+testAccessKey+":notbase64!!")
	if _, err := verifier.Verify(request, options); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("non-base64 V2 signature error = %v", err)
	}

	request = build("", "not-a-date")
	request.Header.Set("Authorization", "AWS "+testAccessKey+":"+base64SHA1(testSecretKey, "x"))
	if _, err := verifier.Verify(request, options); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("invalid X-Amz-Date error = %v", err)
	}
}

func TestSignV2HelpersMatchManualStringToSign(t *testing.T) {
	if SignV2Request(testSecretKey, nil, VerifyOptions{}) != "" {
		t.Fatal("SignV2Request(nil) returned a signature")
	}
	if SignV2Presign(testSecretKey, nil, "3600", VerifyOptions{}) != "" {
		t.Fatal("SignV2Presign(nil) returned a signature")
	}

	req, err := http.NewRequest(http.MethodPut, "https://s3.example.com/v2 sign/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "s3.example.com"
	req.Header.Set("Date", "Thu, 01 Jan 2026 00:00:00 GMT")
	req.Header.Set("X-Amz-Meta-Note", "  spaced   value  ")

	stringToSign := strings.Join([]string{
		http.MethodPut,
		req.Header.Get("Content-MD5"),
		req.Header.Get("Content-Type"),
		req.Header.Get("Date"),
		"x-amz-meta-note:spaced value\n",
	}, "\n") + "/v2%20sign/object"
	expected := SignV2(testSecretKey, stringToSign)
	if got := SignV2Request(testSecretKey, req, VerifyOptions{}); got != expected {
		t.Fatalf("SignV2Request() = %q, want %q", got, expected)
	}

	presignTarget := *req.URL
	presigned := SignV2Presign(testSecretKey, req, "86400", VerifyOptions{})
	if presigned == "" {
		t.Fatal("SignV2Presign() returned an empty signature")
	}
	if presignTarget.String() != req.URL.String() {
		t.Fatal("SignV2Presign() mutated the request URL")
	}
}

func TestChunkedReaderRejectsWrongDataTerminator(t *testing.T) {
	stream := strings.Replace(fuzzStreamBody("hello"), "\r\nhello\r\n", "\r\nhelloXY", 1)
	if err := readStreamingError(t, stream, ChunkedReaderOptions{}); !errors.Is(err, ErrMalformedChunk) {
		t.Fatalf("wrong data terminator error = %v, want ErrMalformedChunk", err)
	}

	truncated := strings.Replace(fuzzStreamBody("hello"), "\r\nhello\r\n", "\r\nhello", 1)
	if err := readStreamingError(t, truncated, ChunkedReaderOptions{}); !errors.Is(err, ErrMalformedChunk) {
		t.Fatalf("truncated data terminator error = %v, want ErrMalformedChunk", err)
	}
}

func TestPostPolicyConditionSizeValidation(t *testing.T) {
	verifier := testVerifier(t)
	cases := []struct{ conditions string }{
		{`["content-length-range",-1,10]`},
		{`["content-length-range",0,1.5]`},
		{`["content-length-range",0,"huge"]`},
	}
	for _, testCase := range cases {
		document := `{"expiration":"2026-01-01T01:00:00Z","conditions":[` + testCase.conditions + `]}`
		form := signedPostForm(t, document)
		size := int64(5)
		_, err := verifier.VerifyPostPolicy(form, VerifyOptions{
			Service:                 "s3",
			Region:                  "us-east-1",
			PostPolicyContentLength: &size,
		})
		if !errors.Is(err, ErrMalformedPostPolicy) {
			t.Errorf("conditions %s error = %v, want ErrMalformedPostPolicy", testCase.conditions, err)
		}
	}
}
