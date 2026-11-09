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
	"testing"
	"time"
)

func awsDocsVerifier(at time.Time) *Verifier {
	return NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		}),
		Clock: func() time.Time { return at },
	})
}

// v2SigningTime matches the Date header used by the AWS documentation examples.
var v2SigningTime = time.Date(2007, 3, 27, 19, 36, 42, 0, time.UTC)

const v2DateHeader = "Tue, 27 Mar 2007 19:36:42 +0000"

func TestVerifyV2HeaderAWSVector(t *testing.T) {
	verifier := awsDocsVerifier(v2SigningTime)
	req := httptest.NewRequest(http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg", nil)
	req.Host = "johnsmith.s3.amazonaws.com"
	req.Header.Set("Date", v2DateHeader)
	req.Header.Set("Authorization", "AWS "+testAccessKey+":bWq2s1WEIj+Ydj0vQ697zp+IXMU=")

	result, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Version != SigV2 || result.AccessKeyID != testAccessKey {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyV2HeaderWithContentTypeAWSVector(t *testing.T) {
	verifier := awsDocsVerifier(time.Date(2007, 3, 27, 21, 15, 45, 0, time.UTC))
	req := httptest.NewRequest(http.MethodPut, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg", nil)
	req.Host = "johnsmith.s3.amazonaws.com"
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
	req.Header.Set("Authorization", "AWS "+testAccessKey+":MyyxeRY7whkBe+bq8fHCL/2kKUg=")

	if _, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyV2SubresourceAWSVector(t *testing.T) {
	verifier := awsDocsVerifier(time.Date(2007, 3, 27, 19, 42, 41, 0, time.UTC))
	req := httptest.NewRequest(http.MethodGet, "https://johnsmith.s3.amazonaws.com/?acl", nil)
	req.Host = "johnsmith.s3.amazonaws.com"
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:42:41 +0000")
	req.Header.Set("Authorization", "AWS "+testAccessKey+":/dUAUi+fuxkz/MzNKEEbO2tmXwQ=")
	if _, err := verifier.Verify(req, VerifyOptions{S3Bucket: "johnsmith"}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// TestVerifyV2OfflineVectors pins request shapes that the published AWS
// examples do not cover. Each signature below was computed outside this
// repository with HMAC-SHA1 over the string-to-sign quoted in the comment,
// using the example secret key, so it is an independent check of the rules
// rather than a round-trip of this package's own signing code.
func TestVerifyV2OfflineVectors(t *testing.T) {
	expires := time.Unix(1174414242, 0)
	for _, testCase := range []struct {
		name          string
		stringToSign  string
		clock         time.Time
		method        string
		target        string
		headers       map[string]string
		authorization string
		query         string
		bucket        string
	}{
		{
			name:   "escaped path in the canonical resource",
			target: "https://s3.example.com/bucket/my%20file%20%C3%A9.txt",
			// "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/bucket/my%20file%20%C3%A9.txt"
			authorization: "kLpcpcDcLJAfcQneUZzI9bLmBaU=",
			stringToSign:  "GET\n\n\n" + v2DateHeader + "\n/bucket/my%20file%20%C3%A9.txt",
			clock:         v2SigningTime,
			headers:       map[string]string{"Date": v2DateHeader},
		},
		{
			name:   "canonicalized amz headers",
			method: http.MethodPut,
			target: "https://s3.example.com/bucket/notes.txt",
			// "PUT\n1B2M2Y8AsgTpgAmY7PhCfg==\ntext/plain\n<Date>\n" +
			// "x-amz-meta-author:anita\nx-amz-storage-class:REDUCED_REDUNDANCY\n/bucket/notes.txt"
			authorization: "J9usZaYaJ3kHxI7MJblWIRl5yDo=",
			stringToSign: "PUT\n1B2M2Y8AsgTpgAmY7PhCfg==\ntext/plain\n" + v2DateHeader +
				"\nx-amz-meta-author:anita\nx-amz-storage-class:REDUCED_REDUNDANCY\n/bucket/notes.txt",
			clock: v2SigningTime,
			headers: map[string]string{
				"Date":                v2DateHeader,
				"Content-Md5":         "1B2M2Y8AsgTpgAmY7PhCfg==",
				"Content-Type":        "text/plain",
				"X-Amz-Meta-Author":   "anita",
				"X-Amz-Storage-Class": "REDUCED_REDUNDANCY",
			},
		},
		{
			name:   "subresource with a value",
			target: "https://s3.example.com/bucket/file.txt?versionId=3.LaCRXyjzSlXp0CEgS5bVCEXzcYDs~jpwTd08b.k6mcU",
			// "GET\n\n\n<Date>\n/bucket/file.txt?versionId=3.LaCRXyjzSlXp0CEgS5bVCEXzcYDs~jpwTd08b.k6mcU"
			authorization: "cq+UTBuFLt02ZoUnu0OKcRKGjGg=",
			stringToSign:  "GET\n\n\n" + v2DateHeader + "\n/bucket/file.txt?versionId=3.LaCRXyjzSlXp0CEgS5bVCEXzcYDs~jpwTd08b.k6mcU",
			clock:         v2SigningTime,
			headers:       map[string]string{"Date": v2DateHeader},
		},
		{
			name:   "x-amz-date alone leaves the date line empty",
			target: "https://s3.example.com/bucket/file.txt",
			// "GET\n\n\n\nx-amz-content-sha256:e3b0c442...b855\n" +
			// "x-amz-date:20070327T193642Z\n/bucket/file.txt"
			authorization: "zIyn/JftZa1yyKz0KKpvpz/c0yI=",
			stringToSign: "GET\n\n\n\nx-amz-content-sha256:" +
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
				"x-amz-date:20070327T193642Z\n/bucket/file.txt",
			clock: v2SigningTime,
			headers: map[string]string{
				"X-Amz-Date":           "20070327T193642Z",
				"X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		{
			// When both headers are present the Date value stays in the date line
			// and x-amz-date only joins the canonicalized header list. MinIO's
			// service accepts this shape and rejects the alternative reading, and
			// SeaweedFS's SigV2 reader takes the Date header the same way.
			name:          "date and x-amz-date present together",
			target:        "https://s3.example.com/bucket/file.txt",
			stringToSign:  "GET\n\n\n" + v2DateHeader + "\nx-amz-date:20070327T193642Z\n/bucket/file.txt",
			authorization: "QsoTJmkoQKjel4pCeaqbKQK2XnY=",
			clock:         v2SigningTime,
			headers: map[string]string{
				"Date":       v2DateHeader,
				"X-Amz-Date": "20070327T193642Z",
			},
		},
		{
			name:   "presigned url",
			target: "https://s3.example.com/bucket/file.txt?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1174414242",
			// "GET\n\n\n1174414242\n/bucket/file.txt"
			authorization: "Ziblzp6RzA86I36tmGT51Pg05rQ=",
			stringToSign:  "GET\n\n\n1174414242\n/bucket/file.txt",
			clock:         expires.Add(-time.Minute),
			query:         "&Signature=Ziblzp6RzA86I36tmGT51Pg05rQ%3D",
		},
		{
			name:   "presigned url with subresource",
			target: "https://s3.example.com/bucket/file.txt?acl&AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1174414242",
			// "GET\n\n\n1174414242\n/bucket/file.txt?acl"
			authorization: "fk3XtzhYNtHo+70CDTwPfB+1x9g=",
			stringToSign:  "GET\n\n\n1174414242\n/bucket/file.txt?acl",
			clock:         expires.Add(-time.Minute),
			query:         "&Signature=fk3XtzhYNtHo%2B70CDTwPfB%2B1x9g%3D",
		},
		{
			name:   "virtual host bucket prefix",
			target: "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg",
			// "GET\n\n\n<Date>\n/johnsmith/photos/puppy.jpg"
			authorization: "bWq2s1WEIj+Ydj0vQ697zp+IXMU=",
			stringToSign:  "GET\n\n\n" + v2DateHeader + "\n/johnsmith/photos/puppy.jpg",
			clock:         v2SigningTime,
			headers:       map[string]string{"Date": v2DateHeader},
			bucket:        "johnsmith",
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Guard the comment: the pinned signature must really be HMAC-SHA1
			// over the quoted string-to-sign.
			if got := base64SHA1(testSecretKey, testCase.stringToSign); got != testCase.authorization {
				t.Fatalf("string-to-sign %q produces %q, comment says %q", testCase.stringToSign, got, testCase.authorization)
			}

			method := testCase.method
			if method == "" {
				method = http.MethodGet
			}
			target := testCase.target + testCase.query
			req := httptest.NewRequest(method, target, nil)
			for name, value := range testCase.headers {
				req.Header.Set(name, value)
			}
			req.Header.Set("Authorization", "AWS "+testAccessKey+":"+testCase.authorization)

			verifier := awsDocsVerifier(testCase.clock)
			if _, err := verifier.Verify(req, VerifyOptions{S3Bucket: testCase.bucket}); err != nil {
				t.Fatalf("Verify() error = %v\nstring-to-sign:\n%s", err, testCase.stringToSign)
			}
		})
	}
}

func TestVerifyV2CanonicalResourceUsesEscapedPath(t *testing.T) {
	// The V2 spec puts the request URI, not the decoded path, into the
	// canonical resource, so %20 and %2F must survive.
	req, err := http.NewRequest(http.MethodGet, "https://s3.example.com/bucket/my%20file%20%C3%A9.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := v2CanonicalResource(req, ""), "/bucket/my%20file%20%C3%A9.txt"; got != want {
		t.Fatalf("canonical resource = %q, want %q", got, want)
	}
	if got, want := v2CanonicalResource(req, "bucket"), "/bucket/bucket/my%20file%20%C3%A9.txt"; got != want {
		t.Fatalf("virtual-host canonical resource = %q, want %q", got, want)
	}
}

func TestVerifyV2CanonicalResourceMinIOSubresources(t *testing.T) {
	// MinIO puts these subresources into the V2 canonical resource
	// (cmd/signature-v2.go resourceList). A whitelist that leaves one out makes
	// a request MinIO signs impossible to verify, so each name is pinned here
	// together with the order the resource list produces.
	for _, testCase := range []struct {
		query string
		want  string
	}{
		{"?retention", "/bucket/file.txt?retention"},
		{"?legal-hold", "/bucket/file.txt?legal-hold"},
		{"?encryption", "/bucket/file.txt?encryption"},
		{"?select", "/bucket/file.txt?select"},
		{"?select-type=2", "/bucket/file.txt?select-type=2"},
		{"?versioning&retention", "/bucket/file.txt?retention&versioning"},
		{"?acl&select&select-type=2", "/bucket/file.txt?acl&select&select-type=2"},
		{"?list-type=2", "/bucket/file.txt"},
		{"?x-id=GetObject", "/bucket/file.txt"},
	} {
		target := "https://s3.example.com/bucket/file.txt" + testCase.query
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("building %q: %v", target, err)
		}
		if got := v2CanonicalResource(req, ""); got != testCase.want {
			t.Errorf("%s -> canonical resource %q, want %q", testCase.query, got, testCase.want)
		}
	}
}

func TestVerifyV2PresignedMinIOSubresource(t *testing.T) {
	// End to end: a client that signed the canonical resource MinIO builds must
	// verify here rather than fail as a tampered request.
	const expires = "1174414242"
	stringToSign := "GET\n\n\n" + expires + "\n/bucket/file.txt?retention"
	signature := base64SHA1(testSecretKey, stringToSign)
	target := "https://s3.example.com/bucket/file.txt?retention" +
		"&AWSAccessKeyId=" + url.QueryEscape(testAccessKey) +
		"&Expires=" + expires +
		"&Signature=" + url.QueryEscape(signature)
	req := httptest.NewRequest(http.MethodGet, target, nil)

	verifier := awsDocsVerifier(time.Unix(1174414242, 0).Add(-time.Minute))
	if _, err := verifier.Verify(req, VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v\nstring-to-sign:\n%s", err, stringToSign)
	}
}
