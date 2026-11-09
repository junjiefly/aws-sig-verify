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
	"crypto/md5"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7/pkg/signer"
)

func hostRequest(t *testing.T, host, method, target string, body []byte) *http.Request {
	t.Helper()
	req := buildRequest(t, method, target, body)
	req.Host = host
	req.URL.Host = host
	return req
}

func signV2WithClient(req *http.Request, virtualHost bool) *http.Request {
	return signer.SignV2(*req, accessKeyID, secretAccessKey, virtualHost)
}

func TestSigV2HeaderInterop(t *testing.T) {
	const bucket = "examplebucket"
	body := []byte("hello sigv2")
	digest := base64.StdEncoding.EncodeToString(md5Sum(body))

	for _, testCase := range []struct {
		name        string
		host        string
		method      string
		target      string
		body        []byte
		headers     http.Header
		virtualHost bool
		bucket      string
	}{
		{name: "get_object", host: "s3.example.com", method: http.MethodGet, target: "/bucket/file.txt"},
		{name: "head_object", host: "s3.example.com", method: http.MethodHead, target: "/bucket/file.txt"},
		{name: "put_with_content_type", host: "s3.example.com", method: http.MethodPut, target: "/bucket/file.txt",
			body: body, headers: http.Header{"Content-Type": {"text/plain"}}},
		{name: "put_with_content_md5", host: "s3.example.com", method: http.MethodPut, target: "/bucket/file.txt",
			body: body, headers: http.Header{"Content-Type": {"text/plain"}, "Content-Md5": {digest}}},
		{name: "metadata_headers", host: "s3.example.com", method: http.MethodGet, target: "/bucket/file.txt",
			headers: http.Header{"X-Amz-Meta-Author": {"anita"}, "X-Amz-Storage-Class": {"REDUCED_REDUNDANCY"}}},
		{name: "duplicate_metadata_header", host: "s3.example.com", method: http.MethodGet, target: "/bucket/file.txt",
			headers: http.Header{"X-Amz-Meta-Tag": {"one", "two"}}},
		{name: "acl_subresource", host: "s3.example.com", method: http.MethodGet, target: "/bucket/?acl"},
		{name: "multipart_subresources", host: "s3.example.com", method: http.MethodPost, target: "/bucket/file.txt?uploads"},
		{name: "upload_id_and_part", host: "s3.example.com", method: http.MethodPut, target: "/bucket/file.txt?partNumber=1&uploadId=8oPSxLcH7WpbSvRFn8~Q_fDdYjSP0rQ6"},
		{name: "version_subresource", host: "s3.example.com", method: http.MethodGet, target: "/bucket/file.txt?versionId=3.LaCRXyjzSlXp0CEgS5bVCEXzcYDs~jpwTd08b.k6mcU"},
		{name: "response_override_subresource", host: "s3.example.com", method: http.MethodGet,
			target: "/bucket/file.txt?response-content-disposition=attachment"},
		{name: "encoded_key", host: "s3.example.com", method: http.MethodGet, target: "/bucket/my%20file%20%C3%A9.txt"},
		{name: "virtual_host", host: bucket + ".s3.example.com", method: http.MethodGet, target: "/photos/puppy.jpg",
			virtualHost: true, bucket: bucket},
		{name: "virtual_host_put", host: bucket + ".s3.example.com", method: http.MethodPut, target: "/photos/puppy.jpg",
			body: body, headers: http.Header{"Content-Type": {"image/jpeg"}}, virtualHost: true, bucket: bucket},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := hostRequest(t, testCase.host, testCase.method, testCase.target, testCase.body)
			for name, values := range testCase.headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			signed := signV2WithClient(req, testCase.virtualHost)
			if signed.Header.Get("Date") == "" {
				t.Fatal("the client did not stamp a Date header")
			}

			verifier := newVerifier(time.Now)
			result, err := verifier.Verify(signed, awsverify.VerifyOptions{S3Bucket: testCase.bucket})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Version != awsverify.SigV2 || result.AccessKeyID != accessKeyID {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestSigV2PresignInterop(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		target string
	}{
		{name: "get_object", target: "/bucket/file.txt"},
		{name: "acl_subresource", target: "/bucket/file.txt?acl"},
		{name: "encoded_key", target: "/bucket/my%20file.txt"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := hostRequest(t, "s3.example.com", http.MethodGet, testCase.target, nil)
			signed := signer.PreSignV2(*req, accessKeyID, secretAccessKey, 3600, false)
			result, err := newVerifier(time.Now).Verify(signed, awsverify.VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify() on %s: %v", signed.URL.String(), err)
			}
			if result.ExpiresAt.Before(time.Now()) {
				t.Fatalf("ExpiresAt = %s already passed", result.ExpiresAt)
			}
		})
	}
}

func TestSigV2RejectsTampering(t *testing.T) {
	req := hostRequest(t, "s3.example.com", http.MethodGet, "/bucket/file.txt?versionId=1", nil)
	req.Header.Set("X-Amz-Meta-Tag", "one")
	signed := signV2WithClient(req, false)

	for _, mutation := range []struct {
		name  string
		input func(*http.Request)
		want  error
	}{
		{
			name: "object key changed",
			input: func(r *http.Request) {
				r.URL.Path = "/bucket/other.txt"
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "subresource value changed",
			input: func(r *http.Request) {
				r.URL.RawQuery = "versionId=2"
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "signed metadata header changed",
			input: func(r *http.Request) {
				r.Header.Set("X-Amz-Meta-Tag", "two")
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "content type changed",
			input: func(r *http.Request) {
				r.Header.Set("Content-Type", "application/json")
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "date replaced beyond the skew",
			input: func(r *http.Request) {
				r.Header.Set("Date", time.Now().Add(-3*24*time.Hour).UTC().Format(http.TimeFormat))
			},
			want: awsverify.ErrClockSkew,
		},
		{
			name: "signature character flipped",
			input: func(r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth[len(auth)-2] == 'A' {
					r.Header.Set("Authorization", auth[:len(auth)-2]+"B"+auth[len(auth)-1:])
				} else {
					r.Header.Set("Authorization", auth[:len(auth)-2]+"A"+auth[len(auth)-1:])
				}
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "signature is not valid base64",
			input: func(r *http.Request) {
				auth := r.Header.Get("Authorization")
				r.Header.Set("Authorization", strings.TrimSuffix(auth, "=")+"!!=")
			},
			want: awsverify.ErrMalformedSignature,
		},
		{
			name: "authorization prefix replaced",
			input: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS "+accessKeyID+":AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			},
			want: awsverify.ErrSignatureMismatch,
		},
	} {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			target := forkRequest(t, signed, nil)
			mutation.input(target)
			_, err := newVerifier(time.Now).Verify(target, awsverify.VerifyOptions{})
			if !errors.Is(err, mutation.want) {
				t.Fatalf("error = %v, want %v", err, mutation.want)
			}
		})
	}
}

func TestSigV2PresignExpiry(t *testing.T) {
	req := hostRequest(t, "s3.example.com", http.MethodGet, "/bucket/file.txt", nil)
	signed := signer.PreSignV2(*req, accessKeyID, secretAccessKey, 60, false)

	later := newVerifier(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, err := later.Verify(forkRequest(t, signed, nil), awsverify.VerifyOptions{}); !errors.Is(err, awsverify.ErrExpiredSignature) {
		t.Fatalf("error = %v, want ErrExpiredSignature", err)
	}
	if _, err := newVerifier(time.Now).Verify(forkRequest(t, signed, nil), awsverify.VerifyOptions{}); err != nil {
		t.Fatalf("a live presigned V2 URL was rejected: %v", err)
	}
}

func md5Sum(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
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
