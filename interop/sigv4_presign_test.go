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

// presign builds a presigned URL with the independent client signer, which
// always stamps X-Amz-Date with the real clock.
func presign(t *testing.T, req *http.Request, token string, expires int64) *http.Request {
	t.Helper()
	signed := signer.PreSignV4(*req, accessKeyID, secretAccessKey, token, region, expires)
	if signed.URL.Query().Get("X-Amz-Signature") == "" {
		t.Fatal("the client produced an unsigned URL")
	}
	return signed
}

func TestSigV4PresignInterop(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		method  string
		target  string
		headers http.Header
		token   string
	}{
		{name: "get_object", method: http.MethodGet, target: "/bucket/file.txt"},
		{name: "head_object", method: http.MethodHead, target: "/bucket/file.txt"},
		{name: "key_needs_encoding", method: http.MethodGet, target: "/bucket/my%20file%20%C3%A9.txt"},
		{name: "response_overrides", method: http.MethodGet, target: "/bucket/file.txt?response-content-disposition=attachment%3B%20filename%3D%22a.txt%22&versionId=3/LaCRXyjzSlXp0CEgS5bVCEXzcYDs~jpwTd08b.k6mcU"},
		{name: "list_query", method: http.MethodGet, target: "/bucket/?list-type=2&prefix=a%2Fb%2F&max-keys=10"},
		{name: "unsigned_payload_put", method: http.MethodPut, target: "/bucket/file.txt"},
		{name: "with_metadata", method: http.MethodGet, target: "/bucket/file.txt", headers: http.Header{"X-Amz-Meta-Source": {"server-1"}}},
		{name: "temporary_credential", method: http.MethodGet, target: "/bucket/file.txt", token: sessionToken},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := buildRequest(t, testCase.method, testCase.target, nil)
			for name, values := range testCase.headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			verifier := newVerifier(time.Now)
			if testCase.token != "" {
				verifier = newSessionVerifier(time.Now, testCase.token)
			}
			signed := presign(t, req, testCase.token, 3600)
			result, err := verifier.Verify(signed, verifyOptions())
			if err != nil {
				t.Fatalf("Verify() on presigned %s: %v", signed.URL.String(), err)
			}
			if result.Version != awsverify.SigV4 {
				t.Fatalf("Version = %q, want %q", result.Version, awsverify.SigV4)
			}
			if result.ExpiresAt.Before(time.Now()) {
				t.Fatalf("ExpiresAt = %s, already passed", result.ExpiresAt)
			}
		})
	}
}

func TestSigV4PresignRejectsTampering(t *testing.T) {
	req := buildRequest(t, http.MethodGet, "/bucket/file.txt?versionId=1", nil)
	req.Header.Set("X-Amz-Meta-Source", "server-1")
	signed := presign(t, req, "", 3600)
	if signed.Header.Get("X-Amz-Meta-Source") == "" {
		t.Fatal("the request lost the header the client signed")
	}

	for _, mutation := range []struct {
		name  string
		want  error
		input func(*http.Request)
	}{
		{
			name: "object key changed",
			want: awsverify.ErrSignatureMismatch,
			input: func(r *http.Request) {
				r.URL.Path = "/bucket/other.txt"
			},
		},
		{
			name: "query parameter changed",
			want: awsverify.ErrSignatureMismatch,
			input: func(r *http.Request) {
				query := r.URL.Query()
				query.Set("versionId", "2")
				r.URL.RawQuery = query.Encode()
			},
		},
		{
			name: "expiry extended",
			want: awsverify.ErrSignatureMismatch,
			input: func(r *http.Request) {
				query := r.URL.Query()
				query.Set("X-Amz-Expires", "86400")
				r.URL.RawQuery = query.Encode()
			},
		},
		{
			// The scope is checked against the configured region before the
			// signature is recomputed, so this fails as a malformed credential.
			name: "credential region swapped",
			want: awsverify.ErrMalformedCredential,
			input: func(r *http.Request) {
				query := r.URL.Query()
				credential := query.Get("X-Amz-Credential")
				parts := strings.Split(credential, "/")
				// Credential is <access key>/<date>/<region>/<service>/aws4_request.
				parts[2] = "eu-west-1"
				query.Set("X-Amz-Credential", strings.Join(parts, "/"))
				r.URL.RawQuery = query.Encode()
			},
		},
		{
			name: "signature changed",
			want: awsverify.ErrSignatureMismatch,
			input: func(r *http.Request) {
				query := r.URL.Query()
				value := query.Get("X-Amz-Signature")
				if value[0] == 'a' {
					query.Set("X-Amz-Signature", "b"+value[1:])
				} else {
					query.Set("X-Amz-Signature", "a"+value[1:])
				}
				r.URL.RawQuery = query.Encode()
			},
		},
		{
			// A presigned URL that omits a header it declared gets a different
			// canonical request, so the verifier rejects it through the hash.
			name: "signed header dropped",
			want: awsverify.ErrSignatureMismatch,
			input: func(r *http.Request) {
				r.Header.Del("X-Amz-Meta-Source")
			},
		},
	} {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			target := forkRequest(t, signed, nil)
			mutation.input(target)
			_, err := newVerifier(time.Now).Verify(target, verifyOptions())
			if !errors.Is(err, mutation.want) {
				t.Fatalf("error = %v, want %v", err, mutation.want)
			}
		})
	}
}

func TestSigV4PresignExpiry(t *testing.T) {
	req := buildRequest(t, http.MethodGet, "/bucket/file.txt", nil)
	signed := presign(t, req, "", 60)

	// The client signed with the real clock, so a verifier two hours ahead sees
	// a URL that has already expired.
	later := newVerifier(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, err := later.Verify(forkRequest(t, signed, nil), verifyOptions()); !errors.Is(err, awsverify.ErrExpiredSignature) {
		t.Fatalf("error = %v, want ErrExpiredSignature", err)
	}
	if _, err := newVerifier(time.Now).Verify(forkRequest(t, signed, nil), verifyOptions()); err != nil {
		t.Fatalf("a live presigned URL was rejected: %v", err)
	}
}

func TestSigV4PresignRejectsLongExpiry(t *testing.T) {
	req := buildRequest(t, http.MethodGet, "/bucket/file.txt", nil)
	signed := presign(t, req, "", 3600)
	verifier := awsverify.NewVerifier(awsverify.Config{
		Clock:            time.Now,
		MaxPresignExpiry: 5 * time.Minute,
		Credentials:      testCredentials(""),
	})
	if _, err := verifier.Verify(signed, verifyOptions()); !errors.Is(err, awsverify.ErrPresignExpiryTooLong) {
		t.Fatalf("error = %v, want ErrPresignExpiryTooLong", err)
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
