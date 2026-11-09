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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	md5simd "github.com/minio/md5-simd"
)

const (
	accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	sessionToken    = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmzppwYmoLpyvEX"
	region          = "us-east-1"
	service         = "s3"
	v4AlgorithmName = "AWS4-HMAC-SHA256"
)

// fixedStreamingTime pins the streaming vectors so runs stay byte-reproducible.
var fixedStreamingTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// sha256Hasher adapts the standard library hasher to the interface required by
// the independent streaming signer.
type sha256Hasher struct{ hash.Hash }

func (s sha256Hasher) Close() {}

func newHasher() md5simd.Hasher { return sha256Hasher{sha256.New()} }

func newVerifier(clock func() time.Time) *awsverify.Verifier {
	return newSessionVerifier(clock, "")
}

// testCredentials stores a session token for the test access key, so temporary
// credential requests must present the same token.
func testCredentials(token string) awsverify.CredentialFunc {
	return func(_ context.Context, presented string) (awsverify.Credentials, error) {
		if presented != accessKeyID {
			return awsverify.Credentials{}, awsverify.ErrUnknownAccessKey
		}
		return awsverify.Credentials{
			AccessKeyID:     presented,
			SecretAccessKey: secretAccessKey,
			SessionToken:    token,
		}, nil
	}
}

func newSessionVerifier(clock func() time.Time, token string) *awsverify.Verifier {
	return awsverify.NewVerifier(awsverify.Config{Clock: clock, Credentials: testCredentials(token)})
}

func verifyOptions() awsverify.VerifyOptions {
	return awsverify.VerifyOptions{Service: service, Region: region}
}

// buildRequest creates a path-style S3 request.
func buildRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://s3.example.com"+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "s3.example.com"
	if body != nil {
		req.ContentLength = int64(len(body))
	} else {
		req.Body = io.NopCloser(bytes.NewReader(nil))
	}
	return req
}

// payloadHashOf is what a client commits to in X-Amz-Content-Sha256.
func payloadHashOf(body []byte) string {
	if body == nil {
		return awsverify.EmptyPayloadSHA256
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func mustVerify(t *testing.T, verifier *awsverify.Verifier, req *http.Request, options awsverify.VerifyOptions) *awsverify.Result {
	t.Helper()
	result, err := verifier.Verify(req, options)
	if err != nil {
		t.Fatalf("Verify() on %s %s: %v", req.Method, req.URL.String(), err)
	}
	if result.AccessKeyID != accessKeyID {
		t.Fatalf("AccessKeyID = %q, want %q", result.AccessKeyID, accessKeyID)
	}
	return result
}

func mustReject(t *testing.T, verifier *awsverify.Verifier, req *http.Request, options awsverify.VerifyOptions, why string) {
	t.Helper()
	if _, err := verifier.Verify(req, options); err == nil {
		t.Fatalf("accepted a request it must reject: %s", why)
	}
}

// forkRequest rebuilds a request from scratch so a mutation cannot leak into
// sibling cases, and replaces the body when the payload is covered by a hash.
func forkRequest(t *testing.T, req *http.Request, body []byte) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	clone, err := http.NewRequest(req.Method, req.URL.String(), reader)
	if err != nil {
		t.Fatal(err)
	}
	clone.Host = req.Host
	clone.Header = req.Header.Clone()
	if body != nil {
		clone.ContentLength = int64(len(body))
	} else {
		clone.Body = io.NopCloser(bytes.NewReader(nil))
	}
	return clone
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
