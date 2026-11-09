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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyUsesRequestScopedCredentialLookup(t *testing.T) {
	verifier := NewVerifier(Config{Clock: func() time.Time { return testTime }})
	bucketSecret := "bucket-specific-secret"

	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt", nil)
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")

	scope := "20260101/us-east-1/s3/aws4_request"
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	globalVerifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		}),
		Clock: func() time.Time { return testTime },
	})
	signature := signV4HeaderWithSecret(bucketSecret, req, scope, headers, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

	options := VerifyOptions{Service: "s3", Region: "us-east-1"}
	options.Credentials = func(_ context.Context, accessKeyID string) (Credentials, error) {
		if accessKeyID != testAccessKey {
			return Credentials{}, ErrUnknownAccessKey
		}
		return Credentials{AccessKeyID: accessKeyID, SecretAccessKey: bucketSecret}, nil
	}

	if _, err := verifier.Verify(req, options); err != nil {
		t.Fatalf("Verify() with request-scoped lookup error = %v", err)
	}

	_, err := globalVerifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("Verify() with global lookup error = %v, want ErrSignatureMismatch", err)
	}
}
