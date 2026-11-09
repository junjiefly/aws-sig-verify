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

func TestV4HeaderAcceptsHTTPDate(t *testing.T) {
	verifier := testVerifier(t)
	req := requestWithURL(t, http.MethodGet, "https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	req.Header.Set("Date", testTime.UTC().Format(http.TimeFormat))
	scope := "20260101/us-east-1/s3/aws4_request"
	headers := []string{"date", "host", "x-amz-content-sha256"}
	signature := signV4Header(req, scope, headers, emptyPayloadHash, testTime)
	req.Header.Set("Authorization", v4AuthorizationHeader(scope, signature, headers))

	result, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.SigningTime.Equal(testTime) {
		t.Fatalf("signing time = %v, want %v", result.SigningTime, testTime)
	}
}
