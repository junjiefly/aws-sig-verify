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
	"testing"
)

func TestV4PresignedExpiresDoesNotOverflowDuration(t *testing.T) {
	verifier := testVerifier(t)
	target, err := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
	if err != nil {
		t.Fatal(err)
	}
	scope := "20260101/us-east-1/s3/aws4_request"
	addV4PresignedParameters(target, scope, "9223372036854775807", testTime)
	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = target.Host
	signature := signV4Presigned(req, scope, []string{"host"}, unsignedPayloadHash, testTime)
	signed := completeV4PresignedURL(target, signature)
	if _, err := verifier.Verify(signed, VerifyOptions{Service: "s3", Region: "us-east-1"}); !errors.Is(err, ErrPresignExpiryTooLong) {
		t.Fatal("maximum expiry was not rejected")
	}
}
