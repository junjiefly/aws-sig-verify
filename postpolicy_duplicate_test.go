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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
)

func TestVerifyPostPolicyRejectsDuplicateAuthFields(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	scope := "20260101/us-east-1/s3/aws4_request"
	key := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	signature := hex.EncodeToString(hmacSHA256(key, []byte(encoded)))

	form := url.Values{}
	form.Set("policy", encoded)
	form.Set("key", "photo.png")
	form.Set("x-amz-algorithm", v4Algorithm)
	form.Set("x-amz-credential", testAccessKey+"/"+scope)
	form.Set("x-amz-date", "20260101T000000Z")
	form.Set("x-amz-signature", signature)
	form.Add("x-amz-credential", testAccessKey+"/"+scope)

	verifier := testVerifier(t)
	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{Service: "s3", Region: "us-east-1"}); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
	}
}

func TestVerifyPostPolicyRejectsDuplicateV2AuthFields(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("policy", encoded)
	form.Set("key", "photo.png")
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("Signature", SignV2(testSecretKey, encoded))
	form.Add("AWSAccessKeyId", testAccessKey)

	verifier := testVerifier(t)
	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
	}
}

func TestVerifyPostPolicyRejectsNullConditionOperator(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[[null,"$key","photo.png"]]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("policy", encoded)
	form.Set("key", "photo.png")
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("Signature", SignV2(testSecretKey, encoded))

	verifier := testVerifier(t)
	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrMalformedPostPolicy) {
		t.Fatalf("error = %v, want ErrMalformedPostPolicy", err)
	}
}
