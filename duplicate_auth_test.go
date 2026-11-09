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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseV4AuthorizationRejectsDuplicateField(t *testing.T) {
	scope := "20260101/us-east-1/s3/aws4_request"
	authorization := fmt.Sprintf(
		"%s Credential=%s/%s,Credential=%s/%s,SignedHeaders=host,Signature=%s",
		v4Algorithm, testAccessKey, scope, testAccessKey, scope, strings.Repeat("a", 64),
	)
	if _, err := parseV4Authorization(authorization, v4Algorithm); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
	}
}

func TestVerifyV4PresignedRejectsDuplicateAuthField(t *testing.T) {
	target, err := url.Parse("https://examplebucket.s3.us-east-1.amazonaws.com/test.txt")
	if err != nil {
		t.Fatal(err)
	}
	scope := "20260101/us-east-1/s3/aws4_request"
	addV4PresignedParameters(target, scope, "300", testTime)
	req := completeV4PresignedURL(target, strings.Repeat("a", 64))
	query := req.URL.Query()
	query.Add("X-Amz-Credential", testAccessKey+"/"+scope)
	req.URL.RawQuery = query.Encode()

	verifier := testVerifier(t)
	if _, err := verifier.Verify(req, VerifyOptions{Service: "s3", Region: "us-east-1"}); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
	}
}

func TestVerifyV2PresignedRejectsDuplicateAuthField(t *testing.T) {
	const expires = "1174414242"
	stringToSign := "GET\n\n\n" + expires + "\n/bucket/file.txt?retention"
	signature := base64SHA1(testSecretKey, stringToSign)
	target := "https://s3.example.com/bucket/file.txt?retention" +
		"&AWSAccessKeyId=" + url.QueryEscape(testAccessKey) +
		"&Expires=" + expires +
		"&Signature=" + url.QueryEscape(signature)
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Add("AWSAccessKeyId", testAccessKey)
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = parsed.Host

	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		}),
		Clock: func() time.Time { return time.Unix(1174414242, 0).Add(-time.Minute) },
	})
	if _, err := verifier.Verify(req, VerifyOptions{}); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
	}
}

func TestVerifyPostPolicyRejectsMixedSignatureSpellings(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("policy", encoded)
	form.Set("key", "photo.png")
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("Signature", SignV2(testSecretKey, encoded))
	form.Set("signature", SignV2(testSecretKey, encoded))

	verifier := testVerifier(t)
	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrMalformedAuthorization) {
		t.Fatalf("error = %v, want ErrMalformedAuthorization", err)
	}
}
