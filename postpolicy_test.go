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
	"time"
)

func TestVerifyV4PostPolicy(t *testing.T) {
	verifier := testVerifier(t)
	policy := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"bucket":"examplebucket"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(policy))
	scope := "20260101/us-east-1/s3/aws4_request"
	key := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	signature := hex.EncodeToString(hmacSHA256(key, []byte(encoded)))

	form := url.Values{}
	form.Set("policy", encoded)
	form.Set("bucket", "examplebucket")
	form.Set("x-amz-algorithm", v4Algorithm)
	form.Set("x-amz-credential", testAccessKey+"/"+scope)
	form.Set("x-amz-date", "20260101T000000Z")
	form.Set("x-amz-signature", signature)

	result, err := verifier.VerifyPostPolicy(form, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("VerifyPostPolicy() error = %v", err)
	}
	if result.Version != SigV4 || string(result.Policy) != policy {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyV2PostPolicy(t *testing.T) {
	verifier := testVerifier(t)
	policy := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"bucket":"examplebucket"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(policy))
	signature := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(testSecretKey), []byte(encoded)))
	form := url.Values{}
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("signature", signature)
	form.Set("policy", encoded)
	form.Set("bucket", "examplebucket")

	result, err := verifier.VerifyPostPolicy(form, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyPostPolicy() error = %v", err)
	}
	if result.Version != SigV2 || string(result.Policy) != policy {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestVerifyPostPolicyConditions(t *testing.T) {
	conditionsTests := []struct {
		name          string
		policy        string
		fields        map[string]string
		repeatKey     bool
		contentLength *int64
		options       VerifyOptions
		want          error
	}{
		{
			name:   "exact match passes",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"uploads/photo.png"},{"success_action_status":"200"}]}`,
			fields: map[string]string{"key": "uploads/photo.png", "success_action_status": "200"},
		},
		{
			name:   "exact match fails",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"uploads/photo.png"}]}`,
			fields: map[string]string{"key": "uploads/other.png"},
			want:   ErrPostPolicyConditionFailed,
		},
		{
			name:   "omitted field fails an exact match",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"success_action_status":"200"}]}`,
			fields: map[string]string{"key": "photo.png"},
			want:   ErrPostPolicyConditionFailed,
		},
		{
			name:   "starts with passes",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["starts-with","$key","uploads/"]]}`,
			fields: map[string]string{"key": "uploads/photo.png"},
		},
		{
			name:   "starts with fails",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["starts-with","$key","uploads/"]]}`,
			fields: map[string]string{"key": "downloads/photo.png"},
			want:   ErrPostPolicyConditionFailed,
		},
		{
			name:   "eq array form fails",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["eq","$key","photo.png"]]}`,
			fields: map[string]string{"key": "other.png"},
			want:   ErrPostPolicyConditionFailed,
		},
		{
			name:    "virtual host bucket satisfies the bucket condition",
			policy:  `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"bucket":"examplebucket"}]}`,
			fields:  map[string]string{"key": "photo.png"},
			options: VerifyOptions{S3Bucket: "examplebucket"},
		},
		{
			name:   "in list passes",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["in","$content-type",["image/png","image/jpeg"]]]}`,
			fields: map[string]string{"content-type": "image/jpeg"},
		},
		{
			name:   "in list fails",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["in","$content-type",["image/png"]]]}`,
			fields: map[string]string{"content-type": "image/gif"},
			want:   ErrPostPolicyConditionFailed,
		},
		{
			name:   "not-in list passes",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["not-in","$content-type",["image/png"]]]}`,
			fields: map[string]string{"content-type": "image/gif"},
		},
		{
			name:   "not-in list fails",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["not-in","$content-type",["image/gif"]]]}`,
			fields: map[string]string{"content-type": "image/gif"},
			want:   ErrPostPolicyConditionFailed,
		},
		{
			name:      "repeated field fails",
			policy:    `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`,
			fields:    map[string]string{"key": "photo.png"},
			repeatKey: true,
			want:      ErrPostPolicyConditionFailed,
		},
		{
			name:          "size inside the range passes",
			policy:        `{"expiration":"2026-01-01T00:01:00Z","conditions":[["content-length-range",0,1024]]}`,
			fields:        map[string]string{"key": "photo.png"},
			contentLength: pointerTo(int64(512)),
		},
		{
			name:          "size outside the range fails",
			policy:        `{"expiration":"2026-01-01T00:01:00Z","conditions":[["content-length-range",0,1024]]}`,
			fields:        map[string]string{"key": "photo.png"},
			contentLength: pointerTo(int64(2048)),
			want:          ErrPostPolicyConditionFailed,
		},
		{
			name:   "size range without a size fails closed",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["content-length-range",0,1024]]}`,
			fields: map[string]string{"key": "photo.png"},
			want:   ErrUnsupportedPostPolicyCondition,
		},
		{
			name:   "unknown operator fails closed",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["x-amz-credential-match","$key","photo.png"]]}`,
			fields: map[string]string{"key": "photo.png"},
			want:   ErrUnsupportedPostPolicyCondition,
		},
		{
			name:   "null condition value is refused",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":null}]}`,
			fields: map[string]string{"key": "photo.png"},
			want:   ErrUnsupportedPostPolicyCondition,
		},
		{
			name:   "missing field does not match a null condition",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":null}]}`,
			fields: map[string]string{"success_action_status": "200"},
			want:   ErrUnsupportedPostPolicyCondition,
		},
		{
			name:   "null inside an in list is refused",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["in","$content-type",["image/png",null]]]}`,
			fields: map[string]string{"content-type": "image/png"},
			want:   ErrMalformedPostPolicy,
		},
		{
			name:   "empty in list is refused",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["in","$content-type",[]]]}`,
			fields: map[string]string{"content-type": "image/png"},
			want:   ErrMalformedPostPolicy,
		},
		{
			name:   "empty condition is refused",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[[]]}`,
			fields: map[string]string{"key": "photo.png"},
			want:   ErrMalformedPostPolicy,
		},
		{
			name:   "condition that needs a field and two values is refused",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[["starts-with","$key"]]}`,
			fields: map[string]string{"key": "photo.png"},
			want:   ErrMalformedPostPolicy,
		},
		{
			name:   "signing an empty condition list is allowed",
			policy: `{"expiration":"2026-01-01T00:01:00Z","conditions":[]}`,
			fields: map[string]string{"key": "photo.png"},
		},
	}

	for _, test := range conditionsTests {
		t.Run(test.name, func(t *testing.T) {
			options := test.options
			options.PostPolicyContentLength = test.contentLength
			encoded := base64.StdEncoding.EncodeToString([]byte(test.policy))
			form := url.Values{}
			for name, value := range test.fields {
				form.Set(name, value)
			}
			if test.repeatKey {
				form.Add("key", "second.png")
			}
			form.Set("policy", encoded)
			form.Set("AWSAccessKeyId", testAccessKey)
			form.Set("Signature", SignV2(testSecretKey, encoded))

			verifier := testVerifier(t)
			_, err := verifier.VerifyPostPolicy(form, options)
			if test.want == nil {
				if err != nil {
					t.Fatalf("VerifyPostPolicy() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyPostPolicyAmbiguousFormFields(t *testing.T) {
	verifier := testVerifier(t)
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))

	t.Run("field spelled two ways", func(t *testing.T) {
		form := url.Values{}
		form.Set("policy", encoded)
		form.Set("AWSAccessKeyId", testAccessKey)
		form.Set("Signature", SignV2(testSecretKey, encoded))
		form.Set("key", "photo.png")
		form.Set("Key", "other.png")
		if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrPostPolicyConditionFailed) {
			t.Fatalf("error = %v, want ErrPostPolicyConditionFailed", err)
		}
	})

	t.Run("policy field repeated", func(t *testing.T) {
		other := base64.StdEncoding.EncodeToString([]byte(
			`{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"other.png"}]}`))
		form := url.Values{}
		form.Add("policy", encoded)
		form.Add("policy", other)
		form.Set("AWSAccessKeyId", testAccessKey)
		form.Set("Signature", SignV2(testSecretKey, other))
		form.Set("key", "other.png")
		if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrMalformedPostPolicy) {
			t.Fatalf("error = %v, want ErrMalformedPostPolicy", err)
		}
	})
}

func TestVerifyPostPolicyRequiresExpiration(t *testing.T) {
	verifier := testVerifier(t)
	document := `{"conditions":[{"bucket":"examplebucket"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("policy", encoded)
	form.Set("bucket", "examplebucket")
	form.Set("Signature", SignV2(testSecretKey, encoded))

	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrMalformedPostPolicy) {
		t.Fatalf("error = %v, want ErrMalformedPostPolicy", err)
	}
}

func TestVerifyPostPolicyConditionsRunAfterSignatureCheck(t *testing.T) {
	verifier := testVerifier(t)
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("policy", encoded)
	form.Set("key", "other.png")
	form.Set("Signature", SignV2(testSecretKey, "a different document"))

	// The form fails both checks. Reporting the signature failure keeps a
	// caller's error handling from leaking which condition went unmet before
	// the document has been authenticated.
	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerifyPostPolicyExpiryIsCheckedFirst(t *testing.T) {
	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}}),
		Clock:       func() time.Time { return time.Date(2026, 1, 1, 0, 2, 0, 0, time.UTC) },
	})
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":null}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("policy", encoded)
	form.Set("Signature", SignV2(testSecretKey, encoded))

	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{}); !errors.Is(err, ErrExpiredSignature) {
		t.Fatalf("error = %v, want ErrExpiredSignature", err)
	}
}

func pointerTo[T any](value T) *T { return &value }
