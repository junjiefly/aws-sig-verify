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
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// postPolicy builds the base64 policy document that a browser form upload
// carries. Only the signature is produced by the independent client signer;
// the document itself follows the field names in the AWS POST documentation.
func postPolicy(t *testing.T, expiration time.Time, key string) string {
	t.Helper()
	document := fmt.Sprintf(
		`{"expiration":%q,"conditions":[{"bucket":"bucket"},{"key":%q},{"content-type":"text/plain"},`+
			`["content-length-range",0,1048576]]}`,
		expiration.UTC().Format("2006-01-02T15:04:05Z"), key)
	return base64.StdEncoding.EncodeToString([]byte(document))
}

// postPolicyOptions carries the object size that the shared policy document's
// content-length-range condition is checked against.
func postPolicyOptions(size int64) awsverify.VerifyOptions {
	options := verifyOptions()
	options.PostPolicyContentLength = &size
	return options
}

func v4PostForm(policy, date, signature, token string) url.Values {
	form := url.Values{
		"key":             {"uploads/notes.txt"},
		"bucket":          {"bucket"},
		"content-type":    {"text/plain"},
		"policy":          {policy},
		"x-amz-algorithm": {v4AlgorithmName},
		"x-amz-credential": {fmt.Sprintf("%s/%s/%s/s3/aws4_request",
			accessKeyID, date, region)},
		"x-amz-date":      {date + "T000000Z"},
		"x-amz-signature": {signature},
	}
	if token != "" {
		form.Set("x-amz-security-token", token)
	}
	return form
}

func TestPostPolicyV4Interop(t *testing.T) {
	expiration := fixedStreamingTime.Add(time.Hour)
	policy := postPolicy(t, expiration, "uploads/notes.txt")
	date := fixedStreamingTime.UTC().Format("20060102")
	signature := signer.PostPresignSignatureV4(policy, fixedStreamingTime, secretAccessKey, region)

	form := v4PostForm(policy, date, signature, "")
	result, err := newVerifier(func() time.Time { return fixedStreamingTime }).
		VerifyPostPolicy(form, postPolicyOptions(1024))
	if err != nil {
		t.Fatalf("VerifyPostPolicy() error = %v", err)
	}
	if result.Version != awsverify.SigV4 || result.AccessKeyID != accessKeyID {
		t.Fatalf("unexpected result: %+v", result)
	}
	if string(result.Policy) == "" {
		t.Fatal("the policy document was not returned")
	}

	t.Run("temporary credential", func(t *testing.T) {
		stsForm := v4PostForm(policy, date, signer.PostPresignSignatureV4(policy, fixedStreamingTime, secretAccessKey, region), sessionToken)
		verifier := newSessionVerifier(func() time.Time { return fixedStreamingTime }, sessionToken)
		if _, err := verifier.VerifyPostPolicy(stsForm, postPolicyOptions(1024)); err != nil {
			t.Fatalf("VerifyPostPolicy() error = %v", err)
		}
		stsForm.Del("x-amz-security-token")
		if _, err := verifier.VerifyPostPolicy(stsForm, postPolicyOptions(1024)); !errors.Is(err, awsverify.ErrSessionTokenMismatch) {
			t.Fatalf("error = %v, want ErrSessionTokenMismatch", err)
		}
	})

	t.Run("object larger than the range", func(t *testing.T) {
		form := v4PostForm(policy, date, signature, "")
		if _, err := newVerifier(func() time.Time { return fixedStreamingTime }).
			VerifyPostPolicy(form, postPolicyOptions(2097152)); !errors.Is(err, awsverify.ErrPostPolicyConditionFailed) {
			t.Fatalf("error = %v, want ErrPostPolicyConditionFailed", err)
		}
	})

	t.Run("size unknown to the caller", func(t *testing.T) {
		// Fails closed: a content-length-range condition the caller cannot
		// evaluate is an error, not a skipped check.
		form := v4PostForm(policy, date, signature, "")
		if _, err := newVerifier(func() time.Time { return fixedStreamingTime }).
			VerifyPostPolicy(form, verifyOptions()); !errors.Is(err, awsverify.ErrUnsupportedPostPolicyCondition) {
			t.Fatalf("error = %v, want ErrUnsupportedPostPolicyCondition", err)
		}
	})
}

func TestPostPolicyV2Interop(t *testing.T) {
	expiration := fixedStreamingTime.Add(time.Hour)
	policy := postPolicy(t, expiration, "uploads/notes.txt")
	signature := signer.PostPresignSignatureV2(policy, secretAccessKey)

	form := url.Values{
		"key":            {"uploads/notes.txt"},
		"bucket":         {"bucket"},
		"content-type":   {"text/plain"},
		"policy":         {policy},
		"AWSAccessKeyId": {accessKeyID},
		"Signature":      {signature},
	}
	result, err := newVerifier(func() time.Time { return fixedStreamingTime }).
		VerifyPostPolicy(form, postPolicyOptions(1024))
	if err != nil {
		t.Fatalf("VerifyPostPolicy() error = %v", err)
	}
	if result.Version != awsverify.SigV2 {
		t.Fatalf("Version = %q, want %q", result.Version, awsverify.SigV2)
	}
}

func TestPostPolicyRejectsTampering(t *testing.T) {
	expiration := fixedStreamingTime.Add(time.Hour)
	policy := postPolicy(t, expiration, "uploads/notes.txt")
	otherPolicy := postPolicy(t, expiration, "uploads/other.txt")
	date := fixedStreamingTime.UTC().Format("20060102")
	signature := signer.PostPresignSignatureV4(policy, fixedStreamingTime, secretAccessKey, region)
	verifier := newVerifier(func() time.Time { return fixedStreamingTime })

	for _, mutation := range []struct {
		name  string
		input func(url.Values)
		want  error
	}{
		{
			name: "signature changed",
			input: func(form url.Values) {
				value := form.Get("x-amz-signature")
				if value[0] == 'a' {
					form.Set("x-amz-signature", "b"+value[1:])
				} else {
					form.Set("x-amz-signature", "a"+value[1:])
				}
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "policy swapped for another document",
			input: func(form url.Values) {
				form.Set("policy", otherPolicy)
			},
			want: awsverify.ErrSignatureMismatch,
		},
		{
			name: "credential date moved",
			input: func(form url.Values) {
				form.Set("x-amz-credential", accessKeyID+"/20251231/us-east-1/s3/aws4_request")
			},
			want: awsverify.ErrMalformedCredential,
		},
		{
			name: "algorithm replaced",
			input: func(form url.Values) {
				form.Set("x-amz-algorithm", "AWS4-HMAC-SHA256-STREAMING")
			},
			want: awsverify.ErrUnsupportedSignatureVersion,
		},
		{
			name: "unknown access key",
			input: func(form url.Values) {
				form.Set("x-amz-credential", "AKIAUNKNOWNKEY000000/"+date+"/us-east-1/s3/aws4_request")
			},
			want: awsverify.ErrUnknownAccessKey,
		},
		{
			name: "policy missing",
			input: func(form url.Values) {
				form.Del("policy")
			},
			want: awsverify.ErrPostPolicyRequired,
		},
		{
			name: "key changed outside its condition",
			input: func(form url.Values) {
				form.Set("key", "uploads/somethingelse.txt")
			},
			want: awsverify.ErrPostPolicyConditionFailed,
		},
		{
			name: "bucket changed outside its condition",
			input: func(form url.Values) {
				form.Set("bucket", "otherbucket")
			},
			want: awsverify.ErrPostPolicyConditionFailed,
		},
		{
			name: "content type dropped",
			input: func(form url.Values) {
				form.Del("content-type")
			},
			want: awsverify.ErrPostPolicyConditionFailed,
		},
	} {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			form := v4PostForm(policy, date, signature, "")
			mutation.input(form)
			_, err := verifier.VerifyPostPolicy(form, postPolicyOptions(1024))
			if !errors.Is(err, mutation.want) {
				t.Fatalf("error = %v, want %v", err, mutation.want)
			}
		})
	}

	t.Run("expired policy", func(t *testing.T) {
		stale := postPolicy(t, fixedStreamingTime.Add(-time.Hour), "uploads/notes.txt")
		form := v4PostForm(stale, date,
			signer.PostPresignSignatureV4(stale, fixedStreamingTime, secretAccessKey, region), "")
		if _, err := verifier.VerifyPostPolicy(form, postPolicyOptions(1024)); !errors.Is(err, awsverify.ErrExpiredSignature) {
			t.Fatalf("error = %v, want ErrExpiredSignature", err)
		}
	})

	t.Run("policy without an expiration is refused", func(t *testing.T) {
		evergreen := base64.StdEncoding.EncodeToString([]byte(
			`{"conditions":[{"bucket":"bucket"},{"key":"uploads/notes.txt"}]}`))
		form := v4PostForm(evergreen, date,
			signer.PostPresignSignatureV4(evergreen, fixedStreamingTime, secretAccessKey, region), "")
		if _, err := verifier.VerifyPostPolicy(form, postPolicyOptions(1024)); !errors.Is(err, awsverify.ErrMalformedPostPolicy) {
			t.Fatalf("error = %v, want ErrMalformedPostPolicy", err)
		}
	})

	t.Run("condition failure is reported after the signature", func(t *testing.T) {
		// The document below is signed correctly and violates its own condition;
		// a forged document that violates conditions must not get a different
		// error before authentication.
		mismatched := v4PostForm(otherPolicy, date,
			signer.PostPresignSignatureV4(otherPolicy, fixedStreamingTime, secretAccessKey, region), "")
		mismatched.Set("key", "uploads/notes.txt")
		if _, err := verifier.VerifyPostPolicy(mismatched, postPolicyOptions(1024)); !errors.Is(err, awsverify.ErrPostPolicyConditionFailed) {
			t.Fatalf("error = %v, want ErrPostPolicyConditionFailed", err)
		}
	})
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
