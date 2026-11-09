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
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// These cases record where the independent client signer deviates from the AWS
// canonicalization rules, instead of dropping the shapes from the test suite.
// The verifier follows AWS, so a request signed under the client's rules is
// rejected; that is a real interoperability limit for a gateway and belongs in
// the documentation.

// TestSigV4EncodedSlashClientDivergence: S3 signs the path exactly as it
// arrives on the wire, so %2F stays one path segment. The client signer builds
// its canonical path from the decoded URL path and re-encodes it, which turns
// %2F into a separator.
func TestSigV4EncodedSlashClientDivergence(t *testing.T) {
	req := buildRequest(t, http.MethodGet, "/bucket/a%2Fb", nil)
	req.Header.Set("X-Amz-Content-Sha256", payloadHashOf(nil))
	signed := signer.SignV4(*req, accessKeyID, secretAccessKey, "", region)

	_, err := newVerifier(time.Now).Verify(signed, verifyOptions())
	if !errors.Is(err, awsverify.ErrSignatureMismatch) {
		t.Fatalf("error = %v, want ErrSignatureMismatch", err)
	}
	t.Log("rejected: the client signed /bucket/a/b while the request carries /bucket/a%2Fb")

	// Positive control: the same client agrees with AWS as soon as the key has
	// no encoded separator, which is the only shape the client generates itself.
	plain := buildRequest(t, http.MethodGet, "/bucket/a/b", nil)
	plain.Header.Set("X-Amz-Content-Sha256", payloadHashOf(nil))
	mustVerify(t, newVerifier(time.Now), signer.SignV4(*plain, accessKeyID, secretAccessKey, "", region), verifyOptions())

	// Second implementation: AWS's own signer keeps %2F as one segment, and this
	// package accepts it, so the disagreement belongs to the client library and
	// not to the rule.
	official := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/bucket/a%2Fb", awsverify.EmptyPayloadSHA256, nil)
	if _, err := sdkSignerFor("").Sign(official, nil, service, region, fixedStreamingTime); err != nil {
		t.Fatalf("official signer failed: %v", err)
	}
	mustVerify(t, newVerifier(func() time.Time { return fixedStreamingTime }), official, verifyOptions())
}

// TestSigV4DuplicateQueryKeyClientDivergence: AWS sorts the values of a
// repeated query key, which the public AWS test suite pins in
// get-vanilla-query-order-value. The client signer keeps the order the values
// were written in, so a reversed pair produces a different signature.
func TestSigV4DuplicateQueryKeyClientDivergence(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		target string
	}{
		{name: "values already sorted", target: "/bucket/?marker=a&marker=b"},
		{name: "values reversed", target: "/bucket/?marker=b&marker=a"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req := buildRequest(t, http.MethodGet, testCase.target, nil)
			req.Header.Set("X-Amz-Content-Sha256", payloadHashOf(nil))
			signed := signer.SignV4(*req, accessKeyID, secretAccessKey, "", region)
			_, err := newVerifier(time.Now).Verify(signed, verifyOptions())
			if testCase.name == "values reversed" {
				if !errors.Is(err, awsverify.ErrSignatureMismatch) {
					t.Fatalf("error = %v, want ErrSignatureMismatch", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}

	// Second implementation: AWS's own signer sorts the values of a repeated key
	// before signing, and its signature for the reversed wire order verifies
	// here, which pins the rule the client library gets wrong.
	reversed := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/bucket/?marker=b&marker=a", awsverify.EmptyPayloadSHA256, nil)
	if _, err := sdkSignerFor("").Sign(reversed, nil, service, region, fixedStreamingTime); err != nil {
		t.Fatalf("official signer failed: %v", err)
	}
	t.Run("official signer sorts values", func(t *testing.T) {
		mustVerify(t, newVerifier(func() time.Time { return fixedStreamingTime }), reversed, verifyOptions())
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
