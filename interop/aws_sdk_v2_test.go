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
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/junjiefly/aws-sig-verify"
)

// This file uses the official AWS SDK for Go v2 signer as another independent
// implementation. Together with aws-sdk-go v1, minio-go, and the recorded AWS
// vectors, agreement across four independent sources is strong evidence that
// the canonical request this package reconstructs matches what real clients
// sign.

func sdkV2Credentials(token string) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    token,
	}
}

func sdkV2SignerFor(token string) *v4.Signer {
	return v4.NewSigner(func(options *v4.SignerOptions) {
		// S3 signs the path exactly as sent on the wire, without additional
		// escaping, the same rule this package implements.
		options.DisableURIPathEscaping = true
	})
}

func TestAWSSDKV2HeaderInterop(t *testing.T) {
	for _, testCase := range sdkHeaderCases() {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, testCase.method, testCase.target, testCase.payloadHash(), testCase.headers)
			if err := sdkV2SignerFor(testCase.token).SignHTTP(context.Background(),
				sdkV2Credentials(testCase.token), req, testCase.payloadHash(), service, region, fixedStreamingTime); err != nil {
				t.Fatalf("official signer failed: %v", err)
			}
			verifier := newSessionVerifier(func() time.Time { return fixedStreamingTime }, testCase.token)
			mustVerify(t, verifier, req, verifyOptions())
		})
	}
}

func TestAWSSDKV2HeaderRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"changed object key", func(req *http.Request) { req.URL.Path = "/key-2" }},
		{"changed query value", func(req *http.Request) { req.URL.RawQuery = "versionId=4" }},
		{"changed signature", func(req *http.Request) {
			req.Header.Set("Authorization", flipLastCharacter(req.Header.Get("Authorization")))
		}},
		{"swapped region in scope", func(req *http.Request) {
			req.Header.Set("Authorization", strings.Replace(req.Header.Get("Authorization"), "/s3/", "/sqs/", 1))
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/key?versionId=3",
				awsverify.EmptyPayloadSHA256, nil)
			if err := sdkV2SignerFor("").SignHTTP(context.Background(),
				sdkV2Credentials(""), req, awsverify.EmptyPayloadSHA256, service, region, fixedStreamingTime); err != nil {
				t.Fatalf("official signer failed: %v", err)
			}
			testCase.mutate(req)
			verifier := newVerifier(func() time.Time { return fixedStreamingTime })
			mustReject(t, verifier, req, verifyOptions(), testCase.name)
		})
	}
}

func TestAWSSDKV2PresignInterop(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		target      string
		expires     time.Duration
		payloadHash string
		token       string
	}{
		{name: "get_object", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key", expires: time.Hour, payloadHash: "UNSIGNED-PAYLOAD"},
		{name: "put_object", method: http.MethodPut, target: "https://examplebucket.s3.example.com/key", expires: 15 * time.Minute, payloadHash: "UNSIGNED-PAYLOAD"},
		{name: "temporary_credential", method: http.MethodGet, target: "https://examplebucket.s3.example.com/key", expires: time.Hour, payloadHash: "UNSIGNED-PAYLOAD", token: sessionToken},
		{name: "encoded_slash_key", method: http.MethodGet, target: "https://examplebucket.s3.example.com/dir%2Fnested/key", expires: time.Hour, payloadHash: "UNSIGNED-PAYLOAD"},
		{name: "percent_encoded_key", method: http.MethodGet, target: "https://examplebucket.s3.example.com/my%20file%20%C3%A9.txt", expires: time.Hour, payloadHash: "UNSIGNED-PAYLOAD"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// A presigned URL must be self-contained: the payload commitment
			// stays in the signing call, not on the wire request, so the URL
			// works for consumers that cannot send signed headers.
			req := sdkNewRequest(t, testCase.method, testCase.target, "", nil)
			query := req.URL.Query()
			query.Set("X-Amz-Expires", strconv.FormatInt(int64(testCase.expires/time.Second), 10))
			req.URL.RawQuery = query.Encode()
			presigned, _, err := sdkV2SignerFor(testCase.token).PresignHTTP(context.Background(),
				sdkV2Credentials(testCase.token), req, testCase.payloadHash, service, region, fixedStreamingTime)
			if err != nil {
				t.Fatalf("official presigner failed: %v", err)
			}
			signed, err := http.NewRequest(testCase.method, presigned, nil)
			if err != nil {
				t.Fatal(err)
			}
			verifier := newSessionVerifier(func() time.Time { return fixedStreamingTime }, testCase.token)
			mustVerify(t, verifier, signed, verifyOptions())
		})
	}
}

func TestAWSSDKV2PresignRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"changed key", func(req *http.Request) { req.URL.Path = "/other" }},
		{"changed expiry", func(req *http.Request) {
			req.URL.RawQuery = strings.Replace(req.URL.RawQuery, "X-Amz-Expires=3600", "X-Amz-Expires=7200", 1)
		}},
		{"added query parameter", func(req *http.Request) { req.URL.RawQuery += "&acl" }},
		{"changed signature", func(req *http.Request) {
			req.URL.RawQuery = flipLastCharacter(req.URL.RawQuery)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := sdkNewRequest(t, http.MethodGet, "https://examplebucket.s3.example.com/key", "", nil)
			query := req.URL.Query()
			query.Set("X-Amz-Expires", "3600")
			req.URL.RawQuery = query.Encode()
			presigned, _, err := sdkV2SignerFor("").PresignHTTP(context.Background(),
				sdkV2Credentials(""), req, "", service, region, fixedStreamingTime)
			if err != nil {
				t.Fatalf("official presigner failed: %v", err)
			}
			signed, err := http.NewRequest(http.MethodGet, presigned, nil)
			if err != nil {
				t.Fatal(err)
			}
			testCase.mutate(signed)
			verifier := newVerifier(func() time.Time { return fixedStreamingTime })
			mustReject(t, verifier, signed, verifyOptions(), testCase.name)
		})
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
