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
	"net/http"
	"net/url"
	"strings"
)

// SignV2 returns the base64 Signature Version 2 signature for a caller-built
// AWS canonical string. This helper is useful for clients and tests; the
// Verifier API should be used for server-side request validation.
func SignV2(secret, stringToSign string) string {
	return base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secret), []byte(stringToSign)))
}

// SignV2Request signs the same canonical string as SigV2 header verification.
func SignV2Request(secret string, req *http.Request, options VerifyOptions) string {
	if req == nil {
		return ""
	}
	return SignV2(secret, v2StringToSign(req, "", v2CanonicalResource(req, options.S3Bucket)))
}

// SignV2Presign signs the SigV2 canonical string for query authentication.
func SignV2Presign(secret string, req *http.Request, expires string, options VerifyOptions) string {
	if req == nil {
		return ""
	}
	return SignV2(secret, v2StringToSign(req, expires, v2CanonicalResource(req, options.S3Bucket)))
}

// RequestPostPolicyAccessKeyID extracts the POST form's presented AccessKeyID
// without verifying the policy signature.
func RequestPostPolicyAccessKeyID(form url.Values) (string, AuthType, bool) {
	if form == nil {
		return "", AuthTypeUnknown, false
	}
	if form.Get("x-amz-algorithm") == v4Algorithm || form.Has("x-amz-credential") {
		return accessKeyFromCredential(form.Get("x-amz-credential")), AuthTypeSigV4Post, true
	}
	accessKeyID := form.Get("AWSAccessKeyId")
	return accessKeyID, AuthTypeSigV2Post, accessKeyID != ""
}

func accessKeyFromCredential(credential string) string {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[0] == "" {
		return ""
	}
	return parts[0]
}
