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
	"strings"
)

type AuthType string

const (
	AuthTypeUnknown       AuthType = ""
	AuthTypeSigV2Header   AuthType = "SigV2Header"
	AuthTypeSigV2Presign  AuthType = "SigV2Presign"
	AuthTypeSigV4Header   AuthType = "SigV4Header"
	AuthTypeSigV4Presign  AuthType = "SigV4Presign"
	AuthTypeSigV4Post     AuthType = "SigV4Post"
	AuthTypeSigV2Post     AuthType = "SigV2Post"
	AuthTypeStreamingV4   AuthType = "SigV4Streaming"
	AuthTypeStreamingV4Tr AuthType = "SigV4StreamingTrailer"
	AuthTypeUnsignedTr    AuthType = "UnsignedStreamingTrailer"
	AuthTypeAnonymous     AuthType = "Anonymous"
)

// RequestAccessKeyID extracts only the presented AccessKeyID. It performs no
// signature verification and must not be used to authorize a request alone.
func RequestAccessKeyID(req *http.Request) (string, AuthType, bool) {
	authType, present := RequestAuthType(req)
	if !present {
		return "", AuthTypeAnonymous, false
	}
	switch authType {
	case AuthTypeSigV2Header:
		accessKeyID, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "AWS ")), ":")
		return accessKeyID, authType, accessKeyID != ""
	case AuthTypeSigV4Header, AuthTypeStreamingV4, AuthTypeStreamingV4Tr:
		auth, err := parseV4Authorization(req.Header.Get("Authorization"), v4Algorithm)
		if err != nil {
			return "", authType, false
		}
		return auth.AccessKeyID, authType, auth.AccessKeyID != ""
	case AuthTypeSigV4Presign:
		accessKeyID := accessKeyFromCredential(req.URL.Query().Get("X-Amz-Credential"))
		return accessKeyID, authType, accessKeyID != ""
	case AuthTypeSigV2Presign:
		return req.URL.Query().Get("AWSAccessKeyId"), authType, true
	default:
		return "", authType, false
	}
}

func RequestAuthType(req *http.Request) (AuthType, bool) {
	if req == nil {
		return AuthTypeUnknown, false
	}
	authorization := req.Header.Get("Authorization")
	query := req.URL.Query()
	switch {
	case query.Has("X-Amz-Algorithm"):
		return AuthTypeSigV4Presign, true
	case strings.HasPrefix(authorization, v4Algorithm+" "):
		if req.Header.Get("X-Amz-Content-Sha256") == streamingPayloadTrailer {
			return AuthTypeStreamingV4Tr, true
		}
		if req.Header.Get("X-Amz-Content-Sha256") == streamingPayload {
			return AuthTypeStreamingV4, true
		}
		return AuthTypeSigV4Header, true
	case query.Has("X-Amz-Credential"):
		return AuthTypeSigV4Presign, true
	case query.Has("AWSAccessKeyId"):
		return AuthTypeSigV2Presign, true
	case strings.HasPrefix(authorization, "AWS "):
		return AuthTypeSigV2Header, true
	case req.Method == http.MethodPut &&
		req.Header.Get("X-Amz-Content-Sha256") == unsignedStreamingPayload:
		return AuthTypeUnsignedTr, true
	case req.Method == http.MethodPost &&
		strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "multipart/form-data"):
		if query.Get("x-amz-signature") != "" || query.Get("x-amz-credential") != "" {
			return AuthTypeSigV4Post, true
		}
		return AuthTypeSigV2Post, true
	case authorization == "":
		return AuthTypeAnonymous, true
	default:
		return AuthTypeUnknown, true
	}
}

// RequestBucketFromHost returns the prefix before the longest configured
// service domain. Domain matches ignore case and have no port or scheme.
func RequestBucketFromHost(host string, domains []string) string {
	hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if index := strings.Index(hostname, ":"); index >= 0 {
		hostname = hostname[:index]
	}
	matched := ""
	for _, domain := range domains {
		suffix := "." + strings.ToLower(strings.Trim(domain, "."))
		if suffix == "." {
			continue
		}
		if strings.HasSuffix(hostname, suffix) {
			if len(suffix) > len(matched) {
				matched = suffix
			}
		}
	}
	if matched != "" {
		return hostname[:len(hostname)-len(matched)]
	}
	return ""
}
