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

func TestRequestAuthTypeDoesNotMisclassifyPolicyQuery(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/object?policy=ignored", nil)
	if err != nil {
		t.Fatal(err)
	}
	authType, ok := RequestAuthType(req)
	if !ok || authType != AuthTypeAnonymous {
		t.Fatalf("RequestAuthType() = %q, %v; want %q, true", authType, ok, AuthTypeAnonymous)
	}
}

func TestRequestAuthTypeAcceptsMultipartContentTypeCase(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "Multipart/Form-Data; boundary=example")
	authType, ok := RequestAuthType(req)
	if !ok || authType != AuthTypeSigV2Post {
		t.Fatalf("RequestAuthType() = %q, %v; want %q, true", authType, ok, AuthTypeSigV2Post)
	}
}
