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
	"encoding/hex"
	"testing"
	"time"
)

// The vector below is the public AWS Signature Version 4 "get-vanilla"
// documentation vector. It pins string-to-sign construction independently of
// the package's request-signing test helpers.
func TestV4StringToSignAWSVector(t *testing.T) {
	scope := "20150830/us-east-1/iam/aws4_request"
	canonicalRequest := "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	signingTime := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	key := deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
	signature := hex.EncodeToString(hmacSHA256(key, []byte(v4StringToSign(signingTime, scope, canonicalRequest))))
	want := "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if signature != want {
		t.Fatalf("signature = %s, want %s", signature, want)
	}
}
