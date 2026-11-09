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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

var testTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func testVerifier(t *testing.T) *Verifier {
	t.Helper()
	return staticTestVerifier()
}

// staticTestVerifier has no *testing.T so fuzz targets can build it once.
func staticTestVerifier() *Verifier {
	return NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			testAccessKey: {AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
		}),
		Clock: func() time.Time { return testTime },
	})
}

// base64SHA1 recomputes a SigV2 signature so a pinned vector can prove that
// its quoted string-to-sign really produces it.
func base64SHA1(secret, message string) string {
	return base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secret), []byte(message)))
}

func v4AuthorizationHeader(scope, signature string, signedHeaders []string) string {
	return fmt.Sprintf(
		"%s Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		v4Algorithm,
		testAccessKey,
		scope,
		strings.Join(signedHeaders, ";"),
		signature,
	)
}

func signV4Header(req *http.Request, scope string, signedHeaders []string, payloadHash string, signingTime time.Time) string {
	return signV4HeaderWithSecret(testSecretKey, req, scope, signedHeaders, payloadHash, signingTime)
}

func signV4HeaderWithSecret(secret string, req *http.Request, scope string, signedHeaders []string, payloadHash string, signingTime time.Time) string {
	date := strings.Split(scope, "/")[0]
	region := strings.Split(scope, "/")[1]
	service := strings.Split(scope, "/")[2]
	signingKey := deriveSigningKey(secret, date, region, service)
	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req, service == "s3"),
		canonicalQuery(req.URL.Query(), ""),
		canonicalHeaders(req, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	return v4Signature(signingKey, signingTime, scope, canonical)
}

func signV4Presigned(req *http.Request, scope string, signedHeaders []string, payloadHash string, signingTime time.Time) string {
	date := strings.Split(scope, "/")[0]
	region := strings.Split(scope, "/")[1]
	service := strings.Split(scope, "/")[2]
	signingKey := deriveSigningKey(testSecretKey, date, region, service)
	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req, service == "s3"),
		canonicalQuery(req.URL.Query(), "X-Amz-Signature"),
		canonicalHeaders(req, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	return v4Signature(signingKey, signingTime, scope, canonical)
}

func addV4PresignedParameters(target *url.URL, scope string, expires string, signingTime time.Time) *url.Values {
	query := target.Query()
	query.Set("X-Amz-Algorithm", v4Algorithm)
	query.Set("X-Amz-Credential", testAccessKey+"/"+scope)
	query.Set("X-Amz-Date", signingTime.UTC().Format("20060102T150405Z"))
	query.Set("X-Amz-Expires", expires)
	query.Set("X-Amz-SignedHeaders", "host")
	target.RawQuery = query.Encode()
	return &query
}

func completeV4PresignedURL(target *url.URL, signature string) *http.Request {
	query := target.Query()
	query.Set("X-Amz-Signature", signature)
	target.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		panic(err)
	}
	req.Host = target.Host
	return req
}

func expectedChunkSignature(signingKey []byte, signingTime time.Time, scope, previous string, data []byte) string {
	stringToSign := strings.Join([]string{
		chunkedPayloadAlgorithm,
		signingTime.UTC().Format("20060102T150405Z"),
		scope,
		previous,
		emptyPayloadHash,
		sha256Hex(data),
	}, "\n")
	return hexString(hmacSHA256(signingKey, []byte(stringToSign)))
}

func expectedTrailerSignature(signingKey []byte, signingTime time.Time, scope, previous string, trailer []byte) string {
	canonical := append([]byte(nil), trailer...)
	if len(canonical) == 0 || canonical[len(canonical)-1] != '\n' {
		canonical = append(canonical, '\n')
	}
	trailerHash := sha256.Sum256(canonical)
	stringToSign := strings.Join([]string{
		chunkedTrailerAlgorithm,
		signingTime.UTC().Format("20060102T150405Z"),
		scope,
		previous,
		hexString(trailerHash[:]),
	}, "\n")
	return hexString(hmacSHA256(signingKey, []byte(stringToSign)))
}
