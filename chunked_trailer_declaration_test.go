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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChunkedReaderRequiresTrailerDeclaration(t *testing.T) {
	verifier := testVerifier(t)
	req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.us-east-1.amazonaws.com/object", strings.NewReader("hello"))
	req.Host = "examplebucket.s3.us-east-1.amazonaws.com"
	req.Header.Set("X-Amz-Content-Sha256", streamingPayloadTrailer)
	req.Header.Set("X-Amz-Date", "20260101T000000Z")
	req.Header.Set("Authorization", v4AuthorizationHeader(
		"20260101/us-east-1/s3/aws4_request", strings.Repeat("a", 64), []string{"host", "x-amz-content-sha256", "x-amz-date"},
	))
	req.Body = io.NopCloser(strings.NewReader("hello"))

	result := &Result{
		PayloadHash: streamingPayloadTrailer,
		Signature:   strings.Repeat("a", 64),
		SigningTime: testTime,
		Service:     "s3",
		Region:      "us-east-1",
		credentials: Credentials{SecretAccessKey: testSecretKey},
	}
	if _, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{}); err != ErrMalformedChunk {
		t.Fatalf("ChunkedReader() error = %v, want ErrMalformedChunk", err)
	}
}
