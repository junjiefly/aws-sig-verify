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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// TestVerifierConcurrentUse hammers one shared Verifier from many goroutines.
// The Verifier holds mutable per-request state only in local values, so this
// doubles as a data-race check under -race.
func TestVerifierConcurrentUse(t *testing.T) {
	verifier := testVerifier(t)

	v4Requests := make([]*http.Request, 8)
	for index := range v4Requests {
		req, err := http.NewRequest(http.MethodPut,
			fmt.Sprintf("https://s3.example.com/concurrent-%d", index), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "s3.example.com"
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
		req.Header.Set("X-Amz-Date", "20260101T000000Z")
		signature := signV4Header(req, taxonomyScope, taxonomyHeaders, emptyPayloadHash, testTime)
		req.Header.Set("Authorization", v4AuthorizationHeader(taxonomyScope, signature, taxonomyHeaders))
		v4Requests[index] = req
	}

	presigned := make([]*http.Request, 4)
	for index := range presigned {
		req, err := taxonomyPresign(t, fmt.Sprintf("/concurrent-%d", index), "3600", "20260101T000000Z", testTime, taxonomyScope)
		if err != nil {
			t.Fatal(err)
		}
		presigned[index] = req
	}

	policies := make([]url.Values, 4)
	signingKey := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	for index := range policies {
		policy := base64EncodeForTest(fmt.Sprintf(
			`{"expiration":"2026-01-01T01:00:00Z","conditions":[{"key":"post-%d"}]}`, index))
		policies[index] = url.Values{
			"key":              {fmt.Sprintf("post-%d", index)},
			"bucket":           {"bucket"},
			"policy":           {policy},
			"x-amz-algorithm":  {v4Algorithm},
			"x-amz-credential": {testAccessKey + "/" + taxonomyScope},
			"x-amz-date":       {"20260101T000000Z"},
			"x-amz-signature":  {hexString(hmacSHA256(signingKey, []byte(policy)))},
		}
	}

	streamBodies := make([]string, 4)
	for index := range streamBodies {
		streamBodies[index] = fuzzStreamBody(fmt.Sprintf("stream-%d", index), "tail")
	}

	var wg sync.WaitGroup
	errors := make(chan error, 256)
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			options := VerifyOptions{Service: "s3", Region: "us-east-1"}

			for round := 0; round < 8; round++ {
				if _, err := verifier.Verify(v4Requests[(worker+round)%len(v4Requests)], options); err != nil {
					errors <- fmt.Errorf("v4 header: %w", err)
					return
				}
			}
			for round := 0; round < 8; round++ {
				if _, err := verifier.Verify(presigned[(worker+round)%len(presigned)], options); err != nil {
					errors <- fmt.Errorf("presigned: %w", err)
					return
				}
			}
			for round := 0; round < 8; round++ {
				if _, err := verifier.VerifyPostPolicy(policies[(worker+round)%len(policies)], options); err != nil {
					errors <- fmt.Errorf("post policy: %w", err)
					return
				}
			}
			for round := 0; round < 4; round++ {
				firstPayload := fmt.Sprintf("stream-%d", (worker+round)%len(streamBodies))
				req := fuzzStreamingRequest()
				headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
				seed := signV4Header(req, fuzzScope, headers, streamingPayload, testTime)
				req.Header.Set("Authorization", v4AuthorizationHeader(fuzzScope, seed, headers))
				req.Body = io.NopCloser(strings.NewReader(streamBodies[(worker+round)%len(streamBodies)]))
				result, err := verifier.Verify(req, options)
				if err != nil {
					errors <- fmt.Errorf("streaming verify: %w", err)
					return
				}
				reader, err := verifier.ChunkedReader(req, result, ChunkedReaderOptions{})
				if err != nil {
					errors <- fmt.Errorf("chunked reader: %w", err)
					return
				}
				decoded, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					errors <- fmt.Errorf("chunked read: %w", err)
					return
				}
				if got, want := string(decoded), firstPayload+"tail"; got != want {
					errors <- fmt.Errorf("decoded %q, want %q", got, want)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
}

func base64EncodeForTest(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}
