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
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Live check against a real S3-compatible server. The package's own
// canonicalization produces the signature and the server decides whether it
// accepts it, so an acceptance is a third-party verdict on the canonical request
// rather than a self-consistency check.
//
// Nothing is committed: the target and the credentials come from the environment
// and the test skips when they are absent.
//
//	AWSSIGVERIFY_LIVE_ENDPOINT    http://host:port
//	AWSSIGVERIFY_LIVE_ACCESS_KEY  access key id
//	AWSSIGVERIFY_LIVE_SECRET_KEY  secret access key
//	AWSSIGVERIFY_LIVE_WRITE       set to 1 to also run the write checks, which
//	                           create and delete one temporary bucket
const (
	envLiveEndpoint  = "AWSSIGVERIFY_LIVE_ENDPOINT"
	envLiveAccessKey = "AWSSIGVERIFY_LIVE_ACCESS_KEY"
	envLiveSecretKey = "AWSSIGVERIFY_LIVE_SECRET_KEY"
	envLiveWrite     = "AWSSIGVERIFY_LIVE_WRITE"
)

const liveRegion = "us-east-1"

type liveTarget struct {
	endpoint  string
	accessKey string
	secretKey string
	bucket    string
	clock     time.Time
	scope     string
	client    *http.Client
}

func requireLiveTarget(t *testing.T) *liveTarget {
	t.Helper()
	endpoint := os.Getenv(envLiveEndpoint)
	accessKey := os.Getenv(envLiveAccessKey)
	secretKey := os.Getenv(envLiveSecretKey)
	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skipf("live check needs %s, %s and %s", envLiveEndpoint, envLiveAccessKey, envLiveSecretKey)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		t.Fatalf("%s = %q is not a valid endpoint", envLiveEndpoint, endpoint)
	}
	return newLiveTarget(endpoint, accessKey, secretKey, "")
}

func newLiveTarget(endpoint, accessKey, secretKey, bucket string) *liveTarget {
	target := &liveTarget{
		endpoint:  endpoint,
		accessKey: accessKey,
		secretKey: secretKey,
		bucket:    bucket,
		clock:     time.Now().UTC(),
		client:    &http.Client{Timeout: 30 * time.Second},
	}
	target.scope = fmt.Sprintf("%s/%s/s3/aws4_request", target.clock.Format("20060102"), liveRegion)
	return target
}

// signatureV4 returns the hex Signature Version 4 for a request using this
// package's canonicalization. canonicalPath, when set, replaces the URI line so
// a deliberately different rule can be tested.
func (target *liveTarget) signatureV4(req *http.Request, signedHeaders []string, payloadHash, canonicalPath string) string {
	uri := canonicalURI(req, true)
	if canonicalPath != "" {
		uri = canonicalPath
	}
	canonical := strings.Join([]string{
		req.Method,
		uri,
		canonicalQuery(req.URL.Query(), ""),
		canonicalHeaders(req, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	return v4Signature(target.signingKey(), target.clock, target.scope, canonical)
}

func (target *liveTarget) signingKey() []byte {
	return deriveSigningKey(target.secretKey, target.clock.Format("20060102"), liveRegion, "s3")
}

// signV4Live returns the Authorization header value for a request.
func (target *liveTarget) signV4Live(req *http.Request, signedHeaders []string, payloadHash, canonicalPath string) string {
	return target.authorization(
		target.signatureV4(req, signedHeaders, payloadHash, canonicalPath), signedHeaders)
}

func (target *liveTarget) authorization(signature string, signedHeaders []string) string {
	return fmt.Sprintf(
		"%s Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		v4Algorithm, target.accessKey, target.scope, strings.Join(signedHeaders, ";"), signature)
}

type liveRoundTrip struct {
	status     int
	body       string
	server     string
	awsRequest string
}

// do signs and sends one request. escapedPath keeps the wire form of the key so
// the S3 "canonicalize as sent" rule is exercised rather than bypassed.
func (target *liveTarget) do(t *testing.T, method, escapedPath string, query url.Values, headers map[string]string, body io.Reader, payloadHash string) liveRoundTrip {
	t.Helper()
	return target.doWithCanonicalPath(t, method, escapedPath, query, headers, body, payloadHash, "")
}

func (target *liveTarget) doWithCanonicalPath(t *testing.T, method, escapedPath string, query url.Values, headers map[string]string, body io.Reader, payloadHash, canonicalPath string) liveRoundTrip {
	t.Helper()
	result, err := target.request(method, escapedPath, query, headers, body, payloadHash, canonicalPath)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, escapedPath, err)
	}
	return result
}

// request is the no-test half of do, so bucket cleanup can run after the test
// that created the bucket has already finished.
func (target *liveTarget) request(method, escapedPath string, query url.Values, headers map[string]string, body io.Reader, payloadHash, canonicalPath string) (liveRoundTrip, error) {
	targetURL := target.endpoint + escapedPath
	if len(query) > 0 {
		targetURL += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return liveRoundTrip{}, err
	}
	names := target.prepare(req, headers, payloadHash)
	req.Header.Set("Authorization", target.signV4Live(req, names, payloadHashOrDefault(payloadHash), canonicalPath))
	return target.send(req)
}

// prepare adds the headers this package always signs and returns the sorted
// signed-header list. It is separate from sending so a streaming body can be
// built from the seed signature before the request exists.
func (target *liveTarget) prepare(req *http.Request, headers map[string]string, payloadHash string) []string {
	req.Header.Set("X-Amz-Date", target.clock.Format("20060102T150405Z"))
	if payloadHash != "" {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	names := []string{"host", "x-amz-date"}
	if payloadHash != "" {
		names = append(names, "x-amz-content-sha256")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
		lower := strings.ToLower(name)
		if lower != "host" {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	return names
}

func (target *liveTarget) send(req *http.Request) (liveRoundTrip, error) {
	response, err := target.client.Do(req)
	if err != nil {
		return liveRoundTrip{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return liveRoundTrip{}, err
	}
	return liveRoundTrip{
		status: response.StatusCode,
		body:   string(raw),
		server: response.Header.Get("Server"),
	}, nil
}

func payloadHashOrDefault(payloadHash string) string {
	if payloadHash == "" {
		return EmptyPayloadSHA256
	}
	return payloadHash
}

// TestLiveListBuckets signs with this package's canonicalization and lets the
// service decide.
func TestLiveListBuckets(t *testing.T) {
	target := requireLiveTarget(t)
	result := target.do(t, http.MethodGet, "/", nil, nil, nil, EmptyPayloadSHA256)
	if result.status != http.StatusOK {
		t.Fatalf("GET / with a signature produced by this package -> %d: %s", result.status, result.body)
	}
	var list struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal([]byte(result.body), &list); err != nil {
		t.Fatalf("unmarshalling bucket list: %v", err)
	}
	names := make([]string, 0, len(list.Buckets))
	for _, bucket := range list.Buckets {
		names = append(names, bucket.Name)
	}
	t.Logf("accepted (Server=%q): buckets %v", result.server, names)
}

func TestLiveObjectRoundTrip(t *testing.T) {
	target := requireLiveWriteBucket(t)
	key := target.writeKey("plain.txt")
	body := []byte("awsverify live check\n")

	result := target.do(t, http.MethodPut, target.bucketPath()+"/"+key, nil, nil, strings.NewReader(string(body)), sha256Hex(body))
	if result.status != http.StatusOK {
		t.Fatalf("PUT %s -> %d: %s", key, result.status, result.body)
	}

	result = target.do(t, http.MethodGet, target.bucketPath()+"/"+key, nil, nil, nil, EmptyPayloadSHA256)
	if result.status != http.StatusOK || result.body != string(body) {
		t.Fatalf("GET %s -> %d, body %q", key, result.status, result.body)
	}
	t.Logf("PUT and GET of %d bytes accepted on bucket %s", len(body), target.bucket)
}

func (target *liveTarget) bucketPath() string {
	return "/" + target.bucket
}

// signV4LivePresign builds a query-string signature. The payload hash is the
// UNSIGNED-PAYLOAD sentinel because the browser or CLI that uses the URL never
// signs a body digest.
func (target *liveTarget) signV4LivePresign(req *http.Request, expires string) string {
	signingKey := deriveSigningKey(target.secretKey, target.clock.Format("20060102"), liveRegion, "s3")
	query := req.URL.Query()
	query.Set("X-Amz-Algorithm", v4Algorithm)
	query.Set("X-Amz-Credential", target.accessKey+"/"+target.scope)
	query.Set("X-Amz-Date", target.clock.Format("20060102T150405Z"))
	query.Set("X-Amz-Expires", expires)
	query.Set("X-Amz-SignedHeaders", "host")
	req.URL.RawQuery = query.Encode()
	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req, true),
		canonicalQuery(req.URL.Query(), "X-Amz-Signature"),
		canonicalHeaders(req, []string{"host"}),
		"host",
		unsignedPayloadHash,
	}, "\n")
	return v4Signature(signingKey, target.clock, target.scope, canonical)
}

// get sends a request without any signature, used for presigned URLs.
func (target *liveTarget) get(t *testing.T, rawURL string) liveRoundTrip {
	t.Helper()
	response, err := target.client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s error = %v", rawURL, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading response body error = %v", err)
	}
	return liveRoundTrip{status: response.StatusCode, body: string(raw), server: response.Header.Get("Server")}
}

// firstReadableKey lists objects until one small enough to fetch is found, and
// returns its bucket and escaped key. Every case below is read-only: the test
// service holds real data and nothing here writes or deletes.
func firstReadableKey(t *testing.T) (bucket, escapedKey string) {
	t.Helper()
	target := requireLiveTarget(t)
	result := target.do(t, http.MethodGet, "/", nil, nil, nil, EmptyPayloadSHA256)
	if result.status != http.StatusOK {
		t.Fatalf("GET / -> %d: %s", result.status, result.body)
	}
	var list struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal([]byte(result.body), &list); err != nil {
		t.Fatalf("unmarshalling bucket list: %v", err)
	}
	for _, candidate := range list.Buckets {
		bucket = candidate.Name
		target.bucket = bucket
		result := target.do(t, http.MethodGet, "/"+bucket, url.Values{"list-type": []string{"2"}, "max-keys": []string{"10"}}, nil, nil, EmptyPayloadSHA256)
		if result.status != http.StatusOK {
			continue
		}
		var page struct {
			Contents []struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal([]byte(result.body), &page); err != nil {
			t.Fatalf("unmarshalling object list for %q: %v", bucket, err)
		}
		for _, object := range page.Contents {
			if object.Size > 0 && object.Size <= 1<<20 {
				return bucket, escapeKeyPath(object.Key)
			}
		}
	}
	t.Skip("no small object to read on the live service")
	return "", ""
}

func escapeKeyPath(key string) string {
	var out strings.Builder
	for _, segment := range strings.Split(key, "/") {
		out.WriteString("/")
		out.WriteString(url.PathEscape(segment))
	}
	return out.String()
}

// accepted reports whether the service got far enough to check the object layer,
// which means the signature and the canonical request were agreed. A 404 on a key
// that deliberately does not exist is therefore evidence of agreement, and it lets
// the awkward path shapes be tested without writing to real buckets.
func (result liveRoundTrip) accepted(t *testing.T, what string) bool {
	t.Helper()
	code := result.errorCode()
	switch code {
	case "SignatureDoesNotMatch", "AuthorizationHeaderMalformed", "IncompleteSignature", "XAmzContentSHA256Mismatch", "MalformedXML", "AccessDenied":
		t.Errorf("%s: service rejected the signature produced here (%s %d): %s", what, code, result.status, firstLine(result.body))
		return false
	}
	t.Logf("%s -> %d %s", what, result.status, code)
	return true
}

func (result liveRoundTrip) bodyContains(needle string) bool {
	return strings.Contains(result.body, needle)
}

func (result liveRoundTrip) errorCode() string {
	start := strings.Index(result.body, "<Code>")
	if start < 0 {
		return ""
	}
	rest := result.body[start+len("<Code>"):]
	if end := strings.Index(rest, "</Code>"); end >= 0 {
		return rest[:end]
	}
	return ""
}

func firstLine(body string) string {
	if end := strings.IndexByte(body, '\n'); end > 0 {
		return body[:end]
	}
	if end := strings.IndexByte(body, '>'); end > 0 {
		return body[:end+1]
	}
	return body
}

func TestLiveSigV4HeaderShapes(t *testing.T) {
	target := requireLiveTarget(t)
	bucket, escapedKey := firstReadableKey(t)
	target.bucket = bucket
	prefix := "/" + bucket

	for _, testCase := range []struct {
		name    string
		method  string
		path    string
		query   url.Values
		headers map[string]string
		payload string
	}{
		{name: "get existing object", method: http.MethodGet, path: prefix + escapedKey, payload: EmptyPayloadSHA256},
		{name: "head object", method: http.MethodHead, path: prefix + escapedKey, payload: EmptyPayloadSHA256},
		{name: "unsigned payload sentinel", method: http.MethodGet, path: prefix + escapedKey, payload: unsignedPayloadHash},
		{name: "signed range header", method: http.MethodGet, path: prefix + escapedKey,
			headers: map[string]string{"Range": "bytes=0-1"}, payload: EmptyPayloadSHA256},
		{name: "bucket subresource location", method: http.MethodGet, path: prefix + "/?location", payload: EmptyPayloadSHA256},
		{name: "list with query in wire order", method: http.MethodGet, path: prefix,
			query: url.Values{"list-type": []string{"2"}, "max-keys": []string{"3"}, "prefix": []string{"a"}}, payload: EmptyPayloadSHA256},
		{name: "duplicate query keys sorted", method: http.MethodGet, path: prefix,
			query: url.Values{"list-type": []string{"2"}, "max-keys": []string{"1"}, "delimiter": []string{"/", "/"}}, payload: EmptyPayloadSHA256},
		{name: "percent encoded space", method: http.MethodGet, path: prefix + "/awsverify-no-such/a%20b.txt", payload: EmptyPayloadSHA256},
		{name: "percent encoded plus", method: http.MethodGet, path: prefix + "/awsverify-no-such/a+b%2Bc.txt", payload: EmptyPayloadSHA256},
		{name: "unicode key", method: http.MethodGet, path: prefix + "/awsverify-no-such/%E4%B8%AD%E6%96%87.txt", payload: EmptyPayloadSHA256},
		{name: "dot segment kept for s3", method: http.MethodGet, path: prefix + "/awsverify-no-such/./missing.txt", payload: EmptyPayloadSHA256},
		{name: "empty query value", method: http.MethodGet, path: prefix,
			query: url.Values{"list-type": []string{"2"}, "max-keys": []string{""}, "encoding-type": []string{"url"}}, payload: EmptyPayloadSHA256},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			result := target.do(t, testCase.method, testCase.path, testCase.query, testCase.headers, nil, testCase.payload)
			result.accepted(t, testCase.method+" "+testCase.path)
		})
	}
}

// The encoded separator is the one canonicalization rule that the two recorded
// client divergences left open. Signing the same wire request under each rule and
// letting the service decide shows which rule this service follows.
func TestLiveSigV4EncodedSlashAgainstService(t *testing.T) {
	target := requireLiveTarget(t)
	bucket, _ := firstReadableKey(t)
	path := "/" + bucket + "/awsverify-no-such/a%2Fb.txt"

	awsRule := target.do(t, http.MethodGet, path, nil, nil, nil, EmptyPayloadSHA256)
	if awsRule.bodyContains("SignatureDoesNotMatch") {
		t.Logf("service rejected the AWS rule (path canonicalized as sent): %d", awsRule.status)
	} else {
		t.Logf("service accepted the AWS rule: %d", awsRule.status)
	}

	decodedRule := target.doWithCanonicalPath(t, http.MethodGet, path, nil, nil, nil, EmptyPayloadSHA256, "/"+bucket+"/awsverify-no-such/a/b.txt")
	if decodedRule.bodyContains("SignatureDoesNotMatch") {
		t.Logf("service rejected the decoded-path rule: %d", decodedRule.status)
	} else {
		t.Logf("service accepted the decoded-path rule: %d %s", decodedRule.status, decodedRule.errorCode())
	}

	if awsRule.bodyContains("SignatureDoesNotMatch") && !decodedRule.bodyContains("SignatureDoesNotMatch") {
		t.Skip("this service canonicalizes the decoded path, unlike AWS S3 and the official vectors: documented divergence")
	}
}

func TestLiveSigV4PresignedGET(t *testing.T) {
	target := requireLiveTarget(t)
	bucket, escapedKey := firstReadableKey(t)
	req, err := http.NewRequest(http.MethodGet, target.endpoint+"/"+bucket+escapedKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = ""
	signature := target.signV4LivePresign(req, "900")
	result := target.get(t, req.URL.String()+"&X-Amz-Signature="+signature)
	if result.status != http.StatusOK {
		t.Errorf("presigned GET produced by this package -> %d: %s", result.status, firstLine(result.body))
	} else {
		t.Logf("presigned GET accepted (%d bytes)", len(result.body))
	}
}

// The service still answers Signature Version 2 requests, so it is an oracle for
// the two rules the AWS documentation leaves ambiguous: which header carries the
// date, and what the canonicalized resource looks like for an escaped path.
func TestLiveSigV2Shapes(t *testing.T) {
	target := requireLiveTarget(t)
	bucket, escapedKey := firstReadableKey(t)
	prefix := "/" + bucket

	for _, testCase := range []struct {
		name    string
		path    string
		query   url.Values
		headers map[string]string
		sign    func(*http.Request) string
	}{
		{
			name: "date header only", path: "/",
			headers: map[string]string{"Date": target.clock.Format(http.TimeFormat)},
		},
		{
			name: "x-amz-date replaces date", path: "/",
			headers: map[string]string{"X-Amz-Date": target.clock.Format("20060102T150405Z")},
		},
		{
			name: "date and x-amz-date together", path: "/",
			headers: map[string]string{
				"Date":       target.clock.Format(http.TimeFormat),
				"X-Amz-Date": target.clock.Format("20060102T150405Z"),
			},
		},
		{
			name: "metadata header sorted", path: prefix + escapedKey,
			headers: map[string]string{
				"Date":         target.clock.Format(http.TimeFormat),
				"X-Amz-Meta-B": "2",
				"X-Amz-Meta-A": "1",
				"Content-Type": "text/plain",
			},
		},
		{
			name: "subresource acl", path: prefix + "/?acl",
			headers: map[string]string{"Date": target.clock.Format(http.TimeFormat)},
		},
		{
			name: "escaped path in resource", path: prefix + "/awsverify-no-such/a%20b.txt",
			headers: map[string]string{"Date": target.clock.Format(http.TimeFormat)},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, target.endpoint+testCase.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(testCase.query) > 0 {
				req.URL.RawQuery = testCase.query.Encode()
			}
			for name, value := range testCase.headers {
				req.Header.Set(name, value)
			}
			sign := testCase.sign
			if sign == nil {
				sign = func(req *http.Request) string {
					return SignV2Request(target.secretKey, req, VerifyOptions{Service: "s3"})
				}
			}
			req.Header.Set("Authorization", "AWS "+target.accessKey+":"+sign(req))
			response, err := target.client.Do(req)
			if err != nil {
				t.Fatalf("GET %s error = %v", testCase.path, err)
			}
			defer response.Body.Close()
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			result := liveRoundTrip{status: response.StatusCode, body: string(raw)}
			result.accepted(t, "SigV2 GET "+testCase.path)
		})
	}
}

// Which reading of the SigV2 date rule a service implements is decided here by
// trying all of them against a live request. The AWS documentation is ambiguous,
// no offline implementation signs SigV2 any more, and the service still accepts
// it, so it is the only oracle available. Everything but the Date element comes
// from this package's own canonicalization.
func TestLiveSigV2BothDateHeaders(t *testing.T) {
	target := requireLiveTarget(t)
	amzDate := target.clock.Format("20060102T150405Z")
	rfcDate := target.clock.Format(http.TimeFormat)

	req, err := http.NewRequest(http.MethodGet, target.endpoint+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Date", rfcDate)
	req.Header.Set("X-Amz-Date", amzDate)
	options := VerifyOptions{Service: "s3"}
	headers := v2CanonicalAmzHeaders(req)
	resource := v2CanonicalResource(req, options.S3Bucket)

	accepted := make([]string, 0, 1)
	for _, testCase := range []struct {
		name        string
		dateElement string
		includeAmz  bool
		matchesHere bool // what this package's canonicalization computes
	}{
		{name: "empty date element, x-amz-date canonicalized", dateElement: "", includeAmz: true},
		{name: "date element kept, x-amz-date also canonicalized", dateElement: rfcDate, includeAmz: true, matchesHere: true},
		{name: "date element replaced by x-amz-date value", dateElement: amzDate, includeAmz: false},
		{name: "date element kept, x-amz-date ignored", dateElement: rfcDate, includeAmz: false},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			amzBlock := ""
			if testCase.includeAmz {
				amzBlock = headers
			}
			stringToSign := strings.Join([]string{req.Method, "", "", testCase.dateElement, amzBlock}, "\n") + resource
			signed, err := http.NewRequest(http.MethodGet, target.endpoint+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			signed.Header.Set("Date", rfcDate)
			signed.Header.Set("X-Amz-Date", amzDate)
			signed.Header.Set("Authorization", "AWS "+target.accessKey+":"+SignV2(target.secretKey, stringToSign))
			response, err := target.client.Do(signed)
			if err != nil {
				t.Fatalf("GET / error = %v", err)
			}
			defer response.Body.Close()
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			result := liveRoundTrip{status: response.StatusCode, body: string(raw)}
			if result.bodyContains("SignatureDoesNotMatch") {
				t.Logf("service rejected it (this package computes it: %v)", testCase.matchesHere)
				if testCase.matchesHere {
					t.Errorf("the service rejects the reading this package signs")
				}
				return
			}
			t.Logf("ACCEPTED by the service (this package computes it: %v)", testCase.matchesHere)
			accepted = append(accepted, testCase.name)
			if !testCase.matchesHere {
				t.Errorf("the service accepts a reading this package does not sign")
			}
		})
	}
	if len(accepted) != 1 {
		t.Fatalf("expected exactly one accepted reading, got %v", accepted)
	}
}

func TestLiveSigV2PresignedGET(t *testing.T) {
	target := requireLiveTarget(t)
	bucket, escapedKey := firstReadableKey(t)
	req, err := http.NewRequest(http.MethodGet, target.endpoint+"/"+bucket+escapedKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Set("AWSAccessKeyId", target.accessKey)
	expires := fmt.Sprintf("%d", target.clock.Add(15*time.Minute).Unix())
	query.Set("Expires", expires)
	query.Set("Signature", SignV2Presign(target.secretKey, req, expires, VerifyOptions{Service: "s3"}))
	req.URL.RawQuery = query.Encode()

	result := target.get(t, req.URL.String())
	if result.status == http.StatusOK {
		t.Logf("SigV2 presigned GET accepted (%d bytes)", len(result.body))
		return
	}
	result.accepted(t, "SigV2 presigned GET")
}

// The write checks need somewhere to put objects. Rather than touch the buckets
// that already exist on the service, one bucket is created for the whole live run
// and emptied and removed after it, which is why it stays behind an opt-in.
var (
	liveWriteOnce   sync.Once
	liveWriteBucket string
	liveWriteError  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if liveWriteBucket != "" {
		if err := removeLiveBucket(liveWriteBucket); err != nil {
			fmt.Fprintf(os.Stderr, "live check: removing bucket %q failed: %v\n", liveWriteBucket, err)
		}
	}
	os.Exit(code)
}

func requireLiveWriteBucket(t *testing.T) *liveTarget {
	t.Helper()
	target := requireLiveTarget(t)
	if os.Getenv(envLiveWrite) != "1" {
		t.Skipf("write checks need %s=1: they create and delete a temporary bucket", envLiveWrite)
	}
	liveWriteOnce.Do(func() {
		name := fmt.Sprintf("awsverify-live-%s-%d", target.clock.Format("20060102-150405"), os.Getpid())
		result, err := target.request(http.MethodPut, "/"+name, nil, nil, nil, EmptyPayloadSHA256, "")
		switch {
		case err != nil:
			liveWriteError = err
		case result.status != http.StatusOK:
			liveWriteError = fmt.Errorf("PUT /%s -> %d: %s", name, result.status, firstLine(result.body))
		default:
			liveWriteBucket = name
		}
	})
	if liveWriteError != nil {
		t.Fatalf("creating the temporary bucket: %v", liveWriteError)
	}
	target.bucket = liveWriteBucket
	return target
}

// removeLiveBucket deletes every object and then the bucket. The name always
// belongs to this run, so nothing pre-existing is touched.
func removeLiveBucket(name string) error {
	target := newLiveTarget(os.Getenv(envLiveEndpoint), os.Getenv(envLiveAccessKey), os.Getenv(envLiveSecretKey), name)
	for round := 0; round < 10; round++ {
		result, err := target.request(http.MethodGet, "/"+name,
			url.Values{"list-type": []string{"2"}, "max-keys": []string{"1000"}}, nil, nil, EmptyPayloadSHA256, "")
		if err != nil {
			return err
		}
		if result.status != http.StatusOK {
			return fmt.Errorf("listing %s -> %d: %s", name, result.status, firstLine(result.body))
		}
		var page struct {
			Contents []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal([]byte(result.body), &page); err != nil {
			return err
		}
		if len(page.Contents) == 0 {
			break
		}
		for _, object := range page.Contents {
			result, err := target.request(http.MethodDelete, "/"+name+escapeKeyPath(object.Key), nil, nil, nil, EmptyPayloadSHA256, "")
			if err != nil {
				return err
			}
			if !bucketWriteAccepted(result.status) {
				return fmt.Errorf("DELETE %s/%s -> %d: %s", name, object.Key, result.status, firstLine(result.body))
			}
		}
	}
	result, err := target.request(http.MethodDelete, "/"+name, nil, nil, nil, EmptyPayloadSHA256, "")
	if err != nil {
		return err
	}
	if !bucketWriteAccepted(result.status) {
		return fmt.Errorf("DELETE /%s -> %d: %s", name, result.status, firstLine(result.body))
	}
	return nil
}

func bucketWriteAccepted(status int) bool {
	return status == http.StatusOK || status == http.StatusNoContent
}

// liveStream describes one streaming PUT: the sentinel that goes in
// X-Amz-Content-Sha256, the chunk payloads in order, the declared trailer names,
// the trailer block as it goes on the wire, and what its signature covers.
type liveStream struct {
	sentinel      string
	chunks        [][]byte
	declared      string
	trailer       string
	trailerSigned string

	// tamper edits the framed bytes after signing, which is the only way to send
	// a stream whose payload no longer matches its chunk signatures.
	tamper func(string) string
}

// streamRequest builds the PUT and returns it with its signed-header list and the
// seed signature, which is the previous-signature value for the first chunk.
func (target *liveTarget) streamRequest(t *testing.T, key string, stream liveStream) (*http.Request, []string, string) {
	t.Helper()
	decoded := 0
	for _, chunk := range stream.chunks {
		decoded += len(chunk)
	}
	headers := map[string]string{
		"Content-Encoding":             "aws-chunked",
		"x-amz-decoded-content-length": strconv.Itoa(decoded),
	}
	if stream.declared != "" {
		headers["x-amz-trailer"] = stream.declared
	}
	req, err := http.NewRequest(http.MethodPut, target.endpoint+target.bucketPath()+"/"+key, nil)
	if err != nil {
		t.Fatalf("NewRequest(PUT %s) error = %v", key, err)
	}
	names := target.prepare(req, headers, stream.sentinel)
	return req, names, target.signatureV4(req, names, stream.sentinel, "")
}

// putStream frames, signs and sends one streaming PUT.
func (target *liveTarget) putStream(t *testing.T, key string, stream liveStream) liveRoundTrip {
	t.Helper()
	req, names, seed := target.streamRequest(t, key, stream)
	body := target.frameStream(stream, seed)
	if stream.tamper != nil {
		body = stream.tamper(body)
	}
	return target.sendStream(t, req, names, seed, body)
}

// frameStream writes the wire form an AWS client produces: one signed header line
// per chunk, then the terminator chunk, then the trailer block and its signature.
func (target *liveTarget) frameStream(stream liveStream, seed string) string {
	signed := stream.sentinel == streamingPayload || stream.sentinel == streamingPayloadTrailer
	key := target.signingKey()
	previous := seed
	signedOver := stream.trailer
	if stream.trailerSigned != "" {
		signedOver = stream.trailerSigned
	}

	var out strings.Builder
	for _, chunk := range stream.chunks {
		if signed {
			previous = expectedChunkSignature(key, target.clock, target.scope, previous, chunk)
			fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n", len(chunk), previous)
		} else {
			fmt.Fprintf(&out, "%x\r\n", len(chunk))
		}
		out.Write(chunk)
		out.WriteString("\r\n")
	}
	if signed {
		previous = expectedChunkSignature(key, target.clock, target.scope, previous, nil)
		out.WriteString("0;chunk-signature=" + previous + "\r\n")
	} else {
		out.WriteString("0\r\n")
	}
	switch stream.sentinel {
	case streamingPayload:
		out.WriteString("\r\n")
	case streamingPayloadTrailer:
		out.WriteString(stream.trailer + "\r\n")
		signature := expectedTrailerSignature(key, target.clock, target.scope, previous, []byte(signedOver))
		out.WriteString(trailerSignatureHeader + ":" + signature + "\r\n\r\n")
	case unsignedStreamingPayload:
		out.WriteString(stream.trailer + "\r\n")
	}
	return out.String()
}

func (target *liveTarget) sendStream(t *testing.T, req *http.Request, names []string, seed, body string) liveRoundTrip {
	t.Helper()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	req.Header.Set("Authorization", target.authorization(seed, names))
	result, err := target.send(req)
	if err != nil {
		t.Fatalf("%s %s error = %v", req.Method, req.URL.Path, err)
	}
	t.Logf("PUT %s -> %d %s", req.URL.Path, result.status, result.errorCode())
	return result
}

func (target *liveTarget) writeKey(name string) string {
	return "awsverify-" + target.clock.Format("20060102T150405") + "-" + name
}

func TestLiveStreamingChunkedPUT(t *testing.T) {
	target := requireLiveWriteBucket(t)
	big := strings.Repeat("awsverify", 6000)

	for _, testCase := range []struct {
		name   string
		stream liveStream
	}{
		{
			name:   "single chunk",
			stream: liveStream{sentinel: streamingPayload, chunks: [][]byte{[]byte("awsverify live streaming\n")}},
		},
		{
			name: "three chunk chain",
			stream: liveStream{sentinel: streamingPayload, chunks: [][]byte{
				[]byte("first-"), []byte("second-"), []byte("third-")}},
		},
		{
			name: "54,000-byte chunk plus tail",
			stream: liveStream{sentinel: streamingPayload, chunks: [][]byte{
				[]byte(big), []byte("tail")}},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			key := target.writeKey("stream")
			result := target.putStream(t, key, testCase.stream)
			if result.status != http.StatusOK {
				t.Fatalf("PUT %s -> %d %s: %s", key, result.status, result.errorCode(), result.body)
			}
			target.readBack(t, key, testCase.stream.chunks)
		})
	}
}

// readBack GETs the key and requires exactly the concatenation of the chunks.
func (target *liveTarget) readBack(t *testing.T, key string, chunks [][]byte) {
	t.Helper()
	var want bytes.Buffer
	for _, chunk := range chunks {
		want.Write(chunk)
	}
	read := target.do(t, http.MethodGet, target.bucketPath()+"/"+key, nil, nil, nil, EmptyPayloadSHA256)
	if read.status != http.StatusOK || read.body != want.String() {
		t.Fatalf("GET %s -> %d, body of %d bytes, want %d", key, read.status, len(read.body), want.Len())
	}
	t.Logf("read back %d decoded bytes", want.Len())
}

// This service build does not implement the trailer sentinels: every trailer-mode
// PUT comes back as XAmzContentSHA256Mismatch. The probe below shows that the
// refusal is not about the signature: the same request signed with a wrong secret
// gets SignatureDoesNotMatch instead. MinIO checks the Authorization header before
// it tries to hex-decode x-amz-content-sha256 (auth-handler.go:547-585 of
// RELEASE.2025-02-03T21-03-04Z), so a canonical request that used the trailer
// sentinel as the payload hash was accepted here, and the classification then fell
// through to the ordinary signed-request path. The stream framing itself cannot be
// checked on this service, so the case skips; on a service that does implement the
// sentinels it becomes a normal acceptance check.
func TestLiveStreamingTrailerPUT(t *testing.T) {
	target := requireLiveWriteBucket(t)
	trailerLine := "x-amz-checksum-crc32:AAAAAA=="

	for _, testCase := range []struct {
		name   string
		stream liveStream
	}{
		{
			name: "signed trailer, LF terminated block",
			stream: liveStream{sentinel: streamingPayloadTrailer, chunks: [][]byte{[]byte("trailer-body")},
				declared: "x-amz-checksum-crc32", trailer: trailerLine + "\n"},
		},
		{
			name: "signed trailer, CRLF terminated block",
			stream: liveStream{sentinel: streamingPayloadTrailer, chunks: [][]byte{[]byte("trailer-body")},
				declared: "x-amz-checksum-crc32", trailer: trailerLine + "\r\n"},
		},
		{
			// The signature covers the LF-terminated block but CRLF is transmitted,
			// the shape this package's reader rejects and MinIO's source accepts.
			name: "signed trailer, block re-terminated after signing",
			stream: liveStream{sentinel: streamingPayloadTrailer, chunks: [][]byte{[]byte("reframed-body")},
				declared: "x-amz-checksum-crc32", trailer: trailerLine + "\r\n", trailerSigned: trailerLine + "\n"},
		},
		{
			name: "unsigned payload trailer",
			stream: liveStream{sentinel: unsignedStreamingPayload, chunks: [][]byte{[]byte("unsigned-body")},
				declared: "x-amz-checksum-crc32", trailer: trailerLine + "\n"},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			key := target.writeKey("trailer")
			result := target.putStream(t, key, testCase.stream)
			if streamingUnsupported(result) {
				probe := newLiveTarget(target.endpoint, target.accessKey, "not-the-live-secret", target.bucket)
				probe.clock, probe.scope = target.clock, target.scope
				bogus := probe.putStream(t, key+"-wrong-secret", testCase.stream)
				if bogus.errorCode() != "SignatureDoesNotMatch" {
					t.Fatalf("with a wrong secret the service answers %d %s, so the refusal is not only about the sentinel",
						bogus.status, bogus.errorCode())
				}
				t.Skipf("the trailer sentinel is not recognised here: right secret -> %d %s, wrong secret -> %d %s, so the header signature was checked and passed",
					result.status, result.errorCode(), bogus.status, bogus.errorCode())
			}
			if result.status != http.StatusOK {
				t.Fatalf("PUT %s -> %d %s: %s", key, result.status, result.errorCode(), result.body)
			}
			target.readBack(t, key, testCase.stream.chunks)
		})
	}
}

func streamingUnsupported(result liveRoundTrip) bool {
	return result.status == http.StatusBadRequest && result.errorCode() == "XAmzContentSHA256Mismatch"
}

// A chunk chain only means something if changing a payload after signing breaks
// it on the service, too. Each case edits the framed bytes and requires a refusal.
func TestLiveStreamingPUTRejectsTamperedStream(t *testing.T) {
	target := requireLiveWriteBucket(t)
	chunks := [][]byte{[]byte("first-chunk-payload"), []byte("second-chunk-payload")}

	for _, testCase := range []struct {
		name   string
		tamper func(string) string
	}{
		{
			name: "payload changed inside a signed chunk",
			tamper: func(framed string) string {
				const needle = "first-chunk-payload"
				index := strings.Index(framed, needle)
				if index < 0 {
					return framed + "no such payload"
				}
				return framed[:index] + "First-chunk-payload" + framed[index+len(needle):]
			},
		},
		{
			name: "chunk signature digit changed",
			tamper: func(framed string) string {
				index := strings.Index(framed, chunkSignatureMarker)
				if index < 0 {
					return framed + "no chunk signature"
				}
				position := index + len(chunkSignatureMarker)
				swapped := byte('0')
				if framed[position] == '0' {
					swapped = '1'
				}
				return framed[:position] + string(swapped) + framed[position+1:]
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			key := target.writeKey("tampered")
			result := target.putStream(t, key, liveStream{
				sentinel: streamingPayload, chunks: chunks, tamper: testCase.tamper,
			})
			if result.status == http.StatusOK {
				t.Fatalf("the service stored a stream whose framing was edited after signing")
			}
			t.Logf("refused with %d %s", result.status, result.errorCode())
		})
	}
}

// Two more refusals that do not touch the framing: a stream signed with the wrong
// secret, and a stream whose last chunk was signed with a copy of the previous
// signature. Both must be refused, which is what makes the accepted chains above
// evidence rather than a service that ignores the stream.
func TestLiveStreamingPUTRejectsWrongKeyAndReplay(t *testing.T) {
	target := requireLiveWriteBucket(t)
	chunks := [][]byte{[]byte("first-chunk-payload"), []byte("second-chunk-payload")}

	wrongKey := newLiveTarget(target.endpoint, target.accessKey, "not-the-live-secret", target.bucket)
	wrongKey.clock, wrongKey.scope = target.clock, target.scope
	key := target.writeKey("wrong-key")
	result := wrongKey.putStream(t, key, liveStream{sentinel: streamingPayload, chunks: chunks})
	if result.status == http.StatusOK {
		t.Fatalf("the service accepted a chunk chain signed with the wrong secret")
	}
	t.Logf("wrong secret refused with %d %s", result.status, result.errorCode())

	replayed := target.writeKey("replayed")
	result = target.putStream(t, replayed, liveStream{
		sentinel: streamingPayload,
		chunks:   chunks,
		tamper: func(framed string) string {
			// Replace the second chunk's signature with the first chunk's.
			first := strings.Index(framed, chunkSignatureMarker)
			if first < 0 {
				return framed + "no chunk signature"
			}
			start := first + len(chunkSignatureMarker)
			next := strings.Index(framed[start:], chunkSignatureMarker)
			if next < 0 {
				return framed + "no second chunk signature"
			}
			second := start + next + len(chunkSignatureMarker)
			return framed[:second] + framed[start:start+64] + framed[second+64:]
		},
	})
	if result.status == http.StatusOK {
		t.Fatalf("the service accepted a chunk that reused the previous signature")
	}
	t.Logf("replayed signature refused with %d %s", result.status, result.errorCode())
}

// The stream is cut short after the last data chunk, so no terminator chunk is
// sent. Whether that is stored is a server choice; if it is, the bytes still have
// to decode to what was signed. This package's reader always rejects it.
func TestLiveStreamingPUTWithoutTerminatorChunk(t *testing.T) {
	target := requireLiveWriteBucket(t)
	chunks := [][]byte{[]byte("first-chunk-payload"), []byte("second-chunk-payload")}
	key := target.writeKey("no-terminator")
	result := target.putStream(t, key, liveStream{
		sentinel: streamingPayload,
		chunks:   chunks,
		tamper: func(framed string) string {
			index := strings.LastIndex(framed, "\r\n0;chunk-signature")
			if index < 0 {
				return framed + "no terminator chunk"
			}
			return framed[:index+2]
		},
	})
	if result.status != http.StatusOK {
		t.Logf("the service refused a stream with no terminator chunk: %d %s", result.status, result.errorCode())
		return
	}
	target.readBack(t, key, chunks)
	t.Logf("the service stores a stream with no terminator chunk; this package's reader requires one")
}

// A browser or CLI posting a form does not sign an Authorization header; it signs
// the base64 policy document. Both versions are sent here, so the rule this
// package's VerifyPostPolicy implements is checked against the service.
func TestLivePostPolicyUpload(t *testing.T) {
	target := requireLiveWriteBucket(t)
	content := "posted by the awsverify live check\n"
	date := target.clock.Format("20060102T150405Z")
	expiration := target.clock.Add(15 * time.Minute).Format(time.RFC3339)

	for _, testCase := range []struct {
		name   string
		fields func(key, encodedPolicy string) [][2]string
		digest func(encodedPolicy string) [2]string
	}{
		{
			name: "sigv4 policy",
			fields: func(key, encodedPolicy string) [][2]string {
				return [][2]string{
					{"key", key},
					{"x-amz-algorithm", v4Algorithm},
					{"x-amz-credential", target.accessKey + "/" + target.scope},
					{"x-amz-date", date},
					{"policy", encodedPolicy},
				}
			},
			digest: func(encodedPolicy string) [2]string {
				return [2]string{"x-amz-signature", hexString(hmacSHA256(target.signingKey(), []byte(encodedPolicy)))}
			},
		},
		{
			name: "sigv2 policy",
			fields: func(key, encodedPolicy string) [][2]string {
				return [][2]string{
					{"key", key},
					{"AWSAccessKeyId", target.accessKey},
					{"policy", encodedPolicy},
				}
			},
			digest: func(encodedPolicy string) [2]string {
				return [2]string{"signature", SignV2(target.secretKey, encodedPolicy)}
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			key := target.writeKey("post")
			policy := fmt.Sprintf(
				`{"expiration":%q,"conditions":[{"bucket":%q},{"key":%q}]}`,
				expiration, target.bucket, key)
			encodedPolicy := base64.StdEncoding.EncodeToString([]byte(policy))
			fields := append(testCase.fields(key, encodedPolicy), testCase.digest(encodedPolicy))

			var form bytes.Buffer
			writer := multipart.NewWriter(&form)
			for _, field := range fields {
				if err := writer.WriteField(field[0], field[1]); err != nil {
					t.Fatalf("WriteField(%s) error = %v", field[0], err)
				}
			}
			part, err := writer.CreateFormFile("file", key)
			if err != nil {
				t.Fatalf("CreateFormFile error = %v", err)
			}
			if _, err := part.Write([]byte(content)); err != nil {
				t.Fatalf("writing the form file error = %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("closing the multipart form error = %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, target.endpoint+"/"+target.bucket, &form)
			if err != nil {
				t.Fatalf("NewRequest(POST) error = %v", err)
			}
			req.Header.Set("Content-Type", writer.FormDataContentType())
			result, err := target.send(req)
			if err != nil {
				t.Fatalf("POST /%s error = %v", target.bucket, err)
			}
			if result.status != http.StatusNoContent && result.status != http.StatusOK {
				t.Fatalf("POST policy upload -> %d %s: %s", result.status, result.errorCode(), firstLine(result.body))
			}
			read := target.do(t, http.MethodGet, target.bucketPath()+"/"+key, nil, nil, nil, EmptyPayloadSHA256)
			if read.status != http.StatusOK || read.body != content {
				t.Fatalf("GET %s -> %d, body %q", key, read.status, firstLine(read.body))
			}
			t.Logf("accepted and read back %d bytes", len(read.body))
		})
	}
}
