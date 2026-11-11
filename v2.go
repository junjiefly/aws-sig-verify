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
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// v2Subresources is the query parameters whitelist used in the canonical
// resource. It is the union of the AWS S3 operation subresources, the legacy
// botocore SigV2 query list, and the list MinIO signs
// (cmd/signature-v2.go resourceList), kept in ASCII order: a client that
// signs a subresource missing here produces a signature that can never match.
var v2Subresources = []string{
	"abac",
	"accelerate",
	"acl",
	"analytics",
	"annotation",
	"attributes",
	"cors",
	"defaultObjectAcl",
	"delete",
	"encryption",
	"intelligent-tiering",
	"inventory",
	"legal-hold",
	"lifecycle",
	"location",
	"logging",
	"metadataAnnotationTable",
	"metadataConfiguration",
	"metadataInventoryTable",
	"metadataJournalTable",
	"metadataTable",
	"metrics",
	"notification",
	"object-lock",
	"ownershipControls",
	"partNumber",
	"policy",
	"policyStatus",
	"publicAccessBlock",
	"renameObject",
	"replication",
	"requestPayment",
	"response-cache-control",
	"response-content-disposition",
	"response-content-encoding",
	"response-content-language",
	"response-content-type",
	"response-expires",
	"restore",
	"retention",
	"select",
	"select-type",
	"session",
	"storageClass",
	"tagging",
	"torrent",
	"uploadId",
	"uploads",
	"versionId",
	"versioning",
	"versions",
	"website",
}

func (v *Verifier) verifyV2(req *http.Request, query url.Values, options VerifyOptions) (*Result, error) {
	if query.Has("AWSAccessKeyId") {
		return v.verifyV2Presigned(req, query, options)
	}
	return v.verifyV2Header(req, options)
}

func (v *Verifier) verifyV2Header(req *http.Request, options VerifyOptions) (*Result, error) {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "AWS ") {
		return nil, fmt.Errorf("%w: prefix %q", ErrUnsupportedSignatureVersion, auth)
	}
	accessKeyID, presentedSignature, found := strings.Cut(strings.TrimSpace(strings.TrimPrefix(auth, "AWS ")), ":")
	if !found || accessKeyID == "" || presentedSignature == "" {
		return nil, ErrMalformedAuthorization
	}
	if _, err := base64.StdEncoding.DecodeString(presentedSignature); err != nil {
		return nil, ErrMalformedSignature
	}

	amzDate := req.Header.Get("X-Amz-Date")
	if amzDate == "" && req.Header.Get("Date") == "" {
		return nil, fmt.Errorf("%w: missing Date", ErrMalformedAuthorization)
	}
	signingTime := time.Time{}
	if amzDate != "" {
		parsed, err := parseV4Time(amzDate)
		if err != nil {
			return nil, err
		}
		signingTime = parsed
		if err := checkSigningTime(signingTime, v.clock().UTC(), v.maxSkew); err != nil {
			return nil, err
		}
	} else {
		parsed, err := parseHTTPDate(req.Header.Get("Date"))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid Date", ErrMalformedAuthorization)
		}
		signingTime = parsed.UTC()
		if err := checkSigningTime(signingTime, v.clock().UTC(), v.maxSkew); err != nil {
			return nil, err
		}
	}

	credential, err := v.credentialsFor(requestContext(req), v.credentialLookup(options), accessKeyID, req.Header.Get("X-Amz-Security-Token"))
	if err != nil {
		return nil, err
	}
	stringToSign := v2StringToSign(req, "", v2CanonicalResource(req, options.S3Bucket))
	expected := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(credential.SecretAccessKey), []byte(stringToSign)))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presentedSignature)) != 1 {
		return nil, ErrSignatureMismatch
	}

	return &Result{
		Version:       SigV2,
		AccessKeyID:   accessKeyID,
		Signature:     presentedSignature,
		SignedHeaders: v2CanonicalHeaderNames(req),
		SecurityToken: req.Header.Get("X-Amz-Security-Token"),
		SigningTime:   signingTime,
		credentials:   credential,
	}, nil
}

func parseHTTPDate(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, http.TimeFormat, time.RFC850, time.ANSIC} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: invalid Date", ErrMalformedAuthorization)
}

func (v *Verifier) verifyV2Presigned(req *http.Request, query url.Values, options VerifyOptions) (*Result, error) {
	if err := rejectDuplicateQueryFields(query, []string{"AWSAccessKeyId", "Signature", "Expires", "X-Amz-Security-Token"}); err != nil {
		return nil, err
	}
	accessKeyID := query.Get("AWSAccessKeyId")
	presentedSignature := query.Get("Signature")
	rawExpires := query.Get("Expires")
	if accessKeyID == "" || presentedSignature == "" || rawExpires == "" {
		return nil, ErrMalformedAuthorization
	}
	if _, err := base64.StdEncoding.DecodeString(presentedSignature); err != nil {
		return nil, ErrMalformedSignature
	}
	expiresUnix, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil || expiresUnix < 1 {
		return nil, fmt.Errorf("%w: invalid Expires", ErrMalformedAuthorization)
	}
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	now := v.clock()
	if now.After(expiresAt) {
		return nil, ErrExpiredSignature
	}
	if expiresAt.Sub(now) > v.maxPresignExpiry {
		return nil, ErrPresignExpiryTooLong
	}

	credential, err := v.credentialsFor(requestContext(req), v.credentialLookup(options), accessKeyID, query.Get("X-Amz-Security-Token"))
	if err != nil {
		return nil, err
	}
	stringToSign := v2StringToSign(req, rawExpires, v2CanonicalResource(req, options.S3Bucket))
	expected := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(credential.SecretAccessKey), []byte(stringToSign)))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presentedSignature)) != 1 {
		return nil, ErrSignatureMismatch
	}

	return &Result{
		Version:       SigV2,
		AccessKeyID:   accessKeyID,
		Signature:     presentedSignature,
		SignedHeaders: v2CanonicalHeaderNames(req),
		SecurityToken: query.Get("X-Amz-Security-Token"),
		ExpiresAt:     expiresAt,
		credentials:   credential,
	}, nil
}

func v2StringToSign(req *http.Request, expires, resource string) string {
	date := req.Header.Get("Date")
	if expires != "" {
		date = expires
	}
	return strings.Join([]string{
		req.Method,
		req.Header.Get("Content-MD5"),
		req.Header.Get("Content-Type"),
		date,
		v2CanonicalAmzHeaders(req),
	}, "\n") + resource
}

func v2CanonicalHeaderNames(req *http.Request) []string {
	names := v2AmzHeaderNames(req)
	if req.Header.Get("Date") != "" {
		names = append([]string{"date"}, names...)
	}
	sort.Strings(names)
	return names
}

func v2AmzHeaderNames(req *http.Request) []string {
	var names []string
	for name := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	return names
}

func v2CanonicalAmzHeaders(req *http.Request) string {
	var output strings.Builder
	for _, name := range v2AmzHeaderNames(req) {
		output.WriteString(name)
		output.WriteByte(':')
		for index, value := range req.Header.Values(name) {
			if index > 0 {
				output.WriteByte(',')
			}
			output.WriteString(collapseSpaces(value))
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func v2CanonicalResource(req *http.Request, virtualHostBucket string) string {
	// The spec puts the request URI, from the protocol name up to the query
	// string, into the canonical resource, so percent-encoding stays as sent.
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if virtualHostBucket == "" {
		return path + v2SubresourceQuery(req)
	}
	return "/" + virtualHostBucket + path + v2SubresourceQuery(req)
}

func v2SubresourceQuery(req *http.Request) string {
	query := req.URL.Query()
	var output strings.Builder
	for _, name := range v2Subresources {
		values, ok := query[name]
		if !ok {
			continue
		}
		for _, value := range values {
			separator := byte('&')
			if output.Len() == 0 {
				separator = '?'
			}
			output.WriteByte(separator)
			output.WriteString(name)
			if value != "" {
				output.WriteByte('=')
				output.WriteString(awsURIEncode(value, true))
			}
		}
	}
	return output.String()
}
