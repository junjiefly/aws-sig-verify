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
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	streamingPayload         = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingPayloadTrailer  = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	unsignedStreamingPayload = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	// EmptyPayloadSHA256 can be passed as Config.DefaultPayloadHash for
	// compatibility with gateways that accept a missing x-amz-content-sha256.
	EmptyPayloadSHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	emptyPayloadHash    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	unsignedPayloadHash = "UNSIGNED-PAYLOAD"
)

type v4Credential struct {
	Date     string
	Region   string
	Service  string
	Terminal string
}

type v4Authorization struct {
	Credential    v4Credential
	AccessKeyID   string
	SignedHeaders []string
	Signature     string
}

func (v *Verifier) verifyV4(req *http.Request, query url.Values, options VerifyOptions) (*Result, error) {
	if query.Has("X-Amz-Algorithm") {
		return v.verifyV4Presigned(req, query, options)
	}
	return v.verifyV4Header(req, query, options)
}

func (v *Verifier) verifyV4Header(req *http.Request, query url.Values, options VerifyOptions) (*Result, error) {
	auth, err := parseV4Authorization(req.Header.Get("Authorization"), v4Algorithm)
	if err != nil {
		return nil, err
	}
	signingTime, err := v4HeaderSigningTime(req)
	if err != nil {
		return nil, err
	}
	if err := checkSigningTime(signingTime, v.clock().UTC(), v.maxSkew); err != nil {
		return nil, err
	}
	if err := checkScope(auth.Credential, signingTime, options); err != nil {
		return nil, err
	}
	if err := validateSignedHeaders(auth.SignedHeaders, true); err != nil {
		return nil, err
	}
	if err := validateRequestSignedHeaders(req, auth.SignedHeaders); err != nil {
		return nil, err
	}

	payloadHash, err := v.v4HeaderPayloadHash(req, query, options)
	if err != nil {
		return nil, err
	}
	credential, err := v.credentialsFor(requestContext(req), v.credentialLookup(options), auth.AccessKeyID, req.Header.Get("X-Amz-Security-Token"))
	if err != nil {
		return nil, err
	}

	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req, auth.Credential.Service == "s3"),
		canonicalQuery(query, ""),
		canonicalHeaders(req, auth.SignedHeaders),
		strings.Join(auth.SignedHeaders, ";"),
		payloadHash,
	}, "\n")
	signingKey := deriveSigningKey(credential.SecretAccessKey, auth.Credential.Date, auth.Credential.Region, auth.Credential.Service)
	expected := v4Signature(signingKey, signingTime, auth.Credential.Date+"/"+auth.Credential.Region+"/"+auth.Credential.Service+"/aws4_request", canonical)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(auth.Signature)) != 1 {
		return nil, ErrSignatureMismatch
	}

	return &Result{
		Version:       SigV4,
		AccessKeyID:   auth.AccessKeyID,
		Region:        auth.Credential.Region,
		Service:       auth.Credential.Service,
		Signature:     auth.Signature,
		SignedHeaders: append([]string(nil), auth.SignedHeaders...),
		PayloadHash:   payloadHash,
		SecurityToken: req.Header.Get("X-Amz-Security-Token"),
		SigningTime:   signingTime,
		credentials:   credential,
	}, nil
}

func (v *Verifier) verifyV4Presigned(req *http.Request, query url.Values, options VerifyOptions) (*Result, error) {
	if query.Get("X-Amz-Algorithm") != v4Algorithm {
		return nil, fmt.Errorf("%w: algorithm %q", ErrUnsupportedSignatureVersion, query.Get("X-Amz-Algorithm"))
	}
	if err := rejectDuplicateQueryFields(query, []string{
		"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature", "X-Amz-Date",
		"X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Security-Token",
		"X-Amz-Content-Sha256",
	}); err != nil {
		return nil, err
	}
	auth, err := parseV4Credential(query.Get("X-Amz-Credential"), query.Get("X-Amz-Signature"))
	if err != nil {
		return nil, err
	}
	signedHeaderList := query.Get("X-Amz-SignedHeaders")
	if signedHeaderList == "" {
		return nil, fmt.Errorf("%w: missing X-Amz-SignedHeaders", ErrMalformedAuthorization)
	}
	auth.SignedHeaders = strings.Split(signedHeaderList, ";")
	if err := validateSignedHeaders(auth.SignedHeaders, true); err != nil {
		return nil, err
	}
	if err := validateRequestSignedHeaders(req, auth.SignedHeaders); err != nil {
		return nil, err
	}

	signingTime, err := parseV4Time(query.Get("X-Amz-Date"))
	if err != nil {
		return nil, err
	}
	if err := checkSigningTimeNotInFuture(signingTime, v.clock().UTC(), v.maxSkew); err != nil {
		return nil, err
	}
	if err := checkScope(auth.Credential, signingTime, options); err != nil {
		return nil, err
	}

	rawExpires := query.Get("X-Amz-Expires")
	if rawExpires == "" {
		return nil, fmt.Errorf("%w: missing X-Amz-Expires", ErrMalformedAuthorization)
	}
	expiresSeconds, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil || expiresSeconds < 1 {
		return nil, fmt.Errorf("%w: invalid X-Amz-Expires", ErrMalformedAuthorization)
	}
	if expiresSeconds > int64(v.maxPresignExpiry/time.Second) {
		return nil, ErrPresignExpiryTooLong
	}
	expires := time.Duration(expiresSeconds) * time.Second
	expiresAt := signingTime.Add(expires)
	if v.clock().After(expiresAt) {
		return nil, ErrExpiredSignature
	}

	payloadHash, err := v4PresignedPayloadHash(req, query, options, auth.Credential.Service == "s3")
	if err != nil {
		return nil, err
	}
	credential, err := v.credentialsFor(requestContext(req), v.credentialLookup(options), auth.AccessKeyID, query.Get("X-Amz-Security-Token"))
	if err != nil {
		return nil, err
	}

	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req, auth.Credential.Service == "s3"),
		canonicalQuery(query, "X-Amz-Signature"),
		canonicalHeaders(req, auth.SignedHeaders),
		signedHeaderList,
		payloadHash,
	}, "\n")
	signingKey := deriveSigningKey(credential.SecretAccessKey, auth.Credential.Date, auth.Credential.Region, auth.Credential.Service)
	expected := v4Signature(signingKey, signingTime, auth.Credential.Date+"/"+auth.Credential.Region+"/"+auth.Credential.Service+"/aws4_request", canonical)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(auth.Signature)) != 1 {
		return nil, ErrSignatureMismatch
	}

	return &Result{
		Version:       SigV4,
		AccessKeyID:   auth.AccessKeyID,
		Region:        auth.Credential.Region,
		Service:       auth.Credential.Service,
		Signature:     auth.Signature,
		SignedHeaders: append([]string(nil), auth.SignedHeaders...),
		PayloadHash:   payloadHash,
		SecurityToken: query.Get("X-Amz-Security-Token"),
		SigningTime:   signingTime,
		ExpiresAt:     expiresAt,
		credentials:   credential,
	}, nil
}

func parseV4Authorization(authorization, algorithm string) (v4Authorization, error) {
	authorization = strings.TrimSpace(authorization)
	if !strings.HasPrefix(authorization, algorithm+" ") {
		return v4Authorization{}, fmt.Errorf("%w: algorithm %q", ErrUnsupportedSignatureVersion, authorization)
	}
	fields := strings.Split(strings.TrimSpace(strings.TrimPrefix(authorization, algorithm+" ")), ",")
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found || key == "" || value == "" {
			return v4Authorization{}, fmt.Errorf("%w: field %q", ErrMalformedAuthorization, field)
		}
		if _, exists := values[key]; exists {
			return v4Authorization{}, fmt.Errorf("%w: %s field was repeated", ErrMalformedAuthorization, key)
		}
		values[key] = value
	}
	auth, err := parseV4Credential(values["Credential"], values["Signature"])
	if err != nil {
		return v4Authorization{}, err
	}
	signedHeaders := values["SignedHeaders"]
	if signedHeaders == "" {
		return v4Authorization{}, fmt.Errorf("%w: missing SignedHeaders", ErrMalformedAuthorization)
	}
	auth.SignedHeaders = strings.Split(signedHeaders, ";")
	return auth, nil
}

func parseV4Credential(credential, signature string) (v4Authorization, error) {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[0] == "" {
		return v4Authorization{}, ErrMalformedCredential
	}
	auth := v4Authorization{
		AccessKeyID: parts[0],
		Credential: v4Credential{
			Date:     parts[1],
			Region:   parts[2],
			Service:  parts[3],
			Terminal: parts[4],
		},
		Signature: signature,
	}
	if auth.Credential.Terminal != "aws4_request" || auth.Credential.Date == "" || auth.Credential.Region == "" || auth.Credential.Service == "" {
		return v4Authorization{}, ErrMalformedCredential
	}
	if len(signature) != 64 {
		return v4Authorization{}, ErrMalformedSignature
	}
	if _, err := hex.DecodeString(signature); err != nil {
		return v4Authorization{}, ErrMalformedSignature
	}
	return auth, nil
}

func validateSignedHeaders(names []string, requireHost bool) error {
	if len(names) == 0 {
		return fmt.Errorf("%w: empty signed header list", ErrMalformedAuthorization)
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for index := 1; index < len(sorted); index++ {
		if sorted[index-1] == sorted[index] {
			return fmt.Errorf("%w: duplicate header %q", ErrMalformedAuthorization, sorted[index])
		}
	}
	if !sort.StringsAreSorted(names) {
		return fmt.Errorf("%w: signed headers are not sorted", ErrMalformedAuthorization)
	}
	for _, name := range names {
		if name == "" || name != strings.ToLower(name) {
			return fmt.Errorf("%w: invalid signed header %q", ErrMalformedAuthorization, name)
		}
	}
	if requireHost && !containsString(names, "host") {
		return fmt.Errorf("%w: host", ErrMissingSignedHeader)
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validateRequestSignedHeaders(req *http.Request, signedHeaders []string) error {
	for name := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") && !containsString(signedHeaders, lower) {
			return fmt.Errorf("%w: %s", ErrMissingSignedHeader, lower)
		}
	}
	return nil
}

func v4HeaderSigningTime(req *http.Request) (time.Time, error) {
	if value := req.Header.Get("X-Amz-Date"); value != "" {
		return parseV4Time(value)
	}
	if value := req.Header.Get("Date"); value != "" {
		return parseV4Time(value)
	}
	return time.Time{}, fmt.Errorf("%w: missing signing date", ErrMalformedAuthorization)
}

func parseV4Time(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if parsed, err := time.Parse("20060102T150405Z", value); err == nil {
		return parsed.UTC(), nil
	}
	if parsed, err := http.ParseTime(value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%w: invalid signing date", ErrMalformedAuthorization)
}

func (v *Verifier) v4HeaderPayloadHash(req *http.Request, query url.Values, options VerifyOptions) (string, error) {
	if options.PayloadHash != "" {
		return options.PayloadHash, nil
	}
	if value := req.Header.Get("X-Amz-Content-Sha256"); value != "" {
		return value, nil
	}
	if value := query.Get("X-Amz-Content-Sha256"); value != "" {
		return value, nil
	}
	if v.defaultPayloadHash != "" {
		return v.defaultPayloadHash, nil
	}
	return "", ErrPayloadHashRequired
}

func v4PresignedPayloadHash(req *http.Request, query url.Values, options VerifyOptions, s3 bool) (string, error) {
	if options.PayloadHash != "" {
		return options.PayloadHash, nil
	}
	if value := query.Get("X-Amz-Content-Sha256"); value != "" {
		return value, nil
	}
	if value := req.Header.Get("X-Amz-Content-Sha256"); value != "" {
		return value, nil
	}
	if s3 {
		return unsignedPayloadHash, nil
	}
	return "", ErrPayloadHashRequired
}

func v4Signature(signingKey []byte, signingTime time.Time, scope, canonicalRequest string) string {
	stringToSign := v4StringToSign(signingTime, scope, sha256Hex([]byte(canonicalRequest)))
	return hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
}

func v4StringToSign(signingTime time.Time, scope, hashedCanonicalRequest string) string {
	return strings.Join([]string{
		v4Algorithm,
		signingTime.UTC().Format("20060102T150405Z"),
		scope,
		hashedCanonicalRequest,
	}, "\n")
}

// Credentials returns the credential selected during verification. Secret
// material is only available to code that already received a Result.
func (r Result) Credentials() Credentials {
	return r.credentials
}
