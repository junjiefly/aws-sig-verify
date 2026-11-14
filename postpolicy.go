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
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PostPolicy is a decoded browser-upload policy document.
type PostPolicy struct {
	Raw        []byte
	Expiration time.Time
	Conditions []json.RawMessage
}

// PostPolicyContentLengthRange describes a signed content-length-range
// condition. Valid is false when the policy has no such condition.
type PostPolicyContentLengthRange struct {
	Min   int64
	Max   int64
	Valid bool
}

// ParsePostPolicy decodes a base64 policy document. The document must carry an
// expiration: AWS requires one, and a document without it can never expire, so it
// is refused here rather than silently treated as always valid.
func ParsePostPolicy(encodedPolicy string) (*PostPolicy, error) {
	if encodedPolicy == "" {
		return nil, ErrPostPolicyRequired
	}
	raw, err := base64.StdEncoding.DecodeString(encodedPolicy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64", ErrMalformedPostPolicy)
	}
	return ParsePostPolicyDocument(raw)
}

// ParsePostPolicyDocument parses the decoded JSON representation of an S3 POST
// policy. Duplicate JSON keys are refused because they make the signed document
// ambiguous.
func ParsePostPolicyDocument(raw []byte) (*PostPolicy, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, ErrPostPolicyRequired
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedPostPolicy, err)
	}
	var document struct {
		Expiration string            `json:"expiration"`
		Conditions []json.RawMessage `json:"conditions"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON", ErrMalformedPostPolicy)
	}
	if document.Expiration == "" {
		return nil, fmt.Errorf("%w: policy has no expiration", ErrMalformedPostPolicy)
	}
	parsed, err := time.Parse(time.RFC3339Nano, document.Expiration)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expiration", ErrMalformedPostPolicy)
	}
	if document.Conditions == nil {
		return nil, fmt.Errorf("%w: policy has no conditions", ErrMalformedPostPolicy)
	}
	policy := &PostPolicy{Raw: append([]byte(nil), raw...), Expiration: parsed.UTC()}
	policy.Conditions = append([]json.RawMessage(nil), document.Conditions...)
	return policy, nil
}

// ContentLengthRange extracts the signed upload size range. Multiple ranges are
// refused to keep the effective restriction unambiguous.
func (policy *PostPolicy) ContentLengthRange() (PostPolicyContentLengthRange, error) {
	if policy == nil {
		return PostPolicyContentLengthRange{}, ErrMalformedPostPolicy
	}
	var found *PostPolicyContentLengthRange
	for _, condition := range policy.Conditions {
		var parts []json.RawMessage
		if err := json.Unmarshal(condition, &parts); err != nil {
			continue
		}
		if len(parts) != 3 {
			continue
		}
		var operator string
		if err := json.Unmarshal(parts[0], &operator); err != nil || !strings.EqualFold(operator, "content-length-range") {
			continue
		}
		if found != nil {
			return PostPolicyContentLengthRange{}, fmt.Errorf("%w: multiple content-length-range conditions", ErrMalformedPostPolicy)
		}
		minimum, err := postPolicyConditionSize(parts[1])
		if err != nil {
			return PostPolicyContentLengthRange{}, err
		}
		maximum, err := postPolicyConditionSize(parts[2])
		if err != nil {
			return PostPolicyContentLengthRange{}, err
		}
		found = &PostPolicyContentLengthRange{Min: minimum, Max: maximum, Valid: true}
	}
	if found == nil {
		return PostPolicyContentLengthRange{}, nil
	}
	return *found, nil
}

// CheckConditions applies signed POST policy conditions to a form. It also
// rejects form fields that the policy does not mention, except the standard
// POST exceptions and fields named in VerifyOptions.PostPolicyUnconditionedFields.
// Signature verification, expiration checks, and content-length-range checks
// remain separate because callers may need to stream the file body before the
// final content length is known; call ContentLengthRange to obtain the signed
// upload limit.
func (policy *PostPolicy) CheckConditions(form url.Values, options VerifyOptions) error {
	if policy == nil {
		return ErrMalformedPostPolicy
	}
	if err := checkPostPolicyConditions(form, policy.Conditions, options, true); err != nil {
		return err
	}
	return enforcePostPolicyFields(form, policy.Conditions, options)
}

func (v *Verifier) VerifyPostPolicy(form url.Values, options VerifyOptions) (*Result, error) {
	_, policyDocument, err := v.verifyPostPolicySignature(form, options)
	if err != nil {
		return nil, err
	}
	policy := form.Get("policy")
	var result *Result
	if form.Get("x-amz-algorithm") != "" || form.Has("x-amz-credential") {
		for _, name := range []string{"x-amz-algorithm", "x-amz-credential", "x-amz-signature", "x-amz-date", "x-amz-security-token"} {
			if len(form[name]) > 1 {
				return nil, fmt.Errorf("%w: %s field was repeated", ErrMalformedAuthorization, name)
			}
		}
		result, err = v.verifyV4PostPolicy(form, options, policy, policyDocument)
	} else {
		for _, name := range []string{"AWSAccessKeyId", "Signature", "signature", "x-amz-security-token"} {
			if len(form[name]) > 1 {
				return nil, fmt.Errorf("%w: %s field was repeated", ErrMalformedAuthorization, name)
			}
		}
		if len(form["Signature"])+len(form["signature"]) > 1 {
			return nil, fmt.Errorf("%w: Signature field was repeated", ErrMalformedAuthorization)
		}
		result, err = v.verifyV2PostPolicy(form, options, policy, policyDocument)
	}
	if err != nil {
		return nil, err
	}
	// The conditions are only worth checking once the document they belong to is
	// authenticated: the signature proves the credential holder agreed to them.
	if err := checkPostPolicyConditions(form, policyDocument.Conditions, options, false); err != nil {
		return nil, err
	}
	if options.PostPolicyStrictFields {
		if err := enforcePostPolicyFields(form, policyDocument.Conditions, options); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// VerifyPostPolicySignature authenticates the signed policy document and its
// expiration, but does not check policy conditions. Use this when a condition
// such as content-length-range can only be evaluated while the upload body is
// streamed; the caller remains responsible for checking every condition.
func (v *Verifier) VerifyPostPolicySignature(form url.Values, options VerifyOptions) (*Result, error) {
	result, _, err := v.verifyPostPolicySignature(form, options)
	return result, err
}

func (v *Verifier) verifyPostPolicySignature(form url.Values, options VerifyOptions) (*Result, *PostPolicy, error) {
	if form == nil {
		return nil, nil, ErrPostPolicyRequired
	}
	if form.Get("policy") == "" {
		return nil, nil, ErrPostPolicyRequired
	}
	if len(form["policy"]) != 1 {
		return nil, nil, fmt.Errorf("%w: %d policy fields in one form", ErrMalformedPostPolicy, len(form["policy"]))
	}
	if form.Get("x-amz-algorithm") != "" || form.Has("x-amz-credential") {
		for _, name := range []string{"x-amz-algorithm", "x-amz-credential", "x-amz-signature", "x-amz-date", "x-amz-security-token"} {
			if len(form[name]) > 1 {
				return nil, nil, fmt.Errorf("%w: %s field was repeated", ErrMalformedAuthorization, name)
			}
		}
	} else {
		for _, name := range []string{"AWSAccessKeyId", "Signature", "signature", "x-amz-security-token"} {
			if len(form[name]) > 1 {
				return nil, nil, fmt.Errorf("%w: %s field was repeated", ErrMalformedAuthorization, name)
			}
		}
		if len(form["Signature"])+len(form["signature"]) > 1 {
			return nil, nil, fmt.Errorf("%w: Signature field was repeated", ErrMalformedAuthorization)
		}
	}
	encodedPolicy := form.Get("policy")
	parsedPolicy, err := ParsePostPolicy(encodedPolicy)
	if err != nil {
		return nil, nil, err
	}
	if v.clock().After(parsedPolicy.Expiration) {
		return nil, nil, ErrExpiredSignature
	}
	if form.Get("x-amz-algorithm") != "" || form.Has("x-amz-credential") {
		result, err := v.verifyV4PostPolicy(form, options, encodedPolicy, parsedPolicy)
		return result, parsedPolicy, err
	}
	result, err := v.verifyV2PostPolicy(form, options, encodedPolicy, parsedPolicy)
	return result, parsedPolicy, err
}

func (v *Verifier) verifyV4PostPolicy(form url.Values, options VerifyOptions, encodedPolicy string, policy *PostPolicy) (*Result, error) {
	if form.Get("x-amz-algorithm") != v4Algorithm {
		return nil, fmt.Errorf("%w: algorithm %q", ErrUnsupportedSignatureVersion, form.Get("x-amz-algorithm"))
	}
	auth, err := parseV4Credential(form.Get("x-amz-credential"), form.Get("x-amz-signature"))
	if err != nil {
		return nil, err
	}
	signingTime, err := parseV4Time(form.Get("x-amz-date"))
	if err != nil {
		return nil, err
	}
	if err := checkSigningTime(signingTime, v.clock().UTC(), v.maxSkew); err != nil {
		return nil, err
	}
	if err := checkScope(auth.Credential, signingTime, options); err != nil {
		return nil, err
	}
	credential, err := v.credentialsFor(context.Background(), v.credentialLookup(options), auth.AccessKeyID, form.Get("x-amz-security-token"))
	if err != nil {
		return nil, err
	}

	signingKey := deriveSigningKey(credential.SecretAccessKey, auth.Credential.Date, auth.Credential.Region, auth.Credential.Service)
	expected := hex.EncodeToString(hmacSHA256(signingKey, []byte(encodedPolicy)))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(auth.Signature)) != 1 {
		return nil, ErrSignatureMismatch
	}
	return &Result{
		Version:       SigV4,
		AccessKeyID:   auth.AccessKeyID,
		Region:        auth.Credential.Region,
		Service:       auth.Credential.Service,
		Signature:     auth.Signature,
		PayloadHash:   encodedPolicy,
		SecurityToken: form.Get("x-amz-security-token"),
		Policy:        policy.Raw,
		SigningTime:   signingTime,
		credentials:   credential,
	}, nil
}

func (v *Verifier) verifyV2PostPolicy(form url.Values, options VerifyOptions, encodedPolicy string, policy *PostPolicy) (*Result, error) {
	accessKeyID := form.Get("AWSAccessKeyId")
	presented := form.Get("Signature")
	if presented == "" {
		presented = form.Get("signature")
	}
	if accessKeyID == "" || presented == "" {
		return nil, ErrMalformedAuthorization
	}
	if _, err := base64.StdEncoding.DecodeString(presented); err != nil {
		return nil, ErrMalformedSignature
	}
	credential, err := v.credentialsFor(context.Background(), v.credentialLookup(options), accessKeyID, form.Get("x-amz-security-token"))
	if err != nil {
		return nil, err
	}
	expected := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(credential.SecretAccessKey), []byte(encodedPolicy)))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
		return nil, ErrSignatureMismatch
	}
	return &Result{
		Version:       SigV2,
		AccessKeyID:   accessKeyID,
		Signature:     presented,
		SecurityToken: form.Get("x-amz-security-token"),
		Policy:        policy.Raw,
		credentials:   credential,
	}, nil
}

// checkPostPolicyConditions matches the form fields against the conditions the
// credential holder signed. A condition this package cannot evaluate is an error,
// never a silent pass: an ignored condition is the hole this closes.
func checkPostPolicyConditions(form url.Values, conditions []json.RawMessage, options VerifyOptions, ignoreContentLengthRange bool) error {
	for _, condition := range conditions {
		if ignoreContentLengthRange && postPolicyConditionIsContentLengthRange(condition) {
			continue
		}
		if err := checkPostPolicyCondition(form, condition, options); err != nil {
			return err
		}
	}
	return nil
}

func postPolicyConditionIsContentLengthRange(condition json.RawMessage) bool {
	var parts []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(condition), &parts); err != nil || len(parts) != 3 {
		return false
	}
	var operator string
	if err := json.Unmarshal(parts[0], &operator); err != nil {
		return false
	}
	return strings.EqualFold(operator, "content-length-range")
}

func enforcePostPolicyFields(form url.Values, conditions []json.RawMessage, options VerifyOptions) error {
	if form == nil {
		form = url.Values{}
	}
	referenced := make(map[string]struct{})
	for _, condition := range conditions {
		trimmed := bytes.TrimSpace(condition)
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] == '{' {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &fields); err != nil {
				continue
			}
			for name := range fields {
				referenced[strings.ToLower(strings.TrimPrefix(name, "$"))] = struct{}{}
			}
			continue
		}
		var parts []json.RawMessage
		if err := json.Unmarshal(trimmed, &parts); err != nil || len(parts) < 2 {
			continue
		}
		var operator string
		if err := json.Unmarshal(parts[0], &operator); err != nil {
			continue
		}
		switch strings.ToLower(operator) {
		case "eq", "starts-with", "in", "not-in":
			name, err := postPolicyConditionField(parts[1])
			if err != nil {
				continue
			}
			referenced[strings.ToLower(name)] = struct{}{}
		}
	}

	unconditioned := make([]string, 0)
	isSigV4 := postPolicyFormIsSigV4(form)
	for name := range form {
		lowerName := strings.ToLower(name)
		if postPolicyFieldIsException(lowerName, isSigV4, options) {
			continue
		}
		if _, found := referenced[lowerName]; !found {
			unconditioned = append(unconditioned, name)
		}
	}
	if len(unconditioned) == 0 {
		return nil
	}
	sort.Strings(unconditioned)
	return fmt.Errorf("%w: fields %q", ErrFormFieldNotInPolicy, strings.Join(unconditioned, ", "))
}

func postPolicyFormIsSigV4(form url.Values) bool {
	for name := range form {
		switch strings.ToLower(name) {
		case "x-amz-algorithm", "x-amz-credential":
			return true
		}
	}
	return false
}

func postPolicyFieldIsException(lowerName string, isSigV4 bool, options VerifyOptions) bool {
	switch lowerName {
	case "policy", "file", "x-amz-signature":
		return true
	}
	if !isSigV4 && (lowerName == "signature" || lowerName == "awsaccesskeyid") {
		return true
	}
	if strings.HasPrefix(lowerName, "x-ignore-") {
		return true
	}
	for _, name := range options.PostPolicyUnconditionedFields {
		if lowerName == strings.ToLower(strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return fmt.Errorf("unexpected JSON token %v", token)
	}
	switch delim {
	case '{':
		return scanDuplicateJSONObject(decoder)
	case '[':
		return scanDuplicateJSONArray(decoder)
	default:
		return fmt.Errorf("invalid JSON delimiter %v", delim)
	}
}

func scanDuplicateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			return scanDuplicateJSONObject(decoder)
		case '[':
			return scanDuplicateJSONArray(decoder)
		default:
			return fmt.Errorf("invalid JSON delimiter %v", delim)
		}
	}
	return nil
}

func scanDuplicateJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return fmt.Errorf("invalid JSON object key")
		}
		if _, found := seen[name]; found {
			return fmt.Errorf("duplicate JSON key %q", name)
		}
		seen[name] = struct{}{}
		if err := scanDuplicateJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func scanDuplicateJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := scanDuplicateJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func checkPostPolicyCondition(form url.Values, condition json.RawMessage, options VerifyOptions) error {
	trimmed := bytes.TrimSpace(condition)
	if len(trimmed) == 0 {
		return fmt.Errorf("%w: empty condition", ErrMalformedPostPolicy)
	}
	if trimmed[0] == '{' {
		return checkExactMatchCondition(form, trimmed, options)
	}

	var parts []json.RawMessage
	if err := json.Unmarshal(trimmed, &parts); err != nil {
		return fmt.Errorf("%w: condition is neither an object nor an array", ErrMalformedPostPolicy)
	}
	if len(parts) == 0 {
		return fmt.Errorf("%w: empty condition", ErrMalformedPostPolicy)
	}
	var operatorValue any
	if err := json.Unmarshal(parts[0], &operatorValue); err != nil {
		return fmt.Errorf("%w: condition operator is not a string", ErrMalformedPostPolicy)
	}
	operator, ok := operatorValue.(string)
	if !ok {
		return fmt.Errorf("%w: condition operator is not a string", ErrMalformedPostPolicy)
	}
	switch strings.ToLower(operator) {
	case "eq", "starts-with":
		if len(parts) != 3 {
			return fmt.Errorf("%w: %s takes a field and a value", ErrMalformedPostPolicy, operator)
		}
		field, err := postPolicyConditionField(parts[1])
		if err != nil {
			return err
		}
		expected, err := postPolicyConditionString(parts[2])
		if err != nil {
			return err
		}
		return matchPostPolicyField(strings.ToLower(operator), form, options, field, expected)
	case "in", "not-in":
		if len(parts) != 3 {
			return fmt.Errorf("%w: %s takes a field and a value list", ErrMalformedPostPolicy, operator)
		}
		field, err := postPolicyConditionField(parts[1])
		if err != nil {
			return err
		}
		allowed, err := postPolicyConditionStrings(parts[2])
		if err != nil {
			return fmt.Errorf("%w: %s needs a list of strings", ErrMalformedPostPolicy, operator)
		}
		if len(allowed) == 0 {
			return fmt.Errorf("%w: %s on %s has no allowed value", ErrMalformedPostPolicy, operator, field)
		}
		value, err := postPolicyFieldValue(form, options, field)
		if err != nil {
			return err
		}
		found := false
		for _, candidate := range allowed {
			if candidate == value {
				found = true
				break
			}
		}
		if found == (strings.ToLower(operator) == "in") {
			return nil
		}
		return fmt.Errorf("%w: %s %q", ErrPostPolicyConditionFailed, field, value)
	case "content-length-range":
		if len(parts) != 3 {
			return fmt.Errorf("%w: content-length-range takes two sizes", ErrMalformedPostPolicy)
		}
		minSize, err := postPolicyConditionSize(parts[1])
		if err != nil {
			return err
		}
		maxSize, err := postPolicyConditionSize(parts[2])
		if err != nil {
			return err
		}
		if options.PostPolicyContentLength == nil {
			return fmt.Errorf("%w: content-length-range needs VerifyOptions.PostPolicyContentLength",
				ErrUnsupportedPostPolicyCondition)
		}
		size := *options.PostPolicyContentLength
		if size < minSize || size > maxSize {
			return fmt.Errorf("%w: content-length-range %d-%d, size %d",
				ErrPostPolicyConditionFailed, minSize, maxSize, size)
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedPostPolicyCondition, operator)
	}
}

// checkExactMatchCondition handles the {"field":"value"} shape, which is the same
// thing as ["eq","$field","value"] in the AWS documentation.
func checkExactMatchCondition(form url.Values, condition json.RawMessage, options VerifyOptions) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(condition, &fields); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedPostPolicy, err)
	}
	if len(fields) == 0 {
		return fmt.Errorf("%w: condition object has no field", ErrMalformedPostPolicy)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	// Sorted so the reported condition does not depend on map iteration order.
	sort.Strings(names)
	for _, name := range names {
		expected, err := postPolicyConditionString(fields[name])
		if err != nil {
			// A null or numeric condition value has no defined meaning here, and
			// MinIO's server refuses non-string condition values as well.
			return fmt.Errorf("%w: %s has no string value", ErrUnsupportedPostPolicyCondition, name)
		}
		if err := matchPostPolicyField("eq", form, options, name, expected); err != nil {
			return err
		}
	}
	return nil
}

func matchPostPolicyField(operator string, form url.Values, options VerifyOptions, field, expected string) error {
	value, err := postPolicyFieldValue(form, options, field)
	if err != nil {
		return err
	}
	if operator == "starts-with" {
		if !postPolicyStartsWithAllowed(strings.ToLower(field)) {
			return fmt.Errorf("%w: starts-with is not allowed for %s", ErrUnsupportedPostPolicyCondition, field)
		}
		if strings.HasPrefix(value, expected) {
			return nil
		}
		return fmt.Errorf("%w: %s %q does not start with %q",
			ErrPostPolicyConditionFailed, field, value, expected)
	}
	if value == expected {
		return nil
	}
	return fmt.Errorf("%w: %s is %q, want %q", ErrPostPolicyConditionFailed, field, value, expected)
}

func postPolicyStartsWithAllowed(lowerField string) bool {
	switch lowerField {
	case "bucket", "x-amz-algorithm", "x-amz-credential", "x-amz-date":
		return false
	}
	return true
}

// postPolicyFieldValue resolves one condition field against the posted form.
// Field names are matched case-insensitively, as S3 does. A missing field reads as
// the empty string, which is what an exact-match condition on a field the client
// left out compares against. "bucket" also accepts the virtual-host bucket from
// options, because a browser posts to the bucket URL and does not always repeat
// the bucket as a form field.
func postPolicyFieldValue(form url.Values, options VerifyOptions, field string) (string, error) {
	name := strings.TrimPrefix(field, "$")
	var values []string
	for key, candidates := range form {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	if len(values) == 0 && strings.EqualFold(name, "bucket") && options.S3Bucket != "" {
		return options.S3Bucket, nil
	}
	// Two values for one condition field can come from a repeated field or from
	// two spellings that differ only in case. Which one a condition then matches
	// is up to the form parser, so refuse the request instead of choosing.
	if len(values) > 1 {
		return "", fmt.Errorf("%w: %s was posted %d times", ErrPostPolicyConditionFailed, name, len(values))
	}
	if len(values) == 1 {
		return values[0], nil
	}
	return "", nil
}

func postPolicyConditionField(raw json.RawMessage) (string, error) {
	field, err := postPolicyConditionString(raw)
	if err != nil {
		return "", fmt.Errorf("%w: condition field is not a string", ErrMalformedPostPolicy)
	}
	if !strings.HasPrefix(field, "$") {
		return "", fmt.Errorf("%w: condition field %q must start with \"$\"", ErrMalformedPostPolicy, field)
	}
	field = field[1:]
	if field == "" {
		return "", fmt.Errorf("%w: condition names no field", ErrMalformedPostPolicy)
	}
	return field, nil
}

func postPolicyConditionString(raw json.RawMessage) (string, error) {
	// Decoding into any first keeps JSON null from silently becoming the empty
	// string, which would let a condition match a field the client omitted.
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: condition value %s is not a JSON string", ErrMalformedPostPolicy, bytes.TrimSpace(raw))
	}
	return text, nil
}

func postPolicyConditionStrings(raw json.RawMessage) ([]string, error) {
	var values []any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	texts := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: condition list holds a value that is not a JSON string", ErrMalformedPostPolicy)
		}
		texts = append(texts, text)
	}
	return texts, nil
}

func postPolicyConditionSize(raw json.RawMessage) (int64, error) {
	size, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: condition size %q is not an integer", ErrMalformedPostPolicy, bytes.TrimSpace(raw))
	}
	if size < 0 {
		return 0, fmt.Errorf("%w: condition size is negative", ErrMalformedPostPolicy)
	}
	return size, nil
}

func validHexSignature(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
