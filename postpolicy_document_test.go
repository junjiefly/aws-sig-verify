package awsverify

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
)

func TestParsePostPolicyDocument(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	policy, err := ParsePostPolicyDocument([]byte(document))
	if err != nil {
		t.Fatalf("ParsePostPolicyDocument() error = %v", err)
	}
	if policy.Expiration.IsZero() || len(policy.Conditions) != 1 {
		t.Fatalf("unexpected policy: %+v", policy)
	}
	if lengthRange, err := policy.ContentLengthRange(); err != nil || lengthRange.Valid {
		t.Fatalf("ContentLengthRange() = %+v, %v; want Valid=false and no error", lengthRange, err)
	}
}

func TestParsePostPolicyDocumentRejectsDuplicateKeys(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","expiration":"2026-01-01T00:02:00Z","conditions":[]}`
	if _, err := ParsePostPolicyDocument([]byte(document)); !errors.Is(err, ErrMalformedPostPolicy) {
		t.Fatalf("error = %v, want ErrMalformedPostPolicy", err)
	}
}

func TestParsePostPolicyDocumentRequiresConditions(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z"}`
	if _, err := ParsePostPolicyDocument([]byte(document)); !errors.Is(err, ErrMalformedPostPolicy) {
		t.Fatalf("error = %v, want ErrMalformedPostPolicy", err)
	}
}

func TestParsePostPolicyDocumentRejectsMultipleLengthRanges(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[["content-length-range",0,10],["content-length-range",20,30]]}`
	policy, err := ParsePostPolicyDocument([]byte(document))
	if err != nil {
		t.Fatalf("ParsePostPolicyDocument() error = %v", err)
	}
	if _, err = policy.ContentLengthRange(); !errors.Is(err, ErrMalformedPostPolicy) {
		t.Fatalf("ContentLengthRange() error = %v, want ErrMalformedPostPolicy", err)
	}
}

func TestPostPolicyCheckConditionsEnforcesFields(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	policy, err := ParsePostPolicyDocument([]byte(document))
	if err != nil {
		t.Fatalf("ParsePostPolicyDocument() error = %v", err)
	}
	form := url.Values{"key": {"photo.png"}, "success_action_status": {"200"}}
	if err := policy.CheckConditions(form, VerifyOptions{}); !errors.Is(err, ErrFormFieldNotInPolicy) {
		t.Fatalf("CheckConditions() error = %v, want ErrFormFieldNotInPolicy", err)
	}
}

func TestVerifyPostPolicyStrictFields(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	form := url.Values{}
	form.Set("key", "photo.png")
	form.Set("success_action_status", "200")
	form.Set("policy", encoded)
	form.Set("AWSAccessKeyId", testAccessKey)
	form.Set("Signature", SignV2(testSecretKey, encoded))

	verifier := testVerifier(t)
	if _, err := verifier.VerifyPostPolicy(form, VerifyOptions{PostPolicyStrictFields: true}); !errors.Is(err, ErrFormFieldNotInPolicy) {
		t.Fatalf("VerifyPostPolicy() error = %v, want ErrFormFieldNotInPolicy", err)
	}
}

func TestPostPolicyCheckConditionsKeepsSignatureFieldsVersionSpecific(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	policy, err := ParsePostPolicyDocument([]byte(document))
	if err != nil {
		t.Fatalf("ParsePostPolicyDocument() error = %v", err)
	}

	v2Form := url.Values{
		"key":            {"photo.png"},
		"policy":         {document},
		"AWSAccessKeyId": {testAccessKey},
		"Signature":      {SignV2(testSecretKey, document)},
	}
	if err := policy.CheckConditions(v2Form, VerifyOptions{PostPolicyStrictFields: true}); err != nil {
		t.Fatalf("V2 CheckConditions() error = %v, want nil", err)
	}

	v4Form := url.Values{
		"key":             {"photo.png"},
		"policy":          {document},
		"X-Amz-Algorithm": {"AWS4-HMAC-SHA256"},
		"AWSAccessKeyId":  {testAccessKey},
		"signature":       {"not-a-v4-signature"},
	}
	if err := policy.CheckConditions(v4Form, VerifyOptions{PostPolicyStrictFields: true}); !errors.Is(err, ErrFormFieldNotInPolicy) {
		t.Fatalf("V4 CheckConditions() error = %v, want ErrFormFieldNotInPolicy", err)
	}
}

func TestPostPolicyCheckConditionsRunsConditionsBeforeStrictFields(t *testing.T) {
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"expected.png"}]}`
	policy, err := ParsePostPolicyDocument([]byte(document))
	if err != nil {
		t.Fatalf("ParsePostPolicyDocument() error = %v", err)
	}
	form := url.Values{"key": {"other.png"}, "success_action_status": {"200"}}
	if err := policy.CheckConditions(form, VerifyOptions{PostPolicyStrictFields: true}); !errors.Is(err, ErrPostPolicyConditionFailed) {
		t.Fatalf("CheckConditions() error = %v, want ErrPostPolicyConditionFailed", err)
	}
}

func TestVerifyV4PostPolicyStrictFields(t *testing.T) {
	verifier := testVerifier(t)
	document := `{"expiration":"2026-01-01T00:01:00Z","conditions":[{"key":"photo.png"}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	scope := "20260101/us-east-1/s3/aws4_request"
	key := deriveSigningKey(testSecretKey, "20260101", "us-east-1", "s3")
	signature := hex.EncodeToString(hmacSHA256(key, []byte(encoded)))

	form := url.Values{}
	form.Set("key", "photo.png")
	form.Set("success_action_status", "200")
	form.Set("policy", encoded)
	form.Set("x-amz-algorithm", v4Algorithm)
	form.Set("x-amz-credential", testAccessKey+"/"+scope)
	form.Set("x-amz-date", "20260101T000000Z")
	form.Set("x-amz-signature", signature)

	_, err := verifier.VerifyPostPolicy(form, VerifyOptions{
		Service:                "s3",
		Region:                 "us-east-1",
		PostPolicyStrictFields: true,
	})
	if !errors.Is(err, ErrFormFieldNotInPolicy) {
		t.Fatalf("VerifyPostPolicy() error = %v, want ErrFormFieldNotInPolicy", err)
	}
}
