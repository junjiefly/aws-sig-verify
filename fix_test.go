package awsverify

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseV4TimeAcceptsRFC1123Z(t *testing.T) {
	value := "Wed, 18 Nov 2026 03:14:44 -0000"
	want := time.Date(2026, 11, 18, 3, 14, 44, 0, time.UTC)
	got, err := parseV4Time(value)
	if err != nil {
		t.Fatalf("parseV4Time(%q) returned %v", value, err)
	}
	if !got.Equal(want) {
		t.Fatalf("parseV4Time(%q) = %s, want %s", value, got, want)
	}
}

func TestCheckSigningTimeDoesNotOverflowForExtremeFuture(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	signingTime := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	err := checkSigningTime(signingTime, now, 15*time.Minute)
	if !errors.Is(err, ErrClockSkew) {
		t.Fatalf("checkSigningTime() error = %v, want ErrClockSkew", err)
	}
}

func TestCheckSigningTimeBeforeEpoch(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	signingTime := time.Date(1950, 7, 7, 21, 53, 4, 0, time.UTC)
	err := checkSigningTime(signingTime, now, 15*time.Minute)
	if !errors.Is(err, ErrTimeBeforeEpoch) {
		t.Fatalf("checkSigningTime() error = %v, want ErrTimeBeforeEpoch", err)
	}
}

func TestVerifyV2HeaderEmptyXAmzDate(t *testing.T) {
	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			"AKIDEXAMPLE": {SecretAccessKey: "secret"},
		}),
	})
	request, err := http.NewRequest(http.MethodPut, "https://s3.example.com/bucket/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	request.Header.Set("X-Amz-Date", "")
	request.Header.Set("Authorization", "AWS AKIDEXAMPLE:"+base64.StdEncoding.EncodeToString(make([]byte, 20)))
	_, err = verifier.verifyV2Header(request, VerifyOptions{})
	if !errors.Is(err, ErrInvalidSigningTime) {
		t.Fatalf("verifyV2Header() error = %v, want ErrInvalidSigningTime", err)
	}
}

func TestVerifyV4PresignInvalidExpiry(t *testing.T) {
	verifier := NewVerifier(Config{
		Credentials: StaticCredentials(map[string]Credentials{
			"AKIDEXAMPLE": {SecretAccessKey: "secret"},
		}),
	})
	request, err := http.NewRequest(http.MethodGet, "https://s3.example.com/bucket/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := request.URL.Query()
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", "AKIDEXAMPLE/20261118/us-east-1/s3/aws4_request")
	query.Set("X-Amz-Date", "20261118T000000Z")
	query.Set("X-Amz-SignedHeaders", "host")
	query.Set("X-Amz-Signature", strings.Repeat("a", 64))
	query.Set("X-Amz-Expires", "0")
	request.URL.RawQuery = query.Encode()
	_, err = verifier.verifyV4Presigned(request, query, VerifyOptions{Service: "s3", Region: "us-east-1"})
	if !errors.Is(err, ErrInvalidPresignExpiry) {
		t.Fatalf("verifyV4Presigned() error = %v, want ErrInvalidPresignExpiry", err)
	}
}
