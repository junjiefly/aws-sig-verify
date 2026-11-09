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
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type SignatureVersion string

const (
	SigV4 SignatureVersion = "SigV4"
	SigV2 SignatureVersion = "SigV2"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type CredentialFunc func(ctx context.Context, accessKeyID string) (Credentials, error)

type Config struct {
	Credentials      CredentialFunc
	Clock            func() time.Time
	MaxSkew          time.Duration
	MaxPresignExpiry time.Duration
	// DefaultPayloadHash is used for a SigV4 header request only when neither
	// the request nor VerifyOptions supplies X-Amz-Content-Sha256. Leave it
	// empty for strict AWS behavior.
	DefaultPayloadHash string
}

type VerifyOptions struct {
	// Credentials overrides Config.Credentials for this Verify call. Use it
	// when credential selection depends on request-scoped data such as a
	// tenant, account, bucket, virtual-host name, or temporary-session store.
	Credentials CredentialFunc

	// Service and Region pin the credential scope a Signature Version 4
	// request must carry. Both are required for every SigV4 request, including
	// presigned ones and browser POST policies: leaving either empty returns
	// ErrScopeRequired instead of accepting whatever scope the request asks
	// for. They are not inferred from the request host. Signature Version 2
	// has no scope in its signature, so a V2 request needs neither.
	Service string
	Region  string

	// PayloadHash overrides X-Amz-Content-Sha256. It is useful when a caller
	// has already hashed or validated the body. The verifier never reads the
	// request body.
	PayloadHash string

	// S3Bucket is the virtual-host bucket. Leave it empty for path-style
	// requests. It is used for Signature Version 2 canonical resources.
	S3Bucket string

	// PostPolicyContentLength is the size of the uploaded object, in bytes,
	// for VerifyPostPolicy. It is the only way a "content-length-range"
	// condition can be checked: the verifier never reads the request body, and
	// the multipart form itself says nothing about the object size. Pass the
	// value you already enforced for the file part. A policy that carries such
	// a condition is rejected with ErrUnsupportedPostPolicyCondition when this
	// is nil, never silently accepted.
	PostPolicyContentLength *int64
}

type Result struct {
	Version       SignatureVersion
	AccessKeyID   string
	Region        string
	Service       string
	Signature     string
	SignedHeaders []string
	PayloadHash   string
	SecurityToken string
	Policy        []byte
	SigningTime   time.Time
	ExpiresAt     time.Time

	credentials Credentials
}

type Verifier struct {
	lookup             CredentialFunc
	clock              func() time.Time
	maxSkew            time.Duration
	maxPresignExpiry   time.Duration
	defaultPayloadHash string
}

func NewVerifier(config Config) *Verifier {
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	maxSkew := config.MaxSkew
	if maxSkew == 0 {
		maxSkew = 15 * time.Minute
	}
	maxPresignExpiry := config.MaxPresignExpiry
	if maxPresignExpiry == 0 {
		maxPresignExpiry = 7 * 24 * time.Hour
	}
	return &Verifier{
		lookup:             config.Credentials,
		clock:              clock,
		maxSkew:            maxSkew,
		maxPresignExpiry:   maxPresignExpiry,
		defaultPayloadHash: config.DefaultPayloadHash,
	}
}

func StaticCredentials(credentials map[string]Credentials) CredentialFunc {
	byAccessKey := make(map[string]Credentials, len(credentials))
	for key, credential := range credentials {
		credential.AccessKeyID = key
		byAccessKey[key] = credential
	}
	return func(_ context.Context, accessKeyID string) (Credentials, error) {
		credential, ok := byAccessKey[accessKeyID]
		if !ok {
			return Credentials{}, ErrUnknownAccessKey
		}
		return credential, nil
	}
}

func (v *Verifier) Verify(req *http.Request, options VerifyOptions) (*Result, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if options.Credentials == nil && v.lookup == nil {
		return nil, ErrCredentialLookupRequired
	}

	query := req.URL.Query()
	switch {
	case query.Has("X-Amz-Algorithm") || query.Has("X-Amz-Credential") ||
		strings.HasPrefix(req.Header.Get("Authorization"), v4Algorithm):
		return v.verifyV4(req, query, options)
	case query.Has("AWSAccessKeyId") || strings.HasPrefix(req.Header.Get("Authorization"), "AWS "):
		return v.verifyV2(req, query, options)
	default:
		return nil, ErrUnsupportedSignatureVersion
	}
}

func (v *Verifier) credentialLookup(options VerifyOptions) CredentialFunc {
	if options.Credentials != nil {
		return options.Credentials
	}
	return v.lookup
}

func (v *Verifier) credentialsFor(ctx context.Context, lookup CredentialFunc, accessKeyID, presentedToken string) (Credentials, error) {
	credential, err := lookup(ctx, accessKeyID)
	if err != nil {
		return Credentials{}, err
	}
	if credential.SecretAccessKey == "" {
		return Credentials{}, ErrUnknownAccessKey
	}
	if subtle.ConstantTimeCompare([]byte(credential.SessionToken), []byte(presentedToken)) != 1 {
		return Credentials{}, ErrSessionTokenMismatch
	}
	return credential, nil
}

func requestContext(req *http.Request) context.Context {
	return req.Context()
}

func checkSigningTime(signingTime time.Time, now time.Time, maxSkew time.Duration) error {
	if signingTime.IsZero() {
		return ErrMalformedAuthorization
	}
	offset := now.Sub(signingTime)
	if offset < 0 {
		offset = -offset
	}
	if offset > maxSkew {
		return fmt.Errorf("%w: signing time %s", ErrClockSkew, signingTime.Format(time.RFC3339))
	}
	return nil
}

func checkSigningTimeNotInFuture(signingTime time.Time, now time.Time, maxSkew time.Duration) error {
	if signingTime.IsZero() {
		return ErrMalformedAuthorization
	}
	if signingTime.After(now.Add(maxSkew)) {
		return fmt.Errorf("%w: signing time %s", ErrClockSkew, signingTime.Format(time.RFC3339))
	}
	return nil
}

func checkScope(scope v4Credential, signingTime time.Time, options VerifyOptions) error {
	if options.Service == "" || options.Region == "" {
		return ErrScopeRequired
	}
	if !strings.EqualFold(scope.Date, signingTime.UTC().Format("20060102")) {
		return fmt.Errorf("%w: credential date does not match signing time", ErrMalformedCredential)
	}
	if scope.Region != options.Region {
		return fmt.Errorf("%w: region %q", ErrMalformedCredential, scope.Region)
	}
	if scope.Service != options.Service {
		return fmt.Errorf("%w: service %q", ErrMalformedCredential, scope.Service)
	}
	return nil
}

func canonicalQueryValues(query url.Values, exclude string) string {
	type pair struct {
		key   string
		value string
	}

	pairs := make([]pair, 0, len(query))
	for key, values := range query {
		if exclude != "" && key == exclude {
			continue
		}
		if len(values) == 0 {
			pairs = append(pairs, pair{key: awsURIEncode(key, true)})
			continue
		}
		for _, value := range values {
			pairs = append(pairs, pair{
				key:   awsURIEncode(key, true),
				value: awsURIEncode(value, true),
			})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].value < pairs[j].value
	})

	parts := make([]string, 0, len(pairs))
	for _, item := range pairs {
		parts = append(parts, item.key+"="+item.value)
	}
	return strings.Join(parts, "&")
}
