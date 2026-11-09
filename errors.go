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

import "errors"

// Errors returned by the verifier. Callers can use errors.Is to distinguish
// malformed client requests from credential and authorization failures.
var (
	ErrNilRequest                     = errors.New("awsverify: nil request")
	ErrCredentialLookupRequired       = errors.New("awsverify: credential lookup is required")
	ErrUnknownAccessKey               = errors.New("awsverify: unknown access key")
	ErrUnsupportedSignatureVersion    = errors.New("awsverify: unsupported signature version")
	ErrMalformedAuthorization         = errors.New("awsverify: malformed authorization")
	ErrMalformedCredential            = errors.New("awsverify: malformed credential scope")
	ErrMalformedSignature             = errors.New("awsverify: malformed signature")
	ErrMissingSignedHeader            = errors.New("awsverify: required signed header is missing")
	ErrSignatureMismatch              = errors.New("awsverify: signature mismatch")
	ErrSessionTokenMismatch           = errors.New("awsverify: session token mismatch")
	ErrExpiredSignature               = errors.New("awsverify: signature expired")
	ErrClockSkew                      = errors.New("awsverify: signing time outside allowed clock skew")
	ErrPresignExpiryTooLong           = errors.New("awsverify: presigned request expires too far in the future")
	ErrPayloadHashRequired            = errors.New("awsverify: payload hash is required")
	ErrPayloadHashMismatch            = errors.New("awsverify: request body does not match the signed payload hash")
	ErrScopeRequired                  = errors.New("awsverify: VerifyOptions.Service and VerifyOptions.Region must be pinned")
	ErrUnsupportedStreamingPayload    = errors.New("awsverify: unsupported streaming payload")
	ErrMalformedChunk                 = errors.New("awsverify: malformed streaming payload")
	ErrChunkSignatureMismatch         = errors.New("awsverify: chunk signature mismatch")
	ErrChunkHeaderTooLong             = errors.New("awsverify: chunk header too long")
	ErrChunkSizeTooLarge              = errors.New("awsverify: chunk size too large")
	ErrPostPolicyRequired             = errors.New("awsverify: post policy is required")
	ErrMalformedPostPolicy            = errors.New("awsverify: malformed post policy document")
	ErrPostPolicyConditionFailed      = errors.New("awsverify: post policy condition failed")
	ErrUnsupportedPostPolicyCondition = errors.New("awsverify: unsupported post policy condition")
	ErrUnsupportedPostPolicyVersion   = errors.New("awsverify: unsupported post policy signature version")
)
