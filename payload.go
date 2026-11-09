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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// PayloadHashReader hashes the bytes a handler reads from a request body and
// compares that hash against the payload hash the verified signature covered.
//
// A verified signature proves only which hash the client claimed. It says
// nothing about the bytes the server actually received, because the signature
// never covers the body itself. A handler that reads req.Body without this
// comparison accepts any body that reuses a captured request.
//
// The reader passes bytes through untouched, and Checked reports false, for
// the payload hashes that carry no hash: UNSIGNED-PAYLOAD and the three
// streaming sentinels. Streaming bodies are authenticated chunk by chunk while
// ChunkedReader is read to EOF, so treat a false Checked result as "something
// else must prove this body", never as evidence the upload is authentic.
type PayloadHashReader struct {
	body     io.Reader
	digest   hash.Hash
	expected string
}

// NewPayloadHashReader returns a reader over body for a payload hash declared
// by a request this verifier accepted, typically Result.PayloadHash. It fails
// when declared is neither a hexadecimal SHA-256 digest nor one of the payload
// hashes that carry no hash.
func NewPayloadHashReader(body io.Reader, declared string) (*PayloadHashReader, error) {
	switch declared {
	case unsignedPayloadHash, streamingPayload, streamingPayloadTrailer, unsignedStreamingPayload:
		return &PayloadHashReader{body: body}, nil
	}
	if !validHexSignature(declared) {
		return nil, fmt.Errorf("%w: payload hash %q is not a SHA-256 digest", ErrMalformedAuthorization, declared)
	}
	return &PayloadHashReader{
		body:     body,
		digest:   sha256.New(),
		expected: strings.ToLower(declared),
	}, nil
}

func (reader *PayloadHashReader) Read(output []byte) (int, error) {
	if reader.digest == nil {
		return reader.body.Read(output)
	}
	read, err := reader.body.Read(output)
	if read > 0 {
		reader.digest.Write(output[:read])
	}
	if err == io.EOF {
		if mismatch := reader.Err(); mismatch != nil {
			return read, mismatch
		}
	}
	return read, err
}

// Checked reports whether the declared payload hash carried a hash to compare.
func (reader *PayloadHashReader) Checked() bool {
	return reader.digest != nil
}

// Err returns the comparison result for a body already read to EOF:
// ErrPayloadHashMismatch when the bytes do not hash to the value the signature
// covered. It is a convenience for handlers that stop reading without
// inspecting the error from Read; Read itself reports the same failure.
func (reader *PayloadHashReader) Err() error {
	if reader.digest == nil {
		return nil
	}
	sum := hex.EncodeToString(reader.digest.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sum), []byte(reader.expected)) != 1 {
		return fmt.Errorf("%w: body hashes to %s, the signature covers %s", ErrPayloadHashMismatch, sum, reader.expected)
	}
	return nil
}
