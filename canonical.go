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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const v4Algorithm = "AWS4-HMAC-SHA256"

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacSHA1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func deriveSigningKey(secret, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	regionKey := hmacSHA256(dateKey, []byte(region))
	serviceKey := hmacSHA256(regionKey, []byte(service))
	return hmacSHA256(serviceKey, []byte("aws4_request"))
}

// awsURIEncode implements the URI encoding rules used by AWS signature
// canonicalization. Space becomes %20 and a literal plus becomes %2B.
func awsURIEncode(input string, encodeSlash bool) string {
	var output strings.Builder
	for index := 0; index < len(input); index++ {
		char := input[index]
		switch {
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9',
			char == '-', char == '_', char == '.', char == '~':
			output.WriteByte(char)
		case char == '/' && !encodeSlash:
			output.WriteByte(char)
		default:
			output.WriteByte('%')
			output.WriteByte(upperHex(char >> 4))
			output.WriteByte(upperHex(char & 0x0f))
		}
	}
	return output.String()
}

func upperHex(value byte) byte {
	if value < 10 {
		return '0' + value
	}
	return 'A' + value - 10
}

func canonicalURI(req *http.Request, s3 bool) string {
	if !s3 {
		escaped := req.URL.EscapedPath()
		if escaped == "" {
			return "/"
		}
		if !strings.HasPrefix(escaped, "/") {
			escaped = "/" + escaped
		}
		return canonicalGenericEscapedPath(escaped)
	}

	escaped := req.URL.EscapedPath()
	if escaped == "" {
		return "/"
	}
	if !strings.HasPrefix(escaped, "/") {
		escaped = "/" + escaped
	}
	return canonicalS3EscapedPath(escaped)
}

// canonicalGenericEscapedPath normalizes dot segments and duplicate slashes as
// required by AWS services other than S3. It works on the escaped path so an
// encoded slash remains one path segment.
func canonicalGenericEscapedPath(path string) string {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	kept := make([]string, 0, len(segments))
	for _, segment := range segments {
		switch segment {
		case "", ".":
		case "..":
			if len(kept) > 0 {
				kept = kept[:len(kept)-1]
			}
		default:
			kept = append(kept, segment)
		}
	}
	canonical := "/" + strings.Join(kept, "/")
	if len(kept) > 0 && strings.HasSuffix(path, "/") {
		canonical += "/"
	}
	return canonical
}

// canonicalS3EscapedPath preserves an encoded slash inside an object name,
// normalizes percent escaping, and follows AWS S3's no-path-normalization rule.
func canonicalS3EscapedPath(path string) string {
	var output strings.Builder
	for index := 0; index < len(path); index++ {
		char := path[index]
		switch {
		case char == '/':
			output.WriteByte('/')
		case isUnreservedByte(char):
			output.WriteByte(char)
		case char == '%' && index+2 < len(path):
			decoded, err := hex.DecodeString(path[index+1 : index+3])
			if err != nil {
				output.WriteString(awsURIEncode(path[index:index+1], false))
				continue
			}
			if isUnreservedByte(decoded[0]) {
				output.WriteByte(decoded[0])
			} else {
				output.WriteByte('%')
				output.WriteByte(upperHex(decoded[0] >> 4))
				output.WriteByte(upperHex(decoded[0] & 0x0f))
			}
			index += 2
		default:
			output.WriteString(awsURIEncode(path[index:index+1], false))
		}
	}
	return output.String()
}

func isUnreservedByte(char byte) bool {
	return char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
		char >= '0' && char <= '9' || char == '-' || char == '_' ||
		char == '.' || char == '~'
}

func canonicalQuery(query url.Values, exclude string) string {
	return canonicalQueryValues(query, exclude)
}

func rejectDuplicateQueryFields(query url.Values, names []string) error {
	for _, name := range names {
		if len(query[name]) > 1 {
			return fmt.Errorf("%w: %s was repeated", ErrMalformedAuthorization, name)
		}
	}
	return nil
}

func headerValues(header http.Header, name string) []string {
	if name == "host" {
		if header.Get("Host") != "" {
			return header.Values("Host")
		}
		return nil
	}
	if values, ok := header[name]; ok {
		return values
	}
	return header.Values(name)
}

func requestHeaderValues(req *http.Request, name string) []string {
	values := headerValues(req.Header, name)
	if len(values) != 0 {
		return values
	}
	switch name {
	case "content-length":
		if req.ContentLength >= 0 {
			return []string{strconv.FormatInt(req.ContentLength, 10)}
		}
	case "transfer-encoding":
		if len(req.TransferEncoding) != 0 {
			return append([]string(nil), req.TransferEncoding...)
		}
	case "expect":
		// Go's server may consume Expect without retaining the header. Older
		// S3 SDKs sign Expect: 100-continue.
		if req.ProtoAtLeast(1, 1) {
			return []string{"100-continue"}
		}
	}
	return nil
}

func canonicalHeaders(req *http.Request, signedHeaders []string) string {
	var output strings.Builder
	for _, name := range signedHeaders {
		output.WriteString(name)
		output.WriteByte(':')
		if name == "host" {
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}
			output.WriteString(collapseSpaces(host))
		} else {
			for index, value := range requestHeaderValues(req, name) {
				if index > 0 {
					output.WriteByte(',')
				}
				output.WriteString(collapseSpaces(value))
			}
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func collapseSpaces(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
