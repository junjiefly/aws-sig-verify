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

package interop

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/junjiefly/aws-sig-verify"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// This file wires a full chain around the verifier: the official minio-go
// client signs real requests, a proxy verifies every one of them with this
// package before forwarding the untouched request to a live S3-compatible
// server, and the server's acceptance is the third-party verdict on the bytes
// that flowed through. It skips when no live endpoint is configured, so plain
// `go test ./...` stays hermetic.
//
//	AWSSIGVERIFY_LIVE_ENDPOINT    http://host:port
//	AWSSIGVERIFY_LIVE_ACCESS_KEY  access key id
//	AWSSIGVERIFY_LIVE_SECRET_KEY  secret access key
const (
	liveProxyEndpoint  = "AWSSIGVERIFY_LIVE_ENDPOINT"
	liveProxyAccessKey = "AWSSIGVERIFY_LIVE_ACCESS_KEY"
	liveProxySecretKey = "AWSSIGVERIFY_LIVE_SECRET_KEY"
	liveProxyRegion    = "us-east-1"
)

func requireLiveProxy(t *testing.T) (proxy *httptest.Server, client *minio.Client) {
	t.Helper()
	endpoint := os.Getenv(liveProxyEndpoint)
	accessKey := os.Getenv(liveProxyAccessKey)
	secretKey := os.Getenv(liveProxySecretKey)
	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skipf("live proxy check needs %s, %s and %s", liveProxyEndpoint, liveProxyAccessKey, liveProxySecretKey)
	}
	target, err := url.Parse(endpoint)
	if err != nil || target.Host == "" {
		t.Fatalf("%s = %q is not a valid endpoint", liveProxyEndpoint, endpoint)
	}

	verifier := awsverify.NewVerifier(awsverify.Config{
		Credentials: func(_ context.Context, presented string) (awsverify.Credentials, error) {
			if presented != accessKey {
				return awsverify.Credentials{}, awsverify.ErrUnknownAccessKey
			}
			return awsverify.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		},
	})

	proxy = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		options := awsverify.VerifyOptions{Service: "s3", Region: liveProxyRegion}
		result, err := verifier.Verify(req, options)
		if err != nil {
			t.Logf("proxy rejected %s %s: %v", req.Method, req.URL.Path, err)
			http.Error(writer, "signature rejected by awsverify: "+err.Error(), http.StatusForbidden)
			return
		}
		authType, _ := awsverify.RequestAuthType(req)
		if authType == awsverify.AuthTypeStreamingV4 ||
			authType == awsverify.AuthTypeStreamingV4Tr ||
			authType == awsverify.AuthTypeUnsignedTr {
			reader, err := verifier.ChunkedReader(req, result, awsverify.ChunkedReaderOptions{})
			if err != nil {
				http.Error(writer, "streaming decode failed: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer reader.Close()
			req.Body = readCloser{Reader: reader, Closer: req.Body}
		}
		forwardRequest(t, writer, req, target)
	}))
	t.Cleanup(proxy.Close)

	client, err = minio.New(target.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}
	return proxy, client
}

type readCloser struct {
	Reader io.Reader
	Closer io.Closer
}

func (rc readCloser) Read(buffer []byte) (int, error) { return rc.Reader.Read(buffer) }
func (rc readCloser) Close() error                    { return rc.Closer.Close() }

// forwardRequest relays the request verbatim, including the Host header, so
// the signature the client produced still covers what the server sees.
func forwardRequest(t *testing.T, writer http.ResponseWriter, req *http.Request, target *url.URL) {
	t.Helper()
	out, err := http.NewRequest(req.Method, target.Scheme+"://"+target.Host+req.URL.RequestURI(), req.Body)
	if err != nil {
		http.Error(writer, "proxy build failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out.Host = req.Host
	out.Header = req.Header.Clone()
	out.ContentLength = req.ContentLength
	relay, err := http.DefaultClient.Do(out)
	if err != nil {
		http.Error(writer, "proxy forward failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer relay.Body.Close()
	for name, values := range relay.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(relay.StatusCode)
	_, _ = io.Copy(writer, relay.Body)
}

func TestLiveProxyInterop(t *testing.T) {
	_, client := requireLiveProxy(t)
	ctx := context.Background()
	bucket := liveBucketName("awsverify-proxy")

	requireCleanBucket(t, ctx, client, bucket)

	payload := strings.Repeat("proxy round trip payload.\n", 64)
	_, err := client.PutObject(ctx, bucket, "proxy/object.txt",
		strings.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("PutObject through the verifying proxy: %v", err)
	}

	object, err := client.GetObject(ctx, bucket, "proxy/object.txt", minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("GetObject through the verifying proxy: %v", err)
	}
	defer object.Close()
	readBack, err := io.ReadAll(object)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(readBack) != payload {
		t.Fatalf("round trip mismatch: %d bytes read, %d sent", len(readBack), len(payload))
	}

	presigned, err := client.PresignedGetObject(ctx, bucket, "proxy/object.txt", 10*time.Minute, url.Values{})
	if err != nil {
		t.Fatalf("PresignedGetObject: %v", err)
	}
	response, err := http.Get(presigned.String())
	if err != nil {
		t.Fatalf("presigned GET through the verifying proxy: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("presigned GET status = %d", response.StatusCode)
	}
	presignedBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("presigned read: %v", err)
	}
	if string(presignedBody) != payload {
		t.Fatalf("presigned round trip mismatch: %d bytes read", len(presignedBody))
	}
}

// requireCleanBucket makes sure the bucket exists for the run and removes it
// afterwards, so repeated runs against the same live server do not collide.
func requireCleanBucket(t *testing.T, ctx context.Context, client *minio.Client, bucket string) {
	t.Helper()
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatalf("BucketExists: %v", err)
	}
	if exists {
		objects := client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true})
		for object := range objects {
			if object.Err != nil {
				t.Fatalf("list for cleanup: %v", object.Err)
			}
			if err := client.RemoveObject(ctx, bucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
				t.Fatalf("cleanup remove: %v", err)
			}
		}
		if err := client.RemoveBucket(ctx, bucket); err != nil {
			t.Fatalf("cleanup bucket: %v", err)
		}
	}
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatalf("MakeBucket through the verifying proxy: %v", err)
	}
	t.Cleanup(func() {
		objects := client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true})
		for object := range objects {
			_ = client.RemoveObject(ctx, bucket, object.Key, minio.RemoveObjectOptions{})
		}
		_ = client.RemoveBucket(ctx, bucket)
	})
}

func liveBucketName(prefix string) string {
	return prefix + "-" + time.Now().UTC().Format("20060102-150405")
}

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
