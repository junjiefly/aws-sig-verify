# aws-sig-verify

[![CI](https://github.com/junjiefly/aws-sig-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/junjiefly/aws-sig-verify/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/junjiefly/aws-sig-verify.svg)](https://pkg.go.dev/github.com/junjiefly/aws-sig-verify)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

English | [简体中文](README.zh-CN.md)

`awsverify` is a dependency-free Go package for verifying AWS Signature
Version 2 and Version 4 HTTP requests on the server side. It is suitable for
S3-compatible gateways and other AWS-style HTTP APIs.

The package is a reusable protocol layer, not a gateway or SDK. Applications
keep control of credential storage, tenant/account mapping, STS sessions,
object ACLs, IAM policy, and response handling.

The package verifies:

- SigV4 `Authorization` header requests
- SigV4 presigned URLs
- SigV4 POST policies
- classic `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` chunked uploads
- signed `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` chunked uploads
- unsigned `STREAMING-UNSIGNED-PAYLOAD-TRAILER` chunked uploads
- SigV2 header and presigned requests
- SigV2 POST policies

It does not load AWS credentials from files or the environment, does not make
network calls, and does not enforce bucket/object ACLs. You provide a credential
lookup function and retain control over authorization policy.

## Install

```sh
go get github.com/junjiefly/aws-sig-verify
```

## Verify a request

```go
verifier := awsverify.NewVerifier(awsverify.Config{
    Credentials: func(ctx context.Context, accessKeyID string) (awsverify.Credentials, error) {
        return loadCredentialsFromYourStore(ctx, accessKeyID)
    },
    MaxSkew: 15 * time.Minute,
})

result, err := verifier.Verify(r, awsverify.VerifyOptions{
    Service:  "s3",
    Region:   "us-east-1",
    S3Bucket: bucketFromVirtualHost,
})
if err != nil {
    // Return an HTTP error. err can be inspected with errors.Is.
}

// result.AccessKeyID identifies the caller. Apply your own ACL or IAM policy
// before granting access to the bucket or object.
```

`Service` and `Region` are required for every SigV4 request. They pin the
credential scope the request must carry; a request that asks for a scope the
caller did not fix is rejected with `ErrScopeRequired` rather than verified
against the scope it requested. SigV2 signatures carry no scope, so a V2
request needs neither field.

The same verifier works for non-S3 AWS-style services. Provide the service and
region that must match the credential scope:

```go
result, err := verifier.Verify(r, awsverify.VerifyOptions{
    Service: "execute-api",
    Region:  "eu-central-1",
})
```

If a non-S3 service does not send `X-Amz-Content-Sha256`, supply the payload
hash through `VerifyOptions.PayloadHash` after applying your own body-handling
policy.

For S3, provide the virtual-host bucket in `VerifyOptions.S3Bucket` only for
virtual-hosted requests such as `bucket.s3.example.com`. Leave it empty for
path-style requests.

AWS requires `X-Amz-Content-Sha256` on SigV4 header requests. If your gateway
must also accept old clients that omit it, configure the empty-payload default:

```go
verifier := awsverify.NewVerifier(awsverify.Config{
    Credentials:        credentialLookup,
    DefaultPayloadHash: awsverify.EmptyPayloadSHA256,
})
```

`RequestAccessKeyID` and `RequestBucketFromHost` are small helpers for gateways
that need to choose a credential store before verifying. They do not authorize
anything by themselves:

```go
accessKeyID, authType, found := awsverify.RequestAccessKeyID(r)
bucket := awsverify.RequestBucketFromHost(r.Host, []string{"s3.example.com"})
```

When credential selection depends on request-scoped state, override the
credential lookup for that call:

```go
options := awsverify.VerifyOptions{
    Service:  "s3",
    Region:   "us-east-1",
    S3Bucket: bucket,
}
options.Credentials = func(ctx context.Context, accessKeyID string) (awsverify.Credentials, error) {
    return tenantCredentialStore.Lookup(ctx, tenantID, bucket, accessKeyID)
}

result, err := verifier.Verify(r, options)
```

The signer extracts the caller's AccessKeyID and invokes that callback. It does
not map buckets to tenants or choose one credential when several could apply;
that policy belongs to the embedding gateway.

## Request-scoped credentials

Some gateways look up credentials by bucket or tenant first. Keep that mapping
in your application and provide it as a callback:

```go
options := awsverify.VerifyOptions{
    Service: "s3",
    Region:  region,
}
options.Credentials = func(ctx context.Context, accessKeyID string) (awsverify.Credentials, error) {
    return credentialStore.Lookup(ctx, bucket, accessKeyID)
}
```

The callback receives only the AccessKeyID presented in the request. It can
consult STS, a database, a cache, or a per-bucket account policy. Signature
verification then uses the credentials it returns.

## Check the body against the signed hash

A verified signature proves which payload hash the client claimed. It does not
prove that the bytes you receive hash to it, because the verifier never reads
the body. Compare the two before storing anything:

```go
body, err := awsverify.NewPayloadHashReader(r.Body, result.PayloadHash)
if err != nil {
    return err
}
r.Body = body
if _, err := io.Copy(dst, body); err != nil {
    return err // errors.Is(err, awsverify.ErrPayloadHashMismatch) if the bytes differ
}
```

`Checked` reports false for `UNSIGNED-PAYLOAD` and the three streaming sentinels,
where the client claimed no hash at all; a streaming upload is authenticated
chunk by chunk by `ChunkedReader` instead. MinIO's server makes this same
comparison before it writes an object, so a gateway that skips it accepts
requests MinIO rejects.

## Decode a signed streaming upload

After `Verify` succeeds, wrap the request body when its payload hash indicates
an AWS streaming upload:

```go
reader, err := verifier.ChunkedReader(r, result, awsverify.ChunkedReaderOptions{})
if err == nil {
    r.Body = reader
}
```

`ChunkedReader` verifies each chunk signature before it releases that chunk to
the application. It decodes only the chunk framing; trailers are not validated
as object checksums.

For signed-trailer streams, the final zero chunk signature is verified first.
The trailer block is then verified with
`AWS4-HMAC-SHA256-TRAILER`, and decoded trailer values are available after EOF:

```go
if _, err := io.ReadAll(reader); err != nil {
    return err
}
checksum := reader.Trailers().Get("X-Amz-Checksum-Crc32")
```

## Verify browser POST uploads

Call `VerifyPostPolicy` after parsing the multipart form:

```go
size := fileHeader.Size
result, err := verifier.VerifyPostPolicy(formValues, awsverify.VerifyOptions{
    Service:                 "s3",
    Region:                  "us-east-1",
    PostPolicyContentLength: &size,
})
```

The policy document must carry an `expiration`, and every condition in it is
checked against the posted form once the document's signature has been verified.
`content-length-range` can only be evaluated from the uploaded part's size, so
pass it through `PostPolicyContentLength`; a policy that carries the condition
while the caller supplies no size fails closed instead of skipping the check.
An operator this package does not implement returns
`ErrUnsupportedPostPolicyCondition` rather than passing silently.

Signature verification and condition checks do not mean the upload is
authorized. Key prefix, storage class, ACL and any application-specific
constraint that the policy does not express remain the application's decision.

## Errors

Sentinel errors are exported in `errors.go`, including:

- `ErrUnknownAccessKey`
- `ErrSignatureMismatch`
- `ErrExpiredSignature`
- `ErrClockSkew`
- `ErrPresignExpiryTooLong`
- `ErrPayloadHashMismatch`
- `ErrUnsupportedSignatureVersion`
- `ErrUnsupportedStreamingPayload`
- `ErrScopeRequired`
- `ErrMalformedPostPolicy`
- `ErrPostPolicyConditionFailed`
- `ErrUnsupportedPostPolicyCondition`

Use `errors.Is(err, awsverify.ErrSignatureMismatch)` rather than matching error
strings.

## Testing

The suite has four layers, from fastest to most thorough:

- **Unit tests** cover every verification path against the official AWS
  [SigV4 test suite](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-test-suite.html)
  (`testdata/aws-sigv4-test-suite.json`), hand-built vectors, error taxonomy
  (`TestErrorTaxonomy` maps every sentinel error to a real trigger), concurrent
  use under `-race`, and boundary behavior for canonicalization, streaming
  framing, and POST policy conditions.
- **Interop tests** (`interop/`, a separate module) sign requests with three
  independent client implementations — aws-sdk-go v1, aws-sdk-go-v2, and
  minio-go — and verify what they produced. Agreement across independent
  signers plus the recorded vectors is the core evidence that the canonical
  request reconstruction matches what real clients send. The suite also pins
  documented client divergences so behavior changes cannot pass silently.
- **Live tests** skip unless an S3-compatible server is configured. They sign
  with this package and let the server accept or reject the result, and a
  verifying proxy runs the reverse direction — a real client's requests are
  verified by this package before they reach the server:

  ```sh
  AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
  AWSSIGVERIFY_LIVE_ACCESS_KEY=... \
  AWSSIGVERIFY_LIVE_SECRET_KEY=... \
  AWSSIGVERIFY_LIVE_WRITE=1 go test -race ./...

  cd interop && AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
  AWSSIGVERIFY_LIVE_ACCESS_KEY=... AWSSIGVERIFY_LIVE_SECRET_KEY=... \
  go test -run TestLiveProxyInterop
  ```

- **Fuzz targets** exercise the streaming framer and trailer parser
  (`FuzzChunkedReader`, `FuzzTrailerBlock`). Seed corpus lives in
  `testdata/fuzz`; anything the fuzzer finds interesting is also a regression
  test:

  ```sh
  go test -fuzz=FuzzChunkedReader -fuzztime=60s ./...
  ```

CI runs the unit and interop suites with `-race` and `go vet` on every push,
plus a short fuzz smoke run.

## Security notes

- Credential lookups happen only after syntactic validation.
- Signature comparisons use `crypto/subtle`.
- Duplicate signature, credential, date, expiry, signed-header and security
  token fields are rejected instead of silently choosing the first value.
- A configured temporary credential must receive the same session token.
- `ChunkedReader` caps chunk-header size and chunk size.
- The verifier does not consume ordinary request bodies.
- A verified signature does not cover the bytes of a body. Use
  `NewPayloadHashReader` or hash the body yourself against `Result.PayloadHash`.
- A presigned request must carry `X-Amz-Expires`; there is no default lifetime.
- A SigV4 request is only verified against the scope named in `VerifyOptions`.
- POST policy conditions are checked after the document is authenticated, and a
  condition that cannot be evaluated is an error rather than a pass.
- Temporary credentials can be modeled with `Credentials.SessionToken`. Your
  credential store should validate that token and the credential's expiration.

## Compatibility

SigV4 follows the public AWS Signature Version 4 process. For S3, the path is
canonicalized exactly as it arrives on the wire, so `%2F` stays one path segment
and dot segments are not removed. For any other service the dot segments are
removed and duplicate slashes merged, which is what the AWS test-suite vector
`get-slashes` (`//example//` becomes `/example/`) requires.

SigV2 puts the escaped request path, not the decoded one, into the canonicalized
resource, following the "HTTP-Request-URI up to the query string" rule. The
subresource whitelist is the union of the AWS subresources and the list MinIO
signs, so `?retention`, `?legal-hold`, `?encryption`, `?select` and
`?select-type` are part of the canonical resource exactly as they are there.

A presigned SigV4 request must carry all six parameters MinIO treats as
mandatory: `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
`X-Amz-SignedHeaders`, `X-Amz-Expires` and `X-Amz-Signature`.

Chunked-stream framing is checked strictly: a chunk header and the
`x-amz-trailer-signature` line must end with CRLF, and the chunk size is read as
bare hexadecimal digits, so `+5` and `0x5` are rejected. The trailer lines inside
their block are hashed exactly as transmitted, so the single-LF terminators
clients send there verify too, and a stream whose signature covers different
framing than the wire does not.

See [docs/VERIFICATION.md](docs/VERIFICATION.md) for what each signature type is
tested against. `interop/` is a second module that signs with two independent
implementations, AWS's own signer (aws-sdk-go) and minio-go's, and verifies the
result here. `live_minio_test.go` goes one step further and drives a running
S3-compatible service over HTTP, which records two places where that server
disagrees with the AWS rules: it canonicalizes an encoded `%2F` into a separator,
and it stores a chunk stream that never sends the terminator chunk. The library
itself keeps no dependencies.

SigV2 is retained for older S3 clients. AWS deprecated Signature Version 2, so
new integrations should prefer SigV4.

## Running the tests

```sh
go test ./...                       # official vectors, offline vectors, unit tests
go test -run FuzzChunkedReader -fuzz FuzzChunkedReader -fuzztime=90s .
cd interop && go test ./...         # differential suite against two independent signers

# live suite, skips unless the environment points at a service
AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
AWSSIGVERIFY_LIVE_ACCESS_KEY=... AWSSIGVERIFY_LIVE_SECRET_KEY=... \
AWSSIGVERIFY_LIVE_WRITE=1 go test -run TestLive .
```

`interop` is a second module, so the library keeps no dependencies: it signs with
AWS's own signer (aws-sdk-go v1.55.8) and with minio-go, then verifies both.
`AWSSIGVERIFY_LIVE_WRITE=1` makes the live run create one temporary bucket and
delete it when the process ends; without it only read requests are sent.
`-race` needs a C toolchain, so it runs in CI rather than on every machine.

## License

Apache License 2.0. See [LICENSE](LICENSE).
