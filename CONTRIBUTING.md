# Contributing

Contributions are welcome. Please keep the package dependency-free and focused
on server-side AWS signature verification.

Before sending a change:

1. Run `go test ./...`.
2. Run `go vet ./...`.
3. Run `gofmt -w .`.
4. Add tests for new protocol behavior, malformed input, or security checks.
5. Run the interoperability suite in `interop/` when the change affects
   canonicalization, signing primitives, or verification outcomes. It signs
   requests with aws-sdk-go v1, aws-sdk-go-v2, and minio-go, so a change that
   diverges from what real clients sign fails there.
6. Run a short fuzz session for the parsers you touched
   (`go test -fuzz=FuzzChunkedReader -fuzztime=30s ./...` for the streaming
   framer, `FuzzTrailerBlock` for the trailer parser). If the fuzzer finds a
   new interesting input, commit it as a seed under `testdata/fuzz`.

Live checks against a real S3-compatible server run only when
`AWSSIGVERIFY_LIVE_ENDPOINT`, `AWSSIGVERIFY_LIVE_ACCESS_KEY` and
`AWSSIGVERIFY_LIVE_SECRET_KEY` are set; they are never required for a
contribution.

Do not copy implementation code, comments, or tests from MinIO, SeaweedFS, or
other projects. Use the public AWS documentation, independent implementations
as black-box interoperability sources, or newly written tests only.

Keep tenant, bucket, and account policy outside this package. Credential lookup
is exposed as a callback so embedding applications can own that mapping.

Prefer protocol-level, service-neutral APIs when a change affects general AWS
signature behavior. Integration-specific policy and storage stay in embedding
applications.
