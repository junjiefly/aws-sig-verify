# How this package's correctness is established

This document records what is actually tested, what that testing proves, and
what it does not prove. Every number below was measured in this repository on
2026-11-03 with the commands in "Running the suites".

## The evidence, ranked by how independent it is

A verifier is only as trustworthy as the source of its expected values, so every
source below is outside this repository: AWS's own artifacts first (recorded
vectors, then AWS's signer code), then a third-party client, then a second
verifier's source read line by line, then a running S3-compatible service, then
values recomputed by a different language, then inputs the fuzzer invents.

Measured totals on this machine:

| Tier | Tests | Named cases | Ran / skipped |
| --- | --- | --- | --- |
| Offline root module (`go test .`) | 66 test functions + 2 fuzz targets | 188 subtests + 14 fuzz seed inputs | all run (the 14 live functions below skip without the environment) |
| `interop` differential module | 28 test functions | 155 named cases (148 subtests + 7 single-case) | all run |
| Live service (§5) | 14 test functions | 41 named cases (33 subtests + 8 inline checks in 7 functions) | 29 subtests run, 4 skipped; 13 functions run, 1 skipped |

`go test -cover .` reports 85.0% of statements for the root module.

### 1. Official AWS SigV4 test-suite vectors (`testdata/aws-sig-v4-test-suite.json`)

28 distinct recorded vectors: canonical request, string-to-sign, authorization
header and the raw request for each. They are run twice, by different code.

| Test | What it does | Cases |
| --- | --- | --- |
| `TestAWSSigV4OfficialSuite` | Rebuilds an `*http.Request` from each recorded request and calls `Verifier.Verify`. The recorded `creq` is deliberately not read by the verifier, so a wrong canonicalization fails the signature comparison. | 56 subtests (each vector runs in the `all` group and its own group), 54 verified, 2 skipped |
| `TestAWSSigV4SuiteVectorIntegrity` | Recomputes `sha256(creq)`, the string-to-sign and the signature using only `crypto/*`, without touching the verifier. A corrupted or self-inconsistent vector is reported as bad data rather than a verifier bug. | 28 subtests, 27 verified, 1 skipped |

One vector, `post-x-www-form-urlencoded-parameters`, is excluded in
`aws_sigv4_suite_test.go:49`: its `sts` and `authz` agree with each other, so
the signature is genuine, but no canonical request built from the recorded
method, path, query, headers and body hashes to that `sts`. Excluding it is the
honest option; matching it would require bending canonicalization until the
number agreed.

Scope: SigV4 header signatures only. The suite carries no streaming, presign or
POST-policy vectors.

### 2. The official AWS SDK signer (`interop/aws_sdk_v1_test.go`, aws-sdk-go v1.55.8)

This is AWS's own signing code, taken from the module cache and used as a second
opinion. Two properties make it usable for streaming:

- `buildBodyDigest` keeps an `X-Amz-Content-Sha256` the caller already set
  (`aws/signer/v4/v4.go:697`), which is how the streaming sentinel gets signed
  without the SDK hashing the body.
- `StreamSigner`'s string-to-sign is `AWS4-HMAC-SHA256-PAYLOAD`, timestamp,
  scope, previous signature, `sha256(headerBlock)`, `sha256(payload)`
  (`aws/signer/v4/stream.go:54`). With an empty header block the fifth line is
  `e3b0c442...`, which is exactly the S3 payload-chunk shape, so the chunk chain
  is produced by AWS's code and checked by this package.
- For S3 the SDK disables URI path escaping with the comment "S3 service should
  not have any escaping applied" (`aws/signer/v4/v4.go:471`), i.e. AWS's own
  client canonicalizes the path as sent. The tests set
  `DisableURIPathEscaping` to match how the SDK signs real S3 traffic.

| Test | Cases | Coverage |
| --- | --- | --- |
| `TestAWSSDKV1HeaderInterop` | 13 | GET/PUT/POST, body hash, `UNSIGNED-PAYLOAD`, streaming sentinel, `Content-MD5` + `Content-Type`, user metadata, duplicate query keys, percent-encoded and `%2F` keys, subresources, temporary credentials |
| `TestAWSSDKV1HeaderRejectsTampering` | 6 | Key, query, unsigned header, content type, scope and signature mutations |
| `TestAWSSDKV1PresignInterop` | 7 | Presigned GET/PUT/list, response overrides, temporary credential, encoded and `%2F` keys |
| `TestAWSSDKV1PresignRejectsTampering` | 4 | Key, expiry, added parameter, signature |
| `TestAWSSDKV1PresignExpiryWindow` | 1 | Signature 2 h old with a 1 h `X-Amz-Expires` |
| `TestAWSSDKV1StreamingChunkChain` | 6 | Streams whose every chunk signature comes from the AWS SDK: single, two, only-final, 1 MiB, binary, five-chunk chains |
| `TestAWSSDKV1StreamingRejectsTampering` | 6 | Changed byte, swapped chunks, inflated declared size, missing final chunk, replaced chunk signature, LF-terminated chunk header |

Totals: 7 test functions, 43 named cases (42 subtests plus 1 single-case test).

The cached SDK versions compute no trailer signatures (`AWS4-HMAC-SHA256-TRAILER`
appears nowhere in aws-sdk-go v1.55.8 or aws-sdk-go-v2 v1.41.1), so the trailer
*client* side still rests on minio-go alone; section 4 covers the verifier side.

### 3. An independent client implementation (`interop/`, minio-go v7.0.84 `pkg/signer`)

minio-go is a different codebase written against the same specification. It
signs; this package verifies. Agreement on both accept and reject paths is
differential evidence, not a self-consistency check.

| Test | Cases | Coverage |
| --- | --- | --- |
| `TestSigV4HeaderInterop` | 13 | Header signatures: GET/PUT/DELETE, encoded keys, multiple headers, session tokens |
| `TestSigV4HeaderRejectsTampering` | 13 | Each mutation must be rejected with a specific sentinel error |
| `TestSigV4StreamingChunksInterop` | 8 | Signed chunk streams at payload sizes 0 B to 1 MiB |
| `TestSigV4StreamingRejectsTampering` | 9 | Changed byte, reordered chunk, dropped/renamed signature, replayed chain |
| `TestSigV4StreamingSignedTrailerInterop` | 3 | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`, trailer hash over transmitted bytes |
| `TestSigV4StreamingUnsignedTrailerInterop` | 1 | `STREAMING-UNSIGNED-PAYLOAD-TRAILER` |
| `TestSigV4StreamingLimits` | 2 | Chunk-size and header-size caps |
| `TestSigV4StreamingEmptyBody` | 1 | Zero-chunk-only stream |
| `TestSigV4PresignInterop` | 8 | Query-string signatures incl. response overrides and temporary credentials |
| `TestSigV4PresignRejectsTampering` | 6 | Key, query, expiry, signature and signed-header mutations |
| `TestSigV4PresignExpiry`, `TestSigV4PresignRejectsLongExpiry` | 2 | `X-Amz-Expires` window and `Config.MaxPresignExpiry` |
| `TestSigV2HeaderInterop` | 14 | SigV2 header signing incl. `x-amz-*` headers, subresources, `response-*` overrides, percent-encoded keys, virtual-host buckets |
| `TestSigV2RejectsTampering` | 8 | Body/header/query mutations, non-base64 signature |
| `TestSigV2PresignInterop`, `TestSigV2PresignExpiry` | 4 | Presigned SigV2 URLs and the `Expires` window |
| `TestPostPolicyV4Interop` / `V2Interop` | 4 | Browser-upload forms signed by the client's POST presigner, plus size-range and unknown-size handling |
| `TestPostPolicyRejectsTampering` | 12 | Policy bytes, signature, algorithm, credential, expiry and form-condition mutations |
| `TestSigV4EncodedSlashClientDivergence`, `TestSigV4DuplicateQueryKeyClientDivergence` | 4 | Documented, intentional disagreements (see below) |

Totals: 21 test functions, 112 named cases (106 subtests plus 6 single-case
tests). The `interop` module as a whole runs 28 test functions and 155 named
cases.

Two disagreements with minio-go are recorded as tests instead of being hidden.
Both now have a third vote from AWS's own signer, which produces the shape this
package expects:

- **Encoded slash.** A request for `/bucket/a%2Fb` is signed by minio over
  `/bucket/a/b`; this package follows the S3 rule and canonicalizes the path as
  sent, so the verifier returns `ErrSignatureMismatch`. The test signs a plain
  `/bucket/a/b` request as a positive control, and signs the same `%2F` request
  with aws-sdk-go, which verifies here. §5 later asked a running service to
  decide, and that service follows minio's decoded-path reading, so the divergence
  is now known to break against at least one real server.
- **Duplicate query keys.** `marker=a&marker=b` and `marker=b&marker=a` sort
  differently under the AWS rule. This package follows the rule (pinned by the
  official `get-vanilla-query-order-value` vector); minio-go's map-based
  canonicalizer loses one value, so the second ordering is rejected. aws-sdk-go
  sorts the values and its signature for the reversed order verifies here.

### 4. A second verifier's source, read line by line (MinIO server, `RELEASE.2025-02-03T21-03-04Z`)

MinIO's server decodes and checks the same `aws-chunked` streams — it is the code
that has to accept real clients in production, written independently of both
minio-go and this package. The copy audited here is a local source tree
(`cmd/streaming-signature-v4.go`, `cmd/streaming-v4-unsigned.go`); it was **not
executed**, because that module's own dependencies are absent from this machine's
cache — `go build ./cmd` starts downloading `go-ldap`, `klauspost/compress` and
the rest. So this is a documented comparison of the framing rules, not a
differential test run in CI. §5 later drives a MinIO *service* over HTTP, but that
server does not report a version and is not a build of this tree, so the two stay
separate pieces of evidence.

Where it agrees with this package, which raises the streaming evidence from "one
implementation" to two:

| Rule | MinIO server | This package |
| --- | --- | --- |
| Chunk header shape | `<hex>;chunk-signature=<64 hex>` then `CR` `LF`, byte-exact (`streaming-signature-v4.go:326-373`) | same (`readCRLFLineLimited`, `validChunkSignature`) |
| Payload terminator | `CR` `LF` after exactly `size` bytes (`:410-437`) | same (`expectCRLF`) |
| Largest accepted chunk | 16 MiB (`:260`) | same default (`defaultMaxChunkSize`) |
| Trailer block end | stops at the first blank `CRLF` line, then reads `x-amz-trailer-signature:<hex>` up to the final `CRLF CRLF` (`:445-512`) | same — the framing adopted in finding 1 |
| Undeclared trailer, or declared trailer missing | both rejected (`:555-568`) | both rejected (`parseTrailers`, `validateTrailerPresence`) |

Three places where the two diverge. The first two change what gets hashed, so
this package keeps the stricter reading; the third is MinIO being the stricter
one, and header names are case-insensitive:

- **Newline normalization (`:519-522`).** If the collected trailer block does not
  end in `LF`, MinIO appends one before hashing, which makes a stream whose trailer
  line is terminated by `CRLF` and whose signature covers `LF` verify. That hashes
  bytes the client never sent. Here the trailer hash covers only transmitted bytes,
  so the same stream fails: `TestSignedTrailerChunkedReaderRejectsReframedBlock`.
  A client that signs its own `CRLF` framing verifies
  (`TestSignedTrailerChunkedReaderAcceptsCRLFTerminatedBlock`).
- **Missing block terminator (`:445-473`).** Because MinIO's block reader stops at
  the first `CRLF` it finds, a trailer line that ends with `CRLF` and is followed
  straight by the signature line — no blank line — parses. Here the blank line is
  the only thing that ends the block, so that stream is reported as truncated:
  `TestSignedTrailerChunkedReaderRequiresBlockTerminator`.
- **Trailer name case (`:537`, `:546-555`).** MinIO lowers the *declared* names but
  looks up the received name as-is, so a capitalized trailer line is rejected.
  Header names are case-insensitive, so this package lowers both:
  `TestSignedTrailerChunkedReaderAcceptsMixedCaseTrailerName`.

The audit also produced one tightening in this package: the size field is parsed
character by character instead of with `strconv.ParseInt`, which had accepted a
signed size such as `+5`. MinIO's byte-wise parser rejects it, and an over-wide
size is reported as too large rather than malformed
(`TestChunkedReaderChunkSizeSyntax`, finding 5).

### 5. A running S3-compatible service (`live_minio_test.go`)

Everything above answers "does this package agree with another implementation's
bytes". Only a service can answer "does code that has to accept real requests
agree with what this package accepts". A MinIO server on the local network
(`Server: MinIO`, the same project whose source §4 reads, but this time executed)
is driven over plain HTTP with `net/http` and no client library in between. It is
not AWS S3, so this tier shows compatibility with one running S3-compatible
implementation, not with AWS.

The suite is opt-in and split in two. The read-only checks need
`AWSSIGVERIFY_LIVE_ENDPOINT` plus the two key variables and skip without them. The
write checks additionally need `AWSSIGVERIFY_LIVE_WRITE=1`; they create one bucket
named `awsverify-live-<timestamp>-<pid>`, write only into it, and `TestMain`
empties and deletes that bucket at the end of the run. Nothing in the suite reads
credentials from a file. The read-only shapes need one object to GET: they list
buckets, ask the first listable bucket for its first ten keys, and read the first
between 1 byte and 1 MiB. In the runs recorded here that landed on the 21-byte
object this suite wrote itself, because its bucket sorted first; listing order is
not part of the S3 contract, so the same run can instead fetch one pre-existing
object, GET only. Path-shape cases that do not need a real object deliberately ask
for a key under `awsverify-no-such/` and expect `404 NoSuchKey`, which still shows
the signature layer agreed. Before pointing this at production data, note both of
those: one small object may be read, and if a signature is ever rejected the
helper logs the first line of the response body.

| Test | Cases | What the service did |
| --- | --- | --- |
| `TestLiveListBuckets` | 1 | SigV4 header signature over `GET /` accepted, 14 buckets listed |
| `TestLiveObjectRoundTrip` | 1 | plain PUT of 21 bytes, GET and HEAD back, then delete |
| `TestLiveSigV4HeaderShapes` | 12 | GET, HEAD, signed `Range` (206), `UNSIGNED-PAYLOAD`, `?location`, list with query in wire order, duplicate query values, `%20` / `%2B` / unicode keys, empty query value and a dot-segment key all pass the signature layer; the dot-segment one is refused later, as `XMinioInvalidResourceName`, not as a signature problem |
| `TestLiveSigV4EncodedSlashAgainstService` | 1 | skipped as a divergence: see below |
| `TestLiveSigV4PresignedGET` | 1 | a query-string signature produced here accepted, object returned |
| `TestLiveSigV2Shapes` | 6 | SigV2 header GETs: `Date` only, `x-amz-date` only, both together, sorted `x-amz-*` metadata, `?acl` subresource, escaped path |
| `TestLiveSigV2BothDateHeaders` | 4 | every candidate reading of the ambiguous date rule sent over one request; exactly one accepted, and it is the one this package signs |
| `TestLiveSigV2PresignedGET` | 1 | presigned SigV2 URL accepted |
| `TestLiveStreamingChunkedPUT` | 3 | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` chains (one chunk, three chunks, one 54,000-byte chunk plus a 4-byte tail) accepted; 25, 19 and 54,004 decoded bytes read back byte-identical |
| `TestLiveStreamingTrailerPUT` | 4 | all four skipped: see the trailer finding below |
| `TestLiveStreamingPUTRejectsTamperedStream` | 2 | a payload byte changed after signing, and one hex digit of a chunk signature changed, both refused with `SignatureDoesNotMatch` |
| `TestLiveStreamingPUTRejectsWrongKeyAndReplay` | 2 | wrong secret refused; the first chunk's signature replayed as the second refused |
| `TestLiveStreamingPUTWithoutTerminatorChunk` | 1 | **accepted** (200): see the leniency below |
| `TestLivePostPolicyUpload` | 2 | browser-form POST policy uploads signed here, SigV4 and SigV2, both accepted and read back |

The Cases column counts signature decisions, not Go subtests: seven of these
functions check inline instead of using `t.Run`, and one of those makes two
decisions, which is why 33 subtests plus 8 inline checks give 41 cases.

One caveat about what "signed here" means in this table: the root module has no
external dependencies, so the live chunk chains are framed by test code that
builds each documented string-to-sign and runs it through `crypto/hmac`
(`expectedChunkSignature`, `testhelpers_test.go:112`). That is the same code the
offline streaming tests use to compute what a correct chain should be, and that
shape is the one §2 verified line by line against AWS's own `StreamSigner` — but
the service is being fed this repository's test code, not a third-party writer.

Three results are only available from a running service.

- **The SigV2 `Date` + `x-amz-date` question is no longer purely local.** §6 used
  to call that reading "pinned, not proven", because the published documentation
  is ambiguous and no cached AWS implementation signs SigV2 any more.
  `TestLiveSigV2BothDateHeaders` sends all four candidate string-to-sign values as
  the same request and the service accepts exactly one: keep the `Date` element
  *and* canonicalize `x-amz-date`, which is what this package computes. One
  service's reading is still not AWS's, so the claim is "corroborated by a live
  verifier", not "proven against AWS".
- **The trailer sentinels cannot be checked on this build, and the reason is
  measured rather than assumed.** All four trailer-mode PUTs return
  `400 XAmzContentSHA256Mismatch`, which reads like a complaint about the payload
  hash. The test then re-sends the identical stream signed with a wrong secret and
  gets `403 SignatureDoesNotMatch`. Those two codes settle the ordering on their
  own: if the sentinel were rejected before signing was checked, the wrong secret
  would produce the same `400`. Instead the signature over the canonical request
  that used the trailer sentinel as its payload hash was reached and **passed**,
  and the refusal comes afterwards, from request classification. That matches the
  audited source, which verifies `Authorization` before hex-decoding
  `x-amz-content-sha256` (`auth-handler.go:547-585`), but the running build does
  not report its version, so the source is corroboration and the two codes are the
  evidence. Read this as: this service does not route
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` or
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER` to a chunked reader at all. The trailer
  framing settled in §4 therefore still has no live confirmation, and those cases
  skip instead of reporting success.
- **A third framing divergence, this time with the service more forgiving.**
  A stream that ends after its last data chunk, with no
  `0;chunk-signature=<hex>` terminator at all, is stored by this service and reads
  back with the correct 39 bytes. This package's reader requires the terminator and
  stops with `io.ErrUnexpectedEOF` after decoding the chunks it saw
  (`TestChunkedReaderRequiresTerminatorChunk`). Same class as the two §4
  divergences: a strict verifier rejects a stream a running service accepted. The
  strict reading is kept — an unterminated stream has no authenticated end — but it
  is now recorded as a compatibility risk rather than as an obvious rejection.

The `%2F` case is the second known divergence: `TestLiveSigV4EncodedSlashAgainstService`
signs one wire request `/bucket/a%2Fb.txt` under both rules and lets the service
choose. This service rejects the path-as-sent rule with `SignatureDoesNotMatch`
and accepts the decoded-path rule — the minio-go reading of §3, not the AWS rule
the official vectors pin. The test skips with that finding rather than failing,
and this package keeps the AWS behavior.

### 6. Vectors recomputed outside Go (`v2_test.go`)

SigV4 has an official vector suite; SigV2 has only the four examples printed in
the old S3 documentation. The second-implementation tier cannot help here either:
aws-sdk-go v1.55.8 ships no SigV2 signer at all (`aws/signer/` contains only
`v4/`). So eight SigV2 string-to-sign values were written out and their HMAC-SHA1
signatures were computed by a separate Python 3 process — nothing in this
repository produced the expected bytes. `TestVerifyV2OfflineVectors`
then re-derives each signature with `base64SHA1` inside the test, so a quoted
signature cannot silently drift away from the quoted string-to-sign.

The three AWS-documentation examples (`TestVerifyV2HeaderAWSVector`,
`TestVerifyV2HeaderWithContentTypeAWSVector`, `TestVerifyV2SubresourceAWSVector`)
are genuine published vectors and all reproduce.

One case used to be **pinned, not proven**: when a SigV2 request carries both
`Date` and `x-amz-date`, this package keeps the `Date` element in the string-to-sign
*and* also lists `x-amz-date` among the canonicalized headers. The AWS
documentation is ambiguous and no offline oracle settled it, so the vector at
`v2_test.go:138` pinned the value as a regression guard. §5 now decides it against
a running service: of the four possible readings, only this one is accepted
(`TestLiveSigV2BothDateHeaders`). That is one implementation's resolution of an
ambiguous rule, not AWS's, so the pinned vector stays and the claim is
"corroborated live", not "proven".

The V2 subresource whitelist is pinned against the service rather than chosen
freely. `TestVerifyV2CanonicalResourceMinIOSubresources` fixes the canonical
resource for `?retention`, `?legal-hold`, `?encryption`, `?select` and
`?select-type` — the five names the running service signs
(`cmd/signature-v2.go:40` resourceList) that this package left out until they
were added — together with the order several of them appear in, and keeps
non-whitelisted parameters such as `list-type` and `x-id` out of the resource.
`TestVerifyV2PresignedMinIOSubresource` then verifies a presigned
`?retention` URL end to end, so the rule is exercised through `Verify` and not
only through the resource builder.

`TestVerifyV2CanonicalResourceAWSSubresources` additionally pins current AWS
S3 operation subresources and the legacy botocore names listed above, while
`TestVerifyV2SubresourcesAreSorted` keeps the canonical ordering deterministic.

### 7. Fuzzing the streaming parser (`chunked_fuzz_test.go`)

`FuzzChunkedReader` feeds arbitrary bytes to the chunk framer behind a valid
signed stream header. `FuzzTrailerBlock` does the same for the trailer parser,
the code that produced the one real streaming bug this package had, with the
chunk chain left valid so mutations land in the trailer block.

Invariants for both: no panic; if a stream is accepted, the decoded bytes must
equal the payloads re-parsed independently from the frame structure; and for the
trailer target, every trailer `Trailers()` reports must be the declared one and
its value must appear literally in the input. Go's fuzzer does not enforce these
itself, so the reader cannot accept a stream that drops, duplicates or invents
bytes.

Measured runs on this machine:

| Target | Corpus run by `go test` | Campaign | Result |
| --- | --- | --- | --- |
| `FuzzChunkedReader` | 8 inputs (7 in-code seeds + 1 stored counterexample) | 90 s, 6,726,247 executions; re-run 45 s, 3,202,951 executions after the size-syntax fix | no failures after the fix; the earlier 45 s run (~1.9M executions) found the LF-terminator deviation |
| `FuzzTrailerBlock` | 6 in-code seeds | 75 s, 4,249,032 executions | no failures |

Findings are written to `testdata/fuzz/FuzzChunkedReader/` and stay in the seed
corpus afterwards, so the LF case is now a permanent regression input.

## Findings this work produced

All five are library fixes, not test edits, and none of them was visible from
inside the package: each was produced by an outside signer, a recorded vector,
another implementation's source or the fuzzer.
1. **Trailer framing (`chunked.go:243`).** The reader expected
   `x-amz-trailer-signature` to be part of the block terminated by the blank
   line. Clients actually send the trailer lines, a blank line, and then the
   signature line, and the trailer hash covers exactly those transmitted block
   bytes. Every real signed-trailer stream failed with `ErrMalformedChunk`.
   `readTrailers` now keeps the raw bytes of each trailer line and reads the
   signature line after the block terminator. Symptom: minio-go's
   `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` request never verified.
2. **SigV2 canonical resource (`v2.go`).** It used the decoded URL path, so
   `/bucket/my%20file.txt` was signed over `/bucket/my file.txt`. The rule uses
   the request URI as sent; the code now uses `URL.EscapedPath()`. Proof: the
   offline Python vector and minio's encoded-key interop case.
3. **Chunk header terminator (`chunked.go:160`, found by fuzzing).** Chunk
   headers accepted a bare `LF` while chunk payloads required `CRLF`. All
   signature checks still passed for such a stream, so a signer-correct but
   non-standard framing was accepted. Chunk headers and the trailer signature
   line now require `CRLF` (`readCRLFLineLimited`); the trailer block stays
   `LF`-tolerant because those bytes are hashed verbatim. Regression test:
   `TestChunkedReaderRejectsLFTerminatedChunkHeader`, plus the original
   counterexample kept in `testdata/fuzz/FuzzChunkedReader/`. aws-sdk-go emits
   `CRLF` for every chunk header, so every stream its signer produces still
   verifies, and the LF variant is now a rejection case
   (`TestAWSSDKV1StreamingRejectsTampering/lf_terminated_chunk_header`).
4. **Non-S3 canonical URI (`canonical.go:93`).** Duplicate slashes were kept,
   so a request for `//example//` did not match the signature AWS computes for
   services other than S3. The escaped path is now normalized (dot segments
   removed, empty segments merged) for non-S3 services only, which is what the
   official `get-slashes` vector requires; S3 keeps the wire form.
5. **Chunk size syntax (`chunked.go:397`).** The size field went through
   `strconv.ParseInt`, which also accepts `+5`; every signature check still passed
   because the payload bytes were unchanged, so a stream no client writes was
   accepted. The size is now parsed as bare hex digits, matching MinIO server's
   byte-wise reader, and a value too wide for `int64` is reported as
   `ErrChunkSizeTooLarge` instead of malformed. Finding 3 and this one are the same
   class: framing leniencies that only an outside implementation could reveal.

The live tier (§5) produced **no** library change, and it is worth saying so
plainly. It corroborated parts of the five above: the CRLF chunk framing was
accepted, a SigV2 request with an escaped path verified against the server, and
S3's path-as-sent canonicalization held for `%20`, `+` and unicode keys — but the
same server refuses the encoded-separator half of that rule, so finding-level
agreement is partial by construction. It could not reach finding 1 at all (the
service ignores trailer sentinels) or finding 4 (only S3 was available, never a
non-S3 service). What it did add is one regression test that pins a behavior the
service disagrees with (`TestChunkedReaderRequiresTerminatorChunk`), a live answer
for the SigV2 `Date` + `x-amz-date` reading, a measured explanation of why trailer
streams cannot be checked against this particular service, and direct confirmation
that a running verifier rejects a changed chunk payload byte, a changed chunk
signature digit, a replayed chain link and a wrong secret.

## What is proven, and what is not

Proven to the level stated above:

- SigV4 canonicalization and signing for the 27 usable official vectors.
- SigV4 header and presigned signatures against two independent implementations:
  AWS's own signer (aws-sdk-go v1.55.8) and minio-go.
- SigV4 chunk streams: the signature chain is produced by AWS's own chunk signer
  in `TestAWSSDKV1StreamingChunkChain`, and rejection when a chunk byte, size or
  order changes is checked against both clients.
- Signed and unsigned trailer streams against one real client, minio-go, plus a
  source audit of MinIO's server reader, which enforces the same framing (§4).
  No service was able to receive them (§5).
- POST policies against one real client implementation, and the condition set
  this package enforces (`eq`, `starts-with`, `in`, `not-in`,
  `content-length-range`, required `expiration`) against both accepted and
  tampered forms.
- SigV2 header and presigned URLs against offline-recomputed vectors plus one
  real client.
- Credential lookup happens only after syntactic validation, and comparisons use
  `crypto/subtle` (`parity_test.go`, `credential_test.go`).

Observed on a running S3-compatible service (§5), which is a different kind of
claim from the list above — it shows one server agrees, not that the rules are
AWS's:

- SigV4 header signatures over 12 request shapes, presigned GET, and both POST
  policy versions uploaded as browser forms, all accepted and read back.
- SigV4 signed chunk streams: three chains accepted and decoded byte-identically
  by the server, and four mutations (payload byte, chunk signature digit, wrong
  secret, replayed chain link) refused.
- SigV2 header signatures over six shapes, presigned GET, and the `Date` +
  `x-amz-date` reading resolved to what this package signs.

Not proven — do not read this document as covering these:

- **No AWS service was contacted.** A real, running S3-compatible server was
  (§5), and it agrees on the shapes listed above. Nothing here demonstrates that
  AWS S3 itself accepts what this package accepts: the service does not report a
  version, it follows the decoded-path reading where AWS does not, and it does not
  implement the trailer sentinels at all.
- **Trailer framing has one client and one server source behind it, neither from
  AWS, and no live observation.** minio-go defines the bytes a client sends and
  MinIO's server reader independently enforces the same framing (§4). No cached
  AWS SDK signs a trailer, and the service in §5 refuses trailer sentinels before
  any chunk reader sees them, so a first-party trailer stream is still unobserved
  end to end. MinIO normalizes newlines in that block precisely because its authors
  wrote "Not all clients send that" (`streaming-signature-v4.go:518`), so trailer
  framing is known to vary in the wild and which side is right can only be settled
  against a service that implements it.
- **SigV2 has no AWS-authored oracle here.** aws-sdk-go v1.55.8 dropped the
  SigV2 signer, so its evidence is documentation examples, offline HMAC-SHA1
  recomputation, minio-go and one live service.
- **SigV2 with `Date` and `x-amz-date` together rests on one server's reading.**
  The documentation is ambiguous; §5 shows a running service accepts only the
  reading this package implements, which is corroboration, not an AWS answer.
- **Two canonicalization rules are known to differ from this service.** Encoded
  `%2F` in a path (server decodes, this package signs as sent) and a stream with
  no terminator chunk (server stores it, this package stops with
  `io.ErrUnexpectedEOF`). Both are recorded as skipped subtests or dedicated tests,
  not fixed.
- **Signature validity is not the whole authorization decision.** This package
  answers "did the holder of this secret sign exactly these bytes"; it does not
  check whether the key may perform the action.
- **A verified signature does not authenticate a body.** The payload hash enters
  the canonical request as a declared value, so a captured request can be replayed
  with different bytes and still verify. `NewPayloadHashReader` is the primitive
  that closes this: it hashes what the handler reads and fails with
  `ErrPayloadHashMismatch` at EOF. It reports `Checked() == false` for
  `UNSIGNED-PAYLOAD` and the streaming sentinels, where no hash was claimed; a
  streaming body is instead authenticated chunk by chunk. MinIO's server compares
  the same hash before writing an object, so this is a check the service performs
  and a verifier must not silently skip. `payload_test.go` verifies a matching
  body, a substituted body behind a valid signature, an empty body, the four
  hash-free payload values, and a declared value that is not a SHA-256 at all.
- **`ChunkedReader` integrity ends with the last chunk.** In
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER` mode, trailers are parsed but nothing
  authenticates them.
- **A stream is identified only by `x-amz-content-sha256`.** Nothing ties the
  declared `Content-Length` to the bytes the reader emits, and the reader stops
  at the zero chunk. Code that sizes buffers or enforces limits from
  `Content-Length` must not assume it matches the decoded body.
- **There is no cap on total decoded bytes.** `ChunkedReader` limits per-chunk
  size (16 MiB by default), chunk-header size and trailer-block size; callers
  must bound how much they read.
- **Session-token validity is out of scope.** `Credentials.SessionToken` is
  compared, not authenticated; the credential store owns expiry and STS checks.
- **SigV2 is deprecated by AWS.** It is kept for old clients; new integrations
  should use SigV4.

Three decisions in this area, all of which fail closed:

- `VerifyOptions.Service` and `Region` are required for every SigV4 request
  (header, presigned and POST policy). A request whose scope the caller did not
  pin is rejected with `ErrScopeRequired`; the verifier never adopts whatever
  scope the client asked for. SigV2 carries no scope, so V2 requests need neither.
- A POST policy must carry `expiration`, and every condition in it is checked
  against the posted form after the document's signature is verified. A
  condition this package cannot evaluate is an error, not a skip:
  `content-length-range` needs `VerifyOptions.PostPolicyContentLength`, and an
  operator outside `eq`, `starts-with`, `in`, `not-in` and
  `content-length-range` returns `ErrUnsupportedPostPolicyCondition`. A field a
  condition names twice — one repeated field, or two spellings that differ only
  in case — and a form carrying two `policy` fields are both refused rather than
  resolved by whichever entry the form parser happened to see first.
- A presigned request must carry every parameter the signature depends on,
  including `X-Amz-Expires`. A URL without it used to be read as a 900-second
  lifetime; it is now `ErrMalformedAuthorization`, matching the six mandatory
  presign parameters MinIO checks (`signature-v4-parser.go:181`). The same holds
  for SigV2, whose `Expires` has always been required.

## Running the suites

```sh
# Root module: official vectors, offline SigV2 vectors, streaming, compatibility tests
cd /path/to/aws-sig-verify
go test -count=1 ./...
go test -count=1 -cover .
gofmt -l . && go vet ./...

# Seed corpus of the streaming fuzzer (part of go test)
go test -count=1 -run FuzzChunkedReader .

# Fuzzing campaign; findings land in testdata/fuzz/FuzzChunkedReader/
go test -run FuzzChunkedReader -fuzz FuzzChunkedReader -fuzztime=90s .

# Differential suite against two client implementations (separate module)
cd interop
go test -count=1 ./...
go mod tidy

# Live suite. Read-only shapes; add AWSSIGVERIFY_LIVE_WRITE=1 for the write checks,
# which create one temporary bucket and delete it at the end of the run:
AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
AWSSIGVERIFY_LIVE_ACCESS_KEY=... AWSSIGVERIFY_LIVE_SECRET_KEY=... \
AWSSIGVERIFY_LIVE_WRITE=1 \
go test -count=1 -run TestLive .
```

The live tests are the only ones that need a server, and they skip when
`AWSSIGVERIFY_LIVE_ENDPOINT` is unset, so `go test ./...` stays self-contained.
Credentials come from the environment only; nothing in the repository stores a
key, and CI has no live job.

`-race` needs cgo and a C toolchain. On this Windows development machine
`go test -race` fails with "-race requires cgo", so race detection runs only in
CI, which enables it for both modules (the interop job starts at Go 1.23 because
that module declares `go 1.23.0`).

`go mod tidy` in `interop` needs network access even though `go test` does not:
it walks the test dependencies of the client libraries (for example
`github.com/davecgh/go-spew`, pulled in by jmespath's own tests) and they are not
in this machine's module cache. Build and test runs resolve entirely offline.

## Strengthening the proof

In rough order of value:

1. Verify against **AWS S3 itself**. §5 closed the "no server at all" gap by
   driving a running S3-compatible service, and that service disagreed with the
   AWS rules in one place (`%2F`). Only first-party traffic can say which side a
   production client will meet.
2. Observe an AWS-authored trailer stream. The framing is corroborated by MinIO's
   server reader (§4) and now also rejected by a live service for reasons that
   have nothing to do with the framing (§5: the sentinel is not routed to a chunk
   reader at all), so the question is still open. aws-sdk-go v1.55.8 and
   aws-sdk-go-v2 v1.41.1 core compute no `AWS4-HMAC-SHA256-TRAILER`; the v2
   `feature/s3/transfermanager`, a Java/Python/Rust SDK or a packet capture would.
3. Re-run the live tier against a service that implements the trailer sentinels.
   The four cases are already written and skip on `XAmzContentSHA256Mismatch`; on
   such a service they become normal acceptance checks, including the two
   re-framed variants that expose the MinIO leniencies.
4. Test a **non-S3** service. Finding 4 changed canonicalization for non-S3
   scopes only, and every tier here is S3, so that code path has only the official
   `get-slashes` vector behind it.
5. Add official-suite style vectors for streaming, presigning and POST policies;
   the published suite covers only header signing.
6. Settle the SigV2 `Date` + `x-amz-date` rule against a second oracle. §5 gives
   one server's answer and the pinned vector at `v2_test.go:138` guards it; an AWS
   answer, or dropping `x-amz-date` from canonicalization to match the documented
   rule exactly, is still missing. No offline AWS implementation signs SigV2 any
   more, so this needs live or captured traffic.
