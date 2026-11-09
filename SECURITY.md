# Security Policy

## Supported Versions

Only the latest released version receives security fixes. This package
verifies AWS Signature Version 2 and Version 4 requests; upgrades are
expected to be drop-in.

## Reporting a Vulnerability

Report security vulnerabilities through GitHub
[Security Advisories](https://github.com/junjiefly/aws-sig-verify/security/advisories/new)
rather than public issues. Please include a request or test case that
demonstrates the problem when possible — the fastest useful report is a
request the verifier accepts but should reject, or the reverse.

You will get an initial response within 7 days. Once a fix is ready, the
advisory is published with credit to the reporter unless anonymity is
requested.

## Scope

In scope: signature verification bypasses, canonical request mismatches,
timing leaks in comparisons, panics on malformed input, and resource
exhaustion through unbounded parsing.

Out of scope: this package intentionally does not manage credentials,
authorization policy, tenant mapping, or object storage. Vulnerabilities in
those layers belong to the embedding application.
