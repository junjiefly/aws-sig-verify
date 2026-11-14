# aws-sig-verify

[![CI](https://github.com/junjiefly/aws-sig-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/junjiefly/aws-sig-verify/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/junjiefly/aws-sig-verify.svg)](https://pkg.go.dev/github.com/junjiefly/aws-sig-verify)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

[English](README.md) | 简体中文

`awsverify` 是一个无第三方依赖的 Go 包，用于在服务端验证 AWS Signature
Version 2 和 Version 4 HTTP 请求。它适用于 S3 兼容网关以及其他 AWS 风格的
HTTP API。

这个包是可复用的协议层，而不是网关或 SDK。应用程序仍然掌握凭据存储、
租户/账户映射、STS 会话、对象 ACL、IAM 策略和响应处理逻辑。

这个包支持验证：

- SigV4 `Authorization` 请求头
- SigV4 预签名 URL
- SigV4 POST policy
- 经典 `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` 分块上传
- 已签名 `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` 分块上传
- 未签名 `STREAMING-UNSIGNED-PAYLOAD-TRAILER` 分块上传
- SigV2 请求头和预签名请求
- SigV2 POST policy

它不会从文件或环境变量加载 AWS 凭据，不会发起网络调用，也不会强制执行
bucket/object ACL。你需要提供凭据查找函数，并保留授权策略的控制权。

## 安装

```sh
go get github.com/junjiefly/aws-sig-verify
```

## 验证请求

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
    // 返回 HTTP 错误。可以使用 errors.Is 检查具体错误类型。
}

// result.AccessKeyID 标识调用者。在允许访问 bucket 或 object 之前，
// 先应用你自己的 ACL 或 IAM 策略。
```

每个 SigV4 请求都必须提供 `Service` 和 `Region`。它们固定了请求必须携带的
凭据作用域；如果请求声明的 scope 不是调用方固定的 scope，会返回
`ErrScopeRequired`，而不是按请求自带的 scope 验证。SigV2 签名没有 scope，
因此 V2 请求不需要这两个字段。

同一个 verifier 也可以用于非 S3 的 AWS 风格服务。提供必须匹配凭据作用域的
service 和 region：

```go
result, err := verifier.Verify(r, awsverify.VerifyOptions{
    Service: "execute-api",
    Region:  "eu-central-1",
})
```

如果非 S3 服务没有发送 `X-Amz-Content-Sha256`，请在你应用自己的请求体处理
策略之后，通过 `VerifyOptions.PayloadHash` 提供负载哈希。

对于 S3，只有虚拟主机风格的请求（例如 `bucket.s3.example.com`）才需要在
`VerifyOptions.S3Bucket` 中提供虚拟主机 bucket。路径风格请求应保持为空。

AWS 要求 SigV4 请求头请求携带 `X-Amz-Content-Sha256`。如果你的网关还必须
接受省略该头的旧客户端，可以配置空负载默认值：

```go
verifier := awsverify.NewVerifier(awsverify.Config{
    Credentials:        credentialLookup,
    DefaultPayloadHash: awsverify.EmptyPayloadSHA256,
})
```

`RequestAccessKeyID` 和 `RequestBucketFromHost` 是两个小辅助函数，供需要先
选择凭据存储的网关使用。它们本身不会进行任何授权：

```go
accessKeyID, authType, found := awsverify.RequestAccessKeyID(r)
bucket := awsverify.RequestBucketFromHost(r.Host, []string{"s3.example.com"})
```

当凭据选择依赖请求级状态时，可以为单次调用覆盖凭据查找逻辑：

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

signer 会提取调用者的 AccessKeyID，并调用该回调。它不会把 bucket 映射到
租户，也不会在多个凭据可能适用时替你选择凭据；这类策略属于上层网关。

## 请求级凭据

有些网关会先按 bucket 或租户查找凭据。请把这个映射保留在你的应用程序中，
并通过回调提供：

```go
options := awsverify.VerifyOptions{
    Service: "s3",
    Region:  "region",
}
options.Credentials = func(ctx context.Context, accessKeyID string) (awsverify.Credentials, error) {
    return credentialStore.Lookup(ctx, bucket, accessKeyID)
}
```

回调只会收到请求中展示的 AccessKeyID。它可以查询 STS、数据库、缓存或
按 bucket 配置的账户策略。签名验证随后会使用该回调返回的凭据。

## 校验请求体是否匹配已签名哈希

签名验证成功只能证明客户端声明了某个负载哈希，不能证明你实际收到的字节
确实会产生该哈希，因为 verifier 从不读取请求体。在存储任何内容之前，请
比较两者：

```go
body, err := awsverify.NewPayloadHashReader(r.Body, result.PayloadHash)
if err != nil {
    return err
}
r.Body = body
if _, err := io.Copy(dst, body); err != nil {
    return err // 如果字节不匹配，可通过 errors.Is 判断 awsverify.ErrPayloadHashMismatch
}
```

对于 `UNSIGNED-PAYLOAD` 和三个流式上传哨兵值，`Checked` 会返回 false，
因为这些请求根本没有声明完整负载哈希；流式上传改由 `ChunkedReader` 逐块
认证。MinIO 服务端在写入 object 前也会做同样的比较，因此跳过这一步的网关
可能会接受 MinIO 本身会拒绝的请求。

## 解码已签名流式上传

当 `Verify` 成功且负载哈希表明这是 AWS 流式上传时，包装请求体：

```go
reader, err := verifier.ChunkedReader(r, result, awsverify.ChunkedReaderOptions{})
if err == nil {
    r.Body = reader
}
```

`ChunkedReader` 会在把每个数据块交给应用程序前验证该块的签名。它只解码
分块帧；trailer 不会作为 object checksum 验证。

对于 signed-trailer 流，最终零长度块的签名会先验证。随后 trailer 块使用
`AWS4-HMAC-SHA256-TRAILER` 验证，解码后的 trailer 值可以在 EOF 后读取：

```go
if _, err := io.ReadAll(reader); err != nil {
    return err
}
checksum := reader.Trailers().Get("X-Amz-Checksum-Crc32")
```

## 验证浏览器 POST 上传

解析 multipart form 后调用 `VerifyPostPolicy`：

```go
size := fileHeader.Size
result, err := verifier.VerifyPostPolicy(formValues, awsverify.VerifyOptions{
    Service:                 "s3",
    Region:                  "us-east-1",
    PostPolicyContentLength: &size,
})
```

policy 文档必须携带 `expiration`。文档签名验证通过后，其中的每个 condition
都会和提交的表单值比较。顶层 `expiration` 和 `conditions` 字段名区分大小写，
符合 AWS S3 要求。`content-length-range` 只能依据实际上传部分的大小
评估，所以要通过 `PostPolicyContentLength` 传入；如果 policy 包含该条件但
调用者没有提供大小，包会失败关闭，而不是跳过检查。遇到本包未实现的操作符
时，会返回 `ErrUnsupportedPostPolicyCondition`，不会静默放行。

如果调用者需要先验证签名，再流式处理文件内容，可以使用
`ParsePostPolicyDocument` 解码 policy，用 `PostPolicy.ContentLengthRange`
读取上传大小限制，最后用 `PostPolicy.CheckConditions` 应用已签名的 condition。
如果这条路径没有执行签名验证，应先调用 `PostPolicy.CheckExpiration` 再接受上传。

设置 `PostPolicyStrictFields` 后，除了标准 POST 例外字段和 `x-ignore-*`
字段外，其他表单字段都必须被已签名 policy 约束，符合 AWS S3 的 POST 规则。
网关自己消费的少量实现专用字段可通过 `PostPolicyUnconditionedFields` 显式
放行；违反规则时返回 `ErrFormFieldNotInPolicy`。签名凭据字段按签名版本区分：
SigV4 只豁免 `x-amz-signature`，SigV2 还会豁免 `AWSAccessKeyId` 和
`Signature`。

签名验证和 condition 检查并不意味着上传已被授权。key 前缀、存储类别、ACL，
以及 policy 没有表达的任何应用层限制，仍然由应用程序决定。

## 错误

Sentinel error 在 `errors.go` 中导出，包括：

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
- `ErrFormFieldNotInPolicy`

请使用 `errors.Is(err, awsverify.ErrSignatureMismatch)`，不要匹配错误字符串。

## 测试

测试套件分为四层，从最快到最完整：

- **单元测试**：使用官方 AWS
  [SigV4 test suite](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-test-suite.html)
  (`testdata/aws-sigv4-test-suite.json`)、手工构造向量、错误分类
  (`TestErrorTaxonomy` 把每个 sentinel error 映射到真实触发路径)、`-race`
  下的并发使用，以及 canonicalization、streaming framing 和 POST policy
  condition 的边界行为。
- **互操作测试** (`interop/`，独立 module)：使用三个独立客户端实现
  (aws-sdk-go v1、aws-sdk-go-v2 和 minio-go) 签名请求，再用本包验证它们
  产生的结果。独立签名器之间的一致性加上已记录向量，是证明 canonical
  request 重建与真实客户端一致的核心证据。套件还固定了已记录的客户端分歧，
  防止行为变化被静默放过。
- **Live 测试**：只有在配置了 S3 兼容服务时才会运行。它们用本包签名，然后
  让真实服务接受或拒绝请求；验证代理则测试反方向：真实客户端的请求在到达
  服务前先由本包验证。

  ```sh
  AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
  AWSSIGVERIFY_LIVE_ACCESS_KEY=... \
  AWSSIGVERIFY_LIVE_SECRET_KEY=... \
  AWSSIGVERIFY_LIVE_WRITE=1 go test -race ./...
  
  cd interop && AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
  AWSSIGVERIFY_LIVE_ACCESS_KEY=... AWSSIGVERIFY_LIVE_SECRET_KEY=... \
  go test -run TestLiveProxyInterop
  ```

- **Fuzz 目标**：覆盖 streaming framer 和 trailer parser
  (`FuzzChunkedReader`、`FuzzTrailerBlock`)。种子语料在 `testdata/fuzz`；
  fuzzer 发现的有趣输入也会成为回归测试。

  ```sh
  go test -fuzz=FuzzChunkedReader -fuzztime=60s ./...
  ```

CI 会在每次 push 时用 `-race` 和 `go vet` 运行单元与互操作套件，并执行一次
短 fuzz 冒烟。

## 安全说明

- 凭据查找只会在语法校验通过后发生。
- 签名比较使用 `crypto/subtle`。
- 重复的签名、credential、日期、有效期、signed header 和 security token 字段
  会被拒绝，而不是静默选择第一个值。
- 已配置的临时凭据必须携带相同的 session token。
- `ChunkedReader` 会限制 chunk header 大小和 chunk 大小。
- verifier 不会读取普通请求体。
- 已验证签名不覆盖请求体字节。请使用 `NewPayloadHashReader`，或者自行按
  `Result.PayloadHash` 对请求体计算哈希。
- 预签名请求必须携带 `X-Amz-Expires`；没有默认有效期。
- SigV4 请求只会按 `VerifyOptions` 指定的 scope 验证。
- POST policy condition 在文档通过认证后检查；无法评估的 condition 会报错，
  而不是放行。
- 临时凭据可以用 `Credentials.SessionToken` 表示。你的凭据存储应验证该
  token 以及凭据的过期时间。

## 兼容性

SigV4 遵循公开的 AWS Signature Version 4 流程。对 S3，路径完全按线上到达
形态 canonicalize，因此 `%2F` 仍然是一个路径段，点号段也不会移除。对其他
服务，点号段会移除并合并重复斜杠，这正是 AWS 测试套件中的 `get-slashes`
向量 (`//example//` 变成 `/example/`) 要求的行为。

SigV2 把转义后的请求路径，而不是解码后的路径，放入 canonicalized resource，
遵循 “HTTP-Request-URI up to the query string” 规则。子资源白名单是 AWS
子资源列表和 MinIO 签名列表的并集，因此 `?retention`、`?legal-hold`、
`?encryption`、`?select` 和 `?select-type` 会与这些实现中的处理方式完全一致。

预签名 SigV4 请求必须携带 MinIO 视为必需的全部六个参数：`X-Amz-Algorithm`、
`X-Amz-Credential`、`X-Amz-Date`、`X-Amz-SignedHeaders`、`X-Amz-Expires` 和
`X-Amz-Signature`。

分块流的 framing 会严格检查：chunk header 和 `x-amz-trailer-signature` 行
必须以 CRLF 结束，chunk size 只按裸十六进制数字解析，因此 `+5` 和 `0x5`
会被拒绝。trailer 块内的 trailer 行按线上原样参与哈希，所以客户端发送的单
LF 结束符也可以通过验证；如果签名覆盖的 framing 与线上字节不同，则不会通过。

每种签名类型的测试依据见 [docs/VERIFICATION.md](docs/VERIFICATION.md)。
`interop/` 是第二个 module，它使用两个独立实现签名：AWS 官方 signer
(aws-sdk-go) 和 minio-go 的 signer，然后在这里验证结果。
`live_minio_test.go` 更进一步，通过 HTTP 驱动运行中的 S3 兼容服务，并记录了
该服务与 AWS 规则不同的两处：它会把编码后的 `%2F` canonicalize 成分隔符；
它也会保存从未发送终止块的 chunk 流。本库本身没有任何第三方依赖。

SigV2 为旧版 S3 客户端保留。AWS 已经弃用 Signature Version 2，新的集成应
优先使用 SigV4。

## 运行测试

```sh
go test ./...                       # 官方向量、离线向量、单元测试
go test -run FuzzChunkedReader -fuzz FuzzChunkedReader -fuzztime=90s .
cd interop && go test ./...         # 与两个独立签名器的差分测试

# live 测试；未通过环境变量指向服务时会跳过
AWSSIGVERIFY_LIVE_ENDPOINT=http://host:port \
AWSSIGVERIFY_LIVE_ACCESS_KEY=... AWSSIGVERIFY_LIVE_SECRET_KEY=... \
AWSSIGVERIFY_LIVE_WRITE=1 go test -run TestLive .
```

`interop` 是第二个 module，因此主库保持无依赖：它会用 AWS 官方 signer
(aws-sdk-go v1.55.8) 和 minio-go 签名，然后用本包验证两者。
`AWSSIGVERIFY_LIVE_WRITE=1` 会让 live 测试创建一个临时 bucket，并在进程结束时
删除；没有该变量时只会发送读取请求。`-race` 需要 C 工具链，因此在 CI 中
运行，而不是要求每台开发机都具备。

## 许可证

Apache License 2.0。参见 [LICENSE](LICENSE)。
