# verify / sign 规则

本仓库给请求-响应成对快照做 RFC 9421 的响应签名，并用 `related-request` 绑回请求上已经存在的那个签名。Content-Digest 只认 RFC 9530 的 `sha-256`。只处理 JSON 快照，不发真实 HTTP。算法只认 `hmac-sha256`（标准库 `hmac` + `hashlib`）。密钥在 `fixtures/keys.json`，32 字节十六进制。时间一律用快照里的 `now`，不要读系统时钟。

一份 exchange 包含：

- `request`：完整的请求快照，字段与请求签名子集相同（`method`、`scheme`、`authority`、`path`、`query`、`headers`、`body`、`now`）。`query` 不含前导 `?`。
- `status`：响应状态码，整数。
- `headers`：响应头，`[name, value]` 数组。
- `body`：响应正文，缺省为空字符串。
- `now`：核验/签发这条响应时用的 Unix 秒。

Structured Field 序列化规则、签名基础串的行格式、派生分量取值、HMAC 计算，与本仓库 `docs/sfv-and-base.md` 一致。响应上还可以覆盖这些分量：

- `@status`：状态码的十进制字符串，例如 `200`。
- 带 `;req` 的分量：从绑定的 `request` 上取值，而不是从响应上取。本子集允许 `;req` 出现在 `@method`、`@authority`、`@scheme`、`@path`、`@query`、`@query-param`、`@target-uri` 以及请求头字段名上。`;req` 之外若再带本子集未说明的参数，记 `unsupported_param`。没有请求可绑时记 `req_without_request`。
- 响应头字段（如 `content-digest`）：从响应头里取。

禁止覆盖 `signature`、`signature-input` 或 `@signature-params`。

## related-request

响应签名的列表参数里若出现 `related-request`，其值是请求 `Signature-Input` 上的一个标签。策略 `require_related_request` 为真时，缺少该参数则 `related_request_missing`。

核对 `related-request` 时，必须先用策略里的 `request_policy`（字段含义与请求验签相同：`allowed_algs`、`allowed_keyids`、`max_clock_skew`、`required_components`、`required_tag`、`require_content_digest`）把请求上那个标签验一遍。找不到该标签，或请求签名本身不能通过，都记 `related_request_invalid`。这个检查和响应签名本身的检查是分开的：请求绑定失败时，仍要尝试核对该条响应签名（用请求快照提供 `;req` 分量），并把所有原因都收进 `reason_codes`。

签发时，`policy.sign` 必须带 `related-request`，并按 `created`、`keyid`、`alg`、`expires`、`nonce`、`tag`、`related-request` 的顺序写进 `@signature-params`（缺省的项跳过）。

## 策略中与响应有关的项

- `required_components`：响应签名必须覆盖的分量。可用字符串，或 `{"name":"@method","params":{"req":true}}` 这种带参数的对象。
- `require_content_digest`：当响应 `body` 非空时，响应必须带正确的 `content-digest`（`sha-256` 为正文 UTF-8 的 SHA-256），并且该头必须被覆盖。否则 `content_digest_mismatch` 或 `missing_component`。
- `required_tag`：若给出，比对的是**响应**签名的 `tag`。
- 时钟：`created` / `expires` 相对的是这条 exchange 的 `now`（不是请求里的 `now`）。请求绑定验签则用请求快照自己的 `now`。

## 命令

`verify` 核验响应上出现的**所有**签名标签。全部通过且绑定检查也通过则为 `ok`。任一原因都使 `decision` 为 `reject`，`reason_codes` 去重并保留首次出现顺序。

`sign` 按 `policy.sign` 给响应补一个签名：`label`、`keyid`、`components`、`created`，以及可选的 `expires`、`nonce`、`tag`、必填的 `related-request`。`ensure_content_digest` 为真时先重写响应 `content-digest`。输出的 exchange 保留原来的 `request`，只更新响应头。不要把内部加载字段写进 output。

## 退出码

- 成功：退出 0，报告 `decision` 为 `ok`（`sign` 还要写出带签名的 exchange）。
- 业务规则失败：退出 1，`decision` 为 `reject`，报告仍要写（`sign` 可以不写 output）。
- 快照、密钥或策略无法解析，或 Signature 头不是合法的本子集 SFV：退出 2。此时可以不写报告。
