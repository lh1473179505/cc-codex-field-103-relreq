# Structured Fields 与签名基础串

本子集使用 RFC 8941 的字典、内列表、token、字符串、整数、字节序列和布尔参数。仓库里的 `relreq.sfv` 已经能解析和写出这一部分，请复用，不要另引第三方 RFC 8941 库。

`Signature-Input` 的值是内列表：被覆盖分量按列出的顺序排列，列表参数写在 `)` 后面。`Signature` 的值是字节序列。同一标签必须在两个头里成对出现，否则视为解析失败（退出 2）。

派生分量 `@method`、`@authority`、`@scheme`、`@path`、`@query`、`@query-param`、`@target-uri`、`@status` 写成带引号的字符串。普通字段名若本身是合法 token（如 `content-digest`），写成 token。`@query-param` 必须带字符串参数 `name`。

签名基础串每一行是 `分量标识: 值`，行与行之间用 `\n` 连接，最后一行之后不要再加换行。最后一行固定为：

```
"@signature-params": (...内列表与参数...)
```

该内列表必须与 `Signature-Input` 里该标签的内列表字节级一致，参数顺序也要一致。

取值规则：

- `@method`：大写方法名。
- `@authority`：小写的 `authority`。
- `@scheme`：小写。
- `@path`：必须以 `/` 开头，否则 `bad_path`。
- `@query`：在原始查询串前加 `?`。查询串为空时值为 `?`。若快照里的 `query` 已带 `?`，视为 `bad_query`。
- `@query-param`：按 `&` 切开，名称与值都做百分号解码（`+` 按 `%20` 处理）。同一 `name` 出现多次则 `duplicate_query_param`；一次都没有则 `missing_component`。
- `@target-uri`：`scheme://authority`（均为小写）+ `path`，查询串非空时再拼 `?` 和原始查询串。
- `@status`：整数状态码的十进制写法。
- 普通头字段：名字不区分大小写，多个值用 `, ` 拼接。缺头则 `missing_component`。

`alg` 必须是 `hmac-sha256`，否则 `alg_not_allowed`。`keyid` 必须能在密钥表里找到，且落在 `allowed_keyids`（若给出）中，否则 `unknown_keyid`。签名是 `HMAC-SHA256(key, base)`，对不上则 `bad_signature`。比较时用固定时间比较。

时钟：`created` 必须是整数；若 `created > now + max_clock_skew`，`not_yet_valid`。若有 `expires` 且 `expires < now - max_clock_skew`，`expired`。
