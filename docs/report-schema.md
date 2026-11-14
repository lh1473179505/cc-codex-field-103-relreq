# 报告 schema

| 字段 | 类型 | 含义 |
|---|---|---|
| input | string | exchange 路径，与 `--exchange` 一致 |
| policy | string | `--policy` 路径 |
| decision | string | `ok` 或 `reject` |
| reason_codes | string[] | 成功时为空数组；失败时去重并保留首次出现顺序 |
| labels | string[] | 本轮涉及的**响应**签名标签 |

`reason_codes` 使用这些值：`missing_signature`、`unknown_keyid`、`alg_not_allowed`、`bad_signature`、`expired`、`not_yet_valid`、`missing_created`、`missing_component`、`content_digest_mismatch`、`tag_mismatch`、`forbidden_component`、`duplicate_query_param`、`bad_query`、`bad_path`、`unsupported_param`、`query_param_name`、`related_request_missing`、`related_request_invalid`、`req_without_request`。
