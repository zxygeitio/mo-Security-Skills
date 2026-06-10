# AI 网关 API Key 明文泄露与配额字段批量赋值

适用场景：OpenAI-compatible API 网关、AI 会员拼车平台、模型代理站，用户登录后可创建/管理 API Key，并通过 `/v1/models`、`/v1/chat/completions` 等接口消费模型资源。

## 高价值测试点

1. API Key 查询接口是否反复返回完整明文 Key

常见接口：
- `GET /api/v1/keys?page=1&page_size=5`
- `GET /api/v1/keys/{id}`
- `GET /api/v1/usage?page=1&page_size=1` 关联对象中的 `api_key.key`

判断成立：响应中出现完整 `sk-...`，且不是 `sk-****abcd` 这类脱敏值。

危害验证：拿返回的 Key 直接调用模型接口：

```bash
curl -sk "https://target/v1/models" -H "Authorization: Bearer sk-xxxx"
```

若返回 200 和模型列表，说明泄露 Key 可直接使用。

2. 创建/更新 Key 时是否存在批量赋值，允许普通用户提交配额/限流字段

常见接口：
- `POST /api/v1/keys`
- `PUT /api/v1/keys/{id}`
- `PATCH /api/v1/keys/{id}`

重点参数：
- `quota`
- `rate_limit_1d`
- `rate_limit_5h`
- `rate_limit_7d`
- `user_id`
- `status`
- `expires_at`
- `group_id`
- `usage_*`

低影响验证请求：

```bash
curl -sk "https://target/api/v1/keys" -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d '{"name":"quota-abuse-proof","group_id":3,"quota":999999999999,"rate_limit_1d":999999999999}'
```

判断成立：后端返回 200，响应/再次读取中保留 `quota=999999999999` 或 `rate_limit_1d=999999999999`。

实质危害验证：使用新建 Key 调用模型接口：

```bash
curl -sk "https://target/v1/chat/completions" -X POST -H "Authorization: Bearer sk-新建Key" -H "Content-Type: application/json" -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"reply exactly OK"}],"max_tokens":5,"stream":false}'
```

若返回 200 且有 `choices` / `usage`，说明异常配额 Key 可真实消耗模型资源。

测试完成后立即删除临时 Key：

```bash
curl -sk "https://target/api/v1/keys/测试KeyID" -X DELETE -H "Authorization: Bearer TOKEN"
```

## 定级建议

- 仅自己的 Key 明文反复可查：中危。若可越权读取他人 Key，升高危/严重。
- 普通用户可设置超大 `quota` / `rate_limit_*`，且新 Key 可真实调用模型：高危。原因是破坏套餐/限流/成本控制边界。
- 若还能跨 `group_id` 绑定更高套餐组，或无订阅用户可创建高权益 Key，可升严重。

## 报告要点

证据链必须闭环：
1. 普通用户登录。
2. 创建或查询 Key 的完整 HTTP 请求。
3. 响应中的敏感字段，仅在报告中脱敏展示 Key。
4. 使用 Key 调用 `/v1/models` 或 `/v1/chat/completions` 成功。
5. 若创建了临时 Key，展示删除成功，避免遗留风险。

## 修复建议

1. 普通用户创建/更新 Key 的 DTO 使用字段白名单；与 Admin DTO 分离。
2. 后端忽略普通用户提交的 `quota`、`rate_limit_*`、`usage_*`、`status`、`user_id`、`expires_at` 等敏感字段。
3. `quota` / `rate_limit_*` 必须由服务端根据套餐、订阅、管理员策略计算，并做上下限校验。
4. Key 创建后只展示一次；查询接口只返回脱敏 Key。
5. 数据库中尽量只保存 Key hash/digest，不保存可反复读取的明文。
6. 扫描历史异常 Key：负数 quota、超大 quota、超大 rate_limit、跨组绑定等。
