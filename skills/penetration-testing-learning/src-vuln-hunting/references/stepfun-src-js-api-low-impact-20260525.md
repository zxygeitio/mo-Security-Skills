# 阶跃星辰/合作伙伴 SRC 前端 JS 与 API 低影响验证记录

适用范围：`*.stepfun.com`、`*.basemind.com`、`*.cashcat.com.cn`、`*.cashcat.cn`、`*.finstep.cn`、合作伙伴 WordPress/SPA/AI 平台类资产。用于未来继续挖掘时快速继承已验证边界，避免把公开接口、SPA fallback、登录前置接口或 WordPress 默认公开面包装成报告。

## 范围与资产优先级

核心系统：
- `www.stepfun.com`
- `platform.stepfun.com`
- `sado-platform.basemind.com`
- `spacer-label.basemind.com`
- `galaxy-bank.basemind.com`

一般/边缘系统：
- `*.stepfun.com`
- `*.basemind.com`
- `*.kmood.cn`
- `*.zyql.com`
- `*.cashcat.com.cn`
- `*.cashcat.cn`
- `*.finstep.cn`
- `@.timesinging.com` 仅主域名

不要把工商/ICP备案额外关联资产默认纳入范围；VPN/第三方供应商类系统提交对应厂商 SRC。

## platform.stepfun.com：OpenAPI/Passport/Dashboard protobuf 边界

前端 JS 可提取 OpenAPI / Passport / Dashboard protobuf 服务定义。低影响验证过的接口：

- `/api/step.openapi.devcenter.Dashboard/Ping`
- `/api/step.openapi.devcenter.Dashboard/UserInfo`
- `/api/step.openapi.devcenter.Dashboard/GetRateLimitRules`
- `/api/step.openapi.devcenter.Dashboard/ListAccessKeys`
- `/api/step.openapi.devcenter.Dashboard/GetAccessKey`
- `/passport/proto.api.passport.v1.GlobalPassportService/Ping`

结论：上述敏感 Dashboard/AccessKey/用户接口在无认证时返回 `401 auth failed: token is missing` 或 `403`。除非后续拿到授权账号态或发现可用 token/key，不要把 JS 中服务定义本身作为漏洞。

后续高收益方向：
1. 授权账号态 A/B 测试 AccessKey、rate-limit、项目/组织资源 IDOR。
2. 检查创建/更新 Key 是否存在 `quota`、`user_id`、`status`、`rate_limit_*` 批量赋值。
3. 若发现完整 API Key，必须实际调用 `/v1/models` 或最小 `/v1/chat/completions` 证明可用。

## cashcat / xcs.cashcat.cn：Next.js API 枚举边界

已分析 `www.cashcat.cn` Next.js bundle，提取到大量 `/api/*`，公开资讯/行情接口可未授权访问，但多为公开业务数据：

公开低价值接口示例：
- `GetEventsBySubject`
- `GetFeedCards`
- `GetGDP`
- `GetHotEvents`
- `GetModels`
- `GetSubjectByID`（如 `subject_id=16807461400002` 返回比亚迪等公开证券信息）

重点验证过但未形成实质漏洞的接口：
- `/api/GetUserAuthInfo`
- `/api/GetSessionList`
- `/api/GetChatMessages`
- `/api/GetDeepResearchTaskDetail`
- `/api/GetOrderDetail`
- `/api/GetOrderPayParameter`
- `/api/GetSignInQRCode`
- `/api/GetQRCodeSignInStatus`
- `/api/GetWxSignature`
- `/api/GetWxUrlLink`
- `/api/GetWxacode`

常见响应：`system error`、`bad request`、`500`、空 body 或仅公开内容。没有用户会话、订单、支付参数、深研任务内容前，不建议提交。

### SPA fallback 排除
`xcs.cashcat.cn` 的以下路径可能看似返回 200：
- `/v3/api-docs`
- `/swagger-ui.html`
- 随机不存在路径

需要对比 body hash/长度；已验证与随机路径一致，是 SPA fallback，不是 Swagger 暴露。

### CORS 边界
对合法 Origin `https://www.cashcat.cn` 可返回 `Access-Control-Allow-Credentials:true`，但对 `https://evil.example` / `null` 不反射 ACAO。不要报 CORS。

后续高收益方向：
1. 从真实前端交互或授权态中获得 `session_id`、`order_id`、deep research task id，再做 A/B IDOR。
2. 检查微信登录二维码状态更新接口是否存在可控 `scene` / `ticket` 未授权绑定，但必须证明能登录或绑定账号，单纯 `status` 变化不够。
3. 关注订单支付参数接口是否能通过枚举真实订单号返回支付参数；没有真实订单号时不要过报。

## spacer-label.basemind.com：Skylab/标注平台 API 边界

Vite 动态 chunk 中可提取：
- `/api/skylab/v1/user/*`
- `/api/skylab/v1/project/*`
- `/api/skylab/v1/acceptance-task/*`
- `/api/skylab/v1/acceptance-queue/*`
- `/api/skylab/v1/visible-import/*`
- `/api/mir/v1/resources/*`
- `/api/mir/v1/label-items/*`

已验证业务项目、验收、导入、资源、标注相关接口均返回：
- `401 AUTHENTICATION_ERROR:无验证信息`
- 或 `31241 请求被拒绝`

低价值公开/登录前置接口：
- `GET /api/skylab/v1/user/version` 返回 `v2.3.1.0313`，仅版本信息。
- `POST /api/skylab/v1/user/tenant_verify` 可验证企业码 `stepfun`，返回 `tenant_id=1100`、`tenant_name=阶跃星辰`、`login_type=sso,email`。
- `POST /api/skylab/v1/user/generate_key` 对任意邮箱返回一次性 `token` 和 `public_key`。这看起来是邮箱验证码登录前置加密材料；未证明可绕过登录、获取验证码或访问业务数据前，不建议提交。

后续高收益方向：
1. 授权态 A/B 测试 project、acceptance、visible-import、label-items 的 IDOR。
2. 对 `presign_upload` / `presign_download` 只在授权态或可证明未授权返回可用签名 URL 时报告。
3. `generate_key` 方向必须证明后续 `send_captcha`、`login` 或 token 加密流程可被滥用，否则仅作为登录流程信息，不报。

## sado-platform.basemind.com

常见敏感路径如：
- `/.git/HEAD`
- `/.env`
- `/config.json`

已出现同一 SPA 壳/非敏感响应。必须用随机路径 hash 对照排除，不要将 200 当作泄露。

## timesinging WordPress 边缘资产

已验证现象：
- `/wp-json/wp/v2/users` 或 oEmbed 可暴露 `admin` 作者。
- `?author=1` 跳转 `/author/admin/`。
- `/xmlrpc.php` 开启 `system.listMethods` / `system.multicall`。
- `/wp-json/wp/v2/media?per_page=5` 可读公开附件列表。

这些一般属于 WordPress 默认公开作者/REST/XML-RPC 面。没有弱口令、认证绕过、任意文件、插件 RCE、未授权后台数据或敏感附件前，不建议提交。

## 继续挖掘时的验证纪律

1. 只输出验证通过的实质漏洞；无实质证据时明确“不建议提交”。
2. 前端 JS/API 枚举必须进入接口级低影响验证：状态码、响应体关键字段、随机路径/随机 ID 对照、认证边界对照。
3. 对 SPA/Vite/Next.js 资产，任意路径 200 必须与随机不存在路径做 hash/长度对照。
4. CORS 只在任意 Origin 反射且能读取敏感数据，或有明确凭证窃取 PoC 时报告；合法 Origin + Credentials 不算漏洞。
5. 登录前置接口（tenant_verify、generate_key、version、public_key、captcha 配置）只有在能推进到未授权登录、验证码滥用、账号枚举稳定差异或业务数据访问时才提交。
6. WordPress 默认作者枚举、XML-RPC 开启、公开 media 列表默认不提交；必须找到插件/主题漏洞、敏感附件或认证绕过。
