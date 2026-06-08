# 地平线(Horizon Robotics) SRC 测试记录 (2026-05-28)

## 目标范围
- *.horizon.ai, *.horizon.cc, *.horizon.auto
- 核心资产: sso.iam.horizon.auto (SSO), mail.horizon.auto (邮箱)
- 边缘资产: developer.horizon.auto (开发者社区), *test.horizon.auto
- 开发者社区: developer.horizon.auto
- 禁测: call-center.horizon.auto, c-gitlab.horizon.ai (仅接受直接危害漏洞)

## 资产发现 (42子域, 10+存活)
| 子域 | 类型 | 技术栈 | IP段 |
|------|------|--------|------|
| sso.iam.horizon.auto | 核心 | Authing SSO + Express.js | 42.62.85.20 |
| mail.horizon.auto | 核心 | Exchange OWA 15.1.2308.27 + feilian-agw | 42.62.85.54 |
| developer.horizon.auto | 边缘 | Nuxt.js SSR + nginx + 阿里云WAF(acw_tc) | 42.62.85.43 |
| oe.horizon.auto | 常规 | Vue.js SPA + Tengine + 阿里CDN | - |
| chat.oe.horizon.auto | 常规 | Open WebUI 0.7.2 + nginx + Envoy | - |
| doc.oe.horizon.auto | 常规 | Tengine + 阿里CDN | - |
| developer.d-robotics.cc | - | Next.js + acw_tc (地瓜机器人) | - |
| autodiscover.horizon.auto | - | feilian-agw (Exchange autodiscover) | 42.62.85.54 |
| cn.horizon.cc | - | nginx → www.horizon.auto | - |
| www.horizon.auto | 常规 | Tengine (多IP CDN) | 182.140.x.x |

## 已确认漏洞

### 1. SSO CORS反射型 (高危/核心)
sso.iam.horizon.auto 全站反射任意Origin + Credentials:true, 影响所有端点含OIDC.
- 验证: `curl -sk -D- "https://sso.iam.horizon.auto/login?app_id=67c91388afda6cf22fdbd93e" -H "Origin: https://evil.com"`
- 受影响: /api/v2/*, /oidc/me, /oidc/token/introspection

### 2. OIDC配置泄露 (中危/核心)
- /.well-known/openid-configuration 和 /oidc/.well-known/openid-configuration 完整暴露
- 泄露: grant_types(password!), scopes(含phone/email/address/birthdate/role), claims, 所有端点
- JWKS公钥: kid=ObKeCDUW_S_ZrPApQzMtQ2IZ5IH7rTfrGJx5OoL4VsU
- password grant启用但需client_secret, introspection端点需client认证

### 3. Open WebUI配置泄露 (低危/边缘)
chat.oe.horizon.auto /api/config 返回完整系统配置(版本/OAuth/功能开关) + CORS:*+creds

## 关键技术指纹

### Authing SSO 指纹
- 登录重定向: `/login?app_id=<hex_id>`
- 页面标题: "Authing", `window.__guardVersion__ = 'v2'`
- 静态资源: `files.iam.horizon.auto/authing-fe-user-portal/`
- OIDC发现: `/oidc/.well-known/openid-configuration`
- 错误格式: `{"uniqueId":"uuid","code":2224,"statusCode":499,"apiCode":2224,"message":"用户池不存在"}`
- 管理API: /api/v2/{applications,roles,groups,resources,userpools}
- 认证端点: Express.js, X-Powered-By: Express

### Open WebUI 指纹
- 配置端点: /api/config (无需认证, 返回JSON)
- 版本泄露: `"version":"0.7.2"`, `"name":"Open WebUI"`
- OAuth信息: `"oauth":{"providers":{"oidc":"..."}}`
- 功能开关: enable_signup, enable_login_form, enable_api_keys, enable_websocket
- CORS: `access-control-allow-origin: *` + `access-control-credentials: true`
- SPA fallback: 大部分/api/*返回HTML壳, 仅/api/config返回JSON

### Exchange OWA 指纹
- feilian-agw (飞连零信任网关) + Microsoft-IIS/10.0
- 版本: x-owa-version: 15.1.2308.27 (Exchange 2016 CU23)
- X-FEServer: EXCHANGE004
- /autodiscover/autodiscover.xml 返回JSON: {"Protocol":"","Url":"https://mail.horizon.auto/api"}
- /powershell/ 返回200但Content-Length: 0 (AGW空响应, 非真实PowerShell)

## 测试教训
- delegate_task对42子域大规模侦察超时(3个子任务各900s), 应改用主Agent顺序执行
- subfinder对horizon.auto仅发现5个子域, crt.sh和DNS brute force补充了大量结果
- developer.horizon.auto的CORS:* 仅在HTML响应头中, API端点不返回CORS头
- chat.oe.horizon.auto的200状态码不等于API可用, 大部分是SPA fallback

## 报告位置
/tmp/vuln_reports/horizon/report-sso-cors.txt
/tmp/vuln_reports/horizon/report-sso-oidc-cors.txt
/tmp/vuln_reports/horizon/report-openwebui-config.txt
