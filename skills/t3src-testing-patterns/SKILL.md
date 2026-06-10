---
name: t3src-testing-patterns
description: "T3出行SRC(t3go.cn)测试模式 — Kong网关+腾讯云WAF+OAuth+AES攻击链+蓝凌OA+用户枚举"
tags: [src, t3go, kong, tencent-waf, oauth, landray, cors]
---

# T3出行SRC Testing Patterns

## Target Architecture
- **API Gateway**: Kong (x-kong-upstream-latency headers) — t3go.cn assets
- **WAF**: 腾讯云WAF (stgw) — HTTP 218 for blocked requests
- **Backend**: Spring Boot (JSON: timestamp/status/error/message/path)
- **Auth**: OAuth2 password grant + AES-ECB encrypted passwords
- **Service Discovery**: Consul (/health → "hello consul")
- **jx-ams.cn Infrastructure** (separate from t3go.cn WAF):
  - Proxy: Envoy (x-envoy-upstream-service-time header) + nginx
  - Frontend: Vue 2.6 SPA (cop) / Vue 3.3 (cop-risk) + Element UI/Plus
  - Auth: 钉钉扫码 + 企业账号登录, TOKEN-based API auth
  - API auth codes: 12000=TOKEN失效, 1006=用户未登录(cop-risk), 1000=参数错误, 5000=服务异常
  - SSO endpoint: /api/sys/sys/dingTalk/auth (requires authCode param)
  - File storage: cpfile.yqcx.faw.cn / cpfile-test.yqcx.faw.cn (一汽启明 OpenResty)

## WAF IP Blocking Pitfall
After ~50+ requests to t3go.cn assets, 腾讯云WAF blocks your IP with HTTP 218 on ALL paths.
- jx-ams.cn is NOT behind t3go.cn WAF (uses Envoy, separate infra) — continue testing there
- To resume t3go.cn testing: rotate IP (VPN/proxy) or wait ~30 minutes (block is temporary)
- Budget requests: ~25 requests per domain before WAF triggers
- Key signals: previously-working endpoints suddenly return 218
- User-Agent rotation does NOT bypass IP block (tested: iPhone/Android/T3App/okhttp all 218)
- After unblock, gateway routes return 4100 (auth) or "no Route matched" — NOT 218

## Gateway Active Kong Routes (verified 2026-06-08)
Routes returning 4100 (registered, need OAuth token):
  gateway: mall-app-api, strategy-gateway-api, driver-core-app-api, solution-carriage,
    pay-center-api, gis-map-api, driver-app-api
  passenger: mall-app-api, solution-passenger-api, solution-trip-general, common-app-api,
    cua-user-api-c, strategy-gateway-api, enterprise-app-api, gis-map-api,
    driver-app-api, strategy-config, pay-center-api
Routes returning "no Route matched" (no backend registered):
  gateway: /, solution-passenger-api, solution-trip-general, common-app-api,
    enterprise-app-api, strategy-config, cua-user-api-c
  passenger: /, driver-core-app-api
Routes returning 2017 "没有权限" (global auth filter, no per-path routing):
  api-driver-rpa.t3go.cn, api-rpa-external.t3go.cn
Gateway CORS: ACAO=* (static wildcard), rate limit 180-200/sec (varies by domain)
OAuth endpoint: /org-manager-boss/api/auth/getKey (intermittent, returns AES key)
OAuth endpoint: /org-manager-boss/api/auth/oauth/password (requires random from getKey)
  - getKey returns 500 on ALL environments as of 2026-06-08 (service degraded)
  - Recovery check: `curl -sk 'https://gateway.t3go.cn/org-manager-boss/api/auth/getKey'`
  - If returns JSON with `data` field containing AES key, flow is restored
OAuth client: org-manager:HwEACu8r2jngK6OM (from vip.t3go.cn JS, still valid 2026-06-08)
  - 4100 = user/pass wrong (client OK), 4114 = client credentials wrong

## Scope (2026-06)
Core (P0): pay/passenger/gateway(specific APIs)/openability/integrated/gis-api/vehicle.t3go.cn
Edge (P2): *.jx-ams.cn, metric*/dingxiang/ticloud/waf/gtm, upload/download, non-prod
Normal: ai.t3go.cn, other *.t3go.cn
Excluded: *obs*.t3go.cn, hwupload/download, cc-side-webapp-api, 优惠券<5元

## Subdomains (2026-06-05 enum: 51 t3go.cn + 5 jx-ams.cn)

### t3go.cn (51 subs)
Core: gateway, passenger, pay, openability, integrated, gis-api, vehicle, vip
Interesting: enterprise, oa, security(SRC portal), llm-app-store, bi, iov-api, api-driver-rpa, api-rpa-external, cube
Edge: dingxiang, metrics, waf, gtm, upload, download, asr-t3-ticloud, resource-manager-t3-ticloud
Mail/Infra: mail(alimail), imap, pop3, smtp, ntp, socket
Static/CDN: static(openresty), tos, s, l, m, short, app, wxpro
Non-prod: gateway-test2, gateway-pre, gateway-dev2, autopilot-dev, gateway-pst2
Other: tracker, special, special-az1, zyjf, www

### jx-ams.cn (5 subs)
- cop.jx-ams.cn — 上海嘉行车辆管理系统 (prod, Envoy+nginx+Spring Boot)
- dev-cop.jx-ams.cn — 同上开发环境 (non-prod, same API surface)
- cop-risk.jx-ams.cn — 运营风控系统 (Vue 3 + Element Plus, CORS limited to cop.jx-ams.cn)
- web.jx-ams.cn — 上海嘉行 (Tengine, corporate site)
- www.jx-ams.cn — same as web

### FAW yqcx.faw.cn (leaked in JS)
cpfile.yqcx.faw.cn / cpfile-test.yqcx.faw.cn — file storage (OpenResty 401)
images.yqcx.faw.cn / dev-images / pre-images — image servers (403/503)
vm-ops.yqcx.faw.cn — default nginx page (200)
dev-vm-ops / pre-vm-ops — 503
pbi.yqcx.faw.cn / pre-pbi — Power BI (timeout/503)
vom.yqcx.faw.cn — Vue SPA (200)

## cop.jx-ams.cn API Endpoints

### Unauthenticated
| Endpoint | Behavior |
|---|---|
| /api/sys/ftp/file/signDownlaodUrl?fileKey=X | 302 redirect to cpfile-test.yqcx.faw.cn/X?e=<ts>&token=<hmac> |
| /api/sys/sys/dingTalk/auth | Requires authCode, returns 5000 for any input |
| / (root) | SPA redirect to /login |

### TOKEN-protected (code 12000)
/api/sys/{user/list, config, menu, dept, role, dict, log, online, session}
/api/{workflow/, finance/}

### Frontend JS files
- Login: /static/js/login.dd2146d7.js (contains DingTalk SSO + internal URLs)
- Main: /static/js/index.0b8e6486.js (prod) / index.da0e6960.js (dev)
- Vendors: /static/js/vendors~app~index.b0ee080c.js

## Key Findings

### 1. vip.t3go.cn OAuth Credential Leak (Medium)
JS file `app.d03540df.js` hardcodes OAuth client: `org-manager:HwEACu8r2jngK6OM`
- getKey endpoint returns AES-128-ECB key (16-digit numeric)
- Password encryption: AES-ECB + PKCS7 + Base64
- errCode 4149 (valid user) vs 4100 (invalid user) = user enumeration
- errCode 4115 (valid mobile) vs 4106 (invalid mobile) = mobile enumeration
- No rate limiting on password endpoint

### 2. oa.jx-ams.cn CORS Origin Reflection (High)
蓝凌OA V15 reflects ANY Origin with ACAC=true
- Steal SESSION cookie + X-Auth-Token
- Unauthenticated endpoint: doingCirculation
- Login page leaks: internal URLs, WeChat corp_id/agentid

### 3. gis-api.t3go.cn CORS (Low)
ACAO=* + ACAC=true (Kong default), no sensitive data endpoints found

### 7. openability.t3go.cn /health/* Tech Stack Disclosure (Low, Core)
CORE asset. 12 unauthenticated health check endpoints leak backend stack:
- /health → {"code":200,"msg":"成功"} (works)
- /health/{redis,mysql,db,consul,kafka,mq,disk,memory,cpu,ready,live,detail}
  → {"code":50001,"message":"server_exception"} (exists but failing)
- All have ACAO=* (static CORS wildcard)
- Leaks: Redis, MySQL, Consul, Kafka, MQ, disk/memory/cpu monitoring
- integrated.t3go.cn also has /health (200) but NO sub-endpoints
- gis-api.t3go.cn /health → "hello consul"
- Reports: /tmp/vuln_reports/t3go/20260605/openability-health-info-leak.txt

### 8. cop.jx-ams.cn DingTalk OAuth Static State (Info, Edge)
Login page iframe exposes OAuth config:
  client_id=dingas4bawefhdn7ixq4, state=xxxxxxxxx (static!)
  redirect_uri=https://cop.jx-ams.cn/api/sys/sys/dingTalk/auth
- Static state = CSRF risk (attacker can pre-craft OAuth callback URL)
- DingTalk challenge page mitigates direct redirect_uri hijack
- oa.jx-ams.cn uses different DingTalk app: dingoambfbga0peamatkde
- WeChat integration on oa: corp_id=wx7b6f5d246b88c3b6, agentid=ww4b1bf0bff6eebd70

## WAF Behavior
- Origin: evil.com → HTTP 218 on some domains
- Referer header → passes through
- actuator/swagger → always 218
- Swagger UI: IP whitelist 403

- User-Agent rotation does NOT bypass IP block (tested: iPhone/Android/T3App/okhttp all return 218)
- VPN/proxy rotation is the only reliable bypass

## Gateway Auth Error Codes
- 4100: "api未授权_03" (needs OAuth token)
- 9999: "用户信息不存在" (client auth passed, no user session)
- 4102: "参数不正确"
- 4114: "client账号或密码错误" (wrong OAuth client)
### 4. cop.jx-ams.cn — Non-Prod Env Public Access (Medium, Edge)
dev-cop.jx-ams.cn is the dev environment, same API surface as prod cop.jx-ams.cn.
- Recently updated (last-modified changes on each visit)
- Same API endpoints, same TOKEN auth
- Reports: /tmp/vuln_reports/t3go/20260605/dev-cop-nonprod-exposure.txt

### 5. cop.jx-ams.cn — JS Internal URL Leakage (Low, Edge)
login.dd2146d7.js hardcodes 7+ internal yqcx.faw.cn URLs + copwiki.jx.cn
- Exposes dev/pre/prod environment separation
- Reports: /tmp/vuln_reports/t3go/20260605/cop-js-info-leak.txt

### 6. cop-risk.jx-ams.cn — Risk Control System Exposed (Low, Edge)
运营风控系统 (Operations Risk Control System)
- Vue 3.3.4 + Element Plus 2.3.7
- CORS: only allows cop.jx-ams.cn origin
- API base: /api, all endpoints return code 1006 (未登录)
- Static assets from cpfile.yqcx.faw.cn

## Second Round Testing (2026-06-08)

### OAuth getKey Service Down (All Environments)
getKey returns 500 "系统异常" on ALL environments:
- gateway.t3go.cn → 500
- gateway-test2.t3go.cn → 500
- gateway-pre.t3go.cn → 500
- gateway-dev2.t3go.cn → empty response
- gateway-pst2.t3go.cn → empty response

Without getKey, cannot obtain AES-128-ECB key for password encryption. OAuth flow is blocked.
OAuth client credentials `org-manager:HwEACu8r2jngK6OM` still valid (returns 4100=user/pass wrong, NOT 4114=client wrong).

**Recovery check**: `curl -sk 'https://gateway.t3go.cn/org-manager-boss/api/auth/getKey'` — if returns JSON with `data` field containing AES key, flow is restored.

### org-manager-boss Partial Degradation
Some endpoints return 500 "系统异常", others return 9999 "用户信息不存在":
- 500: getKey, /api/auth/sms/code, /api/auth/code/image/base
- 9999 (client auth OK, needs user session): /api/boss/common/city/list, /api/boss/common/bank/list, /api/boss/common/previewFile, /api/boss/common/getBusinessVehicle

### cop.jx-ams.cn SPA Catch-All (False Positive Warning)
ALL paths on cop.jx-ams.cn return 200 with 1663B HTML (Vue SPA fallback). This includes:
- /v2/api-docs → SPA HTML (NOT real Swagger)
- /actuator → SPA HTML (NOT real Actuator)
- /swagger-resources → SPA HTML
- /druid → SPA HTML

**Detection**: Compare response sizes. If all paths return same size (~1663B), it's SPA fallback.
**Actual API paths**: Only /api/* paths return JSON responses (12000 TOKEN失效 or 1006 未登录).

### AMAP Key Platform Restriction
vip.t3go.cn HTML exposes AMAP key `b6c2b09a0516da62997aa88e0db75e07`.
REST API test returns `USERKEY_PLAT_NOMATCH` (error 10009) — key is restricted to web JS API platform only.
**Not exploitable** from curl/REST API. Key is properly restricted.
**Test command**: `curl -sk 'https://restapi.amap.com/v3/geocode/geo?address=Beijing&key=KEY'` — USERKEY_PLAT_NOMATCH = restricted.

### metrics.t3go.cn:8663 SensorsData
- POST /sa?project=staff_product → accepts data (SensorsData format)
- GET /sa → 405 Method Not Allowed
- All other paths → 404
- Port 443 → 503 (different service)
- Format: `{"data":[{"distinct_id":"...","type":"track","event":"...","properties":{...}}]}`
- Low value: can only inject fake analytics data

### New Subdomains (2026-06-08)
- vdrtos2.t3go.cn → 403 (OBS)
- obs-t3-admin-public.t3go.cn → 403 (OBS)
- api-driver-rpa.t3go.cn → 200 (Kong, all paths return 2017 "没有权限", global auth filter)
- api-rpa-external.t3go.cn → 200 (Kong, all paths return 2017 "没有权限", global auth filter)

### gateway-dev2/pst2 Empty Response
gateway-dev2.t3go.cn and gateway-pst2.t3go.cn return empty responses (1B) for all paths. These non-prod environments appear to be down or have different WAF rules.

### HTTP Method Testing
passenger.t3go.cn/mall-app-api/ accepts PUT/DELETE/PATCH/OPTIONS (all return 200 with 4100 auth error). Same response for all methods — not exploitable.

### CRLF Injection Blocked
Path-based CRLF injection (`%0d%0aSet-Cookie:%20test=1`) triggers WAF 218 on gateway.t3go.cn.

## vip.t3go.cn — Enterprise Admin Platform ("T3-admin")
Vue.js SPA with 120+ API endpoints (extracted from `js/app.d03540df.js`).
Integrations: DingTalk JS SDK, Lark (飞书) SDK, Feishu SSO SDK, AMAP Maps.
AMAP Key: `b6c2b09a0516da62997aa88e0db75e07` (platform-restricted, not exploitable via REST).

### Key API Endpoints (via gateway.t3go.cn/org-manager-boss/*)
Auth: /api/auth/{getKey, oauth/password, oauth/mobile, sms/code, code/image/base, slider/image/get, forgetPwd/outlogin, outlogin}
Boss: /api/boss/common/{city/list, bank/list, previewFile, getBusinessVehicle, sceneList}
Enterprise: /api/boss/enterprise/{getEnterpriseInfo, query/balance, getOrgRulesByOrgId, refund, logout}
Third-party: /api/boss/company/third/v1/{getToken, getThirdAppInfo, bind, checkStatus}
Fund: /api/boss/fund/supervise/{qryEnterpriseDepository, qryBankNo, qryBusinessObsUrl}
Coupon: /api/boss/coupon/query/companyCouponList

### Response Patterns
- 500 "系统异常" = service degraded (getKey, sms, captcha, forgetPwd)
- 9999 "用户信息不存在" = client auth OK, needs user session (most /api/boss/* endpoints)
- 4100 "用户名或密码错误" = OAuth password endpoint, client OK, wrong credentials
- 4114 "client账号或密码错误" = wrong OAuth client credentials
- 2017 "没有权限" = global auth filter on RPA domains

## SPA Catch-All False Positive Warning
cop.jx-ams.cn and similar Vue SPAs return 200 with identical HTML for ALL paths.
- cop.jx-ams.cn: all paths return 1663B HTML (SPA fallback)
- This includes /v2/api-docs, /actuator, /swagger-resources, /druid — NOT real endpoints
- Detection: if 5+ paths return same response size, it's SPA fallback
- Only /api/* paths return real JSON responses (12000 TOKEN失效 or 1006 未登录)

## WAF GraphQL Blocking
腾讯云WAF blocks GraphQL introspection queries containing `__schema`, `__type` keywords.
- All POST requests to /graphql on openability.t3go.cn return catch-all `{"code":10012,"message":"no_request_resource"}`
- Simple queries without introspection keywords also return catch-all
- WAF triggers on request body content, not just URL path
- No GraphQL endpoint actually exists — 200 status is SPA/catch-all response

## Non-Prod Environment Status (2026-06-08)
- gateway-test2: Kong routes return Spring Boot 404 JSON, actuator blocked by WAF
- gateway-pre: Same as test2
- gateway-dev2: Empty responses (1B), appears down
- gateway-pst2: Empty responses (1B), appears down
- dev-cop.jx-ams.cn: TOKEN auth required (12000), same API surface as prod

## FAW Infrastructure (yqcx.faw.cn) Notes
一汽启明 (FAW QiMing) provides infrastructure for cop.jx-ams.cn:
- File storage: cpfile.yqcx.faw.cn (OpenResty, 401 auth required)
- Test file server: cpfile-test.yqcx.faw.cn (same)
- FTP download flow: cop /api/sys/ftp/file/signDownlaodUrl?fileKey=X → 302 to cpfile-test with HMAC token
- Path traversal in fileKey passes through to redirect URL but file server blocks with 401
- nginx/1.15.5 on cop (old, multiple CVEs)

## References
- `references/vip-t3go-cn-api-endpoints.md` — 120 API paths from vip.t3go.cn JS bundle (auth, enterprise, fund, coupon)
- `references/jx-ams-cn-api-enumeration.md` — jx-ams.cn API endpoints
- `references/jx-ams-cn-architecture.md` — jx-ams.cn architecture details
- `references/chinese-enterprise-platform-patterns.md` in src-vuln-hunting
- `references/cors-origin-reflection-testing.md` in src-vuln-hunting
- Reports: /tmp/vuln_reports/t3go/
