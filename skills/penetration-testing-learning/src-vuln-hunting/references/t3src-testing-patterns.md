# T3出行SRC Testing Patterns

## Target Architecture
- **API Gateway**: Kong (x-kong-upstream-latency headers) — t3go.cn assets
- **WAF**: 腾讯云WAF (stgw) — HTTP 218 for blocked requests
- **Backend**: Spring Boot (JSON: timestamp/status/error/message/path)
- **Auth**: OAuth2 password grant + AES-ECB encrypted passwords
- **Service Discovery**: Consul (/health → "hello consul")
- **DNS**: gateway/passenger/pay → gtm-waf.t3go.cn → WAF IPs

## Kong OAuth Bypass via Double Slash (//) — 2026-06-08 [MEDIUM]
Double slash path normalization bypasses Kong OAuth AND partial WAF:

```bash
# Normal: requires OAuth
curl -sk 'https://gateway.t3go.cn/mall-app-api/'
# → {"code":4100,"msg":"api未授权_03"}

# Bypass: double slash reaches backend directly
curl -sk 'https://gateway.t3go.cn/mall-app-api//'
# → [attack] IP access not allowed for swagger! ip is <CLIENT_IP>
```

**Affected routes (7 core APIs):**
mall-app-api, solution-carriage, driver-app-api, pay-center-api, gis-map-api, strategy-gateway-api, driver-core-app-api

**Backend Actuator endpoints (bypass WAF with //):**
`//health`, `//info`, `//env`, `//metrics`, `//trace`, `//beans`, `//configprops`
All return IP whitelist error (not WAF block).

**WAF still blocks:** `//swagger-ui.html`, `//v2/api-docs`, `//actuator`, `//actuator/health`

**IP whitelist bypass attempts (all failed):**\nX-Forwarded-For, X-Real-IP, True-Client-IP, X-Client-IP — backend uses actual connection IP.

**HEAD request bypasses IP whitelist filter:**\nHEAD requests return 403 (not IP whitelist error), indicating the backend filter has HTTP method inconsistency:\n```bash\ncurl -sk -I 'https://gateway.t3go.cn/mall-app-api//'\n# HTTP/2 403, content-length: 64 (empty body)\n```\nAll other methods (GET/POST/PUT/DELETE/PATCH/OPTIONS) trigger IP whitelist error.

**DNS:** gateway/passenger/pay → gtm-waf.t3go.cn → WAF IPs (101.34.136.120, 49.234.110.140, 81.69.34.150). Direct IP access returns 404.

## OAuth Status (2026-06-08)
- `getKey` returns 500 on ALL environments (prod, test2, pre, dev2, pst2)
- OAuth client `org-manager:HwEACu8r2jngK6OM` still valid (errCode 4100 = user/pass wrong, not 4114 = client wrong)
- VIP API: 120 endpoints enumerated from JS, all require user auth (9999) or return 500
- OAuth mobile flow also returns 500

## Unauthenticated Endpoints (official-website-web-api)
- POST /api/mall/page → 200 (page config, uuid param)
- POST /api/mall/goods/list → 200 (returns empty array)
- POST /api/mall/goods/detail → 200 (returns empty product details)
- Other /api/* paths → 4100 (need auth)

## WAF Behavior
- Origin: evil.com → HTTP 218 on some domains
- Referer header → passes through
- actuator/swagger → always 218
- Swagger UI: IP whitelist on backend (not WAF)
- User-Agent rotation does NOT bypass IP block
- VPN/proxy rotation is the only reliable bypass

## jx-ams.cn Architecture
- Proxy: Envoy (x-envoy-upstream-service-time header) + nginx/1.15.5
- Frontend: Vue 2.6 SPA (cop) / Vue 3.3 (cop-risk) + Element UI/Plus
- Auth: 钉钉扫码 + 企业账号登录, TOKEN-based API auth
- API auth codes: 12000=TOKEN失效, 1006=用户未登录(cop-risk), 1000=参数错误, 5000=服务异常
- CORS: cop-risk only allows cop.jx-ams.cn origin
- SPA catch-all: 1663B for all unknown paths

## Scope (2026-06)
Core (P0): pay/passenger/gateway(specific APIs)/openability/integrated/gis-api/vehicle.t3go.cn
Edge (P2): *.jx-ams.cn, metric*/dingxiang/ticloud/waf/gtm, upload/download, non-prod
Normal: ai.t3go.cn, other *.t3go.cn
Excluded: *obs*.t3go.cn, hwupload/download, cc-side-webapp-api, 优惠券<5元

## Key Subdomains
Core: gateway, passenger, pay, openability, integrated, gis-api, vehicle, vip
Interesting: enterprise, oa, security(SRC portal), llm-app-store, bi, iov-api, api-driver-rpa, api-rpa-external, cube
Edge: dingxiang, metrics, waf, gtm, upload, download
Non-prod: gateway-test2, gateway-pre, gateway-dev2, autopilot-dev, gateway-pst2
jx-ams.cn: cop, dev-cop, cop-risk, web, www
