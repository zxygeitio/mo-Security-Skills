# jx-ams.cn Architecture & Testing Patterns (2026-06-05)

## Infrastructure Stack
- **Proxy**: Envoy (x-envoy-upstream-service-time header) + nginx
- **Backend**: Spring Boot (JSON errors with timestamp/status/error/message/requestId)
- **Frontend**: Vue SPA + Element UI/Plus
- **File Storage**: cpfile.yqcx.faw.cn (一汽启明 OpenResty)
- **Auth**: 钉钉SSO + 企业账号, TOKEN-based API auth

## Three Systems
| Domain | System | Stack | CORS |
|---|---|---|---|
| cop.jx-ams.cn | 上海嘉行车辆管理系统 | Vue 2.6 + Element UI 2.13.2 | None |
| dev-cop.jx-ams.cn | 同上(开发环境) | Same | None |
| cop-risk.jx-ams.cn | 运营风控系统 | Vue 3.3.4 + Element Plus 2.3.7 | ACAO: cop.jx-ams.cn |

## API Auth Error Codes
| Code | Message | Meaning |
|---|---|---|
| 12000 | TOKEN失效 | Auth required (cop) |
| 1006 | 用户没有登录或登录已失效 | Auth required (cop-risk) |
| 1000 | authCode is required / fileKey is required | Parameter missing |
| 5000 | 服务异常，请稍后再试 | Server error (DingTalk auth) |
| 2017 | 没有权限 | No permission (RPA APIs) |

## Unauthenticated Endpoints (cop.jx-ams.cn)
```
GET /api/sys/ftp/file/signDownlaodUrl?fileKey=X
→ 302 redirect to https://cpfile-test.yqcx.faw.cn/X?e=<timestamp>&token=<HMAC>

GET /api/sys/sys/dingTalk/auth
→ {"msg":"authCode is required","code":1000}

POST /api/sys/sys/dingTalk/auth?authCode=anything
→ {"msg":"服务异常","code":5000} (calls DingTalk API, always fails)
```

## Frontend JS Files
- Login: `/static/js/login.dd2146d7.js` — DingTalk SSO + internal URL leaks
- Main (prod): `/static/js/index.0b8e6486.js`
- Main (dev): `/static/js/index.da0e6960.js` (different hash = different code)
- Vendors: `/static/js/vendors~app~index.b0ee080c.js` (shared)

## Internal URLs Leaked in JS
```
https://dev-images.yqcx.faw.cn    # Dev image server
https://dev-vm-ops.yqcx.faw.cn    # Dev VM operations
https://images.yqcx.faw.cn        # Image server
https://pbi.yqcx.faw.cn           # Power BI
https://vm-ops.yqcx.faw.cn        # VM operations (default nginx 200)
https://cpfile-test.yqcx.faw.cn   # File server test
https://pre-images.yqcx.faw.cn    # Pre-prod images
https://pre-pbi.yqcx.faw.cn       # Pre-prod BI
https://pre-vm-ops.yqcx.faw.cn    # Pre-prod VM ops
http://copwiki.jx.cn/             # Internal Wiki
```

## DingTalk SSO Flow
1. User visits cop.jx-ams.cn → redirected to /login
2. Login page loads DingTalk iframe: `https://g.alicdn.com/dingding/h5-dingtalk-login/0.21.0/ddlogin.js`
3. User scans QR or enters enterprise credentials
4. Frontend calls `/api/sys/sys/dingTalk/auth?authCode=<code>`
5. Backend exchanges authCode with DingTalk API → returns user session TOKEN

## File Download Flow
1. Frontend calls `/api/sys/ftp/file/signDownlaodUrl?fileKey=<key>`
2. Backend generates HMAC token and redirects to `cpfile-test.yqcx.faw.cn/<key>?e=<ts>&token=<hmac>`
3. File server validates token, returns file or 404/401
4. Path traversal in fileKey passes through to redirect but file server blocks

## Cop vs Dev-Cop Differences
- JS hash differs: index.0b8e6486.js vs index.da0e6960.js
- API endpoints identical
- Dev environment updated more frequently (last-modified changes on each visit)
- Both use same nginx/1.15.5 (old, CVE-2019-20372 etc.)
