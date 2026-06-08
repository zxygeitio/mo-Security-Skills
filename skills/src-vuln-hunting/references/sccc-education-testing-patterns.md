# SCCC.edu.cn Education SRC Testing Patterns (2026-05)

Target: 四川化工职业技术学院 (sccc.edu.cn) — VSB博达CMS + 致远A8+ OA + Shibboleth IdP + Seafile Pro + Vue.js SPA alumni system.

## Confirmed submittable findings

### 1. VSB CMS getSession.jsp 未授权会话获取 (中危)

**Root cause**: VSB博达CMS exposes `/system/resource/getSession.jsp` without auth. Called from frontend `token.js`:

```
GET /system/resource/getSession.jsp?r=Math.random()
→ returns 32-char JSESSIONID (e.g. C76D790852F8995848DA2E7C38794B2D)
```

Use the session with `getToken.jsp`:
```
GET /system/resource/getToken.jsp?mode=1 (with JSESSIONID cookie)
→ returns "preview" (CMS preview mode)
```

**Interface source**: `GET /system/resource/vue/token.js` — defines three unauthenticated endpoints:
- `/system/resource/getSession.jsp` — returns JSESSIONID
- `/system/resource/getToken.jsp?mode=<mode>` — returns access token
- `/system/resource/sensitiveFilter.jsp` — POST, content filter

**Report angle**: "VSB CMS存在未授权会话获取漏洞" — 中危. The session can be used for CMS preview mode access. Each request returns a different session (not fixed), proving batchability.

### 2. Shibboleth IdP SAML元数据泄露 (中危)

**Endpoint**: `GET /idp/shibboleth` — returns full SAML metadata XML without auth.

**Key leaked info**:
- EntityID: `https://idp.sccc.edu.cn/idp/shibboleth`
- SAML Scope: `sccc.edu.cn`
- Two X509 signing certificates (BackChannel + FrontChannel)
- Jetty container (JSESSIONID with `node0` prefix)

**SSO endpoints confirmed**:
- `/idp/profile/SAML2/POST/SSO` → 500 (endpoint exists)
- `/idp/profile/SAML2/Redirect/SSO` → 400 (endpoint exists)
- `/idp/profile/cas/login` → 500 (CAS endpoint exists)

**Report angle**: "Shibboleth IdP SAML元数据未授权访问" — 中危. Signing certificate exposure enables potential SAML assertion forgery. IdP is the central auth entry point for all school systems.

### 3. Alumni management platform JS architecture leak (中危)

**Target**: xy-admin.sccc.edu.cn — 校友会管理平台

**JS files expose**:
- `https://xy-api.sccc.edu.cn/` — API server (requires appkey)
- `https://xy-file.sccc.edu.cn/group1/upload` — FastDFS file upload
- `https://xy-file.sccc.edu.cn/group1/production/qrcode/` — QR code generation
- `/api/server/server_page`, `/api/tips/read`, `/api/tool/local_oss/update_token`
- **Critical**: `skip_code=skip_auth` parameter in `/api/community_manage/base?skip_code=skip_auth&cid=`

**API auth**: xy-api returns `{"status":1,"errno":1000,"result":{"message":"appkey不能为空"}}` without appkey, and `{"errno":403,"message":"未被授权的appkey"}` with invalid appkey.

**FastDFS**: xy-file.sccc.edu.cn returns `{"error":"auth fail"}` on upload, `list dir deny` on directory listing, `web upload deny` on root. CORS: `Access-Control-Allow-Origin: *` with all methods (GET/POST/OPTIONS/PUT/DELETE).

## Not recommended for submission

- **致远OA版本泄露**: CSS reference leaks `V8_2SP1_231013_1903070` — 低危, version in CSS is common
- **xy-file CORS ***: `Access-Control-Allow-Origin: *` with `Credentials: false` — browser blocks cookie reading with `*`, low impact
- **Seafile Pro v11.0.14**: `/api2/server-info/` leaks version — low value, auth enforced
- **pay.sccc.edu.cn SPA fallback**: All paths return 200 with same HTML — SPA fallback, not real endpoints
- **dc_web config.js**: `serviceHost: "http://"` with empty host — deployment misconfig, not a vulnerability
- **.env files**: pay and xrpt return SPA HTML on `.env` — false positive

## Technical patterns

### VSB博达CMS fingerprinting
- `_sitegray/_sitegray.js` present on all pages
- `index.vsb.css` stylesheet
- `/system/resource/js/counter.js` + `/system/resource/js/base64.js` + `/system/resource/vue/token.js`
- CSP: includes `agent.vsbclub.com:90` and `newagent.vsbclub.com`

### Shibboleth IdP fingerprinting
- Default page: "Welcome to IdP Server"
- Path: `/idp/shibboleth` (SAML metadata)
- Path: `/idp/profile/SAML2/POST/SSO`, `/idp/profile/cas/login`
- Jetty container: JSESSIONID with `node0` prefix in Set-Cookie

### FastDFS fingerprinting
- Upload returns `{"data":null,"error":"auth fail","message":"auth fail","status":"fail"}`
- Directory listing returns `list dir deny`
- Root returns `web upload deny`
- Path pattern: `/group1/upload`, `/group1/M00/`, `/group1/production/`

### Vue.js SPA architecture extraction pattern
1. Fetch main JS from homepage (`app.*.js`, `main.js`, `dist/main.js`)
2. Extract URLs: `grep -oP '"https?://[^"]*"'`
3. Extract API paths: `grep -oP '"/api/[^"]*"'`
4. Extract auth params: `grep -oiP '(skip_code|token|secret|key)[^"]*"[^"]*"'`
5. Verify each endpoint with curl — SPA fallback returns same HTML for all paths; real APIs return JSON
