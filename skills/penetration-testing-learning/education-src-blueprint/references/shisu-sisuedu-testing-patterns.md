# 上海外国语大学 (shisu.edu.cn) Testing Patterns

## Target Profile
- Domain: shisu.edu.cn
- Location: 上海市虹口区
- Subdomains: 200+ (subfinder enumeration)
- Main site: www.shisu.edu.cn → Server: none, CORS `Access-Control-Allow-Origin: *` (no credentials)

## Technology Stack

### SSO — escSSO (企业级统一认证系统)
- URL: sso.shisu.edu.cn
- Vendor: escSSO (likely 北京易诚通信 or similar)
- jQuery 1.7.2 (known CVE-2012-6708, CVE-2015-9251, CVE-2019-11358)
- Auth types: pwd, otp (dynamic code), SMS, AD/LDAP, RSA, UKey
- Login form: POST /sso/login, fields: lt (LT ticket), execution (e1s1), _eventId (submit), authType (pwd), un (username: 学工号/Account ID), pd (password), randomCode (captcha)
- **JSESSIONID URL leak**: POST to /sso/login returns `Location: http://sso.shisu.edu.cn/sso/login;jsessionid=SESSIONID` — session ID embedded in URL, leakable via Referer
- OPTIONS returns `Allow: GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH` (includes TRACE)
- /sso/status → 500 (server error, but renders login page template)
- /sso/loginAuth/forwardAuthType → 200 (returns 3 bytes, auth type forwarding endpoint)
- Password reset: /sso/getBackPasswordMainPage.do exists
- Password validation: /sso/validatePasswordAjax.do exists (returns login page template for all inputs)

### 致远OA (Seeyon OA) — Resin/3.1.8
- URL: oa.shisu.edu.cn
- Server: Resin/3.1.8 (very old, 2008-era Java application server)
- /seeyon/ → 404 (not mounted at standard path)
- /seeyon/index.jsp → 302 to SSO
- /resin-admin/ → 403 Forbidden IP Address (IP-restricted admin console)
- /rest/ → 404 with Resin/3.1.8 server header
- All authenticated paths redirect to SSO login

### SUDY WebPlus CMS (multiple sites)
- admissions.shisu.edu.cn (siteId=15) — 本科招生
- lib.shisu.edu.cn — 图书馆
- info.shisu.edu.cn (siteId=4) — 信息公开网
- graduate.shisu.edu.cn — 研究生院
- news.shisu.edu.cn — 新闻网 (CORS `*`)
- itc.shisu.edu.cn — IT中心

### 金智教育 (wisedu) — 研究生管理系统
- URL: wiseduehall.shisu.edu.cn
- Server: openresty
- /new/index.html → wisedu ehall portal
- /jsonp/school.json → AMPConfigure JSON (研究生管理系统 title, wisedu copyright)
- /jsonp/userInfo.json → guest site data (siteId=69f4533800c149f0b79af19b96332964, menu list)
- /jsonp/appIntroduction.json → {"hasLogin":false,"contextPath":""} (requires valid appId)
- /jsonp/serviceCenterData.json → 302 redirect (requires auth)
- Other JSONP endpoints return {"hasLogin":false} without auth
- jQuery 3.4.1, i18n plugins

### Moodle (SISU-eLearning)
- URL: elearning.shisu.edu.cn
- Server: nginx
- CORS: `Access-Control-Allow-Origin: *`
- Moodle webservice API: /webservice/rest/server.php → returns "无效令牌" (invalid token) for all queries
- /admin/ → 303 (redirect to login)
- /login/signup.php → "错误" (signup disabled)
- App: iOS app-id=633359593

### WebVPN — 网瑞达 (NetReada)
- URL: webvpn.shisu.edu.cn
- Vendor: 北京网瑞达科技有限公司
- /login → Vue.js SPA login portal

### 留学生在线申请 (Classic ASP)
- URL: apply.shisu.edu.cn
- IIS server, gb2312 encoding
- Actions: student_sign, student_main, student_main_en, list
- Error: "25002 : The named action is not found"
- admin/ → 404

### xuegong.shisu.edu.cn (学工系统)
- SaaS platform ("致力打造信息化高校")
- jQuery, Bootstrap, MD5, yiBanEnCode.js, captcha.js v1.3.41
- Tencent Maps API key exposed (key=***, referer=saas)
- /api/login → POST returns {"state":false,"message":"No message available"} for ALL inputs (no user enumeration)
- Other /api/* endpoints redirect to /login

### Sangfor SSL VPN
- URL: vpn.shisu.edu.cn
- sf_ssl_ms_ prefix in JS (Sangfor SSL VPN micro service)

### Shibboleth IdP
- URL: idp.shisu.edu.cn
- Server: nginx/1.30.0
- /idp/shibboleth → SAML metadata XML (standard, not a vulnerability)

### Unreachable Subdomains
- ecard.shisu.edu.cn → 198.18.0.120 (WARP/CDN fake IP)
- fortress.shisu.edu.cn → 198.18.0.121 (WARP/CDN fake IP)
- chat.shisu.edu.cn → 198.18.0.122 (WARP/CDN fake IP)
- class.shisu.edu.cn, gis.shisu.edu.cn, visual.shisu.edu.cn, quiz.shisu.edu.cn → timeout

## WAF / Blocking Behavior
- Main site: Server: none (hidden), no WAF header detected
- After ~150+ requests over ~15 minutes, ALL targets became unreachable (HTTP 000)
- IP blocking appears to be at network level (not application WAF)
- Recovery time unknown (tested up to 90s after block, still blocked)
- No X-Forwarded-For bypass effective
- DNS resolves to 198.18.x.x range (WARP/proxy CDN)

## Key Findings (2026-06-01)

### Confirmed: SSO JSESSIONID URL Leak
- POST /sso/login with any form data → Location header contains ;jsessionid=SESSIONID
- Set-Cookie: JSESSIONID=...; Path=/sso; HttpOnly
- JSESSIONID entropy: 32 hex chars, appears random (not sequential)
- Impact: session ID leakable via Referer, server logs, proxy logs
- Severity: Low (requires user interaction to exploit)

### Confirmed: SUDY CMS Admin IP Leak (variable)
- /admin/login.psp on SUDY CMS sites returns hidden field: `<input id="ipAddress" ... value="X.X.X.X"/>`
- admissions.shisu.edu.cn → 10.2.7.161 (SERVER internal IP — real leak)
- lib.shisu.edu.cn → 127.0.0.1 (localhost proxy — not useful)
- graduate.shisu.edu.cn → 216.195.192.148 (CLIENT IP — reflection, NOT leak)
- **Always verify**: check if the IP matches your own external IP before reporting

### Not Exploitable
- ehall.shisu.edu.cn → 483/403 (blocked externally)
- portal.shisu.edu.cn → 483/403 (blocked externally)
- wiseduehall JSONP endpoints → return {"hasLogin":false} without auth (no PII)
- SUDY CMS search API → {"resultCode":1,"message":"参数异常"} (parameter error, needs correct _p)
- SUDY CMS IDS login API → {"status":0} for all POST payloads (default response, not functional)
- Resin /resin-admin/ → 403 Forbidden IP Address

## Recommendations for Continued Testing
1. Wait for IP unban or use VPN/proxy
2. Focus on ehall/portal from campus network
3. SSO brute force needs CAPTCHA bypass first
4. SUDY CMS search needs correct _p parameter investigation
5. Try SSO password reset flow enumeration
