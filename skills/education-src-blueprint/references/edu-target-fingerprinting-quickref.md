# Education Target Fingerprinting Quick Reference

## CAS System Identification

### Apereo CAS (custom build)
- URL: `/cas/login`
- Indicators: `execution` hidden field, `_eventId=submit`, `service` parameter
- WeChat login: `appid=wxXXX` in page source, `clientredirect;jsessionid=...?client_name=WeChat`
- Default error: unified message "用户名或密码错误" (no user enumeration)
- Actuator: `/cas/actuator/health` may return 403 (WAF protected)

### Wisedu CAS (金智教育)
- URL: `/authserver/login`
- Indicators: `pwdDefaultEncryptSalt`, `encrypt.js`, `login-wisedu_v1.0.js`
- Server: openresty
- CORS vulnerability: ACAO reflects Origin + ACAC:true (systemic, all endpoints)
- Affected endpoints: /login, /status, /serviceValidate, /getBackPasswordMainPage.do

### Custom CAS (e.g., cust.edu.cn)
- URL: `/cas/login` with form action="login" (relative path)
- Service parameter embedded in WeChat redirect URLs
- WeChat AppID leakage in page source

## ehall / Service Hall Identification

### Wisedu ehall (金智教育办事大厅)
- Config: `/jsonp/school.json` → `AMPConfigure` object
- schoolId: 5-digit code (e.g., "10602")
- API base: `/jsonp/`, `/publicapp/`
- Unauthenticated APIs: `/jsonp/userInfo.json`, `/jsonp/serviceCenterData.json`, `/jsonp/appInfo.json?appId=XXX`
- Auth adapter: `/amp-auth-adapter/login` → sessionToken flow
- Stack trace disclosure in 500 errors (Tomcat version, Spring framework, Redis)

### Wengine-auth (网瑞达)
- Login: `/wengine-auth/login?id=XXX&path=/&from=TARGET_URL`
- Indicators: `wengine_new_ticket` cookie, keywords "网瑞达"/"WEBVPN"/"资源访问控制系统"
- 404 page: `/wengine-auth-failed.png` image
- CAS integration: redirects to `mysso.XXX/cas/login?service=http://wengine-auth/login?cas_login=true`

## CMS Identification

### SUDY CMS (博达)
- Admin path: `/_wp3services/general498/index.jsp` (returns 302 → CAS login)
- Editor: `/_wp3services/wps/serviceeditor/main.psp`
- System: `/_csair/main.psp`, `/system/main.psp`
- Error pages: "访问地址不合法（003）" with IP address disclosure
- Upload: `/_upload/` paths accessible but require CAS auth
- Logout API: `/_web/_ids/login/api/logout/create.rst` (POST)

### Chaoxing (超星教学系统)
- Indicators: `jwjx.XXX.edu.cn`, `gxnulocal.jw.chaoxing.com`
- Content-Security-Policy: `frame-ancestors 'self' https://i.chaoxing.com`
- CORS: ACAO restricted to same origin
- CAS integration via `/sso/login/3rd/XXX`

## Email System Identification

### Tencent Enterprise Email (腾讯企业邮箱)
- Server: `Wwebsvr`
- Content: `rescdn.qqmail.com`, `domainEntLogin`, `exmail.qq.com`
- Login: POST `https://mail.qiye.163.com/login/domainEntLogin`
- CSP: nonce-based with `data-csp-bb`

### 163 Enterprise Email (网易企业邮箱)
- Server: nginx
- Login: POST `mailh.qiye.163.com/domainEntLogin`

## Graduate School System Patterns

### ASP.NET Core self-built (e.g., yzcx.gxnu.edu.cn)
- Paths: `/Login`, `/Register/Index`, `/Register/enrolReg`, `/Register/forgetPwd`
- Score query: `/Search/ScoreInfo`, `/Search/checkInfo`
- Captcha: `/code/captcha/captcha?w=105&h=35&t=TIMESTAMP&refresh=1` (PNG image)
- CSRF: `__RequestVerificationToken` hidden field (ASP.NET Core format)
- Cookie: `.AspNetCore.Antiforgery.XXX`, `.AspNetCore.Session`
- Error disclosure: "Object reference not set to an instance of an object" in 500 pages
- Registration requires: 准考证号 + 姓名 + 身份证号 + 验证码

## Attack Priority Matrix (SRC Accepted)

### HIGH VALUE (submit these):
1. **Graduate system IDOR**: Change examId/studentId to read other students' scores
2. **CAS weak credentials**: admin/123456, test/test, studentId/birthday
3. **SUDY CMS path traversal**: `/_wp3services/../../etc/passwd`
4. **ehall unauthenticated API with PII**: student names, IDs, grades
5. **File upload → webshell**: SUDY CMS `/_upload/` with extension bypass
6. **SQL injection**: Graduate system `/noteInfo?id=1` (ASP.NET + SQL Server)

### LOW VALUE (do NOT submit alone):
1. CAS Open Redirect (rejected by SRC reviewers 2026-06)
2. CORS misconfiguration without data read proof
3. SAML metadata / X.509 certificate disclosure
4. WeChat AppID in page source
5. Actuator endpoints returning 403
6. Error page stack traces without further exploitation

## Subdomain Discovery Commands

```bash
# Subfinder
subfinder -d TARGET.edu.cn -silent -o subs.txt

# crt.sh
curl -sk 'https://crt.sh/?q=%.TARGET.edu.cn&output=json' | grep -oP '"name_value":"[^"]*"' | sort -u

# Key subdomain patterns
grep -iE 'auth|cas|sso|oa|ehall|portal|vpn|webvpn|mail|jwc|jw|ecard|pay|admin|manage|system|yjs|yzb|grad' subs.txt
```

## Quick Health Check

```bash
for sub in mysso ehall portal webvpn mail jwgl ecard jwc idp; do
  code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "https://${sub}.TARGET.edu.cn/")
  echo "${code} ${sub}.TARGET.edu.cn"
done
```
