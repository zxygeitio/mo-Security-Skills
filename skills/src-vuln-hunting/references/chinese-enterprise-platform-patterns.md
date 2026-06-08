# Chinese Enterprise Platform Testing Patterns

## Ride-Hailing Platform (T3出行/Didi/类似) Architecture

### Common Stack
- **API Gateway**: Kong (returns x-kong-upstream-latency, x-kong-proxy-latency headers)
- **WAF**: 腾讯云WAF (stgw) — HTTP 218 for blocked requests
- **Backend**: Spring Boot (JSON error responses with timestamp/status/error/message/path)
- **Auth**: OAuth2 password grant with AES-encrypted passwords
- **Service Discovery**: Consul (/health returns "hello consul")

### Kong Gateway Fingerprint
```
x-kong-upstream-latency: N
x-kong-proxy-latency: N
Access-Control-Allow-Origin: *
```
Kong returns `{"message":"no Route matched with those values"}` for undefined routes.

### Tencent WAF (stgw) HTTP 218
Blocked requests return HTTP 218 with HTML page titled "WAF拦截页面".
Trigger patterns: suspicious Origin headers, actuator/swagger paths, SQL injection payloads.
Bypass: Use Referer instead of Origin for CORS testing; use benign-looking headers.

### OAuth2 + AES-ECB Password Encryption
Many Chinese enterprise platforms encrypt passwords before sending:
1. Call /api/auth/getKey → returns {encryptedKey, random}
2. Encrypt password: AES-ECB(key=encryptedKey, data=password, padding=PKCS7)
3. Base64 encode the ciphertext
4. Send: {username, password: encryptedBase64, random, grant_type: "password"}

**Key insight**: encryptedKey is often a 16-digit number (AES-128). Check if key is static across requests (reuse = weak).

### OAuth Client Credentials in Frontend JS
Common pattern: Authorization: Basic base64(client_id:client_secret) hardcoded in JS.
Test: Different error codes for valid vs invalid client credentials proves the credential is validated.
- Wrong client: errCode=4114 "client账号或密码错误"
- Correct client, wrong user: errCode=4100 "用户名或密码错误"
- Correct client, valid user, wrong password: errCode=4149 "用户名或密码错误"

### User Enumeration via Error Codes
Even when error messages are identical, different errCode values leak user existence:
- errCode 4100 vs 4149 (password login)
- errCode 4106 vs 4115 (mobile login)
- Test with encrypted passwords (plaintext may return different codes)

## 蓝凌OA (Landray EKP) Testing

### Fingerprint
- Login page: `j_username` + `j_password` form fields
- CSS path: `/sys/ui/extend/theme/default/style/form.css`
- Module pattern: `com.landray.kmss.*`
- Version in login page: "集团登录-V15版本"

### Default CORS Vulnerability
蓝凌OA reflects ANY Origin with ACAC=true by default. Always test this.

### Key Paths
```
/sys/circulation/sys_circulation_main/sysCirculationMain.do?method=doingCirculation
/sys/notify/sys_notify_todo/sysNotifyTodo.do
/sys/person/sys_person_main/sysPersonMain.do
/sys/news/sys_news_main/sysNewsMain.do
/third/ding/pcScanLogin.do?method=service (钉钉)
/third/wx/pcScanLogin.do?method=service (微信)
/third/wxwork/pcScanLogin.do?method=service (企业微信)
/ekp/ (蓝凌EKP prefix)
```

### WeChat/DingTalk Integration Leak
Login page often contains corp_id, agentid, appid for third-party SSO integration.

## T3SRC Specific Notes

### Scope Classification
- Core (P0): pay.t3go.cn, passenger.t3go.cn, gateway.t3go.cn (specific API paths), openability.t3go.cn, integrated.t3go.cn, gis-api.t3go.cn
- Edge (P2): metric*.t3go.cn, *dingxiang*.t3go.cn, waf.t3go.cn, gtm.t3go.cn, *.jx-ams.cn, upload/download.t3go.cn
- Normal: ai.t3go.cn, all other *.t3go.cn

### WAF Behavior
- Origin: evil.com → HTTP 218 WAF block on some domains (gis-api, gateway)
- Referer header → passes through (no WAF block)
- OPTIONS preflight → may pass through WAF
- actuator/swagger → always WAF blocked (218)
- Swagger UI: IP whitelist check returns 403 "[attack] IP access not allowed for swagger"

### Gateway API Auth Pattern
- 4100: "api未授权_03" — requires OAuth token
- 9999: "用户信息不存在" — passed client auth, no user session
- 4102: "参数不正确" — wrong parameters
- 500: "系统异常" — server error

### Batch Testing
- 29,770 API endpoint enumeration showed ALL require auth (4100)
- Focus on OAuth credential leak and user enumeration as primary attack vectors
