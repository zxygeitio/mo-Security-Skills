# SAIF (上海高级金融学院) SRC Testing Patterns — 2026-05-28

## Target Info
- Domain: www.saif.sjtu.edu.cn (上海交通大学上海高级金融学院)
- IP: 47.110.216.129 (Alibaba Cloud)
- WAF: 云盾WAF (yundunwaf3.com, acw_tc cookie)
- Tech: Apache/2.4.6 (CentOS), PHP/5.4.16, OpenSSL/1.0.2k-fips
- Industry: 教育 (金融商学院)
- Address: 上海市徐汇区淮海西路211号

## Critical Finding: CORS `*` with Auth Token Headers

The main site returns `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Headers` containing authentication-related custom tokens:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Connection, User-Agent, Cookie,Ttoken,Stoken,Mtoken,Appid,terminal,redirect,Token
Access-Control-Allow-Methods: POST,GET,OPTIONS,DELETE,PUT
```

**Key difference from standard CORS `*`:** The Allow-Headers explicitly includes `Cookie`, `Ttoken`, `Stoken`, `Mtoken`, `Appid`, `terminal`, `redirect`, `Token` — these are custom authentication headers used by the application. While browsers technically block `*` with credentials, the server accepts Cookie in request headers.

**Testing:**
```bash
# Confirmed on every response
curl -sk -D- "https://www.saif.sjtu.edu.cn/" -H "Origin: https://evil.com" | grep -i access-control

# Also confirmed with custom token headers
curl -sk -D- "https://www.saif.sjtu.edu.cn/" -H "Origin: https://evil.com" -H "Ttoken: test" | grep -i access-control
```

**Report angle:** "上海高级金融学院网站存在CORS配置不当漏洞" [中危]
- 需证明已登录状态下可跨域读取敏感数据
- 如果无认证态API返回敏感数据，可升级

## Subdomains (12 discovered)

| Subdomain | System | Tech | Notes |
|-----------|--------|------|-------|
| alumni.saif.sjtu.edu.cn | 高金EED学生教务系统 | Apache-Coyote/1.1 (Java) | 302 → /user/login/saif/59 |
| apply.saif.sjtu.edu.cn | 申请系统 | Apache-Coyote/1.1 (Java) | 302 → /user/login/saif/23 |
| portal.saif.sjtu.edu.cn | 门户系统 | nginx/1.27.5 | OAuth2 → sso.saif.sjtu.edu.cn |
| sso.saif.sjtu.edu.cn | 统一身份认证 | nginx | OAuth2 + INGRESSCOOKIE |
| support.saif.sjtu.edu.cn | 支持系统 | nginx/1.27.5 | OAuth2 → sso |
| wiki.saif.sjtu.edu.cn | Wiki系统 | nginx/1.18.0 (Ubuntu) | 302 → /login |
| analytics.saif.sjtu.edu.cn | Matomo分析 | Apache/2.4.16, PHP/5.5.9 | Piwik/Matomo login page |
| admin.saif.sjtu.edu.cn | 管理后台 | — | 202.120.17.7 (different IP!) |
| mail.saif.sjtu.edu.cn | 邮件系统 | — | 116.246.13.35 |
| vpn.saif.sjtu.edu.cn | VPN系统 | — | 124.74.129.162 |
| hr.saif.sjtu.edu.cn | 人力资源 | — | 47.100.232.242 |
| mobile.saif.sjtu.edu.cn | 移动端 | — | 58.32.209.117 |

## SSO System Analysis

**Login page:** https://sso.saif.sjtu.edu.cn/sso/login/
- Title: "统一身份认证"
- Login methods: username/password, phone (SMS), WeChat
- MFA support (mfa-code field)
- Uses `pid` for CSRF, `execution` for CAS-style flow
- Password encryption: publicKey field (likely RSA)
- Cookies: DEVICE_ID, X_REQUEST_ID_TOKEN, INGRESSCOOKIE

**Internal path disclosure (404 error):**
```
GET /sso/apis/v2/open/code/SMS → 404
Response: {"path":"/sso-apis-v3/apis/v2/open/code/SMS"}
```
Reveals internal service name: `sso-apis-v3`

**Registration page:** https://sso.saif.sjtu.edu.cn/sso/register/ — accessible

## Matomo/Piwik Analytics

**URL:** https://analytics.saif.sjtu.edu.cn/
- Title: "Sign in - Matomo"
- Anonymous token: `piwik.token_auth = "anonymous"`
- Anonymous access returns `[]` for site list
- Superuser access required for site data: `{"result":"error","message":"You can't access this resource as it requires a 'superuser' access."}`
- PHP/5.5.9 (slightly newer than main site)

## Upload Directories

```
/uploads/ → 403 (real directory, protected)
/upload/ → 403 (real directory, protected)
/offer/ → 403 (real directory, protected)
/uploads/image/ → 403
/uploads/ico/ → 403
/uploads/file/ → 403
```

## SPA Fallback

Main site uses SPA fallback — most paths return the same HTML (404 page). Only `/robots.txt` and `/index.php` return real content.

## robots.txt

```
User-agent: *
Disallow: */uploads/
Disallow: */upload/
Disallow: */offer/
```

## Information Leakage

- Baidu analytics: `3201e85472b0bc82e742ff3f12bad7b7`
- Matomo siteId: 17
- Yandex Metrika: 86391484
- Facebook domain verification: `d8ejbpxsifum2hgs57r71b91oii2lv`
- jQuery: 1.11.3 + 3.1.1 (both loaded)

## CORS `*` Pattern — Broader Implications

This is a pattern worth noting for other targets. When `Access-Control-Allow-Origin: *` is combined with custom auth token names in Allow-Headers (Ttoken, Stoken, Mtoken, Appid, etc.), it suggests:
1. The application uses custom headers for authentication (not just Cookie)
2. The CORS policy was designed to allow cross-origin API access with these tokens
3. If any API endpoint accepts these tokens for auth, cross-origin attacks are possible

**Test script:**
```bash
# Check if CORS * with custom auth headers
curl -sk -D- "https://TARGET/" -H "Origin: https://evil.com" 2>/dev/null | grep -i "access-control"

# If Allow-Headers contains auth-related tokens, test API endpoints
for path in /api/user/info /api/config /api/health; do
    curl -sk -D- "https://TARGET$path" -H "Origin: https://evil.com" -H "Ttoken: test" 2>/dev/null | head -20
done
```

## Education SRC Report Status

- CORS `*` with auth headers: **中危** (if can prove cross-origin data read with credentials)
- SSO path disclosure: **低危** (infrastructure info leak)
- PHP version leak: **低危** (known CVEs but no exploit verified)
- Matomo exposure: **低危** (login page only, no data leak)
- Upload directories exist but protected: **不建议提交**
