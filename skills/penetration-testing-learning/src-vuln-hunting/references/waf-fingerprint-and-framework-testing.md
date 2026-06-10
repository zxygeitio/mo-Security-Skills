# Multi-WAF Fingerprinting & Bypass Patterns

## WAF Identification Techniques

### Tengine WAF (Alibaba Cloud)
- **Fingerprint**: Returns 405 Method Not Allowed with ~2657B HTML body
- **Response body**: `<!doctypehtml><html lang="zh-cn">...<title>405</title>`
- **Server header**: `Tengine`
- **CORS behavior**: Reflects ANY `Origin` header + sets `Access-Control-Allow-Credentials: true`
  - This occurs even on 405 error pages (no sensitive data in response)
  - Pattern: jobs.mgm.mo, app.mgm.mo, static.mgm.mo, training.mgm.mo
- **Cookie**: `aliyungf_tc`, `acw_tc` (Alibaba Cloud anti-bot)

### Akamai Bot Manager
- **Fingerprint**: Returns HTTP 247 (custom status) with ~440B HTML
- **Response body**: Contains `<script src="/kramericaindustries.ac.lib.js">`
- **Cookie**: Various Akamai cookies
- **Bypass**: Requires real browser JS execution (headless detection)
- Pattern: tickets.mgm.mo

### Alibaba Cloud WAF
- **Fingerprint**: "Request Rejected" with support ID
- **Response**: `<html><head><title>Request Rejected</title></head><body>The requested URL was rejected...`
- **Cookie**: `acw_tc`
- Pattern: mlife.mo, macau2049.mgm.mo

### F5 BIG-IP
- **Fingerprint**: `Server: BigIP` header
- **Cookie**: `BIGipServerpool_*`, `TS0*`
- **Behavior**: Often returns 302 redirects to internal paths
- Pattern: roster.mgm.mo, carpark.mgm.mo, mlife.mo

### BeyondTrust Remote Support
- **Fingerprint**: OAuth2 token validation on API endpoints
- **Response**: `{"message":"The resource owner or authorization server denied the request...","error":"access_denied"}`
- **Paths**: `/api/command`, `/api/reporting`
- Pattern: support.mgm.mo

## Tengine WAF CORS Misconfiguration Pattern

### Detection
```bash
curl -k -sI -H "Origin: https://evil.com" https://target/ | grep -i 'access-control'
```

Expected output if vulnerable:
```
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

### Severity Assessment
- **If 405 page has no sensitive data**: Low/Info (CORS on error page only)
- **If backend returns data with reflected CORS + ACAC=true**: HIGH
- **Key test**: Check if actual API endpoints (not just WAF error pages) also reflect CORS

### Testing Matrix
```bash
# Test multiple origins
for origin in "https://evil.com" "https://attacker.com" "null" "https://target.com"; do
  echo "Origin: $origin"
  curl -k -sI -H "Origin: $origin" https://target/ | grep -iE 'access-control|status'
done
```

## Framework-Specific Testing

### UmiJS (React-based, used by Alibaba ecosystem)
- **Detection**: Single `umi.{hash}.js` bundle, no framework indicator in headers
- **API route extraction**: Backend API routes are embedded in the JS bundle
  ```bash
  curl -s https://target/umi.*.js | grep -oE '"/[A-Z][a-z]+/[A-Za-z/]+"' | sort -u
  ```
- **Common pattern**: SPA returns same 421-byte HTML for all routes; actual API on separate paths
- **Backend discovery**: Look for patterns like `/Controller/Action` in the bundle
- Pattern: booking.mgm.mo (UmiJS → Mlife/Reservation APIs)

### Laravel + Livewire
- **Detection**: `XSRF-TOKEN` + `laravel_session` cookies, `/livewire/livewire.js`
- **CVE targets**:
  - CVE-2020-36191: Livewire update endpoint RCE
  - CVE-2024-13918: Livewire file upload RCE
- **Endpoints to test**:
  ```
  /livewire/update         (POST, component updates)
  /livewire/message/{name} (POST, component messages)
  /livewire/upload-file    (POST, file upload)
  /_ignition/health-check  (Ignition debug)
  /_ignition/execute-solution
  /telescope               (Laravel Telescope)
  /horizon                 (Laravel Horizon)
  /_debugbar               (Debugbar)
  ```
- **CORS check**: Laravel API routes may return `CORS:*` even when redirecting
- Pattern: fanzone.mgm.mo

### Next.js
- **Detection**: `/_next/static/` paths, `__NEXT_DATA__` script tag
- **SSRF via image optimizer**:
  ```
  /_next/image?url=http://127.0.0.1/&w=100&q=75
  /_next/image?url=http://169.254.169.254/latest/meta-data/&w=100&q=75
  ```
- **Key difference**: Some Next.js instances block internal URLs (400 "url parameter is not allowed") while others redirect (302)
  - 302 redirect = may be exploitable (follow redirect to see final response)
  - 400 block = properly configured
- **Build info leak**:
  ```
  /_next/data/{buildId}/page.json
  ```
- **API routes**: `/api/*` may expose backend functionality
- Pattern: mgm.mo, www.mgm.mo

### Express.js (Node.js)
- **Detection**: "Cannot GET /path" error messages
- **Config endpoints**: `/config`, `/env`, `/health`
- **Session**: Check for session cookies and CSRF tokens
- Pattern: mlife.mo

### 瑞数信息 (River Security) Anti-Bot
- **Fingerprint**: Returns 412 Precondition Failed with ~3KB HTML body
- **Response body**: Contains `$_ts` JS object with `nsd`(时间戳) and `cd`(混淆代码) fields
- **JS challenge**: `/VenlhLLec3Sc/zM59tDaHprPq.091bf33.js` (路径固定,文件名混淆)
- **Cookie**: `Sy4oMATxYbbSO` (长随机值, expires 10年, Secure, HttpOnly)
- **Meta tag**: `<meta id="YeAeRI3T43zB" content="..." r='m'>` (content为动态token)
- **CLI不可绕过**: 需要真实浏览器执行JS challenge才能获得有效session
- **常见场景**: 金智教育ehall办事大厅、CAS门户、校园一站式服务
- **确认目标**:
  - ehall.ccnu.edu.cn (华中师范大学, 2026-06-07)
  - ehall系统普遍部署
- **影响**: CLI工具(curl/httpx/nuclei)无法直接访问,必须用浏览器或headless Chrome
- **降级策略**: 跳过被瑞数保护的端点,改测未保护的API/JSONP端点
  - JSONP端点可能301重定向而非412: /jsonp/userFavoriteApps.json, /jsonp/userDesktopMenu.json
  - 但重定向目标通常需要CAS认证
