# SUDY WebPlus CMS (苏迪科技) Testing Patterns

## Fingerprint
- CSS: `/_css/_system/system.css`, `Technical Support SudyTech` in CSS comments
- JS: `/_js/sudy-jquery-autoload.js`, `/_js/jquery.sudy.wp.visitcount.js`, `sudyNavi`
- HTML: `sudy-wp-siteId="N"` attribute on script tags, `class="webplus-main"` on html tag
- Admin: jQuery EasyUI + SM2 encryption (`/_js/sm2.js`, `/_js/jquery.easyui.min.js`)
- Pages: `.psp` extension (redirects from `.htm` to `.psp` via 302)

## Key Endpoints

### Search API (high value)
```
GET /_web/_search/restful/api/search.rst?keyword=KEYWORD&pageSize=10&pageNo=1&siteId=3&_p=BASE64
```
- `_p` parameter is required, base64-encoded config: `as=3&t=14&d=64&p=1&m=SN` → `YXM9MyZ0PTE0JmQ9NjQmcD0xJm09U04m`
- Returns JSON: `{"result":{"total":N,"data":[{title,summary,id,articleUrl,phColName,...}]},"resultCode":0}`
- If _p is wrong/missing: `{"resultCode":1,"message":"参数异常"}` or `{}` (empty JSON)
- Wildcard `*` search reveals total article count
- No authentication required
- Other search endpoints from JS:
  - `/_web/_search/restful/api/hotWords.rst`
  - `/_web/_search/restful/api/hotArticles.rst`
  - `/_web/_search/restful/api/initSearch.rst`
  - `/_web/_search/restful/api/suggestSearch.rst`
  - `/_web/_search/api/column/tree.rst`

### IDS Login API
```
POST /_web/_ids/login/api/login/create.rst
Content-Type: application/json
{"username":"admin","password":"test"}
```
- Returns `{"status":0}` for ALL payloads (POST) or 405 (GET)
- This is a default response, NOT a functional login endpoint
- **Do NOT report as authentication bypass** — the status:0 is meaningless

### Search Frontend
```
/_web/_search/web3/search.html
/_web/_search/web3/ → 403 Forbidden (on some deployments)
```
React SPA, JS at `./static/js/main.*.js`, contains all API endpoint paths

### VisitCount API
```
/_visitcountdisplay?funType=0&type=1&columnIds=ID1,ID2
```
Returns "非法请求" (illegal request) — not exploitable

### Admin Backend
```
/admin/login.psp → 410 Gone OR 200 (varies by deployment)
/admin/login.jsp → 403 Forbidden (with IP/connectionId leak)
/admin/resetPassword.psp → 200 (on some sites, e.g. lib.shisu.edu.cn)
/admin/index.psp → 200 (redirects to main site content)
```
- `.psp` pages return 410 Gone OR 200 depending on deployment config
- `.jsp` pages return 403 with `Client IP` and `connectionId` in body
- 200 pages show "提示信息" (prompt message) with EasyUI-based error template — NOT a functional admin login
- **IP leak via `ipAddress` hidden field**: `<input id="ipAddress" name="ipAddress" type="hidden" value="10.x.x.x"/>`
  - ⚠️ **CRITICAL DISTINCTION**: On some deployments (e.g. admissions.shisu.edu.cn) this leaks the SERVER's internal IP (10.2.7.161). On others (e.g. graduate.shisu.edu.cn) this reflects the CLIENT's IP (your own IP). Always verify by checking if the IP matches your own external IP (`curl ifconfig.me`) before reporting as a server IP leak.
  - Some deployments return 127.0.0.1 (localhost proxy — not useful)
- Login form fields: username field, password field, ipAddress hidden field
- POST to admin/login.psp returns 200 with Set-Cookie: JSESSIONID — the page renders but login is not functional (returns same error page for all credentials)
- Brute force is NOT effective — all POST attempts return same "提示信息" error page

### Actuator Behind SUDY Proxy
On some deployments (e.g. admissions.shisu.edu.cn, graduate.shisu.edu.cn), Spring Boot Actuator endpoints are proxied behind SUDY CMS:
```
/actuator → 302 → /actuator/main.psp
/actuator/env → 302 → /actuator/env/main.psp
/actuator/health → 302 → /actuator/health/main.psp
/actuator/heapdump → 502 (backend error, wengine-auth-failed.png page)
/actuator/beans → 302
/actuator/metrics → 302
/actuator/threaddump → 302
/actuator/loggers → 302
```
- The `.psp` redirect is a SUDY CMS rewriting behavior — ALL paths get .psp appended (even nonexistent ones like `/nonexistent123` → `/nonexistent123/main.psp`)
- The 302 to `.psp` does NOT mean actuator data is accessible
- All `.psp` versions return "提示信息" error pages
- **Do NOT report as actuator exposure** — the proxy blocks actual access

### Template Directory
```
/_upload/tpl/00/0e/14/template14/ → 200 (accessible)
```
Subdirectories (css/js/images) also accessible

### Upload Directories
```
/_upload/site/ → 403
/_upload/article/images/ → 403
```

## WAF Behavior (493 Response)
- Custom WAF returns HTTP 493 (non-standard) for blocked requests
- Blocked paths: `.git`, `.env`, `actuator`, `swagger`, `druid`, `<script>` in params
- 493 page leaks: visitor IP, connectionId, ruleId (e.g., `020010029`)
- ConnectionId format: `host-INTERNAL_IP-TIMESTAMP-COUNTER`
- 403 pages (for `.jsp`) also leak IP and connectionId

## Page Redirect Pattern
- Any path without extension → 302 to `/path/main.psp`
- `.htm` paths → 302 to corresponding `.psp`
- `.psp` pages → 410 Gone (error page) or 200 (for main/index)
- Only `/main.psp` and `/index.psp` return 200

## Attack Surface Assessment
- **Search API**: Low risk — returns public content, no sensitive data exposure
- **403/493 IP Leak**: Low risk — reveals proxy/WAF IP, not visitor IP
- **Admin Backend**: Protected — returns 410 Gone or non-functional 200
- **File Upload**: Protected — returns 403
- **No CORS**: No CORS headers found (except news.shisu.edu.cn which has `*`)
- **No SQLi**: Search uses full-text engine (tokenizes input)
- **WAF Effective**: Blocks XSS/SQLi payloads
- **IDS Login API**: Returns `{"status":0}` for all inputs — not functional, do not report

## Education SRC Report Angle
- 403/493 IP leak: Low severity, reveals infrastructure info
- Search API unauthenticated access: Low severity, returns public content
- Admin IP leak (server IP only): Low severity, must verify it's not client IP reflection
- Combined: "xxx学院SUDY CMS存在多处信息泄露漏洞" [低危]
- Neither finding alone meets education SRC submission threshold

## Known Deployments
- cztdxy.cn (常州铁道职业技术学院): siteId=3, proxy IP 118.113.85.160, internal host-100-126-132-61-*
- admissions.shisu.edu.cn (上外本科招生): siteId=15, admin leaks 10.2.7.161 (server IP)
- lib.shisu.edu.cn (上外图书馆): admin leaks 127.0.0.1 (localhost)
- graduate.shisu.edu.cn (上外研究生院): admin leaks client IP (reflection)
- info.shisu.edu.cn (上外信息公开): siteId=4, search returns parameter error
- news.shisu.edu.cn (上外新闻): CORS *
