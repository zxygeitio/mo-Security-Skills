# Education SRC Testing Patterns — 2026-05-28 Session Notes

## Schools Tested
- hzau.edu.cn (华中农业大学) — CERNET, 280+ subdomains
- cdut.edu.cn (成都理工大学) — CERNET, 250+ subdomains
- suat-sz.edu.cn (深圳理工大学) — Tencent Cloud, 45+ subdomains

## hzau.edu.cn — Confirmed Vulnerabilities (2 submitted)

### VSB CMS getSession.jsp (14+ subdomains)
- www / my(统一门户) / zs(招生网) / yjs(研究生院) / ai(智慧狮山) / hospital(校医院)
- cwb(财务处) / hq(后勤) / jsgzb / jxjy(继续教育) / jwb(纪检委) / cf(水产学院) / bx / shop
- Each request returns unique 32-hex JSESSIONID in response body
- getToken.jsp returns "preview" (CMS preview mode token)

### CRMEB E-commerce System (shop.hzau.edu.cn)
- Server: Tengine, PHP, PHPSESSID
- CORS: reflects any Origin + Credentials:true on all API endpoints
- Unauthenticated APIs:
  - /api/products → real product data (id, name, price, stock, image URLs)
  - /api/category → full category tree
  - /api/verify_code → bcrypt hash key + expire_time
  - /api/pink → group buying data
- /admin/ → SPA admin panel accessible
- Report: /tmp/vuln_reports/hzau/

### VMware Horizon (desktop.hzau.edu.cn)
- Title: "华中农业大学云桌面"
- /portal/info.jsp → JSON: clientVersion "5.0.0", installerLink leaks internal URL
- JSESSIONIDHTMLACCESS cookie set
- Other paths return 404

### Key Infrastructure
- WebberRASP WAF (X-Protected-By header, 15789-byte 403 pages)
- CSP leaks internal domains: portal-minio/leoagent/agentest + internal IPs (211.69.128.x)
- Shibboleth IdP (idp.hzau.edu.cn) — SAML metadata + Tomcat/7.0.76 version leak
- 360eol robot integration on zs (schoolId in CSP)

## cdut.edu.cn — No Submittable Vulnerabilities

### Anti-Bot Protection Pattern (412 Precondition Failed)
- Most subdomains return HTTP 412 with ~2.4KB response
- Server header masked: `Server: ******`
- Set-Cookie with random name + obfuscated JS (anti-bot fingerprint)
- Only ~6 subdomains accessible from external IP

### AnyShare Netdisk (pan.cdut.edu.cn)
- 302 → /anyshare/ (React SPA)
- CORS: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`
- All API paths return SPA HTML shell (6709 bytes) — SPA fallback, not real API
- Browser blocks `*` + credentials per spec → not exploitable
- Conclusion: CORS config intent wrong but not exploitable

### Sangfor SSL VPN (vpn.cdut.edu.cn)
- /por/login_auth.csp → XML login config (TwfID, CSRF, enablesavepwd, enableautologin)
- Low severity info leak

### xsfw.cdut.edu.cn (金智教育 emap)
- Redis connection error: `failed to connect redis:closedset keepalive error : closed`
- All endpoints return same error — backend infrastructure leak

### Kubernetes Default Backend
- identity.cdut.edu.cn → "default backend - 404" (K8s exposed)

## suat-sz.edu.cn — No Submittable Vulnerabilities

### VSB CMS getSession.jsp BLOCKED Pattern
- 11 subdomains confirmed VSB CMS (counter.js + _sitegray.js = 200)
- getSession.jsp returns custom "系统提示 - 抱歉 - 您访问的页面未找到" (NOT JSESSIONID)
- getToken.jsp same blocked response
- This is a DIFFERENT pattern from hzau where getSession.jsp returns JSESSIONIDs
- Key: VSB CMS presence (counter.js) does NOT guarantee getSession.jsp is vulnerable

### DMARC p=none + QQ Exmail
- `dig +short _dmarc.suat-sz.edu.cn TXT` → `v=DMARC1;p=none;`
- SPF: `v=spf1 include:spf.mail.qq.com ~all`
- Same pattern as many Chinese universities using QQ Exmail
- Not submittable alone — need actual spoofed email proof

### aTrust 2.0 Zero-Trust VPN (hr.suat-sz.edu.cn)
- Server: Sangine (深信服)
- 302 → vpn.suat-sz.edu.cn:443/controller/v1/public/verify?t=eyJhbG...
- Title: "aTrust 2.0"
- All internal systems behind VPN authentication gateway

### Key Pattern: VSB CMS getSession.jsp Testing Decision Tree
```
1. Check _sitegray/_sitegray.js → 200 = VSB CMS confirmed
2. Test getSession.jsp:
   a. Returns 32-hex JSESSIONID → VULNERABLE (e.g., hzau.edu.cn)
   b. Returns custom 404/error page → BLOCKED (e.g., suat-sz.edu.cn)
   c. Returns SPA HTML → SPA fallback, not VSB path (newer deployment)
3. If blocked on www, test OTHER subdomains (zs/yjs/oa/lib/news)
   — different subdomains may have different protection levels
4. Even if getSession.jsp blocked, check:
   - /system/resource/sensitiveFilter.jsp (POST owner+content)
   - /system/resource/code/datainput.jsp (returns Set-Cookie: JSESSIONID)
   - /_dwr/ (DWR test page)
   - /system/resource/openapp/ (OpenApp endpoints)
```

## Report Paths
- /tmp/vuln_reports/hzau/hzau-final-vulnerability-reports.txt
- /tmp/vuln_reports/hzau/hzau-vsb-getsession-jsessionid-leak.txt
