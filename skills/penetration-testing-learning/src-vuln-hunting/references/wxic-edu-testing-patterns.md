# Wxic.edu.cn Education SRC Testing Patterns (2026-05)

Target: 无锡商业职业技术学院 (wxic.edu.cn) — 联奕科技统一门户平台 + 教学资源共享平台 + 网易企业邮 + wengine WAF.

## Confirmed findings

### 1. DMARC p=none 邮件伪造风险 (中危)

**DNS records**:
```
_dmarc.wxic.edu.cn TXT → "v=DMARC1; p=none; fo=1; ruf=mailto:dmarc@qiye.163.com; rua=mailto:dmarc_report@qiye.163.com"
wxic.edu.cn TXT → "v=spf1 include:spf.163.com -all" (hard fail, good)
default._domainkey.wxic.edu.cn TXT → (empty, no DKIM)
MX → 10 qiye163mx01.mxmail.netease.com, 50 qiye163mx02.mxmail.netease.com
```

**Impact**: DMARC p=none means receiving servers won't reject spoofed emails. SPF is correctly configured with -all, but without DMARC enforcement, spoofed emails may still be delivered.

**Report angle**: "DMARC策略配置不当存在邮件伪造漏洞" — 中危. Requires demonstrating actual email spoofing capability.

### 2. SM4加密密钥硬编码泄露 (中危)

**Location**: `https://jxjyxt.wxic.edu.cn/js/des.js`

**Key discovery**: File named `des.js` but actually contains SM4 encryption implementation (obfuscated). Two hardcoded keys found:
- Key 1: `5BD730C485F2AF10` (primary)
- Key 2: `90ACB357C1AC99D4` (set dynamically via `secretKey`)

**SM4 identifiers in code**:
- `SM4_ENCRYPT`, `SM4_DECRYPT`
- `sm4_crypt_ecb`, `sm4_crypt_cbc`
- `sm4Sbox`, `sm4_one_round`
- `encryptData_CBC`

**Usage**: Password encryption on login form. The login page (`/login`) includes:
- `src="/js/des.js?_CP_="` — SM4 encryption library
- `src="/js/commonlogin/js/login/login.js?_CP_="` — Login logic
- Passwords encrypted with SM4 before submission

**Report angle**: "教学资源共享平台SM4加密密钥硬编码泄露" — 中危. Keys can decrypt intercepted passwords or construct encrypted passwords for brute force.

### 3. 新闻公告_enctoken未验证 (低危)

**Endpoint**: `GET /mh/news/info?_enctoken=<token>&id=<id>&typeid=<typeid>`

**Verification**:
```bash
# With valid token → 4484 bytes (real content)
curl -sk 'https://jxjyxt.wxic.edu.cn/mh/news/info?_enctoken=017e3ad6bcc27d07fee647bc515fd919&id=1725&typeid=706'
# Without token → 4484 bytes (same!)
curl -sk 'https://jxjyxt.wxic.edu.cn/mh/news/info?id=1725&typeid=706'
# Wrong token → 4484 bytes (same!)
curl -sk 'https://jxjyxt.wxic.edu.cn/mh/news/info?_enctoken=aaaa&id=1725&typeid=706'
```

**Finding**: _enctoken parameter is decorative, not validated. News content accessible without authentication.

**ID enumeration**: Different IDs return different content (id=1725 → 4484 bytes, id=1 → 2641 bytes). News range appears limited (ids 1500-2000 mostly return 2641 bytes "not found" page).

### 4. 客户端验证码可绕过 (低危)

**CAPTCHA system**: 超星(captcha.chaoxing.com)

**Location**: `https://jxjyxt.wxic.edu.cn/js/commonlogin/js/loadSlide.js`

**Implementation**:
```javascript
document.write("<script type=\"text/javascript\" src=\"https://captcha.chaoxing.com/load.min.js\"></script>");
initCXCaptcha({
    captchaId: 'gEzr3RQauRL9tpUR8s72r0Smb8lyLDZq',
    element: '#captcha',
    mode: 'popup',
    onVerify: function (err, data) {
        $("#verifyCode").val(data.validate);
    }
});
```

**Also**: gVerify.js (client-side graphical CAPTCHA) — completely client-side, no server validation.

**Report angle**: "客户端验证码可绕过" — 低危. CAPTCHA can be bypassed programmatically.

### 5. 开发者信息泄露 (低危)

**Location**: `https://portal.wxic.edu.cn/assets/js/config.js`

**Leaked info**:
```javascript
/*
 * @Author: dengZiJian dengzijian@ly-sky.com
 * @Date: 2022-07-15 13:55:56
 * @LastEditors: dengZiJian dengzijian@ly-sky.com
 * @LastEditTime: 2023-06-20 11:08:05
 * @FilePath: \\ly-upp-site-ui\\assets\\js\\config.js
 */
```

**Vendor**: 联奕科技 (ly-sky.com)
**Product**: ly-upp-site-ui (联奕统一门户平台)
**Developers**: dengZiJian, liyaochuan, chenlei@ly-sky.com

## Technical patterns

### wengine WAF fingerprinting

**Detection**: Blocked pages return:
```html
<img src="/wengine-auth-failed.png" alt="">
<h3>出错啦！您没有权限访问该网站，可能的原因为</h3>
<div>(错误代码：403)</div>
```

**Behavior**:
- Server header: "none" (stripped)
- Blocks: .git, /actuator, /swagger, /druid paths
- Returns 200 initially then serves block page (may be bypassable)
- Custom 404 page: "访问出错 - 404"
- Custom 502 page: "访问出错 - 502"

**Tengine indicator**: Some paths return Tengine default 403:
```html
<title>403 Forbidden</title>
<hr><center>tengine</center>
<!-- event_id: xxx TYPE: A -->
```

### 联奕科技(ly-sky.com) 统一门户平台 fingerprinting

**Detection**:
- JS files: `config.js` with `ly-upp-site-ui` path
- Developer comments: `@ly-sky.com` email domain
- Config structure: `window.config = { firstRoute:'index', isTool: true, ... }`
- Card components: `cardType.js`, `cardComponents.js`
- Locale: `locale.js` with zh_CN/en_US

**Known paths**:
- `/assets/js/config.js` — Configuration
- `/assets/js/cardType.js` — Card component types
- `/assets/js/cardComponents.js` — Card components
- `/assets/js/locale.js` — Language settings

### jxjyxt 教学资源共享平台 fingerprinting

**Detection**:
- URL pattern: `jxjyxt.<domain>`
- Login page: `/login` with SM4 encryption
- News portal: `/mh/` (门户首页)
- robots.txt: `Disallow: /`, `Allow: /mh`
- Cookie: `schoolId=<id>; Domain=<domain>; Path=/; HttpOnly`
- JSESSIONID suffix: `.jvm14111` or `.jvmjxjyxt112`
- Server: Tengine

**Key endpoints**:
- `/login` — Login page (SM4 encrypted passwords)
- `/mh/` — News portal (public)
- `/mh/news/info?id=<id>&typeid=<typeid>` — News articles (no auth required)
- `/mh/news/notice` — Notice list
- `/mh/topjs?index=<n>` — Dynamic JS loader
- `/commonlogin/phonecode` — Phone login
- `/commonlogin/changephone` — Change phone
- `/admin/` — Admin panel (requires auth, returns 404 without)

**CAPTCHA**: 超星(captcha.chaoxing.com) with captchaId

### NetEase Enterprise Email (qiye.163.com) fingerprinting

**Detection**:
- MX records: `qiye163mx01.mxmail.netease.com`, `qiye163mx02.mxmail.netease.com`
- Login form: `action="https://entry.qiye.163.com/domain/domainEntLogin"`
- Headers: `x-cache: from ntes_qiye`, `lingxi-traceid: <id>`
- Admin panel: `/admin/` → redirects to `mailhz.qiye.163.com/static/admin/404.html`

**Login form fields**:
```html
<input type="hidden" name="domain" value="<domain>"/>
<input type="radio" name="type" value="0"/>  <!-- staff -->
<input type="radio" name="type" value="1"/>  <!-- student -->
```

**Not Coremail**: Coremail-specific endpoints (/coremail/s/json, /mailms/s) return FA_INVALID_SESSION or 404.

## Subdomain inventory (56 found)

**Accessible (200 OK)**:
- portal.wxic.edu.cn — 联奕统一门户平台
- my.wxic.edu.cn — 统一权限平台 (SPA, all /api/* redirect to HTTP)
- mail.wxic.edu.cn — 网易企业邮箱
- vpn.wxic.edu.cn — VPN网关 (JS-heavy, noindex)
- jxjyxt.wxic.edu.cn — 教学资源共享平台 (WAF may block)

**WAF blocked (403)**:
- ehall.wxic.edu.cn — 办事大厅 (wengine-auth-failed)
- djts.wxic.edu.cn — 党建 (wengine-auth-failed)
- jd.wxic.edu.cn — (wengine-auth-failed)

**502 Bad Gateway**:
- elearning, jwgl, jwgln, ddh, erpkc, pgzy, jxzg, jwc

**DNS-only (no HTTP)**:
- oa, zs, kyxt, xxgk, cw, hg, bw, bs, ca, cy, etc.

**Infrastructure**:
- dns1/dns2.wxic.edu.cn — Self-hosted DNS (58.193.112.x)
- ns1/ns3.wxic.edu.cn — Nameservers
- mail.stu.wxic.edu.cn — Student email

## Not recommended for submission

- **News IDOR**: News content is public-facing, _enctoken is decorative — low impact, same as public website content
- **schoolId cookie**: Set on domain wxic.edu.cn but manipulation has no demonstrated impact
- **Developer info leak**: Low impact, vendor info is semi-public
- **Client-side CAPTCHA**: gVerify.js is weak but 超星 CAPTCHA is industry standard — need proof of bypass

## Additional findings (continued testing)

### 6. 致远OA CORS配置不当 (中危)

**Location**: `oa.wxic.edu.cn/seeyon/rest/*`

**Version**: V8.0SP1 (V8_0SP1_201101_29551)

**CORS headers on ALL REST endpoints**:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: origin, content-type, accept, authorization
Access-Control-Expose-Headers: LoginOK,LoginError
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD
```

**Affected endpoints**: /seeyon/rest/orgMember, /rest/service, /rest/organization, /rest/department, /rest/user, /rest/session

**Note**: Modern browsers block `ACAO: *` + `Credentials: true` combination, but the misconfiguration still indicates poor security practice and may be exploitable in certain scenarios.

### 7. 致远OA JSESSIONID URL泄露 (低危)

**Location**: `oa.wxic.edu.cn/seeyon/main.do`

**Evidence**:
```
jsessionid=F2D3F91E200FDA3E6431730CF5622501
```
JSESSIONID exposed in URLs and OBJECT codebase attributes. Can be leaked via Referer headers, browser history, proxy logs.

### 8. 多部门网站Druid监控端点 (低危)

**Affected**: All accessible subdomains (bw, fgc, gh, gj, hg, jcb, jj, jjc, kj, kjc, ly, rs, sz, tsg, xc, xg, zpc, etc.)

**Behavior**: `/druid/` → 302 → `/druid/main.psp` (returns "访问禁止" page)

**Exception**: `ztb.wxic.edu.cn/druid/login.html` returns actual Druid monitor login page (title: "druid monitor"), but default credentials (admin/druid, admin/admin, root/root) all return "error".

## Attack surface map (updated)

```
wxic.edu.cn (61.177.124.50)
├── www.wxic.edu.cn (502 - main site down)
├── portal.wxic.edu.cn (联奕统一门户)
├── my.wxic.edu.cn (统一权限平台)
├── jxjyxt.wxic.edu.cn (教学资源共享) ← Main target
│   ├── /login (SM4 encrypted)
│   ├── /mh/ (news portal, no auth)
│   └── /admin/ (requires auth)
├── oa.wxic.edu.cn (致远OA V8.0SP1) ← New finding
│   ├── /seeyon/rest/* (CORS vuln)
│   └── /seeyon/main.do (JSESSIONID URL leak)
├── mail.wxic.edu.cn (网易企业邮)
├── vpn.wxic.edu.cn (VPN)
├── ehall.wxic.edu.cn (403 WAF)
├── ztb.wxic.edu.cn (招标网, Druid login accessible)
└── [50+ subdomains: mostly 502 or DNS-only]
    └── 20+ department sites with /druid/ endpoint
```
