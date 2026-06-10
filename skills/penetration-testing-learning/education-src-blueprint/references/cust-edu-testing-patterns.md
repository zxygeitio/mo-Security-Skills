# cust.edu.cn (长春理工大学) Testing Patterns

**Date**: 2026-06-02 (first round), 2026-06-09 (second round)
**Result**: 1 submitable vuln (CAS Open Redirect, 中危, submitted 06-02), 1 config issue (database ports, 中危)

## Target Profile

- **Main IPs**: 221.8.23.22 (www), 210.47.2.25 (ehall/idp/jwc/cxcy/lab), 210.47.2.22 (yjs/zzb/lib/cwc/tw/rsc), 221.8.23.23 (portal)
- **External IPs**: 121.37.5.226:8090 (Seeyon OA V8.0SP2), 114.116.241.75:8020 (Microsoft-HTTPAPI/2.0, 404 only)
- **CAS**: mysso.cust.edu.cn — Apereo CAS + PAC4J, JSESSIONID in URL, jQuery 3.3.1, captcha field present, WeChat OAuth integration (wx9d23c9b82a4ba0a9, wxeded6858b612a557)
- **WebVPN**: wwwn.cust.edu.cn (网瑞达 wengine-auth), vpn.cust.edu.cn (Astraeus VPN), webvpn.cust.edu.cn (custom with CAS integration)
- **ehall**: ehall.cust.edu.cn → 302 to wwwn.cust.edu.cn/wengine-auth → mysso.cust.edu.cn/cas — all behind WebVPN, JSONP APIs inaccessible
- **Portal**: portal.cust.edu.cn/custp — Shiro + CAS, no actuator/swagger exposed (403)
- **Seeyon OA**: 121.37.5.226:8090 — V8.0SP2, Server: SY8045, patched against all known CVEs
- **CMS**: ic.cust.edu.cn + ai.cust.edu.cn (博达CMS, static content), job.cust.edu.cn (JeeCMS, admin 404), zs.cust.edu.cn (jQuery 1.12.0)
- **Mail**: mail.cust.edu.cn (QQ企业邮箱, Server: Wwebsvr)
- **Shibboleth IdP**: idp.cust.edu.cn — SAML metadata exposed, CAS protocol also enabled on IdP
- **Subdomains**: 150+ found via subfinder, most behind WebVPN or 403 "阻断提示"

## Vulnerabilities Found

### CAS Open Redirect (中危) — SUBMITTED 2026-06-02
- **URL**: `https://mysso.cust.edu.cn/cas/login?service=https://evil.com/`
- **Root cause**: PAC4J CAS does not validate service parameter against whitelist
- **Evidence**: Service parameter rendered in form and clientredirect links for WeChatPublic/WeChat/QyWeChat
- **Attack**: User logs in → CAS redirects to evil.com with ticket → attacker steals ticket → accesses all CAS-protected systems
- **No password reset page** (getBackPasswordMainPage.do → 404)
- **No REST API** (/v1/tickets → 404)
- **Status endpoint** (/cas/status → 401 protected)

### Database Ports Exposed on Seeyon OA Server (中危) — NEW 2026-06-09
- **Target**: 121.37.5.226 (华为云ECS, ecs-121-37-5-226.compute.hwclouds-dns.com)
- **Open ports**: MySQL(3306), Redis(6379), MongoDB(27017), IIS(80), Seeyon(8090)
- **Evidence**: `nmap -sS -Pn -p 3306,6379,27017 121.37.5.226` → all three ports show "open"
- **Connection status**: nc/curl connections fail (tcpwrapped) — cloud security group allows SYN but blocks full handshake
- **Risk**: If firewall rules change, databases directly exposed. Redis/MongoDB default no-auth.
- **Note**: nmap SYN scan ≠ full connection. Report as "端口暴露" not "未授权访问".

### CAS Actuator Endpoints (低危) — NEW 2026-06-09
- /cas/actuator/health → 403 (exists, blocked by WAF/ACL)
- /cas/actuator/env → 403
- /cas/actuator/info → 403
- Spring Boot Actuator enabled on CAS server. 403 = endpoint exists but access denied.

### CAS Password Reset Flow — NEW 2026-06-09
- Password reset page: `_eventId=resetPassword` returns "密码重置" page
- Three verification channels: sendMsg('weschool'), sendMsg('qywechat'), sendMsg('aliyunsms')
- Requires captcha for submission
- sendMsg function: sets `$('#msgType').val(type)` then submits `$('#fm1')`
- No user enumeration confirmed (admin/test/nonexistent all return 401 on login)

### Seeyon OA — Negative Evidence
- Known vuln paths (wpsAssistServlet, htmlofficeservlet, ajax.do, test123456.jsp, autoinstall.do.css/..;/ajax.do) → all 404
- thirdpartyController.do → 200 empty body (GET), deserialization payloads return empty (POST)
- fileUpload.do → requires authentication ("被迫下线")
- REST APIs (/rest/token, /rest/orgMember, /rest/organization, /rest/department, /rest/user, /rest/flow, /rest/menu) → 401 or "被迫下线"
- CORS: Access-Control-Allow-Origin: * + Credentials: true on /rest/* endpoints, but APIs need auth
- /rest/token/identity → 200 with "提示信息：null" (SSRF not working)
- rest/token?service=http://... → returns "提示信息：null" (service parameter ignored)

### Other Negative Evidence
- ecard.cust.edu.cn → 192.168.222.176 (internal, unreachable)
- test.cust.edu.cn → 192.168.230.117 (internal, DNS leak)
- 210.47.2.25 ports 8080-8084 open but return 404 for all paths/hostnames
- 7 subdomains return "阻断提示" (WAF): kjy, air, cr, sjd, kjgd, lxyz, gxxyd
- ai.cust.edu.cn uses jQuery 1.7.2 (old) but static CMS, no upload/login/API
- job.cust.edu.cn JeeCMS admin at /jeeadmin/jeecms/index.do returns "就业信息管理系统" but all .do paths → 404
- Portal actuator: 403 (blocked)
- IIS on 121.37.5.226:80: Default IIS page, /trace.axd → 403, /aspnet_client/ → 403

### 2026-06-09 Deep Negative Evidence
- job.cust.edu.cn front-end references hjiuye.com public employment APIs with collegeId=1806. APIs reflect Origin + Credentials and return JSON, but data is public recruitment/brief/live/double-choose information rendered by the public home page; no student resume/apply/private data was confirmed.
- hjiuye detail endpoint guesses for position/brief/company/double/live IDs returned 404; no unauthenticated private detail expansion.
- hjiuye method boundary: OPTIONS allows only GET/HEAD/OPTIONS; POST/PUT/DELETE/PATCH return JSON "Request method ... not supported". CORS reflection + credentials remains but no unauthenticated write or private read was proven.
- job.cust.edu.cn JeeCMS search/admin paths return fixed 500 page with JeeCMS static assets only; no stack trace, SQL error, or source path disclosure.
- job.cust.edu.cn member/apply/file endpoints either return login redirect, {"result":-1}, or 404; no unauthenticated upload/download.
- yjsxt.cust.edu.cn/ssfw/login.jsp returns wengine 502; rsgl.cust.edu.cn redirects to CAS/WebVPN. /actuator/health and /actuator/env on yjsxt/rsgl return 403 only, same low-value presence signal as CAS.
- yzb.cust.edu.cn 2026 admission PDFs expose names, 15-digit candidate numbers, scores, ranks and admission status. This appears to be official public admission disclosure; no ID card or phone fields in sampled PDFs.
- yjsxx.cust.edu.cn postal-address modification system is referenced by yzb notice and reportedly logs in with public candidate number + SMS code. Direct probe timed out; yjszs/yjszsxx/yjsxt candidates resolve to 198.18.x.x private/benchmark range and are not publicly reachable from this environment. Treat as high-risk hypothesis only, not reportable without page/API evidence or SMS-flow proof.
- CUCAS third-party CUST application site exposes public school/program pages and `school_new/download?id=...`, but download endpoint returns Aliyun WAF challenge in browser and curl; no IDOR/private application document access proven.
- zsb.cust.edu.cn 2024 freshman handbook PDF contains QQ groups and teacher/student phone numbers, but this is public onboarding contact information and low-value; do not submit unless combined with a system-level flaw.
- Public pages expose AMap key 303e24733ada73ca23760ac77f19701b, but live call returns USER_DAILY_QUERY_OVER_LIMIT; no practical data/API abuse proven.

### 2026-06-09 Fourth Round Negative Evidence
- Public attachment search found scholarship XLSX, duty rosters, admissions PDFs, and HR/YJS application templates. Confirmed evidence is either official public disclosure, blank forms, or service guides; no complete real ID-card/phone/student private list was proven from accessible parsed content.
- `rsc.cust.edu.cn/docs/2025-06/b3a76aa97620486891d0be8d1304e6e6.xls` is indexed with fields such as ID number/mobile/email, but parsed content indicates an HR application form/template rather than submitted applicant data. Do not report unless rows with real persons are independently confirmed.
- `www.cust.edu.cn/docs//2026-04/e37b7794534648728d52c8e6cd83be05.xlsx` and `2026-03/4fed5481de934406b435fafd4c9a63f2.xlsx` are scholarship publicity lists. Treat as public award announcements; not a privacy leak unless excessive fields beyond name/college/award are proven.
- Information Center pages disclose business flows for email/network password reset, temporary cards, account unfreeze, campus card binding, and campus network default-password rules. All actionable operations are described as happening inside CAS/portal/Enterprise WeChat/party-mass service center with approval or 2FA; no unauthenticated reset API or direct submit endpoint was found via external index.
- Campus network docs state default password rules (`ID-card last six digits`) and Wi-Fi PSK `1234567890`, but this is a public onboarding configuration guide and requires on-campus network/account context; not submitable alone.
- Upload/component searches for UEditor/KindEditor/WebUploader/upload_json/filemanager across `cust.edu.cn` returned no exposed editor upload endpoint. Information-system deployment/upload is behind party-mass service center, VPN/bastion, and annual filing flow.
- Direct curl/browser access from this environment still frequently returns TLS EOF / ERR_CONNECTION_CLOSED / 000 for CUST hosts. Treat direct network failures as environment noise; use web_extract/search cache for triage and require reproducible direct evidence before reporting.

## CAS Apereo + PAC4J 指纹

- Server: none (hidden by WAF)
- Login page: "统一身份认证平台"
- jQuery 3.3.1, Bootstrap 4.1.0
- JS: cas.js, wxLogin.js, zxcvbn.js (password strength)
- Execution token: UUID_base64JWT format
- Password reset: _eventId=resetPassword (if available)
- Captcha: /cas/captcha (JPEG image)
- Status: /cas/status → 401 JSON {"timestamp":...,"status":401}
- CSP: frame-ancestors https://ic.cust.edu.cn https://potal.cust.edu.cn (typo: potal→portal)
- CAS on IdP: /idp/profile/cas/serviceValidate → 200 (CAS protocol on Shibboleth IdP)

## Stop Conditions for This Target
- CAS Open Redirect is the only exploitable vuln found (submitted 06-02)
- Database port exposure is config issue (中危, 06-09)
- Seeyon OA patched, no credentials available
- ehall/jwgl/etc all behind WebVPN, need CAS auth
- No SQLi/RCE/file-upload/auth-bypass found on any public endpoint
- **Recommendation**: Submit database port exposure if not already done, then move to next target
