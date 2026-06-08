# cust.edu.cn (长春理工大学) Testing Patterns

**Date**: 2026-06-02
**Result**: 1 submitable vuln (CAS Open Redirect, 中危), rest negative evidence

## Target Profile

- **Main IPs**: 221.8.23.22 (www), 210.47.2.25 (ehall/idp/jwc/cxcy/lab), 210.47.2.22 (yjs/zzb/lib/cwc/tw/rsc), 221.8.23.23 (portal)
- **External IPs**: 121.37.5.226:8090 (Seeyon OA V8.0SP2), 114.116.241.75:8020 (Microsoft-HTTPAPI/2.0, 404 only)
- **CAS**: mysso.cust.edu.cn — Apereo CAS + PAC4J, JSESSIONID in URL, jQuery 3.3.1, captcha field present, WeChat OAuth integration (wx9d23c9b82a4ba0a9, wxeded6858b612a557)
- **WebVPN**: wwwn.cust.edu.cn (网瑞达 wengine-auth), vpn.cust.edu.cn (Astraeus VPN), webvpn.cust.edu.cn (custom)
- **ehall**: ehall.cust.edu.cn → 302 to wwwn.cust.edu.cn/wengine-auth → mysso.cust.edu.cn/cas — all behind WebVPN, JSONP APIs inaccessible
- **Portal**: portal.cust.edu.cn/custp — Shiro + CAS, no actuator/swagger exposed
- **Seeyon OA**: 121.37.5.226:8090 — V8.0SP2, Server: SY8045, patched against all known CVEs
- **CMS**: ic.cust.edu.cn + ai.cust.edu.cn (博达CMS, static content), job.cust.edu.cn (JeeCMS, admin 404), zs.cust.edu.cn (jQuery 1.12.0)
- **Mail**: mail.cust.edu.cn (QQ企业邮箱, Server: Wwebsvr)
- **Subdomains**: 200+ found via subfinder, most behind WebVPN or 403 "阻断提示"

## Vulnerabilities Found

### CAS Open Redirect (中危) — SUBMITTED
- **URL**: `https://mysso.cust.edu.cn/cas/login?service=https://evil.com/`
- **Root cause**: PAC4J CAS does not validate service parameter against whitelist
- **Evidence**: Service parameter rendered in form and clientredirect links for WeChatPublic/WeChat/QyWeChat
- **Attack**: User logs in → CAS redirects to evil.com with ticket → attacker steals ticket → accesses all CAS-protected systems
- **No password reset page** (getBackPasswordMainPage.do → 404)
- **No REST API** (/v1/tickets → 404)
- **Status endpoint** (/cas/status → 401 protected)

### Seeyon OA — Negative Evidence
- Known vuln paths (wpsAssistServlet, htmlofficeservlet, ajax.do, test123456.jsp, autoinstall.do.css/..;/ajax.do) → all 404
- thirdpartyController.do → 200 empty body, but SSRF payloads return empty/no response (not exploitable)
- fileUpload.do → requires authentication ("被迫下线")
- REST APIs (/rest/token, /rest/orgMember, /rest/orgDepartment, /rest/flow, etc.) → 401 or "被迫下线"
- CORS: Access-Control-Allow-Origin: * + Credentials: true on /rest/session endpoints, but APIs need auth
- JSESSIONID URL leak in HTML content (codebase="/seeyon/common/setup/install.cab;jsessionid=...")
- **Conclusion**: System patched, not exploitable without credentials

### Other Negative Evidence
- ecard.cust.edu.cn → 192.168.222.176 (internal, unreachable)
- test.cust.edu.cn → 192.168.230.117 (internal, DNS leak)
- 210.47.2.25 ports 8080-8084 open but return 404 for all paths/hostnames
- 7 subdomains return "阻断提示" (WAF): kjy, air, cr, sjd, kjgd, lxyz, gxxyd
- ai.cust.edu.cn uses jQuery 1.7.2 (old) but static CMS, no upload/login/API
- job.cust.edu.cn JeeCMS admin at /jeeadmin/jeecms/index.do returns "就业信息管理系统" but all .do paths → 404

## Stop Conditions for This Target
- CAS Open Redirect is the only exploitable vuln found
- Seeyon OA patched, no credentials available
- ehall/jwgl/etc all behind WebVPN, need CAS auth
- No SQLi/RCE/file-upload/auth-bypass found on any public endpoint
- **Recommendation**: Move to next target unless new assets discovered
