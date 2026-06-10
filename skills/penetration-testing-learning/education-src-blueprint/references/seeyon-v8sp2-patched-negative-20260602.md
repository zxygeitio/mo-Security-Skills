# Seeyon OA V8.0SP2 Patched State (2026-06-02 cust.edu.cn)

## Target: 121.37.5.226:8090 (长春理工大学 Seeyon A6 V8.0SP2)
- Server: SY8045
- CSS/JS version string: V8_0SP2_211020_2025240
- Title: "长春理工协同管理软件.A6 V8.0SP2"

## All Known Vuln Paths Return 404

| Path | Status | Notes |
|------|--------|-------|
| /wpsAssistServlet | 404 | File upload vuln (CNNVD-2021-01627) — patched |
| /htmlofficeservlet | 404 | File upload vuln — patched |
| /thirdpartyController.do.css/..;/ajax.do | 404 | RCE via autoinstall — patched |
| /autoinstall.do.css/..;/ajax.do | 404 | Config file read — patched |
| /test123456.jsp | 404 | Backdoor check — patched |
| /downloadServlet | 404 | Arbitrary file download — patched |
| /management/index.jsp | 404 | Admin console — disabled |
| /rest/token/{user}/{pass} | 401 | REST token — protected |
| /rest/orgMember | 404 | API — not exposed |
| /rest/orgDepartment | 1010 "被迫下线" | Requires auth |
| /rest/flow | 1010 "被迫下线" | Requires auth |
| /rest/formdata | 1010 "被迫下线" | Requires auth |
| /rest/bulletin | 1010 "被迫下线" | Requires auth |
| /rest/message | 1010 "被迫下线" | Requires auth |
| /rest/addressBook | 1010 "被迫下线" | Requires auth |
| /rest/person | 1010 "被迫下线" | Requires auth |
| /rest/contact | 1010 "被迫下线" | Requires auth |
| /rest/session | 1010 "被迫下线" | Requires auth |
| /rest/statistics | 1010 "被迫下线" | Requires auth |

## Still Present (Not Exploitable)

| Path | Status | Notes |
|------|--------|-------|
| /thirdpartyController.do (GET) | 200 empty body | SSRF payloads return empty — not exploitable |
| /fileUpload.do | 200 "被迫下线" | Requires auth session |
| JSESSIONID in HTML | Present | codebase="/seeyon/common/setup/install.cab;jsessionid=..." |
| CORS | Access-Control-Allow-Origin: * | + Credentials:true, but all APIs need auth |

## Decision
V8.0SP2 with build date 2025-10-20 is fully patched against all known public CVEs. Do not spend more than 5 requests testing Seeyon OA V8.0SP2 unless new CVE is published.

## CORS Note
The Seeyon OA REST endpoints return `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. This is a known Seeyon default config. However, since ALL data endpoints require authentication (return code 1010 "被迫下线"), the CORS misconfiguration cannot be exploited to steal data. **Do not submit as standalone CORS vuln** — it's defense-in-depth failure but has no practical impact without auth bypass.
