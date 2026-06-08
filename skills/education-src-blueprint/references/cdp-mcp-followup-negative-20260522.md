# CDP cdp.edu.cn MCP-assisted follow-up negative evidence (2026-05-22)

## Scope
Target: `cdp.edu.cn` / `www.cdp.edu.cn` / selected subdomains after prior low-value findings were already known.

Use this as a session-specific evidence pack under the education SRC umbrella. It is not a standalone vulnerability report.

## Tools and MCP discipline
- HexStrike MCP was useful for class-level recon: `subfinder`, `whatweb`, `waf_detection`, `nikto`, and attempted `nuclei`.
- Burp MCP health check distinguished setup state from target evidence: proxy `127.0.0.1:8080` was not reachable because Burp was not running. Do not phrase that as "Burp MCP broken"; it is an external service state.
- Treat MCP scanner output as triage only. `nikto` no findings, `whatweb` fingerprints, and `nuclei` timeout/no output are not vulnerability evidence. Only manually verified HTTP behavior should be promoted to a report.

## Verified outcomes

### Subdomain recon
HexStrike `subfinder` returned assets including:
`sdmg.sad`, `zhao`, `aic`, `cas`, `jy-hr`, `newvpn`, `special`, `www-443.webvpn`, `course`, `ehall`, `sicsve`, `www`, `kcsz`, `uia`, `ehall-443.webvpn`, `app-vsmg`, `jy-js`, `jy-o`, `jedu`, `yikatong`, `webvpn`, `tafe`, `cas-443.webvpn`, `zyk`, `jw`, `dzmg`, `welcome`, `nac`, `jy` under `cdp.edu.cn`.

Decision: asset inventory only. It does not establish a vulnerability.

### yikatong.cdp.edu.cn
- `whatweb`: HTTP 200, title `校园生活服务`, nginx/1.26.1, HSTS/XFO present.
- `wafw00f`: no generic WAF detected.
- `nikto` with short time limit: no actionable findings.
- Manual API checks showed public helper/validation behavior and protected business APIs:
  - `/server/auth/getEncrypt`: public encryption helper / parameter validation only.
  - `/server/captcha/get` and `/server/captcha/check`: challenge generation/validation; no bypass evidence.
  - `/server/home/sendSms`: requires phone, image code, image code id, org id; historical wrong-code test returned image-code failure.
  - `/server/user/info`, trade/card/balance/order/upload/swagger/actuator/druid paths: mostly 401 or failure objects. Historical decrypt of `/server/user/info` was only `{"code":"","message":"失败","success":false}`.

Decision: do not submit. No sensitive data, IDOR, upload success, business write, SMS abuse, or captcha bypass was proven.

### www / ehall / CAS / VSB-DWR paths
Covered paths:
- `www.cdp.edu.cn`: `/_dwr/interface/FestivalHelperDWR.js`, `/_dwr/engine.js`, `/_web/_search/api/search/new.rst`, `/system/resource/getToken.jsp`, `/.git/HEAD`, `/WEB-INF/web.xml`, random nonexistent control.
- `ehall.cdp.edu.cn`: `/api/authc/systemSetting/`, `/api/authc/user/info`, `/api/authc/service`, `/api/authc/message/unread`, `/api/docrepo/download`, `/jsonp/school.json`, `/jsonp/serviceCenterData.json`, `/jsonp/appIntroduction.json`, with and without fake `Loginuserorgid/Loginuserid` headers.
- `cas.cdp.edu.cn`: `/authserver/login`, password-recovery page, `validatePasswordAjax`.

Observed: no stable unauthenticated business data, process/todo/attachment content, CAS ticket/code/token, password-reset bypass, or user enumeration differential.

Decision: do not submit. Unstable/unreachable responses and lack of data are negative evidence, not a vulnerability.

### Edge subdomains
Short-timeout checks against `zhao`, `special`, `course`, `sicsve`, `kcsz`, `uia`, `app-vsmg`, `jy-js`, `jy-o`, `jedu`, `tafe`, `zyk`, `dzmg`, `welcome`, `nac`, `newvpn` did not yield stable exploitable business responses or exposed swagger/actuator/upload/go-fastdfs/admin bypass.

Decision: do not submit.

### mail.cdp.edu.cn
- MX: Tencent Enterprise Mail (`mxbiz1.qq.com`, `mxbiz2.qq.com`).
- SPF: `v=spf1 include:spf.mail.qq.com ~all`.
- DMARC: no TXT found at `_dmarc.cdp.edu.cn`.
- Low-impact login probes with nonexistent users showed Tencent standard login/error behavior; no account takeover or sensitive leakage.

Decision: do not submit. DMARC missing/SPF softfail/standard Tencent behavior is too low-value without actual authorized spoofing-delivery proof or account takeover chain.

## Evidence artifact pattern
For this target class, when no report is warranted, write a negative conclusion file instead of forcing a low-quality report. In this session the final artifact shape was:

- Conclusion: explicitly `不建议提交`.
- MCP/tool status: separate setup/service state (e.g. Burp not running) from target findings.
- Per-asset evidence paths and endpoint summaries.
- Clear reason each candidate fails the SRC threshold.
- Resume conditions.

Suggested output path pattern:
`/tmp/vuln_reports/cdp/deep-recon-YYYYMMDD-final-followup.txt`

## Resume conditions
Resume only if at least one is available:
1. A legal test account to check yikatong IDOR/authorization around `tradeList`, `cardList`, `balance`, report-loss/cancel-loss/reset-password flows.
2. A proven `captcha/check` bypass/reuse that triggers SMS or a sensitive account action.
3. An unauthenticated ehall/CAS/aic/webvpn API returning real personnel, attachments, process/todo data, tickets, or write capability.
4. Authorized mail spoofing delivery proof or an account takeover chain, not just DNS policy weakness.
