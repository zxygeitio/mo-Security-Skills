# bzuu.edu.cn 2026-05-24 follow-up: high-value negative verification and pivot map

Purpose: reusable follow-up notes for Bozhou University / bzuu.edu.cn when the user asks for high-risk logic bugs. This is not a report template; it records what was actually verified and where future effort should pivot.

## High-level outcome

**2026-05-27:** go-fastdfs `?download=0` HTML rendering phishing angle verified as HIGH-RISK. Submitted. See `references/bzuu-gofastdfs-phishing-20260527.md` for full evidence.

**2026-05-27:** CORS misconfiguration found on three systems:
- zscq.bzuu.edu.cn (知识产权系统) — all API endpoints reflect arbitrary Origin + Credentials
- ekta.bzuu.edu.cn (第二课堂-学生端) — student/user/my-info reflects arbitrary Origin + Credentials
- ektm.bzuu.edu.cn (第二课堂-管理端) — student/user/my-info reflects arbitrary Origin + Credentials
These are separate from the go-fastdfs finding and can be submitted independently.

No other new high-risk-or-above issue was verified in the 2026-05-24 or 2026-05-27 passes.

The previously known `oshall.bzuu.edu.cn` go-fastdfs info-disclosure issue remains the same root cause. The phishing angle (HTML rendering via `?download=0`) is a distinct, higher-severity finding.

## Asset map observed

- `www.bzuu.edu.cn`: main portal, nginx. Many arbitrary paths redirect to `/<path>/main.psp` and return similar content after following redirects; treat this as portal fallback / pseudo-200, not real Actuator/Swagger/admin exposure.
- `oshall.bzuu.edu.cn`: online service hall + go-fastdfs. **CORS: Access-Control-Allow-Origin: * (通配符型). go-fastdfs ?download=0 HTML渲染已提交.**
- `auth.bzuu.edu.cn`: CAS/authserver.
- `vpn.bzuu.edu.cn`, `oa.bzuu.edu.cn`: Sangfor/SSL VPN style portal.
- `webvpn1.bzuu.edu.cn`, `rhmh.bzuu.edu.cn`: WebVPN / guest-session / redirected portal candidates.
- `jwxt.bzuu.edu.cn`: teaching administration, CAS protected, `verifycode.servlet` exists.
- `jyxt.bzuu.edu.cn`: ASP.NET / IIS project-management login system; login, SMS, and password reset logic is the main future logic-bug candidate.
- `ekta.bzuu.edu.cn`: second-classroom SPA (student-facing). **CORS漏洞: student/user/my-info反射任意Origin + Credentials.**
- `ektm.bzuu.edu.cn`: second-classroom SPA (admin-facing). **CORS漏洞: student/user/my-info反射任意Origin + Credentials.**
- `ektdv.bzuu.edu.cn`: 第二课堂数据可视化平台.
- `zscq.bzuu.edu.cn`: 知识产权信息公共服务网点. **CORS漏洞: 所有API反射任意Origin + Credentials.**
- `hr.bzuu.edu.cn`, `file.bzuu.edu.cn`, `live.bzuu.edu.cn`: Jinshan HCM (金蝶人事系统), same instance on 211.141.201.153.
- `idp.bzuu.edu.cn`: Shibboleth IdP Server.
- `mail.bzuu.edu.cn`: NetEase enterprise mail MX/login surface.
- `exchange.bzuu.edu.cn`: 10.10.36.174 (CERNET internal, not externally accessible).

## Confirmed historical go-fastdfs state

`https://oshall.bzuu.edu.cn/fileServer/status` still returns unauthenticated JSON with:

- `Fs.Local`: `http://10.10.36.161:8080`
- file stats, including all-time file count and total uploaded size
- `Sys.DiskInfo`: `/home/go-fastdfs`, filesystem, free/used/total
- `Sys.MemInfo`, `Sys.NumCpu`, `Sys.NumGoroutine`

`https://oshall.bzuu.edu.cn/fileServer/static/uppy.html` still returns the go-fastdfs upload demo page and includes example `auth_token` in commented metadata.

`POST https://oshall.bzuu.edu.cn/fileServer/upload` with `output=json2` and `scene=default` still allows low-impact text-file upload. Access requires prefixing the returned path with `/fileServer`, e.g. returned `/default/.../file.txt` is accessed as:

`https://oshall.bzuu.edu.cn/fileServer/default/.../file.txt`

Default file response is `Content-Type: application/octet-stream` with `Content-Disposition: attachment`; **adding `?download=0` returns the actual MIME type — for HTML files this becomes `text/html; charset=utf-8`, which the browser WILL render.** This was verified 2026-05-27: uploading a phishing HTML and accessing with `?download=0` rendered a full "亳州学院统一身份认证" login page on the trusted `oshall.bzuu.edu.cn` domain. Report angle: "未授权文件上传可在可信域名构造钓鱼页面" (高危).

## Online service hall / zhxy API negative checks

`/zhxy/env.js` exposes `domianURL`, `casUrl`, `imgUrl`, `wxAppId`, `tbAppId`, and `fileUploadUrl`. Treat these as recon leads only.

Relevant JS files:

- `/zhxy/static/js/app.<hash>.js`
- `/zhxy/static/js/app-legacy.<hash>.js`
- `/zhxy/static/js/chunk-vendors.<hash>.js`
- `/zhxy/static/js/chunk-vendors-legacy.<hash>.js`

Extracted API leads included `/sys/common/upload`, `/sys/permission/getUserPermissionByToken`, `/sys/dict/*`, `/sys/role/list`, `/sys/user/*`, `/sys/common/download*`, `/sysDepart/queryTreeList`.

Unauthenticated probes returned either 401 `Token失效，请重新登录`, 302 to `/zhxy/home`, or 404. No unauthenticated data read, business upload, export, delete, or privilege action was verified.

## CAS/authserver negative checks

Checked:

- `/authserver/login`
- `/authserver/status`
- `/authserver/loginParam`
- `/authserver/getBackPasswordMainPage.do`
- `/authserver/validatePasswordAjax.do`
- `/authserver/serviceValidate`
- `/authserver/samlValidate`
- OAuth authorize with arbitrary `redirect_uri`

Observed: login page and public login parameters; `/status` is 401; password reset endpoints tested here were 404; `serviceValidate` returned standard CAS error; OAuth test redirected to a CAS example/service flow, not a proven open redirect. Do not report these without new exploit evidence.

## VPN/OA negative checks

Sangfor-style endpoints checked:

- `/por/login_auth.csp`
- `/por/get_sms.csp`
- `/por/login_sms.csp`
- `/por/rclist.csp`
- `/por/login_psw.csp`

`login_auth.csp` returns login initialization XML with `TwfID`, `CSRF_RAND_CODE`, `RSA_ENCRYPT_KEY`, and `VPNVERSION M7.6.8R2`; this is expected pre-auth metadata. SMS endpoints returned `unexpected user service` / `ErrorCode 20026`. Password login probes for random/admin/student-like users returned `incorrect svpn_req_randcode`, not user enumeration. Do not report version or initialization XML alone.

## jwxt negative checks

`jwxt.bzuu.edu.cn` exposes login and `verifycode.servlet`, but key paths under `/jsxsd/` redirect to CAS login by JavaScript. Common Swagger/Git/env/Actuator paths were 404. No unauthenticated grades, timetable, student data, or CAS bypass was verified.

## jyxt ASP.NET logic-bug candidate

`https://jyxt.bzuu.edu.cn/Account/Login` is worth future deepening if the user prioritizes logic flaws.

Observed from page JS:

- `AppCode = 'ZZZZ'`
- `/Account/Login/SendSmsCode`
- `/Account/Login/Validation_P`
- `/Account/Login/Validation_S`
- `/Account/Login/UpdateNewPassWord`
- `/Account/login/ImageValidate`
- anti-forgery token `__RequestVerificationToken`

**2026-05-27 update:** With fresh session + valid `__RequestVerificationToken`, the SMS endpoint returns JSON (not 500):
- `POST /Account/Login/SendSmsCode` with non-existent mobile+name → `{"Success":false,"Result":"手机号码或姓名不存在！"}`
- `POST /Account/Login/UpdateNewPassWord` with any params (no prior SMS) → `{"Success":false,"Result":"请先获取验证码"}`
- `POST /Account/Login/Validation_P` with wrong captcha → `{"Success":false,"Result":"验证码有误，请重新输入"}`
- Bad `__RequestVerificationToken` → ASP.NET 500 custom error (no stack trace)
- Captcha is enforced server-side: empty/missing/wrong ValidationCode all return "验证码有误"

The SMS endpoint returns a *specific* error for non-existent accounts, but without a known-valid account to show a *different* response for existing accounts, this is incomplete account enumeration. **Not submittable without a valid-account control test.**

Future work should only continue if you can obtain a valid workflow state or known test identity and then prove one of:
- SMS actually sent to an arbitrary attacker-controlled phone,
- stable account-existence difference (need valid account to prove contrast),
- password reset without owning the account,
- login bypass,
- unauthorized project/workflow data access after manipulating IDs.

## Second-classroom systems future route

`ekta.bzuu.edu.cn` and `ektm.bzuu.edu.cn` are SPA systems. Do not rely on the initial HTML. Extract the current `/static/js/app.*.js` and vendor bundles, then look for API base URLs and endpoints containing `api`, `upload`, `login`, `user`, `student`, `activity`, `score`, `course`, `admin`, `token`. Only report if unauthenticated or low-privilege requests return real student/activity/admin data or allow state changes.

## Additional subdomains discovered (2026-05-27)

New subdomains from subfinder:
- `hr.bzuu.edu.cn` → Jinshan HCM (金蝶人事系统), `/templates/index/hcmlogon.jsp`, uses ExtJS, password can be MD5-transmitted. No obvious vuln.
- `idp.bzuu.edu.cn` → Shibboleth IdP Server, passive auth only, no content served.
- `zscq.bzuu.edu.cn` → 知识产权信息公共服务网点, Vue+Element Plus SPA, API at `https://zscq.bzuu.edu.cn/prod/app-api`. `/bpm/patent/page` returns patent data unauthenticated (public info, not sensitive). `/datav/*` endpoints return statistics unauthenticated. **CORS漏洞: 所有API反射任意Origin + Credentials.**
- `web.bzuu.edu.cn` → "域名暂未生效" (domain not active).
- `dns2.bzuu.edu.cn` → DNS server.
- `ektdv.bzuu.edu.cn` → 第二课堂成绩单数据化展示平台, API at `https://ektdv.bzuu.edu.cn/data/statistics/api/`, returns 404 on all tested endpoints.

New subdomains from DNS brute force (2026-05-27):
- `file.bzuu.edu.cn` → 211.141.201.153 → redirects to Jinshan HCM (same as hr)
- `live.bzuu.edu.cn` → 211.141.201.156 → redirects to Jinshan HCM (same as hr)
- `exchange.bzuu.edu.cn` → 10.10.36.174 (CERNET internal, not externally accessible)
- `imap.bzuu.edu.cn` → imaphm.qiye.163.com (NetEase enterprise mail IMAP)
- `smtp.bzuu.edu.cn` → smtphm.qiye.163.com (NetEase enterprise mail SMTP)

hr/file/live all resolve to the same Jinshan HCM instance on 211.141.201.153. Default credential testing returns HTTP 200 for all combinations — this is the login page being re-rendered, not successful authentication.

## Submission status

go-fastdfs phishing vulnerability (`?download=0` renders HTML on trusted domain) — **SUBMITTED** (confirmed by user 2026-05-27). Do not resubmit.

CORS vulnerabilities — **NOT YET SUBMITTED** (discovered 2026-05-27):
- zscq.bzuu.edu.cn CORS reflection + Credentials
- ekta.bzuu.edu.cn CORS reflection + Credentials (student/user/my-info)
- ektm.bzuu.edu.cn CORS reflection + Credentials (student/user/my-info)
Reports at: `/tmp/vuln_reports/bzuu/bzuu-zscq-cors-report.txt` and `/tmp/vuln_reports/bzuu/bzuu-ekta-ektm-cors-report.txt`

## ekta/ektm second-classroom detailed findings (2026-05-27)

**ekta.bzuu.edu.cn:**
- baseUrl: `https://ekta.bzuu.edu.cn/api/app/client/v1/`
- `Encrypt`/`Decrypt` functions are **identity functions** (no actual encryption) — params sent as plaintext `params=<JSON>`
- Hardcoded AES key `ahuSecond0425..?` — used for YiBan third-party integration only
- School ID for bzuu: `12926`
- All business endpoints return `{"code":10001,"msg":"登陆失败，请重新登陆"}` without Token
- Only `/common/all-school` and `/common/login/verificationcode` are unauthenticated

**ektm.bzuu.edu.cn:**
- baseUrl: `https://ektm.bzuu.edu.cn/api/backend/server/v1/`
- Same auth pattern: all business endpoints need Token
- `/common/all-school` returns school info (id:12926, name:亳州学院)
- `/common/login/verificationcode` returns base64 captcha image

## CORS findings (2026-05-27) — SUBMIT as separate reports

**Three CORS misconfigurations discovered:**

1. **zscq.bzuu.edu.cn (知识产权系统)** — 中危
   - All `/prod/app-api/*` endpoints reflect arbitrary Origin + Credentials: true
   - Verified: `curl -sk -I "https://zscq.bzuu.edu.cn/prod/app-api/bpm/patent/page" -H "Origin: https://evil.com"` → `Access-Control-Allow-Origin: https://evil.com`
   - Sensitive endpoints: `/member/user/get` (requires auth, returns user data)
   - Public endpoints: `/bpm/patent/page`, `/datav/*` (return patent data/statistics)
   - Report: `/tmp/vuln_reports/bzuu/bzuu-zscq-cors-report.txt`

2. **ekta.bzuu.edu.cn (第二课堂-学生端)** — 中危
   - `student/user/my-info` reflects arbitrary Origin + Credentials: true
   - Other endpoints use `Access-Control-Allow-Origin: *` (通配符型)
   - Report: `/tmp/vuln_reports/bzuu/bzuu-ekta-ektm-cors-report.txt`

3. **ektm.bzuu.edu.cn (第二课堂-管理端)** — 中危
   - Same pattern as ekta: `student/user/my-info` reflects arbitrary Origin
   - Higher impact: management-side access could expose teacher/admin data

**Attack scenario:** Attacker hosts malicious page → logged-in user visits → attacker's JS reads user data cross-origin with stolen session.

## Reporting decision rule for this target

For bzuu follow-up, do not submit:

- repeated go-fastdfs info-disclosure as a new issue (same root cause as historical report),
- go-fastdfs phishing angle — **already submitted 2026-05-27**, do not resubmit,
- `env.js` frontend config alone,
- CAS login public config,
- VPN initialization XML / version alone,
- main-site `/main.psp` pseudo-200 paths,
- jyxt generic ASP.NET 500 pages.

Submit only if a future pass proves high-value impact: RCE, SQLi, authentication bypass, unauthorized sensitive data, IDOR over real records, arbitrary password reset, or real SMS/verification-code abuse with evidence.

**CORS漏洞可提交** — zscq/ekta/ektm的CORS反射型漏洞是独立发现，与go-fastdfs不同根因，可分别提交。
