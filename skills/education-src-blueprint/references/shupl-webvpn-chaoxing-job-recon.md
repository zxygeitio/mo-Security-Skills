# SHUPL education asset recon patterns: WebVPN, Chaoxing portal, ASP.NET job site (2026-05-21)

Use this as a reusable low-impact pattern for Chinese university public assets that combine:
- WebVPN / zero-trust Vue login portals.
- Chaoxing / smart-portal public pages.
- ASP.NET WebForms employment or admissions portals.

Case signals from `shupl.edu.cn`:
- `webvpn.shupl.edu.cn` redirected to `/frontend_static/frontend/login/index.html#/login` and loaded Vue chunks under `/frontend_static/frontend/login/js/`.
- Login JS exposed `rump_frontend` endpoints.
- `lib.shupl.edu.cn` used Chaoxing / 智慧门户 assets and public JSON endpoints.
- `job.shupl.edu.cn` was ASP.NET WebForms with `Register.aspx/*` JSON web methods.

## WebVPN / zero-trust Vue login workflow

1. Load login page in browser and enumerate resource URLs:
   - `performance.getEntriesByType('resource')`
   - Extract `.js` resources and grep for `rump_frontend`, `login`, `token`, `qrcode`, `getHomeParam`.
2. Common endpoints to probe, low impact only:
   - `/rump_frontend/getLoginParam/`
   - `/rump_frontend/getLoginParam/?domain=HOST`
   - `/rump_frontend/getHomeParam/`
   - `/rump_frontend/getToken/`
   - `/rump_frontend/getTokenQrcode/`
   - `/rump_frontend/login/`
   - `/rump_frontend/loginFromSms/`
   - `/rump_frontend/loginFromToken/`
   - `/rump_frontend/ukLoginApply/`
3. Decision boundary:
   - `getLoginParam` returning site name, auth chain, display text, server name, logo/background config is normally public config, not reportable alone.
   - `getToken` returning a token-like random string is not enough. It only becomes reportable if it can be exchanged for a valid session, device binding, or authenticated resource access.
   - `getHomeParam`/`logout` returning login-timeout is expected.
   - Test `domain` with arbitrary values, localhost/127.0.0.1, path traversal, and quotes; only report if it produces SSRF/LFI/SQLi or returns non-public tenant data.

## Chaoxing / smart-portal workflow

1. Identify Chaoxing smart portal from scripts/resources:
   - `/assets/js/index_page.min.js`
   - `/assets/js/peking_library/index.js`
   - `/webjson/*/content-cache`
   - `/page/*/all-request`
   - `/application/view/*/data`
   - `/cookie/get/`, `/cx-domain/get/`, `/engine2/header/user-info`
2. Probe public endpoints:
   - `/webjson/<id>/content-cache?w=<websiteId>&sversion=<hash>&wfwfid=<fid>`
   - `/page/<pageId>/all-request?head=0&w=<websiteId>&sversion=<hash>&wfwfid=<fid>`
   - `/application/view/<appId>/data?websiteId=<websiteId>&pageId=<pageId>`
   - `/engine2/header/user-info`
   - `/user/getUserIp`
3. Decision boundary:
   - Public page cache, module HTML, page/app IDs, site IDs, and Chaoxing domain config are not sensitive by themselves.
   - `user-info` returning `uid:null` is expected unauthenticated behavior.
   - If `application/view` returns the same public module data for arbitrary IDs, treat as public component rendering unless it reveals private content, unpublished pages, user data, credentials, or writable controls.
   - Check admin-like paths (`/engine2/e1-slide/admin/content/*`, `/top/admin`, `/bottom/admin`); 403/404 is not reportable.
   - CORS must allow cross-origin reading of sensitive JSON to matter; no ACAO or public JSON is not enough.

## ASP.NET WebForms employment/admissions workflow

1. Extract links and WebMethods from page scripts:
   - `Register.aspx/VerifyUserName`
   - `Register.aspx/VerifyOrgcode`
   - `InformationDetail.aspx?XXID=`
   - `PositionDetail.aspx?zwid=`
   - `EnterpriseDetail.aspx?id=`
2. Low-impact checks:
   - Verify numeric/detail parameters with normal ID, nonexistent ID, and one quote.
   - Confirm quote responses are real SQL errors before calling SQLi; WAF/403 blocks are not evidence.
   - For WebMethods, test JSON POST with benign existing/non-existing values and one invalid character.
3. Decision boundary:
   - Registration username availability (`admin` exists, `random` available) is usually normal registration behavior and low value unless it enumerates real student/teacher accounts at scale or exposes privileged roles.
   - Organization/social-credit-code validation returning `valid=1` for any syntactically valid value is not enough unless it bypasses registration approval or grants access.
   - Avoid completing real registrations or submitting fake enterprise/admissions data unless explicitly authorized; do not create dirty data.

## Report only if verified

Do not submit these as standalone findings:
- Public WebVPN login configuration.
- Token-like strings that cannot be exchanged for a session.
- Chaoxing public page cache and component HTML.
- Site/page/application IDs.
- Username availability checks limited to registration UX.
- 403 pages caused by quote payloads.

Escalate only when you prove one of:
- Auth bypass or valid session creation.
- Unauthenticated sensitive data read (students, staff, candidates, enterprise contacts beyond public listings).
- IDOR across private records.
- SQL injection with clear differential/error/time evidence.
- Upload/write action without authorization.
- SSRF/LFI from configurable `domain`, `curl`, or resource URL parameters.
