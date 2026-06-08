# BZUU third-round continuation negative evidence (2026-05-23)

Workspace: `/tmp/bzuu_r3_20260523_195327`

Scope: continuing `bzuu.edu.cn` after the previously submitted go-fastdfs `/fileServer/status` root cause. Goal was to find a new reportable root cause, not repackage the old one.

## Main files

- Host baseline: `/tmp/bzuu_r3_20260523_195327/host_quick.tsv`
- API verification table: `/tmp/bzuu_r3_20260523_195327/api/probe_results.tsv`
- Response bodies/headers: `/tmp/bzuu_r3_20260523_195327/api/*.body`, `*.hdr`
- Additional grep/JS notes: `/tmp/bzuu_r3_20260523_195327/deeper/grep.txt`

## Findings and decisions

### `oshall.bzuu.edu.cn/zhxyApi`

- `/zhxyApi/sys/common/upload` GET and multipart POST: HTTP 401 JSON, `Token失效`.
- `/zhxyApi/sys/permission/getUserPermissionByToken`: HTTP 401 JSON, `Token失效`.
- `/zhxyApi/sys/user/getUserInfo`, `/zhxyApi/sys/user/list`: HTTP 401 JSON, `Token失效`.
- `/zhxyApi/online/cgform/api/*`: HTTP 401 JSON, `Token失效`.
- `/zhxyApi/actuator/env`: HTTP 403.
- `/zhxyApi/v2/api-docs`, `/swagger-ui.html`: HTTP 404.
- `/zhxyApi/sys/dict/getDictItems/sys_user_sex`: HTTP 200 but empty public dictionary result only.

Decision: not reportable. No unauthenticated upload, data read, SQL execution, Swagger/Actuator exposure, or sensitive dictionary data was proven.

### SUDY / VSB main site

- `POST /_web/_search/api/search/new.rst`: HTTP 200 empty body.
- `GET /_dwr/`: HTTP 404.
- Click counter endpoint: HTTP 403 login/error page.

Decision: not reportable.

### CAS/authserver

- `/authserver/login`: normal login page.
- Password reset and password validation candidate paths: HTTP 404 JSON.
- `/authserver/api/user/info`, `/authserver/api/security/config`: HTTP 404.
- `/authserver/serviceValidate?...ST-123456`: normal invalid-ticket style response, no bypass.

Decision: not reportable.

### JWXT 教务系统

- Personal info, grade, framework paths all return small login redirects.
- Random nonexistent path returns the same login redirect pattern.

Decision: not reportable; this is auth redirect/fallback.

### Mail/Coremail-like endpoints

- `/coremail/index.jsp`: 404.
- `/coremail/s/json?...`: HTTP 200 but `FA_INVALID_SESSION`.
- Random nonexistent path: 404.

Decision: not reportable.

### Sangfor SSL VPN / EasyConnect aliases

For `sso`, `vpn`, `oa`, `webvpn`:

- `/por/login_auth.csp`: HTTP 200 XML login initialization.
- `/por/conf.csp`, `/por/rclist.csp`: fixed XML/plain responses such as `unexpected user service`.
- `/api/access/*`, `/api/authentication/conf`, `/siteNav/`: 404 `Error Page`, same as random nonexistent path.

Decision: not reportable without safe version-specific auth bypass/RCE/data access PoC.

### Shibboleth IdP

- `/idp/shibboleth`: public SAML metadata.
- `/idp/profile/admin/resolvertest`, `/idp/status`: HTTP 500 generic exception pages.
- SSO endpoint without valid SAML request: HTTP 400.
- Random nonexistent: HTTP 404.

Decision: not reportable.

### Supwisdom transaction guessed assets

- `transaction.bzuu.edu.cn` and `admin-platform.bzuu.edu.cn` guessed TTC/Supwisdom paths timed out or were unreachable.

Decision: no evidence of the Supwisdom `/ttc/` unauthenticated statistics pattern on this target.

### Additional subdomain hints

- `data.bzuu.edu.cn -> 10.10.36.20` internal/private IP.
- `ky.bzuu.edu.cn -> 10.10.30.12` internal/private IP.
- `job.bzuu.edu.cn -> 121.251.51.10` but HTTP/HTTPS timed out in this run.
- `cas.bzuu.edu.cn -> 211.141.201.146` but HTTP/HTTPS timed out in this run.

Decision: private-IP DNS is useful recon, but not a standalone report.

## Final gate

No new reportable BZUU vulnerability was verified in this round. Do not submit from this round: `zhxyApi` token-expired/upload 401 responses, empty public dictionary endpoint, SUDY empty search response, CAS 404/config/login page observations, JWXT login redirects, Coremail invalid-session errors, Sangfor `/por/*` login initialization/config XML, public Shibboleth metadata/generic IdP 500, or private-IP DNS records without exploitable external impact.
