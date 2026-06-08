# BZUU post-go-fastdfs deepening negative evidence (2026-05-23)

## Scope

Target: `bzuu.edu.cn` / 亳州学院 after the known `oshall.bzuu.edu.cn/fileServer/status` go-fastdfs unauthenticated status exposure had already been submitted.

Purpose: avoid re-submitting weak duplicates and preserve the exact negative evidence patterns for future education-SRC deepening.

## Evidence workspace from session

- `/tmp/bzuu_deep_continue_20260523_173818`
- Final quality gate: `/tmp/bzuu_deep_continue_20260523_173818/verify2/final/gate.tsv`

## Key findings and decisions

### 1. Sangfor SSL VPN / EasyConnect portal

Hosts tested:
- `sso.bzuu.edu.cn`
- `vpn.bzuu.edu.cn`
- `webvpn.bzuu.edu.cn`
- `oa.bzuu.edu.cn`

Representative command:

```bash
curl -sk "https://sso.bzuu.edu.cn/por/login_auth.csp"
```

Observed:
- HTTP 200 XML login-initialization response.
- `VPNVERSION` = `M7.6.8R2`.
- `RSA_ENCRYPT_KEY`, `CSRF_RAND_CODE`, `TwfID` present.
- `Anonymous` = `0`.
- `RESET_PASSWORD` = `0`.

Control:

```bash
curl -sk "https://sso.bzuu.edu.cn/por/nonexistent_123456.csp"
```

Observed: HTTP 404 error page.

Decision: do not report. This is normal login initialization/version/config exposure unless paired with a verified auth bypass, RCE, data access, or a version-specific safe PoC.

### 2. Shibboleth IdP

Command:

```bash
curl -sk "https://idp.bzuu.edu.cn/idp/shibboleth"
```

Observed:
- HTTP 200 SAML metadata.
- `entityID=https://idp.bzuu.edu.cn/idp/shibboleth`.
- `Scope=bzuu.edu.cn`.

Admin-ish endpoint:

```bash
curl -sk "https://idp.bzuu.edu.cn/idp/profile/admin/resolvertest"
```

Observed: HTTP 500 error page, no useful data.

Decision: do not report. `/idp/shibboleth` is public SAML metadata; stale/ugly metadata alone is not an SRC-grade vulnerability.

### 3. JWXT 教务系统

Commands:

```bash
curl -sk "https://jwxt.bzuu.edu.cn/jsxsd/xsgrxx/xsgrxx.do"
curl -sk "https://jwxt.bzuu.edu.cn/jsxsd/nonexistent_123456"
```

Observed:
- Both return small JavaScript redirects to `https://auth.bzuu.edu.cn/authserver/login?service=...`.

Decision: do not report. This is authentication redirect/fallback, not unauthorized student-data access or IDOR.

### 4. `oshall` / `rhptManage` 智慧校园 backend

Useful frontend config:

```bash
curl -sk "https://oshall.bzuu.edu.cn/rhptManage/env.js"
```

Observed:
- `domianURL: https://oshall.bzuu.edu.cn/zhxyApi/`
- `casPrefixUrl: https://auth.bzuu.edu.cn/authserver`
- `imgDomainURL: https://oshall.bzuu.edu.cn/fileServer`
- `isFormDesignSQL: true`

Protected API checks:

```bash
curl -sk "https://oshall.bzuu.edu.cn/zhxyApi/sys/common/upload"
curl -sk "https://oshall.bzuu.edu.cn/zhxyApi/sys/permission/getUserPermissionByToken"
```

Observed:
- HTTP 401 JSON with `Token失效，请重新登录` / status field 500.

Decision: do not report. Frontend config and feature flags only become valuable if they lead to SQL execution, upload, data read, or token/auth bypass.

### 5. SUDY / 主站 search

Command:

```bash
curl -sk -X POST "https://www.bzuu.edu.cn/_web/_search/api/search/new.rst" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
  --data "keyword=test&siteId=1&pageIndex=1&pageSize=10"
```

Observed:
- HTTP 200 with empty body.

Decision: do not report. Empty 200 from search API is not SQLi, data leakage, or unauthorized search.

### 6. Library / readercenter / opac

Observed patterns:
- Some candidate endpoints 404.
- Some redirect to login.
- Some public config endpoints return empty success JSON or no sensitive `extra`.

Decision: do not report unless reader PII, borrowing data, account state, or password-reset bypass is proven.

### 7. go-fastdfs fileServer

Command:

```bash
curl -sk "https://oshall.bzuu.edu.cn/fileServer/status"
```

Observed:
- HTTP 200 JSON status/config/node/file statistics.

Decision: this is the previously submitted BZUU go-fastdfs unauthenticated status/info-disclosure root cause. Do not create a new report; only use as supplemental evidence to the original report if needed.

## Reusable workflow lesson

For education-SRC post-submission deepening:

1. Start from the previous root cause and explicitly mark duplicate boundaries.
2. For every new candidate, keep a final gate TSV with URL, status, size, content type, SHA256, and decision.
3. Always pair login/fallback candidates with random-path controls.
4. Reject these as non-reportable unless they chain to real impact:
   - public SAML metadata;
   - Sangfor login-init XML/version/config;
   - frontend `env.js` config;
   - token-expired JSON;
   - login redirect JavaScript;
   - empty SUDY search response;
   - already submitted go-fastdfs status exposure.
5. Continue only toward new assets or genuinely high-value patterns: LyWebServer/JTopCMS upload, Goldmine/JinZhi ehall JSONP PII, Seeyon REST token leakage, Supwisdom `/ttc/` unauthorized statistics, Swagger/Actuator with sensitive data.
