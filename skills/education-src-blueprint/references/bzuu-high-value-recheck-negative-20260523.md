# BZUU high-value recheck negative gates (2026-05-23)

## Scope

Target: `bzuu.edu.cn` / 亳州学院 follow-up after known go-fastdfs status exposure had already been submitted. This note captures durable false-positive gates from a high-value-only recheck, so future education-SRC runs do not repackage weak findings.

Evidence workspace from the session:

- `/tmp/bzuu_submit_hunt_20260523_180131`
- Core gates: `verify3_core.tsv`, `verify3_lib.tsv`, `verify3_final.tsv`

## Final decision

No new SRC-grade vulnerability was found. Do not submit a new report from these findings unless a later run proves real impact such as unauthorized sensitive data, token issuance, file URL creation, usable download content, auth bypass, SQLi/RCE, or IDOR.

## Negative patterns to reject

### 1. `www.bzuu.edu.cn` SUDY-style `/main.psp` rewrites

Requests such as:

```bash
curl -skI 'https://www.bzuu.edu.cn/actuator/env'
curl -skI 'https://www.bzuu.edu.cn/v2/api-docs'
```

Observed pattern:

- `302` to `/actuator/env/main.psp`, `/v2/api-docs/main.psp`, `/api-docs/main.psp`, etc.
- Body is a generic Apache/SUDY-style moved page, not JSON/OpenAPI/Spring Actuator content.

Decision: not reportable. This is path rewrite/fallback, not exposed Actuator or Swagger.

### 2. `auth.bzuu.edu.cn` and `oshall.bzuu.edu.cn` protected high-value paths

Observed:

- `/actuator/env`, `/actuator/heapdump` return `403` or protected redirects.
- `/swagger-ui.html`, `/v2/api-docs`, `/doc.html`, `/druid/index.html`, `/.git/HEAD`, `/.env`, `/seeyon/*`, `/ecology/*`, `/weaver/*` return `302`, `403`, or no useful business content.
- `/jsonp/school.json`, `/jsonp/serviceCenterData.json`, `/jsonp/appIntroduction.json` are not public Goldmine/JinZhi ehall positives on these hosts.

Decision: not reportable without real JSON/OpenAPI/env data, token issuance, or business data.

### 3. HCM / file hosts: empty upload and download endpoints

Hosts:

- `hr.bzuu.edu.cn`
- `file.bzuu.edu.cn`

Useful controls:

```bash
curl -sk 'https://hr.bzuu.edu.cn/templates/index/hcmlogon.jsp'
curl -sk -X POST 'https://hr.bzuu.edu.cn/templates/index/hrlogon.do?logon.x=link&username=__hermes_invalid__&password=wrong&appdate=2026-05-23' -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=__hermes_invalid__&password=wrong'
curl -sk -X POST 'https://hr.bzuu.edu.cn/general/upload.jsp' -F 'file=@/etc/hostname;filename=hermes_probe.txt'
curl -sk 'https://hr.bzuu.edu.cn/general/attachment/fileDownload.jsp?fileid=1'
```

Observed:

- Login page is public and normal.
- Invalid login returns a normal small HTML response, not auth bypass.
- `general/upload.jsp` returns `200` with zero-length body; no `fileUrl`, no saved path, no accessible uploaded file evidence.
- `general/attachment/fileDownload.jsp?fileid=1` returns `200` with zero-length body; no file content.

Decision: do not report empty-200 upload/download endpoints. Require returned file identifier/path and successful retrieval of uploaded content, or confirmed arbitrary file download content.

### 4. Library `readercenter` public APIs

Public-but-low-value endpoints:

```bash
curl -sk 'https://lib.bzuu.edu.cn/readercenter/api/publicaction/GetNewsType?tag=notice'
curl -sk 'https://lib.bzuu.edu.cn/readercenter/api/publicaction/GetNewsListByType?catalogID=317&pageSize=7'
curl -sk 'https://lib.bzuu.edu.cn/readercenter/api/publicaction/GetDbList?dbCount=20'
```

Observed:

- Returns public categories, notices, news, and database/resource descriptions.
- This may include creator IDs like `bzuu001` and public content, but no reader PII, borrowing records, account state, or credentials.

Protected/absent checks:

- `/readercenter/api/readercenter/GetReaderInfo`
- `/readercenter/api/readercenter/GetBorrowList`
- `/readercenter/api/readercenter/GetCurrentBorrow`
- `/readercenter/api/readercenter/GetHistoryBorrow`
- `/opac/api/service/search`
- `/mobile/api/mobile/reader/GetReaderInfo`
- upload-like paths such as `/readercenter/api/publicaction/Upload`

Observed:

- Sensitive reader/borrow APIs redirect to `/login/...`.
- Upload paths are absent (`404` JSON: no matching controller/action) or redirect to login.

Decision: do not report public notice/resource APIs. Only continue if unauthenticated reader PII, borrowing data, account state, write action, or actual upload result is proven.

### 5. `GetCbookCover?path=` framework error

Command:

```bash
curl -sk 'https://lib.bzuu.edu.cn/readercenter/api/publicaction/GetCbookCover?path=test'
```

Observed:

- `500` HTML with `.NET` missing assembly message: `Microsoft.Web.Infrastructure, Version=1.0.0.0...`.
- No file content, credential, stack trace with sensitive config, or path traversal proof.

Decision: not reportable by itself. Treat as low-value framework error unless it leads to local file read, credential disclosure, or exploitable path traversal.

## Future workflow rule

For BZUU-like education targets, keep a high-value gate TSV and reject candidates where the only evidence is:

- redirect to login or `/main.psp` fallback;
- empty `200` body;
- public notice/resource JSON;
- login page/version/config exposure;
- generic framework error without sensitive data;
- Seeyon/ecology/weaver path returning 302/403/404/empty response.

Write a report only when the response contains independently useful impact evidence: sensitive records, valid token, successful upload path plus retrieval, arbitrary file content, or exploitable auth bypass/SQLi/RCE.
