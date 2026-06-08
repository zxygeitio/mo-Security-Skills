# BZUU continued deep recon: zhxyApi / TTC / Seeyon / CMS negative evidence (2026-05-23)

## Scope

Follow-up after the already-submitted BZUU go-fastdfs/status issue. Goal was to find a new, independent, high-value root cause, not supplemental evidence for the old report.

Evidence directory from the session:

```text
/tmp/bzuu_continue3_20260523_191754
```

Key files:

```text
alive.tsv
js_urls.txt
verify_continue.tsv
verify_zhxyapi.tsv
```

## Assets that were reachable

Representative live assets:

```text
auth.bzuu.edu.cn       网上办事服务大厅, redirects/serves oshall zhxy SPA
oshall.bzuu.edu.cn     网上办事服务大厅
www.bzuu.edu.cn        SUDY/portal style main site
lib.bzuu.edu.cn        图文信息中心 / readercenter
jwxt.bzuu.edu.cn       教务登录
hr.bzuu.edu.cn         HCM/人事登录
file.bzuu.edu.cn       HCM/file login surface
oa/sso/vpn/webvpn      same edge family / login surface
idp.bzuu.edu.cn        Shibboleth IdP welcome/metadata-style surface
mail.bzuu.edu.cn       NetEase enterprise mail login
```

## Important negative findings

### 1. `zhxy/env.js` exposes useful routing but not a submit-worthy issue by itself

`https://oshall.bzuu.edu.cn/zhxy/env.js` exposed:

```text
domianURL: https://oshall.bzuu.edu.cn/zhxyApi
casUrl: https://auth.bzuu.edu.cn/authserver
imgUrl: https://oshall.bzuu.edu.cn/fileServer
fileUploadUrl: https://oshall.bzuu.edu.cn/zhxyApi/sys/common/upload
```

Verification showed the interesting API paths are protected:

```text
/zhxyApi/sys/common/upload                 -> 401 JSON, Token失效，请重新登录
/zhxyApi/sys/common/file/upload            -> 401 JSON, Token失效，请重新登录
/zhxyApi/sys/common/getLoginUser           -> 401 JSON, Token失效，请重新登录
/zhxyApi/sys/common/currentUser            -> 401 JSON, Token失效，请重新登录
/zhxyApi/sys/user/getLoginUser             -> 401 JSON, Token失效，请重新登录
/zhxyApi/online/cgform/api/getColumns/1    -> 401 JSON, Token失效，请重新登录
/zhxyApi/actuator/env                      -> 403 nginx
/zhxyApi/v2/api-docs                       -> 404 JSON
/zhxyApi/swagger-ui.html                   -> 404 JSON
```

`/zhxyApi/sys/dict/getDictItems/sys_user_sex` returned 200 but only an empty public dictionary result:

```json
{"success":true,"message":"操作成功！","code":200,"result":[]}
```

Decision: frontend config + empty dictionary + protected upload endpoint is not reportable. Continue only if a real authenticated token bypass, uploaded file URL, sensitive data, or write action is verified.

### 2. TTC / Supwisdom transaction candidates were SPA fallback

Paths such as:

```text
/ttc/api/ttc/transactionType/getTransactionTypeList
/ttc/api/ttc/service/monitor/getServiceMonitor
/ttc/api/ttc/service/analysis/getServiceAnalysis
/ttc/v1/service/monitor/getServiceMonitor
/ttc/v1/service/analysis/getServiceAnalysis
/admin-platform/serverConfig.json
/taskcenter-v4/static/js/app.js?V=null
```

returned the `网上办事服务大厅` HTML SPA shell with identical body hash rather than JSON business data.

Decision: classify as SPA fallback, not Supwisdom/TTC unauthenticated statistics exposure.

### 3. Seeyon REST token candidates were also fallback, not token issuance

Tested low-impact token endpoints:

```text
/seeyon/rest/token/rest_fwx/admin123?loginName=
/seeyon/rest/token/rest_fwx/admin123?loginName=__hermes_nonexistent__
```

On `auth.bzuu.edu.cn` and `oshall.bzuu.edu.cn`, responses were the same zhxy SPA HTML shell, not a UUID/token and not `User not found`.

Decision: do not report Seeyon REST token leakage unless JS exposes a real `/seeyon/rest/token/<user>/<pass>` endpoint and direct calls return token/UUID or user lookup errors.

### 4. SUDY / Boda / JTopCMS upload/search checks did not produce data or upload

Main-site checks:

```text
/content/multiUpload.do                    -> 403 提示页; TXT multipart upload also 403
/core/SystemManager/login/page.thtml       -> 404
/_web/_search/api/search/new.rst           -> 200 empty body
/_dwr/interface/SudySearch.js              -> 404
/_dwr/test/                                -> 404
/_wp3services/generalQuery                 -> 503 JSON: 非法请求，系统未提供Name=的通用查询
/_wp3services/api/search                   -> 404
```

Decision: no JTopCMS unauthenticated upload, no DWR exposure, no SUDY search data leak.

### 5. CAS/authserver and password reset surfaces were non-reportable

`auth.bzuu.edu.cn/authserver/login` is a normal login page. Follow-up paths:

```text
/authserver/getBackPasswordMainPage.do     -> 404 JSON
/authserver/validatePasswordAjax.do        -> 404 JSON
/authserver/serviceValidate?...ST-1234     -> standard CAS INVALID_TICKET XML
```

`oshall` paths were SPA fallback; `jwxt` paths were 404/error pages.

Decision: no password-reset enumeration, no validatePasswordAjax exposure, and standard `INVALID_TICKET` is not a vulnerability.

### 6. HCM / file attachment checks returned empty bodies

Examples:

```text
/general/sys/portalshow.do                         -> 404 ERROR PAGE INFO
/templates/index/getpersoninfo.jsp                 -> 404 ERROR PAGE INFO
/templates/index/getLoginUserInfo.jsp              -> 404 ERROR PAGE INFO
/templates/index/validateCode.jsp                  -> 404 ERROR PAGE INFO
/general/attachment/fileDownload.jsp?fileid=1000   -> 200 empty body
/general/attachment/fileDownload.jsp?fileid=../../WEB-INF/web.xml -> 200 empty body
```

Decision: empty 200 on attachment endpoints is not arbitrary file download without actual content.

## BZUU follow-up gate

When continuing BZUU after go-fastdfs has already been reported, require at least one of the following before writing a new report:

- `zhxyApi` upload returns `fileUrl`, `url`, `resId`, `ossId`, or a publicly accessible uploaded file.
- `zhxyApi`/TTC returns non-empty JSON business data without token, especially user, workflow, statistics, form, or attachment data.
- Seeyon token endpoint returns a UUID/token or `User not found` from a real OA endpoint, not the zhxy SPA shell.
- SUDY/JTopCMS upload returns a public file URL or search/DWR returns real records.
- HCM/file attachment endpoint returns non-empty sensitive content for an unauthenticated file ID or path traversal.
- CAS/password reset exposes stable account existence differences or reset flow abuse; standard CAS error XML is not enough.

Do not submit:

- `env.js` base URLs, CAS URLs, `fileUploadUrl`, `wxAppId`/`tbAppId` alone.
- `Token失效，请重新登录` JSON.
- HTML body hash matching the zhxy SPA shell for arbitrary paths.
- Empty 200 responses.
- `INVALID_TICKET` CAS responses.
- 403/404/error pages or login pages.
