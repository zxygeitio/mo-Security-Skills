# CQNU rs.cqnu.edu.cn epx-frame negative gate (2026-05-26)

## Scope

Target: `https://rs.cqnu.edu.cn/#/hall/cqsfdx`

This is a Chongqing Normal University recruitment/service hall branch running `epx-frame` / `epxing-frame`. It was investigated after earlier CQNU rounds and should be treated as a negative evidence package unless new authenticated/low-privilege evidence becomes available.

## Framework fingerprint

Unauthenticated SPA shell is available at `/#/hall/cqsfdx` and static JS can be fetched directly.

Observed runtime config from `/js/config.js`:

- `window.VERSION = '5.2.4'`
- `window.BASE_PROJECT_NAME = 'epxing-frame'`
- `window.BASE_AUTH_NAME = 'epx-auth'`
- `window.BASE_CLIENT_ID = 'frame'`
- `window.BASE_SYSTEM_ID = 'epxing-frame-manage'`
- `window.BASE_APP_ID = 'FM_SERVICE_PLATFORM'`
- default redirect: `/#/hall/cqsfdx`

Primary bundles:

- `/js/config.js`
- `/js/ui.ea42e4b6.js`
- `/js/frame.e2265f63.js`
- `/js/vue.af58cdd6.js`
- `/js/app.d4d4342d.js`

## API construction pattern

The frontend builds requests as:

```text
/epxing-frame/api/v1/{client}/{system}/{entityId}/{action}
/epxing-frame/process/v1/{client}/{system}/{entityId}/{action}
/epxing-frame/rule/v1/{client}/{system}/{entityId}/{action}
/epxing-frame/stream/v1/{client}/{system}/{entityId}/{action}
```

Useful entities/actions found in JS:

- `FM_SERVICE`: `getUserServices`, `getHallServiceCode`, `visitService`
- `FM_USER`: `validLogin`, `getQrCodeId`
- `FM_FILE`: `get`, `upload`, `download`, `onlineview`
- `FM_CODE_DEFINE`: `getCodes`, `getTree`
- `FM_ENTITY`: `getMeta`, `getSimpleMeta`
- `FM_MESSAGE`: `list`
- `FM_URL_MAP`: `getShortUrl`, `getLongUrl`

File helper URL logic in the frontend:

```text
api/v1/{client}/{system}/download?id={fileId}&EPXTID=base64(token)&xsrf_token=...
api/v1/{client}/{system}/onlineview?fileId={fileId}&token=...&xsrf_token=...
```

## Low-impact validation results

### Public RSA endpoint

```bash
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/rsa/public/v2'
```

Returned `200 application/json` with `publicKey` and `aesKey`. This appears to be frontend encryption bootstrap configuration only. Do not report unless it chains to token forgery, credential decryption, or sensitive API access.

### Hall/service/user/entity APIs

Representative tests:

```bash
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/frame/epxing-frame-manage/FM_SERVICE/getHallServiceCode?clientCode=cqsfdx'
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/cqsfdx/epxing-frame-manage/FM_SERVICE/getHallServiceCode?clientCode=cqsfdx'
curl -sk -D- -X POST 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/cqsfdx/epxing-frame/FM_SERVICE_HALL' --data 'action=getUserServices&entityId=FM_SERVICE&search.HALL_FLAG%23not_in=0&search.LEVEL=1'
```

Unauthenticated responses were `302` to CAS or `401 {"code":"error.nologin","msg":"会话已过期，请重新登录"}`. This is normal authentication enforcement.

### File download / preview candidates

Tested IDs included `0, 1, 2, 10, 100, 1000, 20240101, 1710000000000` against variants such as:

```bash
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/cqsfdx/epxing-frame/FM_FILE/download?id=1'
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/cqsfdx/epxing-frame/onlineview?fileId=1'
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/frame/epxing-frame/FM_FILE/download?id=1'
```

Results:

- `FM_FILE/download`: `500 接口权限未定义`
- `onlineview`: `302` CAS redirect
- `frame/epxing-frame/FM_FILE/download`: `500 非法的请求系统`

No file body, filename, `Content-Disposition`, PII, or accessible upload/download object was obtained.

### FineReport branch

`/report/ReportServer` exposes FineReport markers, but common management/version/export checks were blocked or returned only error pages:

```bash
curl -sk -D- 'https://rs.cqnu.edu.cn/report/ReportServer?op=fs'
curl -sk -D- 'https://rs.cqnu.edu.cn/report/ReportServer?op=fr_platform'
curl -sk -D- 'https://rs.cqnu.edu.cn/report/ReportServer?op=chart&cmd=version'
curl -sk -D- 'https://rs.cqnu.edu.cn/report/ReportServer?op=plugin&cmd=installed'
curl -sk -D- 'https://rs.cqnu.edu.cn/report/ReportServer?op=export&format=txt&reportlet=../../../../WEB-INF/web.xml'
```

Observed `403`, empty resource responses, or FineReport error page. No version leak, plugin list, report data, file read, or unauthenticated report access was proven.

### CORS branch

Example:

```bash
curl -sk -D- 'https://rs.cqnu.edu.cn/epxing-frame/api/v1/rsa/public/v2' -H 'Origin: https://evil.example'
```

The server reflected `Access-Control-Allow-Origin: https://evil.example`, but `Access-Control-Allow-Credentials: false`. Business APIs still require CAS/session. Treat as not reportable unless a sensitive endpoint becomes cross-origin readable with credentials or equivalent token exposure.

## Decision

Do not submit a report from this branch based on current evidence.

Reasons:

1. API structure and entity names are exposed, but core business APIs enforce CAS/session.
2. Public RSA/bootstrap config is not sensitive enough by itself.
3. File download/preview did not yield any object or sensitive response.
4. FineReport surface is present but management/export/version candidates are blocked or only error pages.
5. CORS reflection lacks credentials and no sensitive cross-origin readable endpoint was found.

## Re-open conditions

Only resume this branch if one of the following becomes available:

- a valid low-privilege account/session for object-level access control tests;
- a real `fileId`, reportlet name, service ID, or process/task ID from a legitimate page that can be tested with invalid/absent token controls;
- mobile/app/mini-program traffic exposing a different API context or token exchange;
- a FineReport-specific safe PoC for the exact deployed version with non-destructive proof;
- evidence that CORS can read sensitive authenticated data, not just public config.
