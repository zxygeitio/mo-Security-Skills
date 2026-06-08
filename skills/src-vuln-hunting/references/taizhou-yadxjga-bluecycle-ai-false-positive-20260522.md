# Taizhou / BlueCycle / AI Assistant false-positive notes

## Scope
This note collects recent session-specific verification patterns for three similar targets:
- 仙居永安盾 / `www.yadxjga.com:11443`
- 蓝色循环 / `lsxh.zjjxkj.top`
- 台州 AI政务助手 / `safety.mtzx.wl.gov.cn:9011`

## Common pattern
These targets expose many endpoint strings in bundled frontend JS. That alone does not mean they are reachable without auth.

Verification rule:
1. If the JS bundle lists an endpoint, test the real backend path directly.
2. If GET/POST to the path returns login/auth failure or a generic SPA shell, treat it as gated or a frontend route until proven otherwise.
3. Only continue if you can show one of:
   - anonymous sensitive data
   - unauthorized state change
   - upload/download with a verifiable file/object
   - role bypass or object-level access beyond your own session

## Session findings

### 1) 仙居永安盾
Observed in JS:
- `/admin/home/upload`
- `/uploadChunk`
- `/task/untube/import`
- `/api/upload/file`

Reality check:
- `/index.php/admin/home/upload` → `{"code":400,"msg":"未做身份鉴定","data":401}`
- `/index.php/admin/task/untube/import` → same auth failure
- `/index.php/admin/uploadChunk` → `405`
- `/api/upload/file` → `404`

Conclusion: JS-referenced upload paths were not anonymously exploitable.

### 2) 蓝色循环
Observed in JS:
- `/system/auth/get-permission-info`
- `/system/effective-date/get`
- `/system/login-log/page`
- `/system/operate-log/page`
- `/system/dict-type/page`
- `/system/dict-data/page`
- `/infra/config/get-value-by-key`
- `/system/ezviz/getLiveAddress`
- `/infra/file/upload/my/video`
- `/zlb/news/page`
- `/zlb/carousel-chart/page`

Reality check:
- Most endpoints returned `{"code":401,"data":null,"msg":"账号未登录"}` when called without auth.
- `/zlb/carousel-chart/page` returned public carousel data and was not a vuln by itself.
- Hitting SPA-looking URLs such as `/zlb/carousel-chart/page?...` returned the app shell, so do not confuse route handling with API availability.

Conclusion: endpoint enumeration succeeded, but no submit-worthy anonymous weakness was confirmed.

### 3) AI政务助手
Observed in JS:
- `/prod-api/common/upload`
- `/chat/basic`
- `/chat/welcome`
- `/chat/fileSearch`
- `/chat/risk`
- `/chat/assistant`
- `/modules/singleLogin/loginUseWlUser`
- `/system/dict/data/list`
- `/authUser`
- `/authRole`

Reality check:
- `GET/POST /prod-api/common/upload` → auth failure JSON
- `GET` to `/chat/*` and `/auth*` often returned the SPA shell
- `POST` to those routes typically returned `405 Not Allowed` unless the correct authenticated API layer was used

Conclusion: route names in JS were not evidence of public API exposure.

## Practical heuristic
When a target behaves like this, prefer this order:
1. Verify the backend prefix from JS (`/prod-api`, `/index.php/admin`, `/blueCycle`, etc.).
2. Test the exact backend path, not the router path shown in the SPA URL.
3. Confirm the response is not just the app shell / login page / generic 401.
4. Avoid reporting plain login-wall results, static route exposure, or SPA fallback as vulnerabilities.

## Reporting boundary
Do not write a report unless you can show a real unauthorized effect beyond:
- login required
- 404 / 405
- SPA shell
- public marketing content
