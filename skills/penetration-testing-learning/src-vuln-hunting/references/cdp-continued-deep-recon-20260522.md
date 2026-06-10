# CDP.edu.cn continued deep-recon notes (2026-05-22 Round 2)

Use this as a negative-verification pack for future 成都职业技术学院 / `cdp.edu.cn` follow-up work. It belongs under the broader education SRC workflow, not as a standalone target-specific skill.

## Scope tested

Target family:
- `www.cdp.edu.cn`
- `ehall.cdp.edu.cn`
- `cas.cdp.edu.cn`
- `aic.cdp.edu.cn`
- `webvpn.cdp.edu.cn`
- `yikatong.cdp.edu.cn`
- edge links exposed from the main portal, including `sdmg.sad.cdp.edu.cn:801`, `118.114.241.97:9081`, AIC `qualityEva` / `xsgl`, and private-IP links embedded in HTML.

Evidence directory from the session:
- `/tmp/cdp_continue_20260522_221917/`
- final write-up: `/tmp/vuln_reports/cdp/deep-recon-20260522-continued-round2.txt`

## Durable technique: recover from DNS/proxy weirdness before judging a host dead

During this target, normal DNS resolution sometimes mapped `*.cdp.edu.cn` to `198.18.0.x` addresses and curl returned `000` / TLS EOF. Do not conclude the asset is dead from that alone.

Useful fallback sequence:
1. Resolve/compare current DNS and historical/public A records.
2. Try direct IP + SNI / Host routing with `curl --resolve host:443:IP`.
3. Compare body length, content-type, title, and random nonexistent paths to distinguish real endpoints from fallback pages.
4. Keep short connect/read timeouts and save headers/body per request, because availability is intermittent.

This is a retry/routing pattern, not a permanent claim that the target or tool is broken.

## Round 2 verification results

### Main site `www.cdp.edu.cn`
- Direct IP/SNI access returned the VSB portal page.
- Static references included VSB/DWR assets such as `/_dwr/engine.js`, `/_dwr/util.js`, and VSB resource JS.
- Follow-up requests to DWR, `.git/HEAD`, `fileServer/status`, and `server/*` did not return exploitable data.
- Public HTML exposed several internal/private links (`192.168.*`, `172.16.*`) and third-party/edge links. Treat these as recon leads only; embedded private IP links are not submit-worthy by themselves.

### `ehall.cdp.edu.cn`
- Homepage and Umi bundle existed when reachable.
- Common Jinzhi/ehall JSONP paths such as `/jsonp/school.json`, `/jsonp/serviceCenterData.json`, and `/jsonp/appIntroduction.json` returned 404 in this deployment.
- `/api/authc/user/info`, `service`, `message`, `task`, `formDesign`, `process` generally redirected or required login.
- `/api/docrepo/download?attachmentId=1` returned only `文件已被删除，请重试！` or method-not-supported, not arbitrary attachment disclosure.
- `/api/authc/systemSetting/` exposed only missing-parameter / missing-`Loginuserorgid` errors. Adding guessed `Loginuserorgid` / `Loginuserid` headers did not produce stable business data.

### `cas.cdp.edu.cn`
- `/lyuapServer/serviceValidate?service=...&ticket=ST-invalid` returned standard CAS XML authentication failure only.
- `/actuator/env`, `/cas/status`, `/v2/api-docs`, and several fake paths returned the login SPA/fallback page or ordinary errors.
- `/api-docs` exposed a Shiro session error, but no config, credentials, usable API docs, or business data. Do not submit this alone.

### `aic.cdp.edu.cn`
- IIS/.NET application redirects unauthenticated users to CAS.
- Responses showed `Access-Control-Allow-Origin: *` plus credentials on some 302/404/error responses, but no sensitive cross-origin data was proven. Do not report as high-impact CORS without an authenticated or sensitive-data read proof.
- `Trace.axd` returned 403. `elmah.axd`, Swagger, Help, Scripts, Content, and guessed API controllers returned 404 or standard not-found controller messages.
- `api/cms/upload`, `api/user/info`, and `api/auth/user` were not valid controllers.

### `webvpn.cdp.edu.cn`
- Unauthenticated `/` and `/vpn_key/update` redirect to `/users/sign_in`.
- `/users/sign_in` and `/login.php` are public login pages only.
- `/api/resource`, `/api/resources`, `__debugger__`, `.git/HEAD`, and guessed assets returned 404 or login-required behavior.

### `yikatong.cdp.edu.cn`
- Round 2 direct requests often returned `000` / TLS EOF due routing/DNS behavior.
- Combine with the earlier `cdp-yikatong-negative-20260522.md` reference: still no proof that `getToken`/`tid`, `captcha/check`, `sendSms`, `tradeList`, `cardList`, or `balance` are bypassable or expose unauthorized data.

## Submit / no-submit rule for this target

Do not submit any of the following as standalone findings:
- SPA fallback / login page 200.
- CAS standard XML error for invalid tickets.
- Shiro session error with no secrets or data.
- CORS headers on 302/404/error pages with no sensitive read proof.
- Public internal links embedded in portal HTML.
- Version/server/banner/error-page information without exploitation.
- `docrepo` returning deleted-file or method-not-supported messages.

Only write a report if one of these is proven:
- unauthenticated real personnel/student/card/trade/attachment/workflow data;
- authenticated IDOR/vertical/horizontal privilege escalation with a legal test account;
- executable unauthenticated upload with a reachable proof file;
- password reset / SMS / captcha bypass that reaches a real sensitive action without abusing real users;
- actual mail spoofing delivered to an authorized inbox or account takeover chain.
