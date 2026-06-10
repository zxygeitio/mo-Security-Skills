# CDP cdp.edu.cn continued deep recon negative pack (2026-05-23)

## Scope
Target: `https://www.cdp.edu.cn/` and discovered `*.cdp.edu.cn` assets after multiple earlier CDP negative-verification rounds.

This is a session-specific reference under the education SRC workflow. It is not a vulnerability report.

## Key lesson
When the user asks to continue digging CDP, do not recycle weak findings. Treat the current threshold as: only report medium+ if there is real unauthenticated sensitive data, IDOR, authentication bypass, executable upload, SQLi/RCE, or account takeover evidence.

If the run only produces DWR resources, WAF/403 pages, public crypto helpers, captcha images, login redirects, standard CAS errors, QQ Exmail/DNS policy weakness, or encrypted failure objects, write a negative conclusion file instead of a report.

## Asset baseline observed
Subdomain enumeration returned assets including:
`kcsz`, `uia`, `welcome`, `zyk`, `cas`, `course`, `ehall`, `jedu`, `tafe`, `dzmg`, `special`, `jy-o`, `zhao`, `aic`, `jy`, `sicsve`, `newvpn`, `sdmg.sad`, `yikatong`, `www`, `app-vsmg`, `nac`, `jy-hr`, `webvpn`, `jw`, `jy-js` under `cdp.edu.cn`.

Observed reachability was intermittent for many hosts. Do not report connection timeouts or empty responses. `yikatong.cdp.edu.cn` remained the most stable target in this run.

## Verified outcomes

### `www.cdp.edu.cn`
- Main site fingerprint: title `成都职业技术学院`; WAF/security layer returns 403 to attack strings.
- DWR resources reachable:
  - `/_dwr/engine.js` -> 200 JavaScript
  - `/_dwr/util.js` -> 200 JavaScript
  - `/_dwr/interface/FestivalHelperDWR.js` -> 200 JavaScript
- `FestivalHelperDWR` exposed only interface declarations such as `getCouplet`; no sensitive data or write action was proven.
- `/.git/HEAD`, `/.env`, `/actuator/env`, `/actuator/heapdump` returned 403/WAF pages. Do not report “exists but blocked”.

### `yikatong.cdp.edu.cn`
Stable low-impact checks:
- `POST /server/auth/getEncrypt {"code":"10051"}` returned `success:true` with temporary `id/publicKey/fixed:false`. This is a public encryption helper, not a vulnerability by itself.
- `POST /server/captcha/get` returned captcha image material, token, and `secretKey`. This is not submit-worthy unless `captcha/check` can be bypassed/reused and tied to SMS or another sensitive action.
- `GET /server/user/info` with no/invalid token returned encrypted `data`. Decrypting with the known frontend SM4 key produced only `{"code":"","message":"失败","success":false}` — not user data.
- `GET /server/user/tradeList` and `/server/card/cardList` returned failure objects, not transactions/cards.
- `/server/card/reportLoss` and `/server/card/cancelLoss` returned encrypted failure objects; decrypt result: `{"code":"","message":"加密缺少必要参数","success":false}`. No unauthorized loss/cancel-loss operation was proven.
- `/server/user/password/checkIdentityNo` and `/server/user/password/resetPwd` returned 401 Unauthorized.
- `/server/home/sendSms` remained blocked by required fields / image captcha; no SMS abuse proof.
- CORS test did not show `Access-Control-Allow-Origin` reflection; do not report CORS.

SM4 decrypt command pattern for this target class:
```bash
printf '%s' '<base64-data>' | base64 -d >/tmp/cdp.enc
openssl enc -d -sm4-ecb -K 773638372d392b33435f48266a655f35 -in /tmp/cdp.enc
```
The durable lesson is to decrypt before claiming leakage; encrypted data wrappers often contain only failure JSON.

### `ehall`, `cas`, `aic`, `webvpn`, `jy`, `mail`
- `ehall`, `cas`, `aic`, `jy`, `welcome`, `sicsve`, and `tafe` were intermittently reachable and later timed out. Treat this as target/network instability, not evidence.
- Earlier CDP references already cover the same JSONP/docrepo/systemSetting/CAS/aic/webvpn/jy leads; this run produced no new sensitive data or write capability.
- **2026-06-10更新**: aic.cdp.edu.cn 确认存在CORS配置不当 (`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`), 但API端点返回空响应(可能需认证)。CAS登录页JS泄露安全中心端口4102/4107(联奕CAS lyuapServer)。详见 `cdp-edu-cn-testing-patterns-20260610.md`。
- `mail.cdp.edu.cn` remains Tencent Enterprise Mail. DNS/DMARC/SPF weakness or standard login failure behavior is not medium+ without authorized spoofed-delivery proof or account takeover chain.

## No-submit rule
Do not submit for CDP when findings are limited to:
- DWR interface JS without sensitive method output;
- WAF/403 on `.git`, `.env`, actuator, or attack strings;
- yikatong public `getEncrypt` or `captcha/get`;
- encrypted yikatong responses that decrypt to failure objects;
- login redirects, CAS standard XML/errors, public login pages;
- intermittent timeouts / connection refused;
- QQ Exmail standard behavior or bare DMARC/SPF weakness.

## Resume conditions
Resume report writing only if one of these is proven:
1. Legal test account demonstrates yikatong IDOR/vertical auth bug in `tradeList`, `cardList`, `reportLoss`, `cancelLoss`, `resetPwd`, etc.
2. `captcha/check` can be bypassed/reused and triggers SMS or another sensitive business action.
3. `ehall`/`docrepo`/`systemSetting` returns non-public personnel, attachments, workflow/todo data, or write capability.
4. CAS/JY password-recovery chain proves real user enumeration, captcha bypass, reset bypass, or account takeover.
5. Mail testing has authorized inbox delivery proof for spoofing, not merely DNS policy weakness.

## Evidence artifact pattern
When no report is warranted, write a concise artifact such as:
`/tmp/vuln_reports/cdp/deep-recon-YYYYMMDD-final.txt`

Include asset list, verified endpoints, decrypted yikatong failure evidence, explicit no-submit reasons, evidence paths, and resume conditions.
