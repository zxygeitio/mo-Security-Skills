# CDP yikatong JS/API negative evidence pack (2026-05-26)

## Scope
Target: `cdp.edu.cn`, focused continuation after prior CDP negative packs. Main stable asset this round: `https://yikatong.cdp.edu.cn/`.

This is a negative-evidence reference for education SRC workflow. It is not a vulnerability report.

## Trigger / when to use
Load this reference when the user asks to continue digging 成都职业技术学院 / CDP and the current path reaches the yikatong campus-card service, frontend JS/API extraction, upload checks, card/trade APIs, captcha/SMS, or CORS.

## Key lesson
Do not report CDP yikatong frontend-exposed endpoints unless a request proves real unauthenticated sensitive data, IDOR, authentication bypass, executable/public upload, SMS/captcha bypass, or business write impact.

Many endpoints return HTTP 200 but only contain failure JSON or encrypted failure wrappers. Decrypt before claiming leakage.

## Asset/reachability notes
A small batch reached or tested `www`, `ehall`, `cas`, `aic`, `jy`, `zhao`, `yikatong`, `welcome`, `course`, `uia`, `zyk`, `jedu`, `tafe`, `dzmg`, `special`, `sicsve`, `newvpn`, `webvpn`, `jw`, `jy-o`, `jy-hr`, `jy-js`, `kcsz`, `nac`, `app-vsmg`, `sdmg.sad` under `cdp.edu.cn`.

Current network behavior was intermittent: many hosts returned `Network is unreachable`, timeout, or DNS no-record. Treat these as network state, not findings.

## Stable frontend/API findings
`https://yikatong.cdp.edu.cn/` title: `校园生活服务`.

Frontend config:
- `/static/config/index.js` defines `baseUrl: '/server'` and `window.V8_SERVER_PRE`.
- Main bundle `/static/js/index.f4e8ebfd.js` exposes many campus-card routes.

High-value extracted routes included:
- `/server/user/info`
- `/server/user/tradeList`
- `/server/user/tradeListCount`
- `/server/user/uploadFacePhoto`
- `/server/user/uploadIdPhoto`
- `/server/card/cardList`
- `/server/card/reportLoss`
- `/server/card/cancelLoss`
- `/server/card/config`
- `/server/auth/getEncrypt`
- `/server/auth/getToken`
- `/server/auth/transferToken`
- `/server/auth/casConfig`
- `/server/auth/organizations`
- `/server/captcha/get`
- `/server/home/simpleSendSms`
- `/server/home/sendSms`
- `/server/merchant/tradeList`
- `/server/water/tradeList`
- `/server/relatedUser/config`
- `/server/virtualCard/config`

## Verified negative outcomes

### User/card/trade/merchant/water APIs
Unauthenticated probes against `/server/user/tradeList`, `/server/user/tradeListCount`, `/server/card/cardList`, `/server/card/config`, `/server/merchant/tradeList`, `/server/water/tradeList`, and related config endpoints returned failure objects such as:

```json
{"code":"","message":"失败","success":false}
```

No user profile, card data, transaction records, merchant data, or water billing data was returned.

### Encrypted wrapper on `/server/user/info`
`GET /server/user/info` returned HTTP 200 with encrypted `data`, but decrypting with the known frontend SM4 key produced only a failure object, not user data.

Decrypt pattern:

```bash
printf '%s' '<base64-data>' | base64 -d >/tmp/cdp.enc
openssl enc -d -sm4-ecb -K 773638372d392b33435f48266a655f35 -in /tmp/cdp.enc
```

Expected negative decrypt result:

```json
{"code":"","message":"失败","success":false}
```

### Auth/token helpers
`/server/auth/getEncrypt` returns `success:true` with a temporary `id`, `publicKey`, and `fixed:false`. Treat as a public login/encryption helper unless it can be used to obtain a token or access real data.

`/server/auth/getToken` and `/server/auth/transferToken` returned failure objects without usable tokens.

### Upload candidates
`/server/user/uploadFacePhoto` and `/server/user/uploadIdPhoto` returned failure objects and did not return `fileUrl`, `resId`, `genName`, OSS URL, or any publicly accessible uploaded file.

`/server/blueutil/recordUploadResult` returned `401 Unauthorized`.

Do not report upload without a returned file handle and public access proof.

### Card report-loss / business write
`/server/card/reportLoss` returned an encrypted `data` wrapper. The behavior matches previous CDP yikatong failure-wrapper cases; no unauthenticated loss/cancel-loss business action was proven.

### Captcha/SMS
`POST /server/captcha/get` with empty input returned `repCode 0011` / `类型不能为空`. SMS-related endpoints such as `/server/home/simpleSendSms` returned `401` or failed. No captcha bypass, reuse, or SMS trigger was proven.

### CORS
Multiple `/server` endpoints tested with `Origin: https://evil.example` did not expose a usable `Access-Control-Allow-Origin` + credentials chain. Do not report CORS from this round.

## No-submit rule
Do not submit CDP yikatong when evidence is limited to:
- frontend routes in JS bundles;
- public `/server/auth/getEncrypt` publicKey/id;
- HTTP 200 failure JSON;
- encrypted wrappers that decrypt to failure JSON;
- upload endpoints returning only failure JSON or 401;
- intermittent timeout / unreachable hosts;
- no CORS reflection or no sensitive cross-origin data.

## Resume/report conditions
Only write a report if one of these is proven:
1. Legal low-privilege account demonstrates IDOR/vertical auth bug in `tradeList`, `cardList`, `reportLoss`, `cancelLoss`, `resetPwd`, etc.
2. Captcha/SMS chain is bypassed or reusable and triggers a real low-frequency sensitive action.
3. Upload endpoint returns `fileUrl`/`resId`/`genName` and the file is publicly accessible or browser-renderable on the school domain.
4. Auth helper can be chained to obtain a token or read real user/card/transaction data.
5. Another CDP asset returns non-public personnel data, attachments, workflow/todo data, write capability, SQLi/RCE, or account takeover proof.

## Evidence artifact pattern
When no report is warranted, save a concise negative conclusion under:

`/tmp/vuln_reports/cdp/deep-recon-YYYYMMDD-final.txt`

Include route list, representative failure responses, decrypt result, CORS result, evidence paths, no-submit reasons, and resume conditions.
