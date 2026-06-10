# CDP yikatong 2026-05-22 negative verification note

## Scope
Target: `https://yikatong.cdp.edu.cn/` campus-card / uni-app H5 system.

This reference is a session-specific negative evidence pack for future `edu-campus-card-uniapp-yikatong` work. It records what was verified and why it should not be submitted unless a later run closes the impact loop.

## Durable workflow lessons

1. Prefer `curl --noproxy '*'` for this target when validating evidence.
   - In this session, Python `requests` and plain curl sometimes stalled or timed out before writing evidence.
   - Short `curl --noproxy '*' --connect-timeout 3 --max-time 10 ...` calls returned stable results for the key endpoints.
   - Do not encode this as "requests is broken"; treat it as a target-specific reliability pattern.

2. Keep negative evidence explicit.
   - The user wants only verifiable, submit-worthy vulnerabilities.
   - For this class of campus-card targets, a final "do not submit" artifact is valuable when the checks only prove normal public helper flows or blocked actions.

3. Redact all crypto/token material in reports.
   - Replace `data`, `token`, `accessToken`, `refreshToken`, `secretKey`, `publicKey`, ids from `getEncrypt`, and encrypted blobs with `[REDACTED]`.
   - It is acceptable to describe the decrypted result when it is only a failure object.

## Verified endpoint outcomes

### Static app entry

Command shape:
`curl -sk --noproxy '*' 'https://yikatong.cdp.edu.cn/'`

Observed:
- HTTP 200
- title: `校园生活服务`
- static uni-app entry only

Decision: not a vulnerability.

### `/server/auth/getEncrypt`

Command shape:
`curl -sk --noproxy '*' -X POST 'https://yikatong.cdp.edu.cn/server/auth/getEncrypt' -H 'Content-Type: application/json' --data '{"code":"10051"}'`

Observed redacted response:
`{"success":true,"message":"成功","resultData":{"id":"[REDACTED]","publicKey":"[REDACTED]","fixed":false},"code":""}`

Decision: public encryption-helper flow only. Do not submit unless it can be used to access or modify protected data.

### `/server/captcha/get`

Command shape:
`curl -sk --noproxy '*' -X POST 'https://yikatong.cdp.edu.cn/server/captcha/get' -H 'Content-Type: application/json' --data '{"captchaType":"blockPuzzle","clientUid":"cdp_test_uid","ts":1710000000000}'`

Observed redacted response:
`{"repCode":"0000","repData":{"secretKey":"[REDACTED]","originalImageBase64":"[REDACTED]","jigsawImageBase64":"[REDACTED]","token":"[REDACTED]"},"success":true}`

Decision: public captcha challenge generation only. Do not submit unless `captcha/check` can be bypassed/reused and tied to a real business action.

### `/server/captcha/check`

Command shape:
`curl -sk --noproxy '*' -X POST 'https://yikatong.cdp.edu.cn/server/captcha/check' -H 'Content-Type: application/json' --data '{"captchaType":"blockPuzzle","pointJson":"{}","token":"invalid-token"}'`

Observed:
`{"repCode":"6110","repMsg":"验证码已失效，请重新获取","repData":null,"success":false}`

Decision: no captcha bypass evidence.

### `/server/home/sendSms`

Command shape:
`curl -sk --noproxy '*' -X POST 'https://yikatong.cdp.edu.cn/server/home/sendSms' -H 'Content-Type: application/json' --data '{"phone":"13800138000","imgCodeId":"ABCDEFGH","imgCode":"0000","orgId":"10051"}'`

Observed:
`{"success":false,"message":"图形验证码不正确","resultData":null,"code":""}`

Decision: SMS flow is blocked by image captcha. Do not claim unauthenticated SMS sending or captcha bypass.

### `/server/user/password/checkIdentityNo`

Command shape:
`curl -sk --noproxy '*' -X POST 'https://yikatong.cdp.edu.cn/server/user/password/checkIdentityNo' -H 'Content-Type: application/json' --data '{}'`

Observed:
- HTTP 401
- empty body

Decision: no password-reset / identity-check bypass evidence.

### `/server/user/info`

Command shape:
`curl -sk --noproxy '*' 'https://yikatong.cdp.edu.cn/server/user/info' -H 'Authorization: invalid'`

Observed redacted raw response:
`{"data":"[REDACTED]"}`

SM4 decrypt result with the known frontend key from `edu-campus-card-uniapp-yikatong.md`:
`{"code":"","message":"失败","success":false}`

Decision: encrypted response is only a failure object, not user-data leakage.

## Submission decision

Do not submit the current yikatong findings. They are only:
- public encryption-helper endpoint;
- public captcha challenge endpoint;
- frontend-discoverable API routes / crypto logic;
- blocked SMS/password/user-info flows.

Submit only if a later run proves at least one of:
1. legal test account + IDOR on `tradeList`, `cardList`, `reportLoss`, `cancelLoss`, or `resetPwd`;
2. `captcha/check` offline calculation/reuse that triggers SMS or sensitive account action;
3. hardcoded crypto logic decrypts real user/card/balance/transaction/phone data;
4. accessible CAS/ehall path returns real personnel or account data without auth.

## Report artifact pattern

When no vulnerability is submit-worthy, produce a plain text negative conclusion file rather than a forced report. Include:
- conclusion: "不建议提交";
- endpoint-by-endpoint evidence with one-line curl;
- redacted key responses;
- explicit reason each item is not submit-worthy;
- conditions required to resume deep testing.
