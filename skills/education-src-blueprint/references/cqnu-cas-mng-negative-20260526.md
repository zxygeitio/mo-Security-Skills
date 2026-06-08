# CQNU CAS/mng 找回密码与账号激活负证据 (2026-05-26)

## 目标
- `https://csxrz.cqnu.edu.cn/mng/forgetPWD.jsp`
- `https://csxrz.cqnu.edu.cn/mng/forgetPWDApp.jsp`
- `https://csxrz.cqnu.edu.cn/mng/activation.jsp`
- `https://csxrz.cqnu.edu.cn/cas/login`

## 前端接口

`/mng/subsystem/acp/js/_forgetPWD.js`:
- `/mng/acp/zhzx/mmzh/checkFindType`
  - `checkLogin=false&findType={findType_mobile|findType_email|findType_question}&findUser=...`
- `/mng/acp/zhzx/mmzh/validateCaptchaAndReset`
  - `captcha, findUser, userPassword, currPwdStratety`
- `/mng/acp/zhzx/mmzh/checkAnswerAndReset`
  - `checkLogin=false, ACPPWDRETRIEVEQUESTION, ACPPWDRETRIEVEANSWER, findUser`

`/mng/subsystem/acp/js/_activation.js`:
- `/mng/acp/zhzx/activate/checkInfo`
  - `ACPUID, ACPNAME, ACPIDCARD, verCode`
- `/mng/acp/zhzx/activate/sendCaptcha`
  - `phoneNum`; requires successful previous session state.
- `/mng/acp/zhzx/activate/saveMobile`
  - `captcha, phoneNum`; requires previous state.
- `/mng/acp/zhzx/activate/changePwd`
  - `userPassword, currPwdStratety`; requires previous state.

CAS login page:
- `/cas/smsValidateCode` with `cellPhoneNum`.

## Verification result

Low-impact checks only; no real user phone bombardment.

- `checkFindType` for random/nonexistent and small common student-id shaped values returned the same XML:
  `<JSONObject><success>false</success><msg>未预留所选的找回方式</msg></JSONObject>`
- `activate/checkInfo` with invalid captcha returned the same front-gate error for random and student-id shaped values:
  `<JSONObject><success>false</success><msg>验证码输入错误！</msg></JSONObject>`
- `activate/sendCaptcha` without prior state returned:
  `<JSONObject><success>false</success><msg>会话失效，请重试！</msg></JSONObject>`
- `saveMobile`/`changePwd` alone only expose required-parameter 400 errors, not state bypass.
- `CAS /smsValidateCode` with invalid phone returned a 500 error page; no proof of SMS send, enumeration, or bypass.
- mng endpoints did not expose usable CORS (`Access-Control-Allow-Credentials:true` absent).

## Decision

Do not submit. This branch lacks:
- stable account enumeration difference;
- unauthorized phone/email/security-question disclosure;
- captcha bypass;
- unauthenticated SMS send;
- direct `saveMobile`/`changePwd` state bypass;
- credentialed CORS sensitive read.

Continue CQNU via mobile/app APIs, WebVPN/low-privileged ehall scenarios, admission query with real safe samples, or new subdomain/API assets rather than CAS/mng black-box guessing.
