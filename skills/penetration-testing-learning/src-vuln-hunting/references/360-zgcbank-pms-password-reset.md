# 360/ZGCBank PMS password-reset account enumeration pattern

Use this reference when continuing 360 众测 work on `pms.zgcbank.com` or similar supplier/procurement systems.

## Why this matters
360 reviewers rejected earlier low-impact submissions because they looked like fixed values, config/errors, missing malicious proof, SMS with 2-minute limits, or reports without inline proof images. Future 360 reports should prioritize real business impact and include proof in the report body.

## Validated pattern: password reset account enum + contact-mask leak
Target class: public password reset / forgot password flow.

Observed on ZGCBank PMS:
- Entry: `/pms/ananymous/zzqx/zhmm`
- Account confirmation: `/pms/ananymous/zzqx/zhmm/confirmAccount`
- Next-step verification page: `/pms/ananymous/zzqx/zhmm/valiYzm`
- Related follow-up endpoints exposed by the page:
  - `/pms/ananymous/zzqx/zhmm/sendMessage`
  - `/pms/ananymous/zzqx/zhmm/sendEmail`
  - `/pms/ananymous/zzqx/zhmm/checkSmsYzm`
  - `/pms/ananymous/zzqx/zhmm/checkEmailYzm`
  - `/pms/ananymous/zzqx/zhmm/resetPwd`

Minimal proof chain:
1. GET the public reset page and keep cookies; extract `_csrf`, `_ResubmitKey`, `_ResubmitToken`.
2. POST `dlh=<candidate>&_csrf=<csrf>&_ResubmitToken=<token>&_ResubmitKey=<key>&url=/pms/ananymous/zzqx/zhmm&from=http://pms.zgcbank.com/pms` to `confirmAccount` with the cookie and `X-CSRF-TOKEN`.
3. A real candidate returns JSON like `{"text":"操作成功！","state":1,"data":"admin","_ResubmitToken":null}`. Use several different account names to prove this is not a fixed value.
4. POST to `valiYzm` in the same session; the HTML can reveal contact masks such as `value="130****2741"`, `手机验证码已发送至您的手机130****2741`, or masked email values.
5. Document follow-up endpoints but do not claim password reset unless actual account takeover is verified.

## Submission framing
Recommended title:
`中关村银行PMS供应商系统找回密码流程存在未授权账号枚举及绑定手机号/邮箱信息泄露`

Risk: try 中危 if multiple real account candidates and bound contact masks are shown; be prepared for downgrade.

Core impact wording:
- 未登录攻击者可确认供应商/管理员账号是否存在。
- 可获取绑定手机号/邮箱掩码。
- 可辅助撞库、社工、定向钓鱼、验证码攻击前置定位及后续账号接管尝试。

## What not to overclaim
- Do not call it arbitrary password reset unless `resetPwd` actually changes the password.
- Do not report `checkSmsYzm/checkEmailYzm` as bypass if it only says `请重新获取验证码` or `验证码错误`.
- Do not present SMS sending as bombing if the platform has a 2-minute limit; 360 has rejected this.
- Do not bundle Tomcat/health/fixed `isec` values as the main issue.

## Evidence checklist for 360
360 often requires inline images in the report body, not just attachments. Capture:
1. Public reset page showing CSRF/session-related fields and `confirmAccount`/`valiYzm` paths.
2. `confirmAccount` request and `state=1,data=<account>` response.
3. Several account candidates returning different `data` values to prove enumeration and avoid fixed-value rejection.
4. `valiYzm` page showing different phone/email masks per account.
5. Negative OTP-control proof showing invalid OTP does not bypass reset, so the report is scoped honestly.
