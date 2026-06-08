# 360 SRC evidence screenshots and high-value reporting notes

Use this reference when a 360 众测 / 360 SRC report needs正文插图 or when earlier submissions were ignored for weak proof.

## Reviewer feedback patterns to design around
360 may ignore or reject reports when:
- The result is a fixed value and the report does not prove real exploitability.
- A SMS/验证码 issue has a built-in interval such as 2 minutes and does not demonstrate practical abuse.
- A script-injection / abnormal-script report only shows suspicious code but does not prove malicious behavior.
- Screenshots are attached separately instead of inserted directly into the report body.
- The report claims a stronger issue than the evidence supports, such as password reset bypass when only account enumeration is proven.

## Preferred evidence shape
For every screenshot inserted into the body, make it prove exactly one step:
1. Environment / scope proof: VPN active if applicable, target HTTP 200, and target URL.
2. Public entry proof: public page contains SESSION/CSRF/hidden tokens and the relevant endpoint path.
3. Action proof: the unauthenticated or low-privilege request and key parameters.
4. Result proof: key response fields, e.g. `state=1`, `data=<account>`, or masked phone/email values.
5. Non-fixed-value proof: multiple inputs produce different meaningful results.
6. Control proof: if a stronger claim is not made, include the negative control; e.g. wrong OTP returns `请重新获取验证码`, proving the report is not claiming OTP bypass.

## When browser screenshots are hard
If the browser cannot load the site due to certificate/UI problems but curl-based reproduction has already captured real responses, it is acceptable to generate PNG evidence panels from the captured request/response text, provided the screenshots contain:
- URL or endpoint path.
- Key parameters or request purpose.
- Key response values.
- Clear conclusion for that step.

Good filenames:
- `01_vpn_connectivity.png`
- `02_public_page_csrf_endpoint.png`
- `03_confirmAccount_enum.png`
- `04_multi_account_enum_compare.png`
- `05_contact_mask_leak.png`
- `06_wrong_otp_control.png`

## Account enumeration + contact leak report pattern
When a find-password flow allows unauthenticated account confirmation and then shows masked bound contact info:
- Title it as account enumeration + bound phone/email information disclosure.
- Do not title it as arbitrary password reset unless the password really changes.
- Include at least 3-4 account examples to prove the response is not fixed.
- Include masked contact examples from the next step.
- Include an OTP negative-control screenshot when tested.
- Impact should focus on supplier/admin account discovery, credential stuffing dictionaries, targeted phishing/social engineering, and account takeover preparation.

## Example concise wording
`未登录攻击者可通过公开找回密码页面获取SESSION/CSRF，调用账号确认接口枚举账号是否存在，并在下一步回显绑定手机号/邮箱掩码，可辅助撞库、社工、定向钓鱼和账号接管攻击。`
