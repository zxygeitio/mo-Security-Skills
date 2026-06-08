# CQNU 第三轮深挖负证据包（2026-05-26）

## 适用场景
教育 SRC 目标在已有招生系统 CORS/弱鉴权候选、智慧校园门户候选、CAS 候选均未达提交门槛后，继续切换到邮件、ehall/portal JSONP、财务/一卡通/教务/API 子域、IIS/Swagger/Trace、找回密码接口等入口做低影响复核。

## 本次目标
重庆师范大学 `cqnu.edu.cn`。

证据目录：
- `/tmp/src_cqnu/round3/probe_results.tsv`
- `/tmp/src_cqnu/round3/dns_mail.json`
- `/tmp/src_cqnu/round3_deep/probe_results.tsv`
- `/tmp/src_cqnu/round3_yscs_more/probe_results.tsv`
- 最终门禁：`/tmp/vuln_reports/cqnu/cqnu-round3-no-submit-decision.txt`

## 验证结论
本轮不建议新增提交漏洞报告。

原因：邮件安全、ehall/portal JSONP、财务/一卡通/教务/API、cwcwx IIS、yscs 找回密码、CAS 状态页均未形成“未授权敏感数据 / 越权 / 任意文件上传下载 / 认证绕过 / RCE / SQLi”等实质漏洞证据。

## 分支判断

### 1. 邮件安全 / mail.cqnu.edu.cn
- MX：`hzmx01.mxmail.netease.com`、`hzmx02.mxmail.netease.com`，属于网易企业邮箱链路，不适用 QQ Exmail 账号枚举侧信道模式。
- SPF：`v=spf1 include:spf.163.com -all`，硬失败策略存在。
- DMARC：`v=DMARC1; p=quarantine; fo=1; ruf/rua 指向 qiye.163.com`，非 DMARC 缺失。
- DKIM：`default._domainkey.cqnu.edu.cn` 存在 DKIM 公钥。
- `mail.cqnu.edu.cn` 首页可访问，Coremail 常见路径大多 404；`/coremail/s/json` 返回小 XML，但无敏感数据、账号枚举分支或凭据。

判断：不提交。

### 2. ehall / portal JSONP
- `ehall.cqnu.edu.cn` 常见 JSONP 路径多数不可达或 000。
- `portal.cqnu.edu.cn/jsonp/school.json`、`serviceCenterData`、`appIntroduction` 等路径最终落到 `csxrz.cqnu.edu.cn` CAS 登录页，返回统一身份认证页面，不是金智 ehall 公开 JSONP 数据。

判断：没有 `appIntroduction` 教职工 PII、服务目录未授权或 school 配置泄露证据，不提交。

### 3. 财务/一卡通/教务/API 子域
- `ykt/card/ecard/pay/api` 等常见校园卡、支付、API 高价值入口多数为不可达、404、403、登录页或 WAF 页面。
- 未发现 `swagger-ui/doc.html/v2-api-docs/actuator/env/druid/.env` 等有效暴露。
- `cwcwx.cqnu.edu.cn` 首页是 IIS 默认页；`/v2/api-docs` 返回“Web应用防火墙”；`/trace.axd` 为 403 “跟踪错误”，提示远程跟踪不可用；`web.config/.env/swagger/api` 等均 404。

判断：默认页、WAF 页、Trace 403 禁止页不满足实质漏洞门槛。

### 4. yscs 智慧校园找回密码/公开接口
- `GET /saas/gateway/fighter-middle/api/forget-password/getType` 返回找回方式配置，如安全问题/手机验证码、`requestWithEncrypt=true`、`needSliderImageCaptchaBeforeSend=true`、`needSliderImageCaptchaOnSubmit=true`、`sendTimeIntervalInMills=60000`。
- `POST getType` 返回参数/方法相关错误；`sendCode/checkAccount/checkUser/validateUser/submit/getPublicKey/captcha` 等猜测路径均 404。
- 未触发短信/验证码发送，未形成账号存在性差异，未绕过滑块/加密请求，未返回真实用户数据。

判断：公开找回方式配置只能作为低价值线索，不构成认证绕过或账号枚举。

### 5. CAS 状态页
- `/cas/status` 仍返回 500 栈信息，与上一轮一致。
- 未结合出访问控制绕过、ticket 绕过或敏感数据读取。

判断：不作为新增漏洞提交；若平台接受低危信息泄露可另行评估，但不符合“只要实质漏洞”的偏好。

## 后续投入条件
只有满足以下任一条件才值得继续：
- 拿到合法测试账号后验证 `yscs/portal` 的 IDOR/越权；
- 获得真实完整低影响样本后再验证 `zsxt` 录取/通知书接口；
- 发现新的非登录保护 API、上传下载入口或真实敏感数据接口。

## 命令模板

```bash
curl -skL --connect-timeout 4 --max-time 10 -D- https://mail.cqnu.edu.cn/
curl -skL --connect-timeout 4 --max-time 10 -D- https://yscs.cqnu.edu.cn/saas/gateway/fighter-middle/api/forget-password/getType
curl -skL --connect-timeout 4 --max-time 10 -D- https://cwcwx.cqnu.edu.cn/trace.axd
curl -skL --connect-timeout 4 --max-time 10 -D- https://csxrz.cqnu.edu.cn/cas/status
curl -skL --connect-timeout 4 --max-time 10 -D- 'https://portal.cqnu.edu.cn/jsonp/appIntroduction.json?appId=1'
```

## 通用教训
- 邮件安全先看 MX 供应商；只有 QQ Exmail 才套用 QQ 登录侧信道枚举模式。
- DMARC/SPF/DKIM 都存在时，不要硬凑邮件安全报告。
- `portal/jsonp/*` 返回 CAS 登录页时，不要误判为金智 ehall JSONP 暴露。
- IIS 默认页、Trace 403 禁止页、WAF 伪 Swagger 页都属于负证据。
- 找回密码方式配置公开不等于账号枚举；必须有真实发送、稳定差异或接管链。
