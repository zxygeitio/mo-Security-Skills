# CQNU 第四/第五轮外网黑盒续挖负证据包（2026-05-26）

## 适用场景
教育 SRC 目标经过多轮招生系统、智慧校园、CAS、邮件、ehall/portal 验证后，用户要求继续深挖；需要判断是否还有外网无账号黑盒投入价值。

本记录归入 `education-src-blueprint`，作为“多轮无实质漏洞后如何收敛”的 CQNU 案例。

## 目标
重庆师范大学 `cqnu.edu.cn` 相关资产。

前序已知负证据：
- `zsxt.cqnu.edu.cn` 招生系统存在 CORS 回显与弱鉴权表象，但公开样本查询不命中真实录取信息，通知书接口仅壳页面/模板占位。
- `yscs.cqnu.edu.cn` 找回密码 getType 返回公开配置，未触发短信/验证码、账号枚举或绕过。
- 邮件、ehall/portal、cwcwx、CAS 等第三轮均未达到实质漏洞门槛。

## 第四轮：yscs / zsxt 继续验证

### 验证假设
1. 浏览器运行态/JS 隐藏接口是否能发现 yscs 或 zsxt 的未授权敏感 API。
2. 招生对象枚举边界是否能从录取查询/通知书接口补到真实录取数据。
3. yscs 公开 API 差异是否能形成账号枚举、短信触发、认证绕过或上传下载入口。

### 关键结果
- `https://yscs.cqnu.edu.cn/saas/gateway/fighter-middle/api/forget-password/getType`：
  - 200 JSON；
  - `Access-Control-Allow-Origin` 回显恶意 Origin；
  - `Access-Control-Allow-Credentials: true`；
  - 只返回公开找回方式配置：安全问题、手机验证码、个人邮箱、工作邮箱、`requestWithEncrypt=true`、滑块验证码开启、60 秒间隔等；
  - 不包含账号、手机号、邮箱、token 或业务数据。
- yscs 登录接口 POST 仅返回“用户名或密码错误”，未发现 token 泄露、认证绕过或账号存在差异。
- 猜测的 `getPublicKey`、`captcha`、`checkAccount`、`sendCode`、`validateUser`、`submit`、`file/upload`、`file/download`、`tenant/listNoPermissionCheck` 等接口多数 404 或错误分支。
- zsxt 录取查询/通知书常见路径当前多为 404 或空响应；结合前序验证，仍不能证明真实考生数据泄露。

### 判定
不提交。当前只有“CORS + 公开配置/404 错误”证据，不满足实质漏洞门槛。

## 第五轮：高价值子域与 rs epx-frame 深挖

### 子域筛选结果
可达资产包括：
- `www.cqnu.edu.cn`
- `portal.cqnu.edu.cn`
- `yscs.cqnu.edu.cn`
- `zsxt.cqnu.edu.cn`
- `csxrz.cqnu.edu.cn`
- `jwc.cqnu.edu.cn`
- `cwcwx.cqnu.edu.cn`
- `oa.cqnu.edu.cn`
- `vpn.cqnu.edu.cn`
- `webvpn.cqnu.edu.cn`
- `mail.cqnu.edu.cn`
- `lib.cqnu.edu.cn`
- `rs.cqnu.edu.cn`
- `rsc.cqnu.edu.cn`

多数核心业务仍在统一认证或网关后。

### cwcwx Swagger / v2-api-docs false positive
- `https://cwcwx.cqnu.edu.cn/v2/api-docs` 返回 200，但响应体是 DPtech/Web 应用防火墙拦截页：标题“Web应用防火墙”，内容“您的请求存在异常，网站管理员设置了拦截访问”。
- 不应当成 Swagger 文档泄露提交。

### 博达/VSB 公共接口边界
- `jwc/lib/rsc` 的 `/system/resource/js/counter.js` 可访问，但只是 Visual SiteBuilder 常规公开计数 JS。
- `/_web/_search/api/search/new.rst` 在 `www/jwc` 等返回 404 错误页，未发现 SQLi、敏感数据或未授权接口。

### VPN / WebVPN 边界
- `vpn.cqnu.edu.cn` 是 DPtech SSL VPN 登录页，暴露客户端组件路径与 codebase 版本形式，但未验证出认证绕过、RCE、任意文件读取或敏感数据访问。
- `webvpn.cqnu.edu.cn` 301 到 `/rump_frontend/nav/`，仍属登录/网关边界。

### rs.cqnu.edu.cn epx-frame
首页为 epx-frame，`/js/config.js` 暴露：
- `VERSION=5.2.4`
- `BASE_PROJECT_NAME=epxing-frame`
- `BASE_CLIENT_ID=frame`
- `BASE_SYSTEM_ID=epxing-frame-manage`
- `BASE_APP_ID=FM_SERVICE_PLATFORM`
- 跳转 `/#/hall/cqsfdx`

前端 JS 中发现 API 模式：
- `/epxing-frame/api/v1/rsa/public/v2`
- `/epxing-frame/api/v1/qrcode/getQrCode`
- `hall/login`
- `hall/role/select`
- `service/setting`
- `attachment/file/download`

验证结果：
- `/epxing-frame/api/v1/rsa/public/v2` 未登录可访问，返回 RSA `publicKey` 和 `aesKey`，但这是前端加密握手公开接口，不含业务数据或凭据。
- `qrcode/getQrCode`、`service/setting`、hall role 等接口返回 302 到 `csxrz` CAS 登录。
- `hall/login`、`hall/role/select` 返回 401 会话过期。
- `attachment/file/download?id=1` 返回“非法的请求租户”，尝试 `tenant/client` 参数仍未下载文件。

### 判定
不提交。`rs.cqnu.edu.cn` 存在公开前端配置和公开加密握手，但业务接口认证正常，无未授权数据、IDOR、上传下载成功或认证绕过。

## CQNU 继续投入条件
只有满足以下之一才建议继续 CQNU：
1. 拿到合法测试账号后做 `rs/yscs/portal` 授权态 IDOR/越权验证。
2. 拿到真实完整低影响考生样本后继续 `zsxt` 录取/通知书接口验证。
3. 发现新的非 CAS 保护 API、真实上传下载入口，或后端返回业务对象 ID 的接口。

否则外网无账号黑盒继续投入产出比低，容易只产出不可提交候选。

## 可复用门禁规则
- 200 状态码不等于接口暴露：必须检查是否 WAF 拦截页、登录页、SPA 壳或公开配置。
- CORS 回显 + Credentials 只有在能跨域读取登录态敏感响应时才形成可提交漏洞；公开配置或错误 JSON 不提交。
- 前端 RSA publicKey/aesKey 获取接口通常属于公开加密握手，不应单独当凭据泄露。
- VPN/WebVPN 登录页、客户端组件路径、版本形式仅为线索；没有认证绕过/RCE/文件读取/敏感数据时不提交。
