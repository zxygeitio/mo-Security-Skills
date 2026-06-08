# 中央戏剧学院 / zhongxi.cn 校外访问网关深挖模式

## 适用场景
教育目标存在 `webexp.*`、`vpn.*`、`ehall.*`、`jw.*`、`jwc.*`、`changping.*` 等资产，业务系统通过 APISIX/OpenResty 网关统一重定向到校外访问或统一身份认证平台。

本记录来自对 `chntheatre.edu.cn` / `zhongxi.cn` 的低影响深挖。它不是单目标报告模板，而是未来遇到同类“WebVPN/校外访问网关 + IDS/authserver + APISIX 保护业务系统”时的判断与验证清单。

## 关键识别特征
- 业务系统首页或任意路径返回 302 到：
  - `https://webexp.<domain>/login/login?externalIds=...&custom=...&returnUrl=...`
- 响应体可能包含：
  - `Powered by APISIX`
  - `openresty`
- `webexp` 前端通常暴露登录配置 API：
  - `/api/access/authentication/list`
  - `/api/access/authentication/all`
  - `/api/authentication/conf`
  - `/api/access/nav/custom`
  - `/api/access/nav/site-list`
  - `/api/access/password-auth`
  - `/api/access/user/info`
- 统一认证常见路径：
  - `/authserver/login`
  - `/authserver/serviceValidate`
  - `/authserver/checkNeedCaptcha.htl`
  - `/authserver/getCaptcha.htl`
  - `/authserver/dynamicCode/getDynamicCode.htl`
  - `/authserver/startAssertion`

## 低影响验证顺序
1. 先确认业务系统是否被网关统一保护。
   - 对 `/`、`/api/user/info`、`/jsonp/school.json`、`/swagger-ui.html`、`/actuator/env`、`/jwglxt/xtgl/login_slogin.html` 做 GET。
   - 如果全部 302 到 `webexp` 登录页，说明业务侧默认受认证网关保护，不能把登录页当漏洞。

2. 抽取 `webexp` 前端 API，只验证公开配置与鉴权边界。
   - 登录方式列表、导航配置、密码登录配置通常是公开登录页配置。
   - 只有返回用户数据、业务资源列表、可用 token、真实凭据或可执行操作时才进入报告候选。

3. 对 `webexp` 用户接口做未授权对照。
   - `/api/access/user/info` 应返回类似 `未授权`。
   - `/api/access/user/change-*`、`logout` 等接口若返回 `未授权` 或 404，不成立。

4. CORS 判断要看是否反射任意 Origin。
   - 若 `Access-Control-Allow-Origin` 固定为 `webexp.<domain>`，即使带 `Access-Control-Allow-Credentials: true`，也不是高危 CORS。
   - 只有任意 Origin 反射 + 凭证可带 + 可读敏感数据，才按高危链路处理。

5. IDS/authserver 的 FIDO / 验证码接口要做差异对照。
   - `/authserver/startAssertion` 若对 `admin`、学号样式、随机不存在用户返回同一类结果（如“未查询到绑定设备信息”），不构成账号枚举。
   - `/authserver/checkNeedCaptcha.htl?username=...` 若不同用户名均返回 `{"isNeed":false}`，也不构成账号枚举。
   - `/authserver/dynamicCode/getDynamicCode.htl` 若对测试输入稳定返回“发送验证码失败”，不构成短信验证码滥用。

6. 认证系统标准错误不应夸大。
   - `/authserver/serviceValidate` 返回 `INVALID_REQUEST`、提示必须提供 `service` 和 `ticket` 是 CAS 标准行为。
   - 除非泄露栈、内部配置、用户属性或可绕过票据校验，否则不报。

## 常见误报与不提交条件
- `webexp` 登录方式配置泄露：通常是公开配置，低敏，不提交。
- `externalId`、CAS/WeCom/支付宝/微信登录名称：仅证明登录方式存在，不提交。
- `/tenant/info` 返回 Logo、主题、背景图片：低敏，不提交。
- 业务系统所有路径 302 到登录页：说明保护有效，不提交。
- 主站 `/.env` 返回语言跳转页/首页脚本：属于路由重写或 fallback，非 `.env` 泄露。
- robots.txt 暴露 `/Application`、`/Public`，但目录 403 或无敏感文件读取：不提交。
- UEditor controller 403/404：不能按上传漏洞提交。

## 可提交升级条件
只有出现以下任一结果才进入教育 SRC 报告候选：
- 业务 API 绕过 `webexp` 认证，未登录直接返回学生/教职工/课程/教务等敏感数据。
- `webexp` 或 `authserver` 返回可用 token、ticket、session、用户属性或可复用登录态。
- `/startAssertion`、`checkNeedCaptcha`、找回密码等接口对存在/不存在账号有稳定差异，并能证明有效账号枚举或进一步敏感信息泄露。
- CORS 任意 Origin 反射 + Credentials + 可读敏感接口。
- 统一认证出现栈泄露、内部配置泄露，且可与其他漏洞组合造成实质影响。
- 文件上传接口无需认证且可上传 HTML/JS/SWF 或服务端可执行文件，并能提供可访问 URL 证明危害。

## 推荐证据保存文件
- `alive.txt`：资产、状态码、标题、跳转地址。
- `webexp_api_probe.txt`：前端 API、GET/POST/OPTIONS 状态码、关键响应。
- `authserver_probe.txt`：统一认证接口对照结果。
- `business_gateway_probe.txt`：ehall/jw/jwc/changping 等业务系统常见路径是否被 302 保护。
- `public_assets_probe.txt`：主站/招生/图书馆/英文站的 UEditor、Actuator、Swagger、`.env`、`.git` 等低影响检查结果。
