# 校园 WebVPN/校外访问系统公开配置接口判定

适用场景：教育 SRC/学校资产中发现 webexp、webvpn、校外访问、网站导航、统一身份认证网关等前端系统，静态 JS 暴露 `/api/access/*`、`/api/authentication/*`、`/siteNav/` 等接口。

低影响验证步骤：
1. 先抓登录页静态资源，抽取 API 路径；只做 GET/HEAD 和空 JSON POST，不进行爆破、撞库、登录绕过或写入。
2. 重点检查：
   - `/api/access/user/info` 是否未授权返回真实用户资料；
   - `/api/access/nav/site-list`、资源/应用列表类接口是否泄露内网系统地址、带票据跳转链接、敏感业务入口；
   - CORS 是否任意 Origin 反射且允许 Credentials；
   - 是否存在未授权资源代理、任意 URL 代理、未授权文件读取或真实后端资源访问。
3. 若仅返回登录方式、认证类型、锁定策略、公开 OAuth/CAS/企业微信配置、空导航列表、站点标题/logo/copyright 等，不按高危报告。
4. 若发现 externalId、authType、password-auth、authentication/conf 等公开配置，不要直接定性为敏感信息泄露；必须证明能造成用户数据读取、认证绕过、访问受限资源或后端系统暴露。

教育 SRC 提交门槛：
- 可提交：未登录读取用户信息/应用资源列表、可访问受限系统、CORS 任意源 + 凭证导致敏感 API 可跨站读取、SSO/CAS 回调绕过、资源代理 SSRF/任意访问。
- 不提交：公开登录配置、验证码/锁定策略、登录方式枚举、空 site-list、仅有登录页或 WebVPN 指纹。

输出原则：用户要求“只要可复现高危”时，如只发现上述公开配置，应输出未发现可报告高危漏洞，而不是凑低危/中危报告。