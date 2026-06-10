# CAS统一认证系统漏洞指纹库

详细测试模式按厂商拆分:
- `references/cas-wisedu-testing-patterns.md` — 金智教育 wisedu ycServer
- `references/lianyi-cas-testing-patterns.md` — 联奕 Lianyi lyuapServer
- `references/cust-edu-cn-testing-patterns.md` — Apereo CAS + PAC4J

## 背景
CAS (Central Authentication Service) 是国内高校最常用的统一认证系统。
常见厂商: 金智教育、新开普、联奕、希尔等。

## 识别特征
- URL: `authserver.XXX.edu.cn/authserver/login`
- 服务器: openresty (常见)
- 页面特征: `pwdDefaultEncryptSalt`, `LT-xxx`, `execution=e1s1`

## 漏洞1: pwdDefaultEncryptSalt泄露

**位置:** 登录页面HTML源码
```javascript
var pwdDefaultEncryptSalt = "KdcRdcq59OeHWDxZ";
```
或
```html
<input type="hidden" id="pwdDefaultEncryptSalt" value="yCXPX7ZB4k1hjotP"/>
```

**影响:** 暴露AES加密盐值，可配合MITM解密密码
**注意:** 盐值每会话轮转，但登录页未认证即可获取

## 漏洞2: JSESSIONID URL泄露

**位置:** 静态资源引用
```html
<link href="/authserver/custom/css/login.css;jsessionid=J0L6q..." rel="stylesheet">
<img src="/authserver/custom/images/login-bg-autumn.png;jsessionid=J0L6q...">
```

**影响:** JSESSIONID暴露在URL中，可被Referer头泄露导致会话劫持

## 漏洞3: 密码重置用户枚举

**位置:** `/authserver/getBackPasswordMainPage.do`
**JS文件:** `/authserver/custom/js/getBackPassword.js`

**API端点:** `POST /authserver/getBackPassword.do`
- type=mobile, step=1: 手机找回(需userId+mobile+captcha)
- type=mail, step=1: 邮箱找回(需userId+mail+captcha)
- type=question, step=1: 密保问题(需userId+birthday+captcha)

**注意:** 需要验证码(captcha)，无法直接枚举

## 漏洞4: serviceValidate信息泄露

**端点:** `/authserver/serviceValidate?service=XXX&ticket=ST-xxx`
**响应:** 返回CAS XML格式的认证结果

## 测试命令
```bash
# 盐值泄露
curl -sk "https://authserver.XXX.edu.cn/authserver/login" | grep -i 'pwdDefaultEncryptSalt'

# JSESSIONID泄露
curl -sk "https://authserver.XXX.edu.cn/authserver/login" | grep -i 'jsessionid'

# 密码重置页面
curl -sk "https://authserver.XXX.edu.cn/authserver/getBackPasswordMainPage.do"

# serviceValidate
curl -sk "https://authserver.XXX.edu.cn/authserver/serviceValidate?service=https://ehall.XXX.edu.cn/login&ticket=ST-1234"
```

## 变体: Apereo CAS + PAC4J (非金智教育)

**不同于金智教育CAS**，部分高校使用原生Apereo CAS + PAC4J认证框架。

**识别特征:**
- PAC4J cookie: `PAC4JDELSESSION=eyJhbG...`
- JSESSIONID in Set-Cookie with Path=/cas
- Bootstrap 4.1.0 + jQuery 3.3.1
- WeChat OAuth集成: `wxLogin.js` + `clientredirect`端点
- `Content-Security-Policy: frame-ancestors ...`
- 无`pwdDefaultEncryptSalt`（不同于金智CAS）

**已确认Open Redirect漏洞:**
service参数**无白名单校验**，接受任意外部域名。登录后用户被重定向到攻击者域名并携带CAS ticket。
```bash
# 验证: 检查service参数是否被传递
curl -sk "https://mysso.HOST/cas/login?service=https://evil.com/" | grep -oE 'service=[^"'"'"' ]+evil[^"'"'"' ]*'
# 如果返回匹配，则存在Open Redirect
```
**对比**: 金智CAS有service白名单校验，Apereo+PAC4J无白名单。
**案例**: cust.edu.cn (长春理工大学), 2026-06-02

## 变体: ycServer / 金智教育 wisedu minos CAS

**不同于标准Apereo CAS**，部分高校使用金智教育(赢领)ycServer身份认证平台。技术栈为Spring Boot + Spring Cloud + Apache Tomcat，后端框架为 `com.wisedu.minos.*`。

**识别特征:**
- 自定义主题: `/authserver/<schoolTheme>/static/` (如 `gxdlxydTheme8`)
- JS注释泄露版本号: `// 7.2.1.SP4从window.onload移入` (在 `common-header.js`)
- `DEFAULT_SALT` 硬编码在 `login.js`: `var DEFAULT_SALT = "rjBFAaHsNkKAhpoi";`
- `pwdEncryptSalt` 为每会话随机值: `<input type="hidden" id="pwdEncryptSalt" value="NY4pMwxgblea3dzQ" />`
- 前端JS暴露: `captchaSwitch`, `_badCredentialsCount`, `QR_LOGIN_ENABLED`, `is_dynamicLogin`, `_fidoEnabled`
- Spring Boot错误响应格式: `{"timestamp":..., "status":500, "exception":"...", "trace":"..."}`

**API端点 (.htl 扩展名):**
```bash
# 租户配置(公开)
curl -sk "https://ids.HOST/authserver/tenant/info"
# 返回: {"mobileFlay":false,"themeName":"gxdlxydTheme8","schoolLogoUrlPc":"..."}

# 二维码登录
curl -sk "https://ids.HOST/authserver/qrCode/getToken?ts=TIMESTAMP"
curl -sk "https://ids.HOST/authserver/qrCode/getCode?uuid=TOKEN"
curl -sk "https://ids.HOST/authserver/qrCode/getStatus.htl?ts=TIMESTAMP&uuid=TOKEN"

# 动态验证码(短信)
curl -sk "https://ids.HOST/authserver/dynamicCode/getDynamicCode.htl" -d "mobile=PHONE"
curl -sk "https://ids.HOST/authserver/checkNeedCaptcha.htl?username=PHONE"
curl -sk "https://ids.HOST/authserver/getCaptcha.htl"

# CAS协议端点
curl -sk "https://ids.HOST/authserver/serviceValidate?service=SERVICE&ticket=TICKET"
curl -sk "https://ids.HOST/authserver/proxyValidate?service=SERVICE&ticket=TICKET"
curl -sk "https://ids.HOST/authserver/p3/serviceValidate?service=SERVICE&ticket=TICKET"
```

**CORS预检反射型配置错误 (2026-05-31 gxdlxy实战):**
所有CAS端点的OPTIONS预检响应反射任意Origin + credentials:true，但实际GET/POST请求中不返回CORS头部。
```bash
curl -sk -X OPTIONS \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Content-Type, Authorization' \
  'https://ids.HOST/authserver/login' -I | grep access-control
# 返回: access-control-allow-origin: https://evil.com
#       access-control-allow-credentials: true
```
根因: `com.wisedu.minos.config.filter.CorsFilter` (从堆栈跟踪泄露)
利用受限: 仅OPTIONS预检返回CORS头，实际请求不返回，浏览器不读取预检响应体。但仍需修复。
报告角度: "统一身份认证平台CAS服务存在CORS配置错误漏洞" [中危]

**Spring Boot堆栈跟踪泄露 (2026-05-31 gxdlxy实战):**
当POST到 `/authserver/login` 时传入非法 `execution` 参数(如 `AAAA`)，返回500 + 完整Java堆栈跟踪(11KB JSON)。
```bash
curl -sk -X POST 'https://ids.HOST/authserver/login?service=SERVICE_URL' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=test&password=test&_eventId=submit&cllt=userNameLogin&dllt=generalLogin&execution=AAAA&lt='
```
泄露: Apereo CAS + Spring Boot + Spring Cloud + Tomcat + Log4j2 + wisedu minos Filter链 + CAS会话格式
报告角度: "统一身份认证平台Spring Boot错误处理信息泄露" [中危]

**CAS Open Redirect via 嵌套callback URL:**
CAS service参数接受嵌入WebVPN回调URL，WebVPN回调的url参数未做白名单校验。
```
https://ids.HOST/authserver/login?service=https%3A%2F%2Fvpn.HOST%2Fusers%2Fauth%2Fcas%2Fcallback%3Furl%3Dhttps%253A%252F%252Fevil.com
```
登录后CAS ticket泄露给evil.com。可与CORS漏洞组合实现账户劫持。
报告角度: "统一身份认证平台CAS服务存在URL重定向漏洞" [中危]

**WebVPN (Astraeus VPN):**
- Ruby on Rails, `_astraeus_session` cookie, `SERVERID=Server1`
- 密码重置: `/users/password/new` (POST, CSRF protected)
- CAS集成: `/users/auth/cas/callback?url=` (未校验url参数)
- `x-runtime`, `x-request-id` 响应头

**⚠️ WAF误报模式 (所有二级学院网站):**
中国高校WAF对敏感路径(.git/.sql/swagger/web.config)返回HTTP 200 + "访问禁止"HTML内容，
导致状态码扫描工具(report 200)误报为真实暴露。**必须检查响应体内容**，而非仅看状态码。
识别: `<TITLE>访问禁止</TITLE>` + `检测到可疑访问，事件编号：XXXXXXXXX`

## 变体: Lianyi CAS (联奕统一身份认证 / lyuapServer)

联奕科技(LIANYI TECHNOLOGY CO.,LTD.)统一身份认证平台，后端Liferay Portal + Tomcat 7.x。

**快速识别:** CAS路径 `/lyuapServer/login`，管理后台 `/ly_web_casconsole/`，RSA加密(BigInt.js/Barrett.js)，`captcha.jsp`验证码，服务器头 `Apache-Coyote/1.1`，LT token含 `cas01.example.org`。

**关键差异:** 有独立管理后台(ly_web_casconsole)且无验证码保护，可暴力破解。验证码通过`getyzm.action`返回明文JSON。密保校验逻辑缺陷(所有用户返回true)。

**详细测试模式:** `references/lianyi-cas-testing-patterns.md`

## 报告角度
- "CAS统一认证系统密码加密盐值泄露" [低危]
- "CAS JSESSIONID URL泄露" [低危]
- 两者可合并为一份报告提交
- ycServer CAS: CORS预检配置错误 [中危] + 堆栈跟踪泄露 [中危] + URL重定向 [中危]
- ycServer CAS: 前端DEFAULT_SALT硬编码 [低危]
- 联奕Lianyi CAS: 管理后台公网暴露 [中危] + Open Redirect [低危] + 验证码明文泄露 [中危] + 密保逻辑缺陷 [中危]
