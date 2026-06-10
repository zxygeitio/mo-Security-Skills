# 广西师范大学 gxnu.edu.cn 测试模式 (2026-06-09)

## 目标概况

- 主站：www.gxnu.edu.cn（SUDY CMS）
- CAS：sso.gxnu.edu.cn（自研，非金智教育wisedu CAS）
- ehall：ehall.gxnu.edu.cn（金智教育wisedu amp平台）
- 教务：jwjx.gxnu.edu.cn（超星Chaoxing教学管理系统）
- 研招：yzcx.gxnu.edu.cn（ASP.NET Core自研系统）
- 邮箱：webmail.gxnu.edu.cn / mail.gxnu.edu.cn（网易企业邮箱）
- 一卡通：ydjk.gxnu.edu.cn（智慧预付费管控系统v3.1.0）
- 远程利用：daly.gxnu.edu.cn（Vue.js SPA，档案/捐赠/支付/预约）
- 学工：dms.gxnu.edu.cn（Angular SPA）
- AI测评：aieval.gxnu.edu.cn（师范生教学能力AI测评系统）
- IdP：idp.gxnu.edu.cn（Shibboleth IdP）
- 学习平台：gxnulb.gxnu.edu.cn（Vue.js SPA）
- 网站群：大量SUDY CMS子域名（office/hr/jjc/tzb/bwc/yy/eb/hqjt等）

## 子域名枚举结果

subfinder: 108个子域名
crt.sh额外发现：jwjx/webmail/yiban/www.szkzx/cg

## CAS认证系统特征

- **自研系统**，不是金智教育wisedu CAS
- Server: nginx
- 登录页面：https://sso.gxnu.edu.cn/cas/login
- 端点：/cas/login, /cas/logout, /cas/serviceValidate
- execution参数：动态生成，Base64编码
- 验证码：图片验证码
- 速率限制：登录接口有频率限制，返回 `{"error":"too_many_requests"}`
- 统一错误消息："用户名或密码错误"（无用户枚举）
- service参数白名单：基于字符串包含匹配（非精确域名匹配）

### CAS CORS配置

所有CAS端点返回：
```
access-control-allow-origin: *
access-control-allow-credentials: true
```
**注意**：此CORS配置虽然违反规范，但审核不收取（被判定为低价值）。

### CAS service参数白名单缺陷

CAS接受以下格式的service参数：
- `http://ehall.gxnu.edu.cn.attacker.com`（子域名拼接）
- `http://ehall.gxnu.edu.cn@evil.com`（用户信息字段）

form action会包含恶意域名。**注意**：此Open Redirect被审核拒绝，不建议提交。

## ehall金智教育平台

### 指纹

- Server: nginx
- 认证适配器：/amp-auth-adapter/login
- sessionToken：32位十六进制随机字符串
- Tomcat: 7.0.81（后端）
- Spring Framework
- Redis session存储

### 未授权JSONP API端点

以下API无需认证可访问：

| 端点 | 响应大小 | 内容 |
|------|---------|------|
| /jsonp/userInfo.json | 1895B | 站点配置（游客模式） |
| /jsonp/school.json | 1530B | 学校配置（schoolId=10602） |
| /jsonp/serviceCenterData.json | 715B | 服务列表 |
| /jsonp/myAppService.json | 35B | 空（需登录） |
| /jsonp/appInfo.json?appId=xxx | - | 应用详细配置 |
| /jsonp/appIntroduction.json?appId=xxx | - | 应用介绍+内部路径 |

### appInfo.json泄露内容

- appId: 4834312099124186
- appName: 学工流程管理
- appKey: 4834312099124186-4.0.11_TR1
- domainId: 8888429c-73bd-4c3d-b8cb-a74c18a9e376
- deployPrefix: http://ehall.gxnu.edu.cn/xsfw
- vendorName: 金智教育
- version: 4.0.11_TR1
- authUrl: /sys/funauthapp/qxgl.do?appName=stateapp&appId=4834312099124186&min=1
- pcOpenUrl: http://ehall.gxnu.edu.cn/xsfw/sys/stateapp/*default/index.do

**注意**：此信息泄露被用户要求提交，但实际价值有限。

### 认证流程

1. 访问受保护资源 → 302到 /amp-auth-adapter/login
2. /amp-auth-adapter/login → 302到 sso.gxnu.edu.cn/cas/login?service=.../loginSuccess?sessionToken=xxx
3. CAS认证成功 → 重定向到 /amp-auth-adapter/loginSuccess?sessionToken=xxx
4. sessionToken绑定session → 访问受保护资源

### 内部路径泄露

/appIntroduction.json泄露的完整堆栈：
- Apache Tomcat/7.0.81
- Spring MVC FrameworkServlet
- com.wisedu.amp.adapter.service.impl.RedisServiceImpl
- com.wisedu.amp.adapter.controller.AuthenticationController

## 研究生招生网 (yzcx.gxnu.edu.cn)

### 技术栈

- ASP.NET Core
- Layui前端框架
- 图片验证码（/code/captcha/captcha）

### 关键端点

| 路径 | 状态 | 功能 |
|------|------|------|
| /Login | 200 | 登录（用户名+密码+验证码） |
| /Register/Index | 200 | 非推免生注册（准考证号+姓名+身份证号+验证码） |
| /Register/enrolReg | - | 推免生注册 |
| /Register/forgetPwd | 200 | 密码找回（准考证号+姓名+身份证号+验证码） |
| /Search/ScoreInfo | 200 | 成绩查询（需登录） |
| /Search/checkInfo | 302 | 成绩复核（需登录） |
| /ChangeInfo | 302 | 信息修改（需登录） |
| /noteInfo?id=N | 500 | 通知公告（部分id返回500） |
| /LoginOut | - | 退出登录 |

### 错误信息泄露

/noteInfo?id=1 返回500错误：
```
Object reference not set to an instance of an object.
Request ID: |e2587783-4e312756845f507a.
```

### 认证特征

- __RequestVerificationToken：ASP.NET防伪令牌
- .AspNetCore.Antiforgery cookie
- .AspNetCore.Session cookie
- 验证码每次请求变化

### 注册接口参数

POST /Register/Index
- examId: 准考证号
- name: 姓名
- identityNum: 身份证号码
- txtCaptcha: 验证码

## 教学管理系统 (jwjx.gxnu.edu.cn)

- 超星(Chaoxing)教学管理系统
- 认证：CAS SSO
- CAS service: https://jwjx.gxnu.edu.cn/sso/login/3rd/432
- CORS: access-control-allow-origin: https://jwjx.gxnu.edu.cn, credentials: true
- CSP: frame-ancestors 'self' https://i.chaoxing.com https://gxnulocal.jw.chaoxing.com

## SUDY CMS 站点群

所有SUDY CMS站点管理后台路径：
- /_wp3services/general498/index.jsp → 302到CAS登录
- /system/_csair/main.psp → 200（但显示"访问地址不合法（003）"，IP白名单限制）
- /system/main.psp → 410 Gone

管理后台需要CAS认证 + IP白名单（内网访问）。

## 安全防护概况

- WAF：拦截Actuator/Swagger/Druid/.git/.env等敏感路径
- CAS：service参数白名单验证（字符串包含匹配）
- 速率限制：CAS登录接口
- 验证码：图片验证码
- IP白名单：SUDY CMS管理后台

## 审核经验

以下类型的漏洞在gxnu.edu.cn被审核拒绝：
1. CAS CORS配置不当（access-control-allow-origin: * + credentials: true）— 不收取
2. CAS Open Redirect（service参数接受子域名拼接）— 不收取
3. ehall appInfo.json信息泄露 — 用户要求提交但价值有限

建议聚焦：
- SQL注入（yzcx.gxnu.edu.cn研招系统）
- 认证绕过（CAS或各业务系统）
- IDOR/越权访问（研招成绩查询、学工平台）
- 弱口令（需要有效账号测试）
