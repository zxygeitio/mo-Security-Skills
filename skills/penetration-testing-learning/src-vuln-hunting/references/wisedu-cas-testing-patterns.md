# 金智教育(Wisedu) CAS 漏洞测试模式

## 指纹识别

### 关键指纹
```
JS文件: login-wisedu_v1.0.js
JS变量: pwdDefaultEncryptSalt, dynamicPwdEncryptSalt
路径: /authserver/login (标准Apereo CAS路径)
Ticket注册表: com.wisedu.authserver.ticket.registry.CacheTicketRegistry
表单字段: dllt=userNamePasswordLogin|dynamicLogin|qrLogin
```

### 快速检测命令
```bash
# 检测是否为金智CAS
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'login-wisedu[^"]*\.js'
# 返回: login-wisedu_v1.0.js;jsessionid=xxx

# 检测密码加密密钥
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'pwdDefaultEncryptSalt\s*=\s*"\K[^"]+'

# 检测状态端点
curl -sk 'https://authserver.<domain>/authserver/status'
```

## 漏洞模式

### 1. 密码加密密钥泄露 (低危 - 黑名单模式)
**特征**: pwdDefaultEncryptSalt暴露在登录页JS中，或DEFAULT_SALT硬编码在login.js

**两种泄露形式:**

a) **HTML隐藏字段/JS变量** (标准变体):
```bash
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'pwdDefaultEncryptSalt\s*=\s*"\K[^"]+'
# 或
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'var pwdDefaultEncryptSalt = "\K[^"]+'
```

b) **login.js硬编码DEFAULT_SALT** (金智ycServer变体):
```bash
# 获取theme名称
curl -sk "http://ids.<domain>/authserver/tenant/info" | grep -oP 'themeName":"\K[^"]+'
# 返回: gxdlxydTheme8

# 获取login.js中的DEFAULT_SALT
curl -sk "http://ids.<domain>/authserver/<theme>/static/web/js/login.js" | grep 'DEFAULT_SALT'
# 返回: var DEFAULT_SALT = "rjBFAaHsNkKAhpoi";
```
**加密方式**: AES-CBC + PKCS7, encrypt.js提供encryptPassword/decryptPassword函数
**注意**: DEFAULT_SALT是固定值(不同于每会话轮转的pwdDefaultEncryptSalt)
**注意**: 此漏洞属于教育SRC黑名单模式(pwdDefaultEncryptSalt泄露), 通过率低

### 6. 非金智CAS的Open Redirect (高危)
**特征**: 部分学校使用自定义CAS(非金智/联奕)，service参数可能无白名单校验
**检测关键**: 检查form action是否包含恶意service参数值（不只是返回200）
```bash
# 有效检测：form action中包含evil.com = 漏洞存在
curl -sk 'https://sso.<domain>/cas/login?service=http://ehall.<domain>.attacker.com' | grep 'action='
# 返回: action="/cas/login?service=http://ehall.<domain>.attacker.com" → 漏洞确认

# 无效检测：只返回200不代表漏洞存在，必须确认action
```

**攻击载荷**（适用于非金智CAS，金智CAS已修复此问题）：
- 子域名攻击: `http://ehall.<domain>.attacker.com`
- 用户信息攻击: `http://ehall.<domain>@evil.com`
- 路径攻击: `http://evil.com/ehall.<domain>`
- 注: 金智CAS会返回"未认证授权服务"拒绝未注册service

**与金智CAS的区别**：金智CAS有白名单校验（返回"未认证授权服务"），自定义CAS可能无校验

### 2. 会话固定 (中危)
**特征**: JSESSIONID暴露在URL和表单action中
```bash
# 检查表单action中的jsessionid
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'action="[^"]*jsessionid[^"]*"'

# 检查CSS/JS资源中的jsessionid
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'jsessionid=[^";]+'
```
**危害**: 攻击者可预设session ID诱导用户登录后劫持会话

### 3. 状态端点信息泄露 (中危)
**特征**: /authserver/status无需认证返回服务器信息
```bash
curl -sk 'https://authserver.<domain>/authserver/status'
```
返回:
```
Health: OK
1.MemoryMonitor: OK - 226.35MB free, 512.03MB total.
2.SessionMonitor: UNKNOWN - Ticket registry com.wisedu.authserver.ticket.registry.CacheTicketRegistry
```
**危害**: 暴露内存配置、内部包名、TicketRegistry类型

### 4. Service Validation端点暴露 (低危)
**特征**: /authserver/serviceValidate可未授权访问
```bash
curl -sk 'https://authserver.<domain>/authserver/serviceValidate?service=https://test.com&ticket=ST-test'
```
返回CAS XML响应（INVALID_TICKET）

### 5. CAS开放重定向 (需验证)
**特征**: service参数可能有白名单校验
```bash
# 测试恶意service
curl -sk 'https://authserver.<domain>/authserver/login?service=https://evil.com/' | grep -oP 'action="[^"]*"'
# 如果action为空或不包含evil.com，则有白名单校验

# 测试合法service
curl -sk 'https://authserver.<domain>/authserver/login?service=https://ehall.<domain>/publicapp/sys/emapfunauth/casValidate.do' | grep -oP 'action="[^"]*"'
# 应该返回包含service的action
```

## 金智CAS登录表单结构

### 三种登录方式
1. **密码登录** (dllt=userNamePasswordLogin)
   - 用户名 + 密码(AES加密) + 验证码
   
2. **动态码登录** (dllt=dynamicLogin)
   - 用户名 + 图片验证码 + 手机动态码
   
3. **QR码登录** (dllt=qrLogin)
   - UUID + QR码扫描

### 关键端点
```
/authserver/login                    # 登录页
/authserver/captcha.html             # 验证码图片
/authserver/status                   # 健康状态(信息泄露)
/authserver/serviceValidate          # CAS 2.0票据验证
/authserver/p3/serviceValidate       # CAS 3.0票据验证
/authserver/validate                 # CAS 1.0票据验证
/authserver/logout                   # 登出
/authserver/getBackPasswordMainPage.do # 密码找回
/authserver/validatePasswordAjax.do  # 密码验证AJAX
```

## 测试注意事项

1. **验证码**: 金智CAS验证码为服务端校验，无法绕过
2. **WAF**: 频繁请求会触发openresty连接级封锁(IP封禁约15-30分钟)
3. **service参数**: 金智CAS有白名单校验，evil.com不会被反射到form action
4. **暴力破解**: 需要有效验证码，无法自动化
5. **WAF误报**: openresty对actuator/swagger等敏感路径返回HTTP 200 + "访问禁止"HTML, XFF绕过无效
6. **DEFAULT_SALT**: 固定值(不同于每会话轮转的pwdDefaultEncryptSalt), 可用于构造加密密码

## 已测试目标

| 目标 | 发现 | 状态 |
|------|------|------|
| hnca.edu.cn | Session Fixation + 密钥泄露 + Status泄露 | 已提交 |
| gxdlxy.com | DEFAULT_SALT泄露(login.js) + tenant/info配置泄露 | 未提交(黑名单模式) |
| cumt.edu.cn | 加固良好: 3次锁定+验证码强制+FIDO+service白名单 | 无漏洞 |
| gxnu.edu.cn | 自定义CAS(非金智): Open Redirect(高危)+CORS通配符(中危)+SAML元数据泄露 | 2026-06-09 |

## 加固良好的金智CAS特征 (cumt.edu.cn模式)

当金智CAS配置良好时，以下JS变量表明安全加固:
```javascript
var captchaSwitch = "1";           // 验证码强制开启
var _badCredentialsCount = "3";    // 3次错误后锁定
var _fidoEnabled = "true";         // FIDO认证支持
var isQrLoginEnabled = "true";     // QR码登录
var is_dynamicLogin = "true";      // 动态码登录
var is_userNameLogin = "true";     // 用户名密码登录
```

**自定义主题路径**: 部分学校使用自定义主题(如cumt.edu.cn用`cumtcusTheme_20250616`)，
JS/CSS路径为 `/authserver/<customTheme>/static/`，标准主题路径探测会404。
检测方法: `curl -sk 'https://authserver.TARGET/authserver/login' | grep -oP 'href="/authserver/[^/]+/static/' | head -1`

**加固CAS的负面验证清单**:
- [ ] pwdDefaultEncryptSalt: 未泄露
- [ ] /authserver/status: 返回401(已加固)
- [ ] needCaptcha: 返回完整HTML页面(需session)
- [ ] service参数: 未注册应用返回"应用未注册"(白名单生效)
- [ ] 暴力破解: 验证码+锁定+可能的WAF封禁
- 结论: 无提交价值，记录为"加固良好"
