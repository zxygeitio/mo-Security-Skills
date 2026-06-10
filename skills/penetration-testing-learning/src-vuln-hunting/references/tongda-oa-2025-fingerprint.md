# 通达OA 2025 指纹与测试模式

## 版本指纹

通达OA 2025 (2026-06-01 gfxy.com实战确认):

| 特征 | 值 |
|------|-----|
| 模板路径 | `/static/templates/2025_year_01/index.css?20241218` |
| SDK版本 | `ispirit_sdk.js?v=20240530202303` |
| Bootstrap | `/static/js/bootstrap/css/bootstrap.css?20230526` |
| 主题 | `/static/theme/1/style.css?20190719` |
| jQuery | `jquery.min.js` + `jquery-with-migrate.min.js` |
| RSA加密 | `/static/js/rsa/{jsbn,prng4,rng,rsa}.js` |
| favicon | `tongda.ico` hash: `1205af91d6b1638c23de1132ae0c7e0b` |
| 域名引用 | `tongda2000.com` |
| 时间戳 | JS中 `1780278750` (约2026-05-30) |
| MYOA变量 | `MYOA_EMAIL_SHOW`, `MYOA_JS_SERVER`, `MYOA_STATIC_SERVER` |

## RSA密码加密 (2025版)

登录页内联JS包含RSA公钥，密码需用RSA加密后传输:
```
var modulus = "B87A3BE2184FED0973FFB0B02A862DCAD15A1A29172EC8FF67E841FE26749A6AA04E48E9B02D963ED81DCE2B0086C034F7D47CCBACF8539C36B9445ABA5EF484F3CA32593762641B4C9683C79801D087198370D5719BB4E422FADAA4D883D13874DE67D8B6E883EBAACC53A8480F41EE8BE70D2F70BECF3CB7F1023D2C901CC3"
var exponent = "10001"
```
- `encode_type=1` 表示密码已RSA加密
- RSA库: `/static/js/rsa/{jsbn,prng4,rng,rsa}.js` + `/static/js/base64/base64.min.js`
- Modulus长度: 384字符(hex), 1536-bit RSA key

## CAPTCHA懒加载

验证码不是立即显示，而是输入框获得焦点时才加载:
```javascript
$('#captcha').focus(function(){
    if($("#captchaImg").css("visibility") == "hidden") {
        getCaptchaImg();  // 调用 /module/captcha/captcha_output.php
    }
});
```
- 验证码图片: `/module/captcha/captcha_output.php?random=N` (image/jpeg)
- 验证码校验: `/module/captcha/captcha_op.php?op_type=check_captcha&captchaInputValue=XXX`
- 校验响应: `{"status":"0"}` (错误) 或 `{"status":"1"}` (正确)
- **首次登录可能不需要CAPTCHA**，失败后触发

## QR码登录流程

```
1. POST /general/login_code_uid.php → {"status":1,"code_uid":"{UUID}"}
2. GET  /general/login_code.php?codeuid={UUID} → QR码图片
3. POST /general/login_code_check.php (codeuid={UUID}) → 轮询:
   {"status":1,"data":{"type":"notscan"}}   # 未扫描
   {"status":1,"data":{"type":"scan","username":"xxx"}}  # 已扫描
   {"status":1,"data":{"type":"confirm","token":"xxx","codeuid":"xxx"}}  # 已确认
   {"status":1,"data":{"type":"invalid"}}  # 已过期
4. POST /logincheck_code.php (TOKEN=xxx&CODEUID=xxx) → {"status":1,"url":"..."}
```
- 轮询间隔: 1秒 (`setInterval(function(){alwaysGet(params)},1000)`)
- **QR码登录无需CAPTCHA**

## logincheck_code.php 详细响应

| 参数组合 | 响应 |
|----------|------|
| 空参数/错误参数 | `{"status":0,"msg":"参数错误！"}` |
| 正确RSA密码+有效CODEUID | `{"status":1,"url":"/general/..."}` |
| 错误密码 | `{"status":0,"msg":"用户名或密码错误，注意大小写!"}` |

## ⚠️ IP封禁与浏览器绕过

通达OA在大量curl请求后会封禁源IP(返回HTTP 000或空响应)。
- **浏览器工具(browser_navigate)可绕过此限制** — 浏览器使用不同的连接路径
- 封禁后切换到浏览器模式继续测试
- 封禁可能在一段时间后自动解除

## 端点测试结果 (2025版本, 全部需认证)

### 公开端点 (无需认证)

| 端点 | 响应 | 说明 |
|------|------|------|
| `/ispirit/login_code.php` | JSON `{codeuid, authcode}` | 登录码生成, 公开设计 |
| `/logincheck_code.php` | `{"status":0,"msg":"参数错误！"}` | 需正确CODEUID+CODE流程 |
| `/module/ueditor/` | UEditor demo HTML (6KB) | demo页面, 上传需认证 |
| `/general/document/` | Zend压缩二进制 (1KB) | 非敏感, PHP框架默认响应 |

### 需认证端点 (返回登录页或RELOGIN)

| 端点 | 响应 | 说明 |
|------|------|------|
| `/ispirit/interface/gateway.php` | `RELOGIN` | 需认证, CVE-2023-2244不可用 |
| `/ispirit/im/upload.php` | `-ERR 用户未登陆` | 需认证 |
| `/module/ueditor/php/controller.php` | "用户未登录" HTML | UEditor需认证 |
| `/general/*/delete.php` (多个) | 登录页HTML | 非真实delete功能 |
| `/general/attendance/personal/index.php` | 登录页HTML | 需认证 |
| `/inc/expired.php` | 200 | 存在 |

### 不存在的端点 (404)

| 端点 | 说明 |
|------|------|
| `/auth_mobi.php` | 已修复/移除 |
| `/general/report/ie2pdf.php` | 不存在 |
| `/mac/gateway.php` | 不存在 |
| `/mobile/api/api.ali.php` | 不存在 |
| `/general/infocenter/insert_info.php` | 不存在 |
| `/general/system/seal_manage/iweboffice/seal_upload.php` | 不存在 |
| `/ispirit/interface/ajax.php` | 不存在 |
| `/mobile/auth_mobi.php` | 不存在 |

## 关键差异 vs 旧版本

1. **2025版本所有敏感端点均已认证保护** — 旧版本的gateway.php RCE (CVE-2023-2244) 在2025版本中不可用
2. **UEditor控制器需认证** — 旧版本可能不需要
3. **logincheck_code.php** — 需要完整的login_code流程(先获取codeuid, 再传入CODE)
4. **auth_mobi.php已移除** — 旧版本的远程认证绕过不再可用
5. **RSA密码加密** — 2025版使用1536-bit RSA key加密密码

## 测试建议

- 如果目标是通达OA 2025, 需要先获取有效账号才能利用已知RCE
- login_code.php公开暴露但无直接利用价值
- 可尝试弱口令爆破(需通过浏览器提交，绕过IP封禁)
- 旧版本CVE在2025版本中均已修复
- **浏览器模式是测试通达OA的首选方式** — 绕过速率限制，支持JS渲染

## 相关CVE (旧版本, 2025已修复)

- CVE-2023-2244: gateway.php 反序列化RCE
- CNVD-2023-0878: gateway.php RCE
- 通达OA auth_mobi.php 远程认证绕过
- 通达OA UEditor 任意文件上传
