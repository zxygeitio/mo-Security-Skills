# SAIF SSO API Discovery Pattern (上海高级金融学院)

## 概述
sso.saif.sjtu.edu.cn 运行 Spring Boot (sso-apis-v3)，通过分析登录页面 JS 可提取 30+ API 端点。

## JS 分析方法

```bash
# 1. 获取登录页面JS路径
curl -sk "https://sso.saif.sjtu.edu.cn/sso/login/" | grep -oP 'src="[^"]*\.js[^"]*"'

# 2. 下载并分析JS中的API路径
curl -sk "https://sso.saif.sjtu.edu.cn/sso/resources/I6guCH9Ys7/static/js/modules/login.455adf133c92f6eed377.js" | grep -oP '"/apis/[^"]*"' | sort -u
```

## 发现的 API 端点

### 公开端点 (/apis/v2/open/, /apis/v3/open/)
| 端点 | 方法 | 说明 |
|------|------|------|
| `/sso/apis/v3/open/captcha?imageWidth=100` | GET | 返回 base64 验证码图片 + token |
| `/sso/apis/v3/open/code/SMS` | POST | 发送短信验证码 |
| `/sso/apis/v3/open/code/EMAIL` | POST | 发送邮件验证码 |
| `/sso/apis/v3/open/register` | POST | 用户注册 |
| `/sso/apis/v3/open/active` | POST | 账号激活 |
| `/sso/apis/v3/open/complete_retrieve_password` | POST | 密码找回 |
| `/sso/apis/v3/open/verify_retrieve_password/sms` | POST | 短信验证找回密码 |
| `/sso/apis/v3/open/verify_retrieve_password/EMAIL` | POST | 邮件验证找回密码 |
| `/sso/apis/v3/open/verify_retrieve_password/FAQ` | POST | 密保问题找回密码 |

### 需认证端点 (/apis/v2/me/, /apis/v3/me/)
| 端点 | 方法 | 说明 |
|------|------|------|
| `/sso/apis/v2/me/profile?showInfo=true` | GET | 用户资料 (PERMISSION_DENIED) |
| `/sso/apis/v3/me/sessions` | GET | 会话列表 (PERMISSION_DENIED) |
| `/sso/apis/v3/me/account-mapping` | POST | 账号映射 |
| `/sso/apis/v3/me/update_profile` | POST | 更新资料 |
| `/sso/apis/v2/me/account/PASSWORD` | - | 密码账号 |
| `/sso/apis/v2/me/account/TELEPHONE` | - | 手机账号 |
| `/sso/apis/v2/me/rights` | - | 用户权限 |

### 管理端点 (/apis/v2/)
| 端点 | 说明 |
|------|------|
| `/apis/v2/accounts` | 账号列表 |
| `/apis/v2/client/` | 客户端 |
| `/apis/v2/dept` | 部门 |
| `/apis/v2/events` | 事件 |
| `/apis/v2/file` | 文件 |
| `/apis/v2/identity/` | 身份 |
| `/apis/v2/role/block` | 角色封禁 |
| `/apis/v2/roleStrategy` | 角色策略 |
| `/apis/v2/setting?configKey=SYSTEM_SETTINGS` | 系统配置 |
| `/apis/v2/theme/` | 主题 |

## 内部路径泄露

SSO API 返回 404 时泄露内部服务路径：
```json
{"timestamp":1779976309792,"status":404,"error":"Not Found","path":"/sso-apis-v3/apis/v2/open/code/SMS"}
```
- 外部路径: `/sso/apis/v2/open/code/SMS`
- 内部路径: `/sso-apis-v3/apis/v2/open/code/SMS`

## 验证码 Token 机制

```bash
# 获取验证码
curl -sk "https://sso.saif.sjtu.edu.cn/sso/apis/v3/open/captcha?imageWidth=100"
# 返回: {"img":"/9j/4AAQ...","token":"11c80e...5b57"}
```

Token 需要与验证码一起提交到 SMS/EMAIL 接口。

## 关联资产

- `netid.saif.sjtu.edu.cn` — NetID 密码管理系统 (IIS/10.0 + ASP.NET 4.0.30319)
  - `/ChangePassword` — 密码修改 (表单: txtID2, txtOldPassword, txtPasssword, txtPassword2)
  - `/ForgetPassword` — 密码找回 (邮箱/工号/手机号)
  - 使用 `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION` (ASP.NET WebForms)

## 测试时间
2026-05-28
