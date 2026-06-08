# SAIF Infrastructure & CORS Systemic Vulnerability (2026-05-28)

## 概述
上海高级金融学院 (SAIF, saif.sjtu.edu.cn) 全站存在 CORS `*` + 自定义认证头的系统性配置不当漏洞。

## 技术栈

| 子域名 | 服务器 | 框架 | IP |
|--------|--------|------|-----|
| www/mf/smp/mba/emba/phd/ee/thinktank | Apache/2.4.6 (CentOS) | PHP/5.4.16 | 47.110.216.129 |
| cafrpro | nginx | PHP/7.3.19 (CodeIgniter) | 47.110.216.129 |
| en | Tengine | PHP/5.5.9 | 182.140.142.199 |
| sso | Spring Boot | sso-apis-v3 | - |
| portal | nginx/1.27.5 | OAuth2 + authjs | - |
| alumni | Apache-Coyote/1.1 | Java (TranzVision) | - |
| apply | Apache-Coyote/1.1 | Java | - |
| wiki | nginx/1.18.0 (Ubuntu) | - | - |
| analytics | Apache/2.4.16 | PHP/5.5.9 (Matomo) | 47.110.216.129 |
| netid | IIS/10.0 | ASP.NET 4.0.30319 | - |
| admin | - | - | 202.120.17.7 |
| mail | - | - | 116.246.13.35 |
| vpn | - | - | 124.74.129.162 |
| hr | - | - | 47.100.232.242 |
| mobile | - | - | 58.32.209.117 |

## CORS 系统性漏洞

全站 6+ 子域名统一配置:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Connection, User-Agent, Cookie,Ttoken,Stoken,Mtoken,Appid,terminal,redirect,Token
Access-Control-Allow-Methods: POST,GET,OPTIONS,DELETE,PUT
```

影响子域名: www, mf, mba, emba, phd, thinktank, ee

## SSO 系统

- 登录页面: https://sso.saif.sjtu.edu.cn/sso/login/
- 注册页面: https://sso.saif.sjtu.edu.cn/sso/register/
- API 前缀: `/sso/apis/v2/` 和 `/sso/apis/v3/`
- 内部服务: sso-apis-v3
- 详情: 见 education-src-blueprint references/saif-sjtu-sso-api-discovery.md

## NetID 系统

- 密码修改: https://netid.saif.sjtu.edu.cn/ChangePassword
- 密码找回: https://netid.saif.sjtu.edu.cn/ForgetPassword
- 表单字段: txtID2, txtOldPassword, txtPasssword, txtPassword2
- 使用 ASP.NET WebForms (__VIEWSTATE, __EVENTVALIDATION)

## 其他发现

1. robots.txt 泄露敏感路径: */uploads/, */upload/, */offer/
2. 上传目录存在但受保护: /uploads/ (403)
3. Matomo 分析系统暴露: analytics.saif.sjtu.edu.cn
4. jQuery 1.11.3 + jQuery 3.1.1 (旧版本)

## WAF

云盾WAF (yundunwaf3.com) — 拦截敏感路径返回 405

## 测试时间
2026-05-28
