# SAIF (上海交通大学上海高级金融学院) SRC 测试记录

## 目标概况
- 主域名: www.saif.sjtu.edu.cn (47.110.216.129)
- WAF: 云盾WAF (yundunwaf3.com), acw_tc cookie
- 证书: DigiCert, *.saif.sjtu.edu.cn
- 技术栈: Apache/2.4.6 + PHP/5.4.16 + OpenSSL/1.0.2k-fips

## 子域名资产 (16个)

主站集群 (47.110.216.129):
- www/mf/smp/mba/emba/phd/ee/thinktank — Apache/2.4.6 + PHP/5.4.16
- cafrpro — nginx + PHP/7.3.19 (CodeIgniter)

认证/门户:
- sso — Spring Boot (sso-apis-v3)
- portal — nginx/1.27.5, OAuth2 + authjs
- alumni/apply — Java (Apache-Coyote/1.1)
- support — nginx/1.27.5

管理/运维:
- admin (202.120.17.7), mail (116.246.13.35), vpn (124.74.129.162)
- hr (47.100.232.242), mobile (58.32.209.117)
- analytics — Apache/2.4.16 + PHP/5.5.9 (Matomo)
- wiki — nginx/1.18.0 (Ubuntu)
- en (182.140.142.199) — Tengine + PHP/5.5.9
- netid — IIS/10.0 + ASP.NET 4.0.30319

## 关键发现

### 1. CORS全站系统性配置不当 (中危)
所有主站子域名统一返回:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Connection, User-Agent, Cookie,Ttoken,Stoken,Mtoken,Appid,terminal,redirect,Token
Access-Control-Allow-Methods: POST,GET,OPTIONS,DELETE,PUT
```
影响: www/mf/mba/emba/phd/thinktank 等6+子域名

### 2. SSO API端点暴露
从JS提取的API路径:
```
/sso/apis/v3/open/captcha?imageWidth=100 — 返回验证码图片+token
/sso/apis/v3/open/register — POST, 返回MALFORMED_CONFIGURE
/sso/apis/v3/open/code/SMS — POST, 返回USER_NOT_FOUND
/sso/apis/v3/open/code/EMAIL — POST
/sso/apis/v3/open/complete_retrieve_password — POST
/sso/apis/v3/open/verify_retrieve_password/sms — POST, 用户枚举
/sso/apis/v3/open/verify_retrieve_password/EMAIL — POST, 用户枚举
/sso/apis/v3/open/verify_retrieve_password/FAQ — POST
/sso/apis/v3/open/active — POST, 返回激活key
/sso/apis/v2/me/profile?showInfo=true — 需认证
/sso/apis/v3/me/sessions — 需认证
/sso/apis/v3/me/account-mapping — POST, 需认证
```

### 3. SSO用户枚举
`verify_retrieve_password` 端点返回 "用户未找到" (USER_NOT_FOUND), 可枚举用户存在性。

### 4. NetID ASP.NET错误泄露
密码修改/找回表单触发ASP.NET错误, 泄露:
- web.config配置结构
- customErrors配置建议
- ASP.NET 4.0.30319框架信息

### 5. CodeIgniter配置错误
cafrpro.saif.sjtu.edu.cn 访问 /application/controllers/ 返回:
"Your system folder path does not appear to be set correctly. Please open the following file and correct this: index.php"

## CVE利用测试结果 (全部被WAF拦截)

| CVE | 目标 | 结果 |
|-----|------|------|
| CVE-2021-41773 | Apache 2.4.6 | 405 WAF |
| CVE-2021-42013 | Apache 2.4.6 | 405 WAF |
| CVE-2012-1823 | PHP-CGI | 405 WAF |
| CVE-2015-4024 | PHP 5.4.16 | 405 WAF |
| CVE-2017-15715 | Apache上传 | 405 WAF |
| CVE-2017-7269 | IIS WebDAV | 405 IIS配置 |
| CVE-2020-0688 | ASP.NET ViewState | 需机器密钥 |
| CVE-2021-23017 | nginx DNS | 400 Bad Request |
| CVE-2022-22947 | Spring Cloud | 405 WAF |
| CVE-2022-22965 | Spring4Shell | 405 WAF |

## WAF特征
- 域名CNAME到 yundunwaf3.com/yundunwaf4.com/yundunwaf5.com
- Cookie: acw_tc
- 拦截返回405 + 阿里云错误页面
- 覆盖所有子域名
- 规则覆盖: 路径遍历、命令注入、文件包含、SQL注入、XSS
