# 深信服 SSL VPN 漏洞数据库

## SF-PSIRT-20220032 — 命令执行 (主要)
- 影响: M7.5 ~ M7.6.9R2
- CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- 原因: "产品未对内部接口做有效控制，导致可以通过非预期的方式访问，造成命令执行"
- 修复: SP_SSL_IMPROVE_COM(20211022) 或更新组合补丁
- 公开 PoC: **无可靠公开 PoC**
- DayDayPoc: DVB-2021-2446 (需登录下载)
- 官方: https://www.sangfor.com.cn/sec_center/details/66c17f8ec98a4bafa125782503f7e35e

## CNVD-2020-57240 — url 参数命令注入
- 影响: <= 7.6.7
- 类型: url 参数注入，可植入 webshell
- 端点: 可能是 checkurl.csp 或类似 url 参数端点
- payload 模式: `url=http://127.0.0.1;sleep${IFS}5;&retry=0&timeout=1`
- M7.6.8R2: checkurl.csp 返回 404，可能已修复

## CNVD-2020-48680 — 升级维护工具命令执行
- 影响: M7.5
- 公开日期: 2020-09-10
- 端点: 未公开

## CNVD-2020-48223 — 客户端升级签名绕过
- 影响: M6.x 系列 (NSFOCUS 确认 M6.3R1, M6.1)
- 类型: 客户端更新模块签名认证缺陷
- 需要: 已控制 VPN 设备
- APT 利用: 是 (NSFOCUS 报告)

## CVE-2016-2183 — SWEET32 (3DES)
- 类型: TLS 弱密码套件
- M7.6.8R2: 通常已禁用 3DES
- 端口 8118: TLSv1.3 但 SSL 握手失败

## 旧版本 PHP-CGI RCE (<= M5.6)
- 端点: /cgi-bin/php-cgi/html/svpn.php, tsproxy.php
- 参数: cmd
- M7.6.8R2: 全部 404，已移除

## Pre-auth 密码重置 (changepwd.csp)
- 影响: M7.6.1, M7.6.6R1
- M7.6.8R2: 端点存在，WAF 拦截 clusterd 参数，RC4 key 未知

## Pre-auth 手机修改 (changetelnum.csp)
- 影响: M7.6.1 确认
- M7.6.8R2: 端点存在，不需 RC4 key 即可传参，但返回错误码 3/6

## DLL 劫持 (客户端)
- 影响: < 7.6.7
- 类型: 本地提权
- 官方: https://www.sangfor.com.cn/sec_center/details/b59b069d5b55474099083d2a673cb57e

## 参考链接
- 安全通告: https://www.sangfor.com.cn/sec_center/details/66c17f8ec98a4bafa125782503f7e35e
- CNVD-2020-57240: https://www.cnvd.org.cn/flaw/show/CNVD-2020-57240
- CNVD-2020-48680: https://www.cnvd.org.cn/flaw/show/CNVD-2020-48680
- NSFOCUS APT: https://nsfocusglobal.com/overseas-apt-organization-exploits-vulnerabilities-to-breach-sangfor-ssl-vpns-and-deliver-malicious-code-threat-alert
- PeiQi changepwd: https://wiki.96.mk/
- ol4three changetelnum: http://www.ol4three.com/2020/09/17/WEB/Exploit/深信服/
- 腾讯云合集: https://cloud.tencent.com/developer/article/2128150
- DayDayPoc: https://www.ddpoc.com/DVB-2021-2446.html
