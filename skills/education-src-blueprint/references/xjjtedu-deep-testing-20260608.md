# 联奕CAS + Liferay Portal 深度测试 (2026-06-08)

## 测试目标
新疆交通职业技术大学 xjjtxy.cn — 联奕CAS + Liferay Portal + Tomcat 7.0.109

## 测试结果: 未发现高危漏洞

### 已验证的中低危漏洞
1. CAS Open Redirect (service参数无白名单)
2. CAS管理后台公网暴露 (ly_web_casconsole)
3. 源码敏感信息泄露 (内网IP/内部域名/RSA公钥)
4. 学生密码找回页面暴露 (完整组织架构)
5. CoCall即时通讯公网暴露 (V6.2.2.16)
6. Liferay Proxy Servlet存在 (/api/liferay/proxy, IP限制)

### 已尝试但未成功的攻击向量
| 攻击向量 | 结果 | 原因 |
|---------|------|------|
| Liferay JSONWS RCE (CVE-2020-7961) | 失败 | expandocolumn端点需认证 |
| CAS管理后台暴力破解 | 失败 | 56组凭据无弱口令 |
| SMS用户枚举 | 失败 | 需验证码 |
| WeChat QR登录劫持 | 失败 | 需有效session |
| SSRF/LFI | 失败 | 被重定向到登录页 |
| XSS | 失败 | 参数被URL编码 |
| AJP Ghostcat | 失败 | 端口8009从外部filtered |
| CAS时序攻击 | 失败 | 无响应时间差异 |
| CAS会话固定 | 失败 | 无漏洞 |
| 内网横向移动 | 失败 | 内网IP不可达 |
| Liferay Proxy SSRF | 失败 | IP限制,无法绕过 |
| CoCall租户枚举 | 失败 | 所有猜测均返回"未找到租户信息" |
| Tomcat CVE利用 | 失败 | CVE-2023-45648/42795/41080不适用于7.0.109 |

## 关键发现

### Liferay Proxy Servlet
```bash
curl -sk "http://HOST/api/liferay/proxy?url=http://127.0.0.1:8080/"
# 返回: 403 "Access denied for X.X.X.X"
# 确认端点存在, 但IP限制无法绕过
```

### 联奕生态子系统 (全部CAS保护)
- `/lyoa/` — OA办公系统
- `/lyhr/` — 人事系统
- `/lycrm/` — CRM系统
- `/lymail/` — 邮件系统
- `/lybpm/` — BPM流程系统

### CoCall即时通讯
- 版本: V6.2.2.16 (Windows/Mac), V6.2.12 (iOS), V6.2.2.31 (Android)
- 框架: Artery UI + Vue.js 2.6.11 + Spring Boot
- 公网地址: https://www.xjjtedu.cn:65083/download
- 租户架构: 所有API需要租户名, 无法枚举

## ⚠️ Tomcat CVE准确性陷阱

**Tomcat 7.0.109 (2022-01-13, EOL) 不受以下CVE影响:**
- CVE-2023-45648: 仅影响 8.5.x/9.x/10.x
- CVE-2023-42795: 仅影响 8.5.x/9.x/10.x
- CVE-2023-41080: 仅影响 9.x/10.x

**报告中引用CVE前必须验证版本适用性!**

## 结论

该目标CAS+Liferay防护较好, 未认证攻击面有限。要发现高危漏洞需要:
1. 有效CAS账号 → 测试认证后漏洞
2. 内网VPN接入 → 测试内部服务
3. 社工获取凭据 → 测试权限提升
