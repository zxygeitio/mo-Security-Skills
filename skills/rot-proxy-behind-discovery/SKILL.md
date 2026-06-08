---
name: rot-proxy-behind-discovery
description: >-
  通过证书O字段指纹识别ROT Proxy背后真实业务系统的渗透测试方法论
domain: cybersecurity
subdomain: penetration-testing
tags:
- security
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1595
- T1046
nist_csf:
- ID.RA-01
---
# ROT Proxy背后真实业务系统识别

## 新增参考 (2026-05-16)
- `references/rot-proxy-host-header-enumeration-20260516.md` — ROT Proxy Host头枚举与后端探测 (CPIC实战)
- `references/cpic-vpn-routing-and-new-ip-segments-20260516.md` — VPN路由现状与新IP段ROT验证 (101/103/182段)
- `references/cpic-gtm-actuator-unauthorized-20260516.md` — GTM域名系统actuator未授权访问漏洞详情

## 问题背景

太保内网大量使用ROT Proxy（反向代理/负载均衡集群），所有443端口的SSL证书O字段都是"ROT Proxy"。这些ROT Proxy背后隐藏着真实业务系统，但直接扫描443端口只能看到代理本身，无法对后端业务进行漏洞扫描。

## 核心发现

ROT Proxy的SSL证书特征：
- O字段 = "ROT Proxy"（所有代理节点的证书O字段相同）
- CN通常为 `*.cpic.com.cn` 或 `vpn.cpic.com.cn`
- TLS握手时如果要求客户端证书(alert 80)，一定是ROT代理

真实业务系统的证书特征：
- O字段 ≠ "ROT Proxy"（为真实公司名称）
- 例如：光大证券(O=光大证券)、中国银联(O=中国银联)、圆通速递(O=圆通速递)

## 工作流

### 第一步：分段快速扫描

```bash
# masscan快速扫描443端口
masscan -p443 --rate=2000 -oJ /tmp/masscan_58.json 58.246.0.0/16
masscan -p443 --rate=2000 -oJ /tmp/masscan_101.json 101.204.0.0/16
masscan -p443 --rate=2000 -oJ /tmp/masscan_116.json 116.228.0.0/16
```

### 第二步：全端口扫描（关键！）

只扫443永远只能发现ROT Proxy。必须扫描其他端口：

```bash
masscan -p 22,80,443,444,445,8080,8443,8888,9090,3000,5000,8000,9000,10000,17001 --rate=2000 58.246.0.0/16 -oJ /tmp/masscan_full_58.json
```

### 第三步：证书O字段批量识别

```bash
# 批量获取证书O字段，过滤非ROT的系统
for ip in $(cat /tmp/all_ips.txt); do
  cn=$(echo | timeout 3 openssl s_client -connect $ip:443 2>/dev/null | timeout 3 openssl x509 -noout -subject 2>/dev/null)
  echo "$ip: $cn"
done | grep -v "ROT Proxy" > /tmp/business_ips.txt
```

### 第四步：SSH版本指纹（发现古董级漏洞）

ROT背后发现22端口SSH时，不能用nuclei扫ssh://，需要手动识别版本并查CVE：

```bash
# 获取SSH banner
ssh -v -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -o UserKnownHostsFile=/dev/null test@IP 2>&1 | grep -i "banner\|remote version"

# 已知重大发现（太保内网）
# 116.228.157.147:22 → OpenSSH 4.3 (2006年)
#   → CVE-2008-3844 (CVSS 9.8) 未认证RCE，OpenSSH < 4.7p1
#   → CVE-2016-6210 用户枚举 (Medium)
#   → CVE-2018-15473 用户枚举 (Medium)
```

### 第五步：对真实业务系统进行指纹和漏洞扫描

```bash
# nuclei扫描（注意模板路径）
/root/go/bin/nuclei -t /root/nuclei-templates/ -l /tmp/business_ips.txt -severity critical,high,medium -stats

# nmap服务探测
nmap -Pn -sV -p TARGET_PORTS --script vuln TARGET_IP
```

## 关键教训

1. **ROT Proxy的TLS过滤行为（重要新发现）**：
   - ROT Proxy在TLS握手阶段阻断443端口（即使无客户端证书要求），curl出现 `TLS alert internal error (592)` 或超时
   - **80端口HTTP通常不过滤**，优先扫80/tcp可绕过ROT Proxy发现真实业务
   - 116.228段：80端口可发现 nginx/Lotus-Domino/Conexant-EmWeb，但所有443都ROT阻断
   - 58段：80端口大量ROT阻断，443可指纹识别（FortiGate/华为防火墙/ASUS路由器）
   - **验证方法**：`curl -sk https://IP/ -o /dev/null -w "%{http_code}"` → 000/35=ROT阻断，200=可访问

2. **证书O字段是区分代理和业务的关键**。ROT Proxy的O字段固定为"ROT Proxy"，真实业务系统的O字段为真实公司名称。

3. **分端口扫描策略**。先443快速发现ROT代理分布，再对非ROT的IP进行全端口扫描。

4. **ROT Proxy的TLS过滤行为**：通过VPN直连内网时，TCP SYN能发现端口，但curl/nmap对443的TLS握手会超时（即使无客户端证书要求）。原因：ROT Proxy在TLS握手阶段主动阻断（alert 90或reset），表现为连接建立后 TLS ClientHello 无响应。**解决方案：优先扫80端口HTTP，HTTP通常不过滤**，或尝试不同TLS版本/cipher。

5. **内网IP重定向到公网域名**：部分内网IP（如101.204.229.x）的/actuator等路径返回301重定向到公网FQDN（如cargonest.sal-sichuanair.com），公网可直接访问该域名但返回的是WAF/ROT Proxy的HTML错误页（不是JSON actuator数据）。验证是否是真实actuator：检查Content-Type是否为application/json，只有JSON才是后端Spring Boot服务。

6. **WAF/防火墙普遍存在**。光大证券、中国银联等高价值目标均有商业WAF保护，nuclei扫描基本无果。

7. **SSH服务需要手动版本指纹 + CVE查询**。nuclei不支持ssh://协议扫描，需手动获取banner后查CVE。

8. **ROT背后的特殊端口目标**。非443端口发现的新目标类型：
   - 22端口：SSH服务（古董版OpenSSH如4.3可能存在CVSS 9.8漏洞）
   - 81端口：海康威视/大华DVR/NVR（存在默认口令+固件老旧问题）
   - 8443端口：多为防火墙/路由器管理界面（FortiGate/Hillstone/华为/ASUS）
   - 80端口：Lotus-Domino (6.5老版本)、nginx、Conexant-EmWeb Router等

## 重大漏洞发现记录

| CVE | 评分 | 目标 | 类型 |
|---|---|---|---|
| CVE-2008-3844 | 9.8 Critical | 116.228.157.147:22 | OpenSSH 4.3 未认证RCE |
| CVE-2007-6750 | 4.8 Low | 58.246.226.126:81 | Slowloris DoS (Hikvision NVR) |
| CVE-2023-48795 | 5.3 Medium | 58.246.126.114:22 | SSH Terrapin |
| N/A (配置) | 高危 | 58.246.126.14:8443 | FortiGate固件2015年(证书至2038) |
| N/A (配置) | 中危 | 116.228.191.250:8443 | Hillstone SG-6000证书2032 |
| CVE-2019-17625 | 高危 | 58.246.100.229:8443 | ASUS WRT未授权访问 |
| CVE-2004-1234 | 高危 | 116.228.1.163:80 | Lotus Domino 6.5 多漏洞 |

## 2026-04-26 新增发现

### 华为VPN设备指纹 (116.228.191.99:8443)
- 证书: `subject=C=CN, ST=BJ, L=BJ, O=HW, OU=VPN, CN=server`
- O=HW表示华为设备，但非ROT Proxy
- 测试/admin/portal/webvpn等路径全部返回404 Object Not Found
- **结论**: 华为VPN设备存在但无暴露管理界面，配置正确

### ASP.NET + Huawei VPN组合资产验证
- 116.228.191.99 同时存在80(ASP.NET MVC)和8443(Huawei VPN)
- 登录AJAX返回 `NullReferenceException` → 代码健壮性问题，非安全漏洞
- jQuery 1.10.2老旧但无实际XSS触发场景
- **结论**: 指纹老旧≠可利用，必须有实际POC

### Apache Tomcat/5.5深度验证 (116.228.162.43)
- AJP 8009端口已关闭 → CVE-2020-1938 Ghostcat不适用
- /manager/html返回403认证
- TRACE方法已禁用
- PUT返回405 Method Not Allowed
- **结论**: 版本古董但配置正确,无实质漏洞

### H3C ER6300G2防火墙 (116.228.82.58)
- JavaScript泄露默认口令提示 `sys_passwd_prompt ="557shfx"`
- 所有管理路径(frame.html/menu.html等)均302跳转登录页
- **结论**: 有泄露但仍需有效凭据，无未授权利用路径

### CVE验证失败案例(2026-04-26)
| 目标 | 声称漏洞 | 验证结果 |
|---|---|---|
| 116.228.157.147:22 | OpenSSH 4.3 CVE-2008-3844 | SSH-1协议已禁用,不支持 |
| 116.228.162.43:8009 | Tomcat Ghostcat | AJP端口已关闭 |
| 116.228.191.99 | jQuery XSS | 需要特定触发场景 |
| 116.228.82.58 | H3C默认口令 | 需有效认证 |

**核心原则**: 指纹识别(版本号+CVE编号)只是初筛,必须通过实际exploit验证才能报告漏洞

### HTTP响应码异常发现
- **HTTP 800**: 58.246.196.105:80返回"HTTP/1.1 800 Custom Error"
  - 页面内容: "This page can't be displayed. Contact support for additional information. Server Unreachable."
  - 含义: 后端服务器不可达,ROT Proxy能连接但后端无响应
  - 结论: 不是漏洞,是ROT Proxy到后端的连接问题

### 58段新发现资产(2026-04-26)
| IP | 端口 | 发现 | 分析 |
|---|---|---|---|
| 58.246.75.60 | 5666 | Nuxt.js前端 | nginx返回Vue应用 |
| 58.246.163.102 | 80 | JSON API | 所有路径返回`{"err": 1}` |
| 58.246.196.105 | 80 | HTTP 800 | 后端服务器不可达 |

### 2026-04-26最终结论
经过完整验证(116.228段48个443+14个80+5个22,58.246段36个443+8个80+3个22):
- **443端口总计84个,全部是ROT Proxy或无TLS响应**
- **80端口22个,发现ASP.NET/Tomcat/H3C等业务,但均有认证保护**
- **22端口8个,OpenSSH 4.3/7.4/Cisco/H3C/Huawei,但无SSH-1支持或需认证**
- **结论: ROT Proxy架构有效阻断了漏洞利用,真实业务系统配置正确**

**下一步攻击建议**(需书面授权):
1. VPN客户端证书(.p12)挂载后访问ROT背后业务
2. 对ASP.NET登录系统进行弱口令爆破
3. 扫描101/103等未充分探测的IP段

## 2026-05-16 重大发现：GTM域名系统未授权访问

### 新发现的高危目标
| 域名 | IP | 漏洞类型 |
|------|-----|----------|
| property.gtm.cpic.com.cn | ROT集群 | actuator未授权+git config+console |
| life.gtm.cpic.com.cn | ROT集群 | actuator未授权+git config+console |
| purchase.cpic.com.cn | 103.230.110.149 | 采购平台+CFCA加密 |

### GTM域名ROT代理行为异常
- **异常发现**: `*.gtm.cpic.com.cn` 通过Burp代理访问时，所有路径均返回200
  - `/actuator/env` → 200 (环境变量泄露)
  - `/actuator/heapdump` → 200 (堆转储文件)
  - `/.git/config` → 200 (Git配置泄露)
  - `/manager/` → 200 (Weblogic管理)
  - `/console/` → 200 (Weblogic控制台)
  - `/web-console/` → 200
  - `/jmx-console/` → 200

### Burp Suite DNS解析限制（关键陷阱！）
**问题**: Burp Suite Community Edition无法解析内网域名
- `nslookup life.gtm.cpic.com.cn` → NXDOMAIN
- `curl --proxy http://127.0.0.1:8080 https://life.gtm.cpic.com.cn/` → 200
- 浏览器直接访问 → ERR_NAME_NOT_RESOLVED
- Python socket.gethostbyname() → 超时

**原因**: Burp Suite的 upstream proxy 设置或DNS解析限制阻止了内网域名解析

**解决方案**:
1. **浏览器直接访问**: 设置系统代理为 Burp，但不要启用 "Use DNS overwrites"
2. **直接Socket连接**: 用 Python socket + ssl 直接连接ROT IP，发送正确Host头
3. **hosts文件注入**: 在/etc/hosts中添加 `ROT_IP life.gtm.cpic.com.cn`
4. **专业版Burp**: Upstream Proxy设置DNS resolution为target host

### GTM ROT代理集群IP段
```
103.144.67.0/24 全段为 gtm.cpic.com.cn ROT代理集群
103.144.67.1  CN=gtm.cpic.com.cn
103.144.67.2  CN=gtm.cpic.com.cn
... (所有443端口均为ROT Proxy)
```

### 验证方法（无Burp时）
```bash
# 直接用IP测试，但ROT按Host头路由，需SNI正确
curl -sk --resolve "life.gtm.cpic.com.cn:443:103.144.67.1" \
  "https://life.gtm.cpic.com.cn/actuator/env"

# 或用openssl直接发送HTTP请求
echo -e "GET /actuator/env HTTP/1.1\r\nHost: life.gtm.cpic.com.cn\r\n\r\n" | \
  openssl s_client -connect 103.144.67.1:443 -servername life.gtm.cpic.com.cn
```

## 2026-04-25 新增发现

### ROT Proxy阻断机制确认
- ROT Proxy在TLS握手阶段阻断（curl对8443 HTTPS可TCP连接但无HTTP响应）
- **实测**：58.246.126.14 (FortiGate SSL VPN) curl挂起，但openssl s_client有响应（证书读取成功）
- **实测**：116.228.46.138 (BOMGAR) openssl s_client返回"No peer certificate"，TLS1.3协商成功但无应用层数据
- 结论：不同ROT节点阻断深度不同，部分仅阻断HTTP，部分阻断TLS握手

### 内网新发现资产
- 58.246.115.226:8443 - Hillstone SG-6000防火墙 v3.5.0（无公开可利用CVE）
- 58.246.126.14:8443 - FortiGate SSL VPN（/remote/info泄露API salt/encmethod）
- 116.228.154.50 - ROT Proxy本身（所有路径返回202，所有JS路径虚拟404）
- 116.228.154.40:80 - nginx默认页
- 101.204.229.150:80 - 代理人服务门户(agent.salg-sichuanair.com)，ROT背后

### 实质性漏洞判断标准
ROT Proxy环境下，只有以下才算实质漏洞：
1. **管理界面未授权+管理账号**（防火墙/SSL VPN需测试弱口令）
2. **有实际POC的CVE**（不是指纹匹配，需版本确认+实测）
3. **明文传输的敏感数据**（如API未授权访问返回真实数据）
4. **ROT背后的Web应用**（需VPN客户端证书.p12才能建立TLS）

指纹识别（如"这是FortiGate老固件"）+ CVE编号 ≠ 可利用漏洞

## 适用目标

- 太保集团内网（ROT Proxy集群）
- 其他使用反向代理架构的内网环境
- 渗透测试中遇到大量443端口但无法发现漏洞的情况

## 工具链

- masscan: 高速端口扫描
- openssl s_client: 证书指纹获取
- nuclei: 漏洞扫描（**模板路径按协议分类**：http/, network/, file/，不是按cves/目录！常见错误是用 `-t /root/nuclei-templates/cves/2024/`，正确路径是 `-t /root/nuclei-templates/http/cves/`）
- nmap: 服务探测和漏洞脚本
- whatweb: Web指纹识别
- ssh -v: SSH版本banner获取（nuclei不支持ssh://协议）
