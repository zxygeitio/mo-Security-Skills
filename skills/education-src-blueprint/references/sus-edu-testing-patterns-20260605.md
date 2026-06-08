# 上海体育大学 sus.edu.cn 测试记录 (2026-06-05) — 第一轮

**注意:** 2026-06-07第二轮测试发现authserver可通过IP直接访问，存在CAS Open Redirect高危漏洞。详见 `sus-edu-testing-patterns-20260607.md`。

## 目标概况
- 域名: sus.edu.cn
- IP: 101.231.216.206 (主站), 101.231.216.135 (webvpn), 219.220.200.10 (idp)
- 主站: Microsoft-IIS/6.0 (标题"访问禁止", 连接超时)
- 子域名: ~83个 (subfinder枚举)
- 存活外网: 仅6-7个子域可达
- MX: hzmx01.mxmail.netease.com / xchzmx01.mxmail.netease.com (网易企业邮箱)
- SPF: v=spf1 include:spf.163.com -all (严格)
- DMARC: p=quarantine (应为reject)

## 可达子域

| 域名 | IP | Server | 技术栈 | 状态 |
|---|---|---|---|---|
| www.sus.edu.cn | 101.231.216.206 | IIS/6.0 | Windows | 标题"访问禁止",超时 |
| vpn.sus.edu.cn | | Server | Sangfor SSL VPN M7.6.8R2 | **RCE漏洞** |
| webvpn.sus.edu.cn | 101.231.216.135 | Server | Sangfor SSL VPN M7.6.8R2 | **RCE漏洞+配置泄露** |
| mail.sus.edu.cn | | nginx | 网易企业163邮箱 | 用户枚举 |
| admission.sus.edu.cn | | nginx | Java/JSP + 17gz.org | 国际学生平台 |
| susbook.sus.edu.cn | | openresty | Vue SPA + Go API | 场馆预约 |
| xxb.sus.edu.cn | | ***** | CAS + jQuery | 信息化办 |
| nic.sus.edu.cn | | ***** | CAS + jQuery | 信息化办 |

## 关键发现

### 1. 深信服SSL VPN远程命令执行 (CVSS 9.8) — 高危(被拒)
- 域名: vpn.sus.edu.cn + webvpn.sus.edu.cn (两个入口,同一版本)
- 版本: M7.6.8R2 (客户端 7.6.7.4)
- 受影响范围: M7.5-M7.6.9R2 (SF-PSIRT-20220032)
- **被拒原因:** 仅版本泄露，无实际利用证明

### 2. 企业微信Corpsecret配置泄露+内网IP — 中危(被拒)
- 域名: susbook.sus.edu.cn (场馆预约, OpenResty)
- 端点: GET /api/wecom/login
- 泄露内容: 内网IP 124.223.216.16, WeChat Work hint ID
- **被拒原因:** 信息泄露，无实质危害

### 3. 网易企业邮箱用户枚举 — 低危(被拒)
- 域名: mail.sus.edu.cn (网易企业163邮箱, nginx)
- 差异响应: 有效用户→VERIFYCODE.REQ, 无效用户→ERR.LOGIN.PASSERR
- **被拒原因:** 信息泄露，无实质危害

### 4. webvpn.sus.edu.cn VPN服务器配置信息泄露 — 低危(被拒)
- **被拒原因:** 信息泄露，无实质危害

### 5. 多子域名缺失安全头 — 低危(被拒)
- **被拒原因:** 配置缺陷，无实质危害

### 6. DMARC quarantine策略 — 低危(被拒)
- **被拒原因:** 配置缺陷，无实质危害

## 不可达子域 (内外网均超时)
authserver, jwxt, jwc, lib, kyc, kygl, eyjs, mehall, eyou, qkzx, xw, mba-mta, xnfzsyjx, sem, stjy, dag, nustps, cttc, cttce, wushu, eng, bksyx, gw, idp — 全部连接超时

**重要更新:** 2026-06-07第二轮测试发现authserver可通过IP 101.231.216.210 + Host头直接访问，存在CAS Open Redirect高危漏洞。详见 `sus-edu-testing-patterns-20260607.md`。

## 教训

所有第一轮发现的漏洞都是低价值信息泄露/配置缺陷，全部被SRC拒绝。第二轮转向寻找可利用的实质性漏洞，发现CAS Open Redirect高危漏洞。
