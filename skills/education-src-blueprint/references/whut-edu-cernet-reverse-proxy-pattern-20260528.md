# 武汉理工大学 whut.edu.cn 测试记录 (2026-05-28)

## 目标概况
- IP: 202.114.50.2 (CERNET教育网)
- 邮件: 网易企业邮 (hzmx01.mxmail.netease.com)
- DMARC: p=none, SPF: -all
- CAS: Oracle CAS (zhlgd.whut.edu.cn), JSESSIONID HttpOnly

## 外网可达资产 (约15个)
| 子域 | 用途 | 技术栈 |
|------|------|--------|
| www | 主站 | 自定义HTML, jQuery |
| mail | 邮件 | 网易企业邮, nginx |
| vpn | VPN | Sangine aTrust 2.0 |
| webvpn | WebVPN | 网瑞达资源访问控制系统, AES加密 |
| news | 新闻 | jQuery 1.12.4 |
| lib | 图书馆 | 超星SSO, layui+vue |
| zs | 招生 | jQuery 1.11.3 |
| nic | 网络中心 | jQuery 3.6.0, Dify AI chatbot |
| lxsgl | 留学生管理 | Vue.js SPA, Dify chatbot |
| scc | 就业网 | 拓扑软件 |
| alumni | 校友会 | jQuery 3.4.1, require.js |
| shhzc | 社会合作 | jQuery 3.4.1 |
| wljy | 继续教育 | 380字节壳页 |
| zhlgd | CAS认证 | Oracle CAS |
| yjsgl | 研究生管理 | 拓扑软件 |

## CERNET-only不可达 (12+个)
ehall, sso, auth, oa, jwc, yjs, pay, card, hr, api, ids, rsc, lqcx, test, dev, open, mobile, m, campus, www2

## ⚠️ 反向代理空200误报模式 (重要!)

**所有 whut.edu.cn 子域共享同一反向代理/WAF配置**, 对以下路径统一返回 HTTP 200 + Content-Length: 0:
- `/swagger-ui.html` → 200 (0B)
- `/v2/api-docs` → 200 (0B)
- `/druid/` → 200 (0B)
- `/.git/HEAD` → 200 (0B)
- `/actuator` → 200 (0B) 或 403 (WAF拦截页)
- `/api/*` → 200 (0B, Content-Type: application/json)

**验证方法**: 比较目标路径和随机路径
```bash
# 真实端点: swagger返回200, 随机路径返回404
curl -sk "https://TARGET/swagger-ui.html" -o /dev/null -w "%{http_code}"
curl -sk "https://TARGET/nonexistent99999" -o /dev/null -w "%{http_code}"
```

**关键区分**: 虽然swagger和随机路径返回不同状态码(200 vs 404), 但swagger的body为空(0字节)。这不是真正的swagger暴露, 而是反向代理对"看起来像敏感路径"的请求返回空响应的行为。

**已确认出现此模式的子域**: scc, alumni, shhzc, wljy, yjsgl

**结论**: 不要将这些空200响应报告为漏洞。需要实际返回内容(swagger JSON、git内容、druid页面)才算真实暴露。

## CERNET防火墙行为
- 主站IP (202.114.50.2) 所有非HTTP端口被过滤
- nmap扫描44个端口全部filtered
- 仅80/443通过反向代理可达

## Sangine aTrust 2.0 VPN
- vpn.whut.edu.cn + gvpn.whut.edu.cn
- 使用SDPC (Sangfor Proxy Client) 代理客户端
- 有防卸载(anti-uninstall)功能
- SPA安全码验证
- CSP限制: 仅允许自身+飞书+阿里+微信+QQ资源

## 网瑞达 WebVPN
- webvpn.whut.edu.cn
- 使用AES加密密码 (aes-js.js)
- CSRF token保护
- 双因素认证(用户名+手机+TOTP)
- 所有API端点返回403 (WAF拦截)
- `/do-second-login` 存在但需CSRF

## 子域名枚举结果
- DNS暴力枚举: ~46个
- subfinder: 221个
- 大部分CERNET-only不可达
- crt.sh 返回502 (服务不可用)

## 测试结论
**未发现可提交的实质漏洞。** 高价值系统全部CERNET-only, 外网可达系统安全配置良好。

## 后续建议
- 获取CERNET VPN或校内网络接入后重新测试
- 重点: ehall(金智教育)/OA(致远OA)/教务/一卡通
- 这些系统使用商业平台, 漏洞概率更高
