# 华中师范大学 ccnu.edu.cn 测试模式 (2026-06-03/06-07)

## 目标概况
- 域名: ccnu.edu.cn
- 子域数量: 200+
- 真实IP: 183.168.162.12 (广东)
- WAF: SafeLine(长亭科技) — 部分子域403"您的访问请求可能对网站造成安全威胁"
- 主站: www.ccnu.edu.cn (博达CMS Visual SiteBuilder 9 + jQuery + Vue.js + Element UI)

## 高价值子域指纹

| 子域 | 技术栈 | 状态 | 可测性 |
|------|--------|------|--------|
| oa.ccnu.edu.cn | 致远Seeyon OA V9.0SP1 (250122) | REST需认证 | 可枚举 |
| mail.ccnu.edu.cn | 自定义代理→腾讯企业邮 | CORS*+客户端验证码 | **可利用** |
| ehall.ccnu.edu.cn | 金智办事大厅+瑞数反爬(412) | CLI不可达 | 跳过 |
| vpn.ccnu.edu.cn | 深信服aTrust 2.0 | 标准安全头 | 可指纹 |
| webvpn.ccnu.edu.cn | WEngine VPN+CAS | 所有API需认证 | 有限 |
| one.ccnu.edu.cn | 金智CAS(COM.WISEDU.CASP) | 标准CAS流程 | 可测试CAS |
| ai-agent.ccnu.edu.cn | React+webpack+CSRF Token | API 403保护 | 有限 |
| certificate.ccnu.edu.cn | nginx 1.26.1 | 403(已修复CORS) | 已修复 |
| ecard.ccnu.edu.cn | 静态页面 | 无交互接口 | 无价值 |
| ec-vlab.ccnu.edu.cn | 静态页面 | 无交互接口 | 无价值 |
| waf.ccnu.edu.cn | 403 | WAF管理(不测) | 跳过 |
| app.ccnu.edu.cn | 403 | SafeLine保护 | 跳过 |

## 已确认漏洞

### mail.ccnu.edu.cn CORS通配符+客户端验证码 [中危]
- POST /mail/loginfun
- Access-Control-Allow-Origin: *
- 参数: txtuserid, usertype(1=教职工,2=学生), pwd
- 客户端验证码: sessionStorage, 4位, 60秒过期
- PoC: curl -sS -D- -X POST "https://mail.ccnu.edu.cn/mail/loginfun" -H "Origin: https://attacker.com" -d "txtuserid=test@ccnu.edu.cn&usertype=1&pwd=test"

### certificate.ccnu.edu.cn CORS [已修复]
- 06-03发现ACAO反射+ACAC=true(高危)
- 06-07确认已修复(403 Forbidden, nginx 1.26.1)

## CAS认证系统
- one.ccnu.edu.cn: 金智CAS(COM.WISEDU.CASP)
  - Cookies: route_casp_portal, gwroute-casp-portal, COM.WISEDU.CASP.IS_RANDOM, WISCPSID
  - 登录: /auth-protocol-core/login?service=...
  - serviceValidate: /auth-protocol-core/serviceValidate (302)
- ehall.ccnu.edu.cn: 金智办事大厅
  - 瑞数信息反爬(412), CLI无法绕过
  - JSONP端点301→one.ccnu.edu.cn

## 致远OA (oa.ccnu.edu.cn) V9.0SP1
- 见 `seeyon-oa-testing-patterns.md` 获取完整端点列表
- V9.0SP1已修补SSRF(httpproxy/thirdpartyController)
- REST API全部401(需认证)
- SafeLine WAF保护.jsp路径

## VPN
- vpn.ccnu.edu.cn: 深信服aTrust 2.0
  - CSP: script-src含atrustcdn.sangfor.com, feishucdn.com, bytegoofy.com
  - 版本戳: SF_VERSION = '1754444585976' (时间戳)
- webvpn.ccnu.edu.cn: WEngine VPN
  - CAS登录: /https/77726476706e69737468656265737421f1f44293323e7c1e7d0b87b9d6502720f39f46/cas/login
  - Cookie: wengine_vpn_ticket

## 06-03 历史发现(需复测)
- OSS混淆页解密(XOR+base64)→fake-ip(198.18.0.x)→hackertarget历史DNS→真实IP
- 236子域枚举完成
