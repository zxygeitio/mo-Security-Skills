# 华中农业大学 hzau.edu.cn 测试记录 (2026-05-28)

## 目标概况
- 域名: hzau.edu.cn (华中农业大学)
- 子域名: 280+ (subfinder), 32 DNS A记录确认, 12+ HTTP可达
- IP段: 211.69.x.x (CERNET教育网), info.hzau.edu.cn为218.199.76.60(非CERNET)
- 技术栈: VSB CMS + nginx/1.27.0 + Coremail + WebberRASP + CRMEB(Tengine/PHP) + VMware Horizon + Shibboleth IdP
- WAF: WebberRASP (news/lib/ehall/portal等路径403, 15789字节)
- 邮件: SPF -all (硬失败), DMARC缺失, DKIM缺失

## 确认漏洞

### 1. VSB CMS getSession.jsp 未授权会话获取 (中危, 已提交)
受影响站点(14+): www, my, zs, yjs, ai, hospital, shop, cwb(财务处), hq(后勤), jsgzb, jxjy(继续教育), jwb(纪检委), cf(水产学院), bx
```
curl -sk 'https://TARGET/system/resource/getSession.jsp?r=0.1'
# 每次返回唯一32位hex JSESSIONID
curl -sk 'https://TARGET/system/resource/getToken.jsp?mode=1'
# 返回 "preview" (大量空行+preview, Content-Length:31)
```
token.js位于 `/system/resource/vue/token.js`，定义getSession.jsp/getToken.jsp/sensitiveFilter.jsp三个接口。

### 2. shop.hzau.edu.cn CRMEB CORS + 未授权API (中危, 已提交)
```
# CORS反射
curl -sk -D- 'https://shop.hzau.edu.cn/api/products' -H 'Origin: https://evil.com'
# ACAO: https://evil.com, ACC: true

# 未授权商品数据
curl -sk 'https://shop.hzau.edu.cn/api/products'
# 返回: id, store_name, price, stock, image URL, cate_id, spec_type等

# 验证码配置泄露
curl -sk 'https://shop.hzau.edu.cn/api/verify_code'
# 返回: {"key":"$2y$10$...bcrypt_hash...","expire_time":"5"}

# 管理后台
curl -sk 'https://shop.hzau.edu.cn/admin/'  # SPA可访问
```

## 未达提交标准的发现

### idp.hzau.edu.cn Shibboleth IdP
- `/idp/shibboleth` 返回完整SAML元数据(entityID, X509Certificate, SSO/SLO endpoints)
- validUntil: 2020-02-08 (已过期)
- `/idp/profile/Status` → Tomcat/7.0.76 错误页(版本泄露)
- 低危: 公开设计, 无实质利用

### desktop.hzau.edu.cn VMware Horizon
- "华中农业大学云桌面", VMware Horizon Client 5.0.0
- `/portal/info.jsp` → JSON: clientVersion, installerLink(内部URL)
- 其他路径(/portal/auth, /broker/sdk等) → 404
- 低危: 版本+内部URL泄露

### portal.hzau.edu.cn CSP泄露
- HTML中含 `portal-minio.hzau.edu.cn`(211.69.132.234, 403)
- `leoagent.hzau.edu.cn`(211.69.128.147, 403)
- `agentest.hzau.edu.cn`(211.69.128.165)
- 内网地址: 211.69.128.148:8080, 211.69.128.144:8000

### ehall.hzau.edu.cn (新版SPA)
- 所有/jsonp/*路径返回SPA HTML壳(非JSON), 旧JSONP API不存在
- actuator/swagger/druid → 403 (WebberRASP拦截)
- 需浏览器分析SPA前端JS提取实际API路径

### CERNET-only子域
- ecard(一卡通): 211.69.129.123, HTTP不可达
- jwgl(教务): 211.69.128.65, HTTP不可达
- moodle(LMS): 211.69.130.76, HTTP不可达
- yjsjw(研究生教务): 211.69.143.70, HTTP不可达
- oa: 所有路径超时
- 连VPN后可测: ecard IDOR/jwgl成绩越权/Moodle已知CVE

### mail.hzau.edu.cn Coremail
- EMPHPSID cookie, 所有端点403
- MX: mx.hzau.edu.cn + smtp.hzau.edu.cn

## 关键子域清单
| 子域 | IP | 状态 | 系统 |
|------|-----|------|------|
| www | 211.69.132.118 | 200 | VSB CMS |
| ehall | 211.69.142.121 | 200(SPA) | 金智教育新版 |
| my | 211.69.132.118 | 200 | VSB CMS |
| shop | 211.69.143.108 | 200 | CRMEB电商 |
| ai | 211.69.143.108 | 200 | 智慧狮山AI广场 |
| hospital | 211.69.143.108 | 200 | 校医院VSB |
| desktop | ? | 200 | VMware Horizon |
| mail | 211.69.143.17 | 200 | Coremail |
| portal | 211.69.132.234 | 200 | VSB CMS |
| cas | 211.69.132.234 | 403 | WebberRASP |
| sso | 211.69.143.135 | 000 | 不可达 |
| idp | 211.69.133.28 | 200 | Shibboleth IdP |
| vpn | 211.69.128.203 | 302 | VPN |
| webvpn | 211.69.143.130 | 000 | 不可达 |
| oa | 211.69.143.162 | 000 | 内网OA |
| ecard | 211.69.129.123 | 000 | 一卡通(CERNET) |
| jwgl | 211.69.128.65 | 000 | 教务(CERNET) |
| moodle | 211.69.130.76 | 000 | LMS(CERNET) |
| news | 211.69.143.107 | WAF | WebberRASP |
| lib | 211.69.133.226 | WAF | WebberRASP |

## 测试教训
1. **280+子域名但大部分不可达**: subfinder枚举出大量实验室/科研子域, 但实际HTTP可达仅12个左右
2. **WebberRASP拦截**: ehall/portal/cas/news/lib等路径返回403(15789字节标准页), 无法绕过
3. **CERNET-only**: ecard/jwgl/moodle/yjsjw等高价值目标需VPN
4. **ehall新版SPA**: 不能用旧JSONP API模式, 需浏览器分析
5. **getSession.jsp批量扩展**: 同一CMS的同根因漏洞可扩展到所有使用该CMS的子域, 但不应作为新漏洞重复提交
