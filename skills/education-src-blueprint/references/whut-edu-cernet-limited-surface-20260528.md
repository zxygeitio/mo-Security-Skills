# whut.edu.cn (武汉理工大学) 测试记录

## 测试时间: 2026-05-28

## 目标概况
- 类型: 211高校, 教育部直属
- 主IP: 202.114.50.2 (CERNET)
- 邮件: 网易企业邮 (hzmx01.mxmail.netease.com)
- DMARC: p=none (弱), SPF: -all (强)
- CAS: zhlgd.whut.edu.cn (Oracle CAS, 非Apereo)

## 资产清单

### 外网可达 (11个)
| 子域 | 用途 | 技术栈 | 备注 |
|------|------|--------|------|
| www | 主站 | 自定义HTML+jQuery | 200 OK |
| mail | 邮件 | 网易企业邮+nginx | .git/HEAD→403(nginx拦截) |
| vpn | VPN | Sangine aTrust 2.0 | 302→/portal/ |
| webvpn | WebVPN | 网瑞达+layui+AES | WAF拦截actuator |
| news | 新闻 | jQuery 1.12.4+自定义CMS | 文章URL: /{栏目}/{年月}/t{id}.shtml |
| lib | 图书馆 | 超星SSO(chaoxing.com) | CORS仅Methods,无Origin反射 |
| zs | 招生 | jQuery 1.11.3+静态 | 链接到lqcx(不可达) |
| nic | 网络中心 | jQuery 3.6.0+Dify AI | Dify token:iHjSYHdOGFQfhGvr(na不可达) |
| lxsgl | 留学生管理 | Vue.js SPA+Dify | Dify token:9p8iH4m1jcupeP3V |
| scc | 就业信息网 | 拓扑软件 | swagger/druid/.git返回200+空body |
| zhlgd | CAS认证 | Oracle CAS | JSESSIONID HttpOnly, serviceValidate可达 |

### CERNET-only不可达 (12+个)
ehall(218.197.104.131), sso(218.197.100.87), auth(218.197.111.6), oa(202.114.173.227), jwc(202.114.90.190), yjs(202.114.88.135), pay(218.197.98.68), card(202.114.88.183), hr(202.114.173.51), api(218.197.100.69), ids(218.197.104.131=ehall同IP), rsc(202.114.88.179), lqcx, yjswx(218.197.101.14)

### 额外可达子域(静态门户)
cgyztb(采购招标), english, gd(研究生教育信息网), gjc(国际交流), kfy(科学技术发展院)

## 发现评估

### Dify Chatbot Token (不建议提交)
- nic和lxsgl前端暴露Dify widget token
- Token是设计上公开的前端集成凭证
- school.eliandong.com Dify 0.15.5, CORS:*, API返回401
- 结论: 非漏洞

### CAS JSESSIONID (配置正确)
- Set-Cookie: JSESSIONID=xxx; HttpOnly
- 未在HTML body中暴露
- serviceValidate返回XML(INVALID_TICKET格式)
- 结论: 配置正确

### scc敏感路径200空body (不建议提交)
- /swagger-ui.html, /v2/api-docs, /druid/, /.git/HEAD → 200 OK, Content-Length: 0
- 随机路径→404, 确认敏感路径被代理层拦截
- 结论: 无实际内容泄露

### 邮件安全 (不建议单独提交)
- DMARC p=none + SPF -all
- 网易企业邮, 无实际伪造邮件证据

## 结论
外网攻击面有限。大部分高价值系统在CERNET教育网内，需校内网络或VPN访问。
外网可达系统安全配置较好(CAS HttpOnly/CSRF/AES加密)。
未发现可提交的实质漏洞。

## 教训
1. CERNET高校外网可达率仅~22%，应先快速筛选再深入
2. Dify chatbot token是公开设计，非漏洞
3. 200空body是反代/WAF拦截模式，非真实端点
4. 大型高校(211/985)安全配置通常较好，低年级/职业学院漏洞更多
