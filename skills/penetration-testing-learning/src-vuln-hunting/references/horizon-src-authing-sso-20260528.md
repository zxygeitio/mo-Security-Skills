# 地平线(Horizon Robotics) SRC 测试记录 (2026-05-28)

## 目标资产
- *.horizon.ai, *.horizon.cc, *.horizon.auto (可测)
- sso.iam.horizon.auto (核心资产)
- mail.horizon.auto (核心资产)
- developer.horizon.auto (边缘资产)
- *test.horizon.auto (边缘资产)
- call-center.horizon.auto (不可测)
- c-gitlab.horizon.ai (不可测, 仅接受直接危害漏洞)

## 资产发现
- subfinder: horizon.ai=18, horizon.cc=15, horizon.auto=5
- crt.sh + DNS暴力: 总计42个唯一子域
- 存活: 10+个可访问

## 存活资产指纹

| 子域 | 类型 | Server | 技术栈 | 备注 |
|------|------|--------|--------|------|
| sso.iam.horizon.auto | 核心 | Express | Authing IDaaS | app_id=67c91388afda6cf22fdbd93e |
| mail.horizon.auto | 核心 | feilian-agw+IIS/10.0 | Exchange 15.1.2308.27 | OWA暴露 |
| developer.horizon.auto | 边缘 | nginx | Nuxt.js SSR | 开发者社区 |
| oe.horizon.auto | 常规 | Tengine | Vue.js SPA | 算法工具链OpenExplorer |
| chat.oe.horizon.auto | 常规 | nginx+Envoy | Open WebUI 0.7.2 | 智能助手天工 |
| doc.oe.horizon.auto | 常规 | Tengine | 静态文档 | 文档中心 |
| autodiscover.horizon.auto | 常规 | feilian-agw | Exchange | 自动发现 |
| developer.d-robotics.cc | 常规 | Next.js | acw_tc(阿里云WAF) | 地瓜机器人开发者社区 |
| cn.horizon.cc | 常规 | nginx | →www.horizon.auto | 重定向 |
| www.horizon.auto | 常规 | Tengine | 官网 | 多IP(CDN) |

## 已确认漏洞

### 1. sso.iam.horizon.auto CORS反射型 [高危, 核心资产]
- **根因:** Authing SSO默认CORS配置反射任意Origin
- **验证:** curl -sk -D- "https://sso.iam.horizon.auto/login?app_id=67c91388afda6cf22fdbd93e" -H "Origin: https://evil.com"
- **响应:** Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true
- **影响范围:** /login, /api/v2/applications, /api/v2/roles, /api/v2/groups, /api/v2/resources, /api/v2/userpools
- **null Origin:** 同样反射 `Access-Control-Allow-Origin: null`
- **报告:** /tmp/vuln_reports/horizon/report-sso-cors.txt

### 2. chat.oe.horizon.auto Open WebUI配置泄露 [低危, 边缘资产]
- **端点:** GET /api/config (无需认证)
- **返回:** {"name":"Open WebUI","version":"0.7.2","oauth":{"providers":{"oidc":"地平线算法工具链官网"}},...}
- **CORS:** Access-Control-Allow-Origin: * + Credentials: true (浏览器阻止)
- **报告:** /tmp/vuln_reports/horizon/report-openwebui-config.txt

## 不建议提交的发现

| 发现 | 原因 |
|------|------|
| mail.horizon.auto Exchange OWA暴露 | 标准部署,版本15.1.2308.27无已知未修复CVE |
| developer.horizon.auto CORS:* | 仅HTML响应头有,API端点无CORS返回 |
| developer.horizon.auto /api/user/{uid}返回isFollow | 仅返回布尔值,无敏感数据 |
| developer.horizon.auto /api/_auth/session返回UUID | Nuxt.js标准会话行为,每次请求新UUID |
| developer.d-robotics.cc Next.js | 系统正常运行,无暴露 |
| Authing API "用户池不存在"错误 | 需认证上下文,非配置泄露 |
| app_id暴露在URL中 | Authing公开设计 |

## 待深挖方向
1. SSO Authing注册/登录后测试IDOR和用户枚举
2. Open WebUI WebSocket未授权连接测试
3. Exchange OWA ProxyShell等CVE验证
4. developer.horizon.auto用户帖子IDOR(/api/post?page=N)
5. oe.horizon.auto Vue.js SPA API端点深入分析

## 技术栈总结
- **身份认证:** Authing IDaaS (sso.iam.horizon.auto)
- **邮件:** Microsoft Exchange 15.1.2308.27 + feilian-agw (飞连零信任网关)
- **开发者社区:** Nuxt.js SSR + acw_tc (阿里云WAF)
- **AI助手:** Open WebUI 0.7.2 + Envoy proxy
- **算法工具链:** Vue.js SPA + Tengine
- **官网:** Tengine + 多IP CDN
- **CDN/防护:** 阿里云WAF (acw_tc), 飞连AGW (feilian-agw)
