# T3出行SRC深度测试补充 (2026-06-08)

## 防护体系画像

### 腾讯云WAF (stgw) 完整拦截规则
- actuator/swagger/api-docs/graphql → 218
- CRLF注入 (%0d%0a) → 218
- 路径遍历 (../) → 218
- open redirect (redirect=evil.com) → 218
- HTTP Request Smuggling (CL.TE) → 400
- GraphQL introspection (__schema) → 218
- IP封禁: ~25请求后触发，约30分钟解封
- User-Agent轮换无效

### OAuth服务降级状态 (2026-06-08)
getKey全线返回500。password端点正常但无法获取AES密钥。
客户端凭据仍有效(4100≠4114)。

## DNS解析
所有域名 → gtm-waf.t3go.cn → 多IP
直接IP访问(Host头): 全部404

## gateway路由活跃状态 (2026-06-08)
4100(有后端): strategy-gateway-api, driver-core-app-api, gis-map-api, driver-app-api, pay-center-api, mall-app-api, solution-carriage
"no Route matched": cua-user-api-c, enterprise-app-api, solution-passenger-api, solution-trip-general, common-app-api, strategy-config

## 已验证不可行的攻击向量
HTTP Smuggling/缓存投毒/SSRF/路径遍历/CRLF/GraphQL/WebSocket/h2c/直接IP → 全部被WAF拦截或不支持
