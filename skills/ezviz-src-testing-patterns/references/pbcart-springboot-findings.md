# pbcart.ys7.com Spring Boot发现 (2026-05-14)

## 服务信息
- 域名: pbcart.ys7.com
- 框架: Spring Boot + Eureka服务发现
- 服务名: mallcartfrontservice (购物车前端服务)
- 版本: 2.1.0.0
- Git提交: 27aa832 (2020-08-01)
- 分支: master

## 暴露端点

### /info (信息泄露)
```json
{
  "description": "mallcartfrontservice",
  "version": "2.1.0.0",
  "name": "mallcartfrontservice",
  "contact": "welcome to mallcartfrontservice",
  "git": {
    "commit": {"time": "2020-08-01T13:48:24Z", "id": "27aa832"},
    "branch": "master"
  }
}
```

### /health (服务发现泄露)
```json
{
  "description": "Remote status from Eureka server",
  "status": "DOWN"
}
```

### /swagger-ui.html (API文档暴露)
- 状态码: 200
- 大小: 3246字节
- 使用: springfox-swagger-ui

## CORS配置缺陷
```
Access-Control-Allow-Origin: https://evil.com (反射任意Origin)
Access-Control-Allow-Credentials: true
set-cookie: JSESSIONID=...; Path=/; HttpOnly
```

## 验证命令
```bash
# 信息泄露
curl -sk "https://pbcart.ys7.com/info"
curl -sk "https://pbcart.ys7.com/health"

# Swagger UI
curl -sk -o /dev/null -w "%{http_code}:%{size_download}" "https://pbcart.ys7.com/swagger-ui.html"

# CORS验证
curl -sk -D- "https://pbcart.ys7.com/" -H "Origin: https://evil.com"
```

## SRC提交状态
- 信息泄露: 被忽略（SRC认为无实质危害）
- CORS缺陷: 被忽略（SRC认为无实质危害）
- Swagger UI: 被忽略（SRC认为无实质危害）

## 教训
Spring Boot /info 和 /health 端点泄露的信息虽然有价值，但SRC认为不足以构成漏洞。需要找到更严重的漏洞（如RCE、SQL注入、越权访问）才能被接受。
