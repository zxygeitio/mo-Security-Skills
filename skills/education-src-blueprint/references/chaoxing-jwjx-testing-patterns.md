# 超星(Chaoxing)教学管理系统指纹与测试

## 识别特征
- URL模式: `jwjx.{domain}` 或 `jw.{domain}`
- 重定向: 首页302到 `/wfw/manage`
- CAS集成: 重定向到 `sso.{domain}/cas/login?service=https://jwjx.{domain}/sso/login/3rd/{id}`
- CORS配置: `access-control-allow-origin: https://jwjx.{domain}`
- Session Cookie: `WFW_SESSION`
- Content-Security-Policy: `frame-ancestors 'self' https://i.chaoxing.com https://gxnulocal.jw.chaoxing.com`
- Server: nginx + tengine

## 系统架构
```
/                           - 首页 (302到/wfw/manage)
/wfw/manage                 - 管理页面 (需CAS认证)
/sso/login                  - SSO登录页面
/actuator                   - Spring Boot Actuator (通常403)
/actuator/health            - 健康检查 (通常403)
```

## CAS认证流程
1. 访问 `https://jwjx.{domain}/wfw/manage`
2. 302重定向到 `https://sso.{domain}/cas/logout?service=...`
3. CAS认证后回调 `https://jwjx.{domain}/sso/login/3rd/{id}`
4. 设置 `WFW_SESSION` cookie

## 漏洞模式

### 1. CORS配置测试
```bash
# 测试CORS是否反射Origin
curl -sk -H 'Origin: https://evil.com' 'https://jwjx.{domain}/sso/login' -D- | grep access-control
# 正确配置: access-control-allow-origin: https://jwjx.{domain}
# 错误配置: access-control-allow-origin: https://evil.com (漏洞)
```

### 2. Actuator端点测试
```bash
# 测试Spring Boot Actuator
curl -sk 'https://jwjx.{domain}/actuator' -o /dev/null -w '%{http_code}\n'
curl -sk 'https://jwjx.{domain}/actuator/health' -o /dev/null -w '%{http_code}\n'
# 通常返回403 (WAF拦截)
```

### 3. CAS认证绕过测试
```bash
# 测试直接访问管理页面
curl -sk 'https://jwjx.{domain}/wfw/manage' -D- | head -10
# 预期: 302重定向到CAS登录

# 测试SSO登录页面
curl -sk 'https://jwjx.{domain}/sso/login' | head -20
# 检查是否有错误信息泄露
```

## 实战案例

### gxnu.edu.cn (2026-06-09)
- 系统: jwjx.gxnu.edu.cn
- CAS: sso.gxnu.edu.cn/cas/login?service=https://jwjx.gxnu.edu.cn/sso/login/3rd/432
- CORS: access-control-allow-origin: https://jwjx.gxnu.edu.cn (正确配置)
- Actuator: 403 (WAF拦截)
- CSP: frame-ancestors 'self' https://i.chaoxing.com https://gxnulocal.jw.chaoxing.com

## 与其他教务系统的区别
| 系统 | 指纹 | 技术栈 |
|------|------|--------|
| 超星(Chaoxing) | jwjx.{domain}, WFW_SESSION | Java + CAS |
| 正方(ZFSOFT) | X-Powered-By: ZFSOFT-SERVER | Java + JSP |
| 强智(Qiangzhi) | /jwglxt/ | Java |
| 金智(Wisedu) | ehall.{domain} | Java + CAS |
