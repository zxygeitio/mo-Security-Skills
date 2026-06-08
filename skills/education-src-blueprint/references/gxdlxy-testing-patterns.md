# gxdlxy.com (广西电力职业技术学院) 测试记录

## 测试日期: 2026-06-02

## 目标概况
- 主站: www.gxdlxy.com (博达CMS Visual SiteBuilder, 111.59.245.69)
- CAS: ids.gxdlxy.com/authserver/login (金智教育 wisedu, theme: gxdlxydTheme8)
- 招聘系统: zp.gxdlxy.com (rums/b反代)
- VPN: vpn.gxdlxy.com (Astraeus VPN)
- 校友系统: xy.gxdlxy.com (Vue.js SPA)
- VAC: vac.gxdlxy.com (Vue.js SPA, Vite构建)
- OA: oa.gxdlxy.com (116.252.81.203, 端口80/443)
- Mail: mail.gxdlxy.com (116.252.81.206)
- IDS: ids.gxdlxy.com (116.252.81.205)
- 资源: res.gxdlxy.com (116.252.81.203)

## 关键发现

### 1. CAS DEFAULT_SALT泄露 (低危)
- 位置: `/authserver/gxdlxydTheme8/static/web/js/login.js`
- 值: `var DEFAULT_SALT = "rjBFAaHsNkKAhpoi";`
- 加密方式: AES-CBC + PKCS7, 使用encrypt.js
- 注意: 属于黑名单模式(pwdDefaultEncryptSalt泄露), 通过率低

### 2. CAS tenant/info配置泄露 (低危)
- 端点: `/authserver/tenant/info`
- 返回: themeName, schoolLogoUrl等配置信息
- 无需认证

### 3. 招聘系统CORS配置不当 (低危)
- zp.gxdlxy.com 所有响应返回 Access-Control-Allow-Origin: *
- 包括外网入口 `/rsfw/sys/zpglxt/extranet/index.do`
- 使用JSESSIONID + _WEU cookie

### 4. 招聘系统JSESSIONID URL泄露 (低危)
- 响应头: Set-Cookie: JSESSIONID=...; path=/; HttpOnly

### 5. WAF拦截模式
- openresty WAF对敏感路径返回HTTP 200 + "访问禁止"HTML
- 拦截路径: /actuator/env, /actuator/health, /swagger-ui.html
- XFF绕过无效
- 事件编号格式: 202606022460005245

## 不建议提交
- CAS DEFAULT_SALT泄露 (黑名单模式, 属于pwdDefaultEncryptSalt泄露)
- CAS tenant/info配置泄露 (公开设计)
- 招聘系统CORS (API返回HTML页面, 无敏感数据)
- JSESSIONID URL泄露 (黑名单模式)

## 测试命令
```bash
# CAS DEFAULT_SALT
curl -sk "http://ids.gxdlxy.com/authserver/gxdlxydTheme8/static/web/js/login.js?v=20250411.074631" | grep 'DEFAULT_SALT'

# CAS tenant/info
curl -sk "http://ids.gxdlxy.com/authserver/tenant/info"

# 招聘系统CORS
curl -sk -D- "https://zp.gxdlxy.com/rsfw/sys/zpglxt/extranet/index.do" -H "Origin: https://evil.com" | grep -i access-control

# CAS actuator (WAF拦截)
curl -sk "http://ids.gxdlxy.com/authserver/actuator/env" | head -3
# 返回: <TITLE>访问禁止</TITLE>
```
