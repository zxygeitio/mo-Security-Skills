# gxdlxy.com (广西电力职业技术学院) 测试记录 (2026-06-02)

## 目标概况
- 域名: gxdlxy.com
- IP: 111.59.245.69 (www), 116.252.81.203 (oa/idp/res), 116.252.81.205 (ids), 116.252.81.206 (mail)
- 子域名: 23个(subfinder)
- CMS: 博达CMS (主站, _sitegray/_sitegray.js 确认)
- CAS: 金智教育 wisedu CAS (ids.gxdlxy.com, _vesi cookie)
- VPN: Astraeus VPN (vpn.gxdlxy.com, /users/sign_in)
- WAF: rums/b反代 (敏感路径返回200+"访问禁止"HTML)

## 技术栈
- 主站: 博达CMS + jQuery (版本隐藏为"x.x.x")
- CAS: ids.gxdlxy.com/authserver/login — 金智教育 ycServer (wisedu minos), _vesi cookie, DEFAULT_SALT未找到
- 招聘系统: zp.gxdlxy.com — rsfw人事人才系统, JEE CGD (rums/b反代)
- 校友系统: xy.gxdlxy.com — Vue SPA, XSRF-TOKEN + new_api_session cookies
- VAC: vac.gxdlxy.com — Vue 3 + Vite SPA ("VAC安全控制系统")
- 招生就业: zsjy2006.gxdlxy.com — 静态HTML
- VPN: vpn.gxdlxy.com — Astraeus VPN, Ruby on Rails, _astraeus_session cookie

## 确认漏洞

### 1. [低危] 招聘系统CORS配置不当
- URL: https://zp.gxdlxy.com/rsfw/sys/zpglxt/extranet/index.do
- 响应头: Access-Control-Allow-Origin: *
- 所有请求(包括302重定向)均返回CORS *
- 无Access-Control-Allow-Credentials
- API返回HTML页面(非JSON), 无法跨域读取敏感数据
- **判定**: 低价值, 不建议单独提交

### 2. [低危] 招聘系统JSESSIONID URL泄露
- URL: https://zp.gxdlxy.com/rsfw/sys/zpglxt/extranet/index.do
- Cookie: JSESSIONID=RhSIPMc3MDusdbEBJIkogcz5LJN9HMcECN-Y_DIigq0Z7BzrSKf9!2006780114
- 同时Set-Cookie中path=/而非path=/rsfw/
- **判定**: 黑名单模式, 不建议提交

## 不建议提交的发现

### CAS系统
- 无Open Redirect (service参数不接受外部域名)
- 无pwdDefaultEncryptSalt泄露
- 无密码重置页面 (getBackPasswordMainPage.do → 空响应)
- Status端点返回401 (受保护)
- serviceValidate正常工作 (INVALID_TICKET响应)
- CORS: 仅OPTIONS预检反射(实际请求不返回CORS头)

### 博达CMS
- 搜索API: /_web/_search/api/search/new.rst → SPA页面(非JSON)
- DWR接口: /_dwr/test/ → SPA页面
- OpenApp: /_web/_openapp/api/app/list.rst → SPA页面
- jQuery版本隐藏为"x.x.x"

### 其他子域
- oa.gxdlxy.com → 无响应
- mail.gxdlxy.com → 无响应
- vac.gxdlxy.com → Vue SPA, 需登录
- xy.gxdlxy.com → Vue SPA, 需登录
- new.gxdlxy.com → 403 Forbidden
- xgc.gxdlxy.com → 403 Forbidden
- fwq.gxdlxy.com → 无响应
- opac.gxdlxy.com → 无响应

### WAF误报
- swagger-ui.html → "访问禁止" + 事件编号 (非真实暴露)
- 敏感路径返回200但body为WAF拦截页面

## 关键命令
```bash
# CAS登录页
curl -sk "http://ids.gxdlxy.com/authserver/login"

# CAS serviceValidate
curl -sk "http://ids.gxdlxy.com/authserver/serviceValidate?service=https://www.gxdlxy.com/&ticket=ST-FAKE"

# 招聘系统CORS
curl -sk -D- "https://zp.gxdlxy.com/rsfw/sys/zpglxt/extranet/index.do" | grep -i access-control

# 招聘系统JSESSIONID
curl -sk -D- "https://zp.gxdlxy.com/rsfw/sys/zpglxt/extranet/index.do" | grep -i jsessionid

# VPN指纹
curl -sk -D- "https://vpn.gxdlxy.com/users/sign_in" | head -10
```

## 停止条件
- CAS无Open Redirect, 无用户枚举, 无密码重置
- 招聘系统CORS * 但API返回HTML(非JSON), 无法跨域读取敏感数据
- 主站博达CMS搜索/DWR接口返回SPA页面
- 所有Vue SPA系统需登录
- **建议**: 除非发现新资产或新漏洞, 否则不建议继续投入
