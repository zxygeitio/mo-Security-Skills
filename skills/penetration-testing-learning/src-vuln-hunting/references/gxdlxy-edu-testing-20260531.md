# 广西电力职业技术学院 (gxdlxy.com) SRC测试记录

## 目标概况
- 主站: www.gxdlxy.com (111.59.245.69) - 访问禁止, rums/b反代, IIS 6.0
- CAS: ids.vpn.gxdlxy.com - ycServer 7.2.1.SP4 (金智教育), openresty反代
- WebVPN: vpn.gxdlxy.com (111.59.245.68) - Ruby on Rails, Astraeus VPN
- 子域名: 23个, 多数指向 116.252.81.203/204 (广西联通)
- 证书: *.gxdlxy.com 通配符

## 子域名资产
```
116.252.81.203: oa, new, xy, my, opac, dlgc, zp, xgc, jz, autocar, mea, dzx, donglgc, glgcx, xy2006, zsjy2006
116.252.81.204: vac
116.252.81.206: mail
111.59.245.69:  www (主站)
111.59.245.68:  vpn
ids.vpn.gxdlxy.com: CAS服务器 (DNS未直接解析, 通过vpn.gxdlxy.com重定向发现)
```

## CAS重定向链追踪
```
vpn.gxdlxy.com/users/auth/cas
  → 302 → ids.vpn.gxdlxy.com/authserver/login?service=https://vpn.gxdlxy.com/users/auth/cas/callback?url
  → 200 (CAS登录页, JSESSIONID, _vesi cookies)
```
关键: CAS服务器域名不在subfinder结果中, 需通过WebVPN重定向链发现

## 确认的漏洞

### 1. CAS CORS配置错误 (中危)
所有CAS OPTIONS响应反射任意Origin + credentials:true
```bash
curl -sk -X OPTIONS -H 'Origin: https://attacker.com' -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: Authorization' \
  'https://ids.vpn.gxdlxy.com/authserver/tenant/info' -I
```
受影响: /authserver/login, /authserver/tenant/info, /authserver/serviceValidate

### 2. CAS Open Redirect (中危)
service参数接受嵌套恶意URL:
```bash
curl -sk 'https://ids.vpn.gxdlxy.com/authserver/login?service=https%3A%2F%2Fvpn.gxdlxy.com%2Fusers%2Fauth%2Fcas%2Fcallback%3Furl%3Dhttps%253A%252F%252Fevil.com' | grep 'var service'
# 输出: var service = ["https:\/\/vpn.gxdlxy.com\/users\/auth\/cas\/callback?url=https%3A%2F%2Fevil.com"];
```

### 3. 硬编码加密盐值 (低危)
login.js中: `var DEFAULT_SALT = "rjBFAaHsNkKAhpoi";`

## 排除的误报
- Druid监控: 路径返回200但内容是自定义错误页"请求不合法"
- SSRF via callback: 重定向到登录页, 未实际请求内部服务
- SMS轰炸: checkNeedCaptcha返回false但服务端仍强制验证码
- WebVPN /go: 未认证时重定向到登录页, 非开放重定向
- QR码登录: 前端QR_LOGIN_ENABLED=0, 后端API存在但无法完成登录

## 报告
- /tmp/vuln_reports/gxdlxy/report-1-cas-cors-openredirect.txt
- /tmp/vuln_reports/gxdlxy/report-2-cas-open-redirect.txt
- /tmp/vuln_reports/gxdlxy/report-3-hardcoded-salt.txt
