# Sangfor SSL VPN M7.6.8R2 端点清单

## 无需认证可访问

### /por/login_auth.csp (200, ~2432 bytes)
- 用途: 登录初始化/版本指纹
- 泄露: VPNVERSION, RSA公钥, CSRF, 配置标志
- 注入: 无
- curl: `curl -sk 'https://TARGET/por/login_auth.csp'`

### /por/login_psw.csp (302→200)
- 用途: 登录 POST
- 参数: svpn_name, svpn_password, svpn_rand_code, CSRF_RAND_CODE
- Cookie: TWFID (从 login_auth 获取)
- curl: `curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' -b "TWFID=XXX" --data 'svpn_name=test&svpn_password=test&svpn_rand_code=&CSRF_RAND_CODE=XXX' 'https://TARGET/por/login_psw.csp?type=cs'`

### /por/ec_pkg.csp (200, ~715 bytes)
- 用途: 客户端包版本信息
- 泄露: Mac/Linux 客户端版本, alias
- curl: `curl -sk 'https://TARGET/por/ec_pkg.csp'`

### /por/index.csp (200, ~7421 bytes)
- 用途: 主页
- 内容: JavaScript 重定向逻辑
- curl: `curl -sk 'https://TARGET/por/index.csp'`

### /por/changepwd.csp (200, ~140 bytes)
- 用途: 密码修改 (集群模式)
- 正常响应: `<ErrorCode>20026</ErrorCode> "unexpected user service"`
- WAF: 拦截 `sessReq=clusterd` (小写精确匹配) → 404
- 绕过: Clusterd/CLUSTERD/空格前缀/Tab前缀 → 200
- curl: `curl -sk 'https://TARGET/por/changepwd.csp'`

### /por/changetelnum.csp (200, ~3 bytes)
- 用途: 绑定手机修改 (集群模式)
- 响应码: "3" (需加密参数) / "6" (解密失败)
- WAF: 不拦截 clusterd
- curl: `curl -sk 'https://TARGET/por/changetelnum.csp?sessReq=clusterd&sessid=0&username=test&grpid=0&newtel=13800138000&ip=127.0.0.1'`

### /por/balance_update.csp (200, ~1 byte)
- 用途: 余额/配额更新
- 响应: "0" (所有参数组合)
- 注入: 无 (pipe/backtick/$() 均返回 "0", 分号返回 404)
- curl: `curl -sk 'https://TARGET/por/balance_update.csp?rcname=test'`

### /por/webfs.csp (200, ~289 bytes)
- 用途: Web 文件系统
- 响应: 重定向到 logout.csp (需认证)
- curl: `curl -sk 'https://TARGET/por/webfs.csp'`

### /por/clusterdSync.csp (200, ~48 bytes)
- 用途: 集群同步
- 响应: `<?xml version="1.0" encoding="utf-8"?><Auth />`
- GET/POST/JSON 均需认证
- curl: `curl -sk 'https://TARGET/por/clusterdSync.csp?cmd=id'`

### /com/installClient.html (200, ~8161 bytes)
- 用途: 客户端安装页
- curl: `curl -sk 'https://TARGET/com/installClient.html'`

### /web/1/http/0/ (403, ~1363 bytes)
- 用途: Web 代理 (SSL VPN 资源代理)
- 状态: 存在但需认证
- SSRF: XFF 绕过无效
- curl: `curl -sk 'https://TARGET/web/1/http/0/127.0.0.1/'`

## 全部 404 (M7.6.8R2 已移除)

```
/por/checkurl.csp
/cgi-bin/php-cgi/html/svpn.php
/cgi-bin/php-cgi/html/daemon/tsproxy.php
/cgi-bin/php-cgi/html/delegatemodule/WebApi.php
/cgi-bin/php-cgi/html/delegatemodule/HttpHandler.php
/admin/
/local/
/prx/
/svpn/
/appSsoApi.php
```

## 管理端口 (全部不可达)

```
4430, 4431, 4443, 8080, 8443, 8118(SSL握手失败), 9443, 60443
```
