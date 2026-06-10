# 东华理工大学 ecut.edu.cn 测试记录 (2026-06-05)

## 目标概况
- 学校代码: 10405
- 地址: 江西省南昌市青山湖区广兰大道418号
- 子域名: 115个发现, 101个存活
- 真实IP: 202.101.244.16 (www), 202.101.245.225 (ehall/authserver)
- 防火墙: CERNET防火墙, 所有非HTTP端口filtered (21/22/25/80/110/143/443/445/993/995/1433/1521/3306/3389/5432/5900/6379/8080/8443 全部filtered)
- WAF/代理: Envoy + nginx反向代理

## 技术栈指纹

| 系统 | 子域 | 技术栈 | 备注 |
|------|------|--------|------|
| 主站 | www | SUDY WebPlus CMS + Envoy + nginx | jQuery + Slick |
| 办事大厅 | ehall | 金智教育平台 (openresty) | jQuery 3.4.1, 仅2个app |
| CAS | authserver | Wisedu CAS | login-wisedu_v1.0.js |
| OA | oa | 致远OA | 全部重定向到CAS, APISIX前置 |
| LIMS | yqgx | Yii 1.1.16 + PHP + nginx/1.14.1 | 大型仪器共享平台 |
| 邮件 | mail | 腾讯企业邮 (Wwebsvr) | 非Coremail |
| WebVPN | webvpn | 统一身份认证 | Java + OpenResty |
| 校友网 | xyh | usho.cn/sosho.cn SaaS | .git/HEAD 403 (存在但被拦截) |
| IDP | idp | Shibboleth IdP | nginx/1.14.1, 标准元数据公开 |
| VPN | atrust1 | Sangine aTrust 2.0 | Loading... SPA |
| 二级学院 | 50+ | Envoy + nginx + jQuery | 静态站点为主 |

## 确认漏洞

### 1. yqgx.ecut.edu.cn LIMS系统敏感文件暴露 [中危]

**application.log 公开访问:**
```bash
curl -sk 'https://yqgx.ecut.edu.cn/protected/runtime/application.log'
# 200 OK, 3154 bytes
# 泄露: /home/wwwroot/lims/, Yii 1.1.16, DdpSevCommand, LimsConsoleCommand, AMQP/RabbitMQ
```

**PHP源代码路径泄露(多文件):**
```bash
curl -sk 'https://yqgx.ecut.edu.cn/protected/yiic.php'         # Warning: /home/wwwroot/lims/protected/yiic.php
curl -sk 'https://yqgx.ecut.edu.cn/protected/controllers/SiteController.php'   # Fatal: Class 'Controller' not found
curl -sk 'https://yqgx.ecut.edu.cn/protected/controllers/UserController.php'   # Fatal: Class 'CController' not found
curl -sk 'https://yqgx.ecut.edu.cn/protected/commands/DdpSevCommand.php'       # Fatal: Class 'LimsConsoleCommand' not found
curl -sk 'https://yqgx.ecut.edu.cn/protected/components/UserIdentity.php'      # Fatal: Class 'CUserIdentity' not found
```

**配置文件返回200但空body:**
```bash
curl -sk 'https://yqgx.ecut.edu.cn/protected/config/main.php'    # 200, 0 bytes
curl -sk 'https://yqgx.ecut.edu.cn/protected/config/db.php'       # 200, 0 bytes
curl -sk 'https://yqgx.ecut.edu.cn/protected/config/console.php'  # 200, 0 bytes
```

**yqgx攻击面评估:**
- 登录: /login.html → POST /lfsms/user/logindata (LfsmsLoginForm[username/password/captcha])
- 注册: /register.html → POST /register.html (Tuser[LoginName/nPassword/password_repeat/FirstName/LastName/Email1/MobilePhone1/Position/OrgID/CodeVerify])
- 验证码: /lfsms/user/captcha?refresh=1 → JSON {hash1, hash2, url}
- SQL注入: cid参数无注入(布尔/时间/联合均无差异)
- XSS: HTML转义,不可利用
- 路径遍历: 400 Bad Request
- /protected/config/ 目录: 403
- /protected/runtime/ 目录: 403 (但application.log直接访问200)
- Gii代码生成器: /gii → 403 (存在但被保护)

### 2. CAS密码加密盐值泄露 [低危]

```bash
curl -sk 'https://authserver.ecut.edu.cn/authserver/login' | grep -oP 'pwdDefaultEncryptSalt.*?"'
# var pwdDefaultEncryptSalt = "M4Dd0gYbKUQOsGTf";
# id="dynamicPwdEncryptSalt" value="wAj2LvKyXAtUyNBb"
```

### 3. CAS needCaptcha用户枚举 [低危]

```bash
curl -sk 'https://authserver.ecut.edu.cn/authserver/needCaptcha.html?username=admin'
# 返回: true (admin存在,需要验证码)

curl -sk 'https://authserver.ecut.edu.cn/authserver/needCaptcha.html?username=test'
# 返回: false (其他用户名)
```

**⚠️ 限制**: 仅admin返回true, 其他所有测试用户名(administrator/root/test/guest/student/teacher/20210001-20250001等)均返回false。枚举价值极低。

### 4. ehall JSONP配置信息泄露 [低危]

```bash
curl -sk 'https://ehall.ecut.edu.cn/jsonp/school.json'
# 泄露: schoolId=10405, ehallTitle, role_data, footer

curl -sk 'https://ehall.ecut.edu.cn/jsonp/serviceCenterData.json?searchKey=&containLabels=true'
# 泄露: 仅2个app (软件正版化平台 + 研究生-学生选课应用)

curl -sk 'https://ehall.ecut.edu.cn/jsonp/userInfo.json'
# 泄露: guest站点结构, menuList, siteId

curl -sk 'https://ehall.ecut.edu.cn/jsonp/appIntroduction.json?appId=7046948748214521'
# 泄露: app配置信息(非PII)
```

## 关键测试结果

### CAS服务白名单验证
- 直接外部域名(evil.com/google.com/baidu.com) → BLOCKED ("应用未注册 不允许使用认证服务")
- ECUT子域名(ehall/oa/mail/lib/jwc/www/webvpn/news/xyh/nic) → ALLOWED
- 嵌套URL(service=https://ehall.ecut.edu.cn/callback?redirect=https://evil.com) → CAS接受,嵌入form action
- ehall处理redirect参数 → 仅内部重定向(/?redirect=X → /new/index.html?redirect=X), 不执行外部重定向
- **结论: 无CAS开放重定向漏洞**

### ehall API端点分类
- /jsonp/* (无认证): school.json, serviceCenterData.json, userInfo.json, appIntroduction.json → 仅返回配置数据, 无PII
- /publicapp/* (需认证): serviceCenter/getServiceList, taskcenter/getTaskList等 → 302到CAS
- /taskcenterapp/* (需认证): lwReportEp498/swpubapp/emappagelog/wdtz/xjgl/jxkhapp → 302到CAS
- /feedbackUpload (需认证): GET/POST均302到CAS
- /psfw/ /rsfw/ /gsapp/ (需认证): 均302到CAS

### 致远OA状态
- /seeyon/index.jsp → 302到CAS
- /seeyon/management/index.jsp → 302到CAS
- /seeyon/rest/token/* /rest/authentication/* → 404
- /seeyon/thirdpartyController.do /wpsAssistServlet /htmlofficeservlet → 404
- /seeyon/test123456.jsp → 302到CAS
- **已修补,无可用CVE路径**

### 邮件系统
- Server: Wwebsvr (腾讯企业邮)
- /coremail/* → 404 (非Coremail)
- 无用户枚举入口

### SUDY CMS
- 主站(news/jwc)从测试环境不可达(curl exit 7)
- 二级学院站点均使用Envoy代理, 静态内容为主

## 不建议提交的发现(黑名单模式)

| 发现 | 原因 |
|------|------|
| CAS pwdDefaultEncryptSalt泄露 | 每会话轮转, 教育SRC黑名单 |
| CAS needCaptcha仅admin=true | 枚举价值极低 |
| ehall JSONP配置数据 | 返回配置非PII, 教育SRC不收 |
| yqgx Yii 1.1.16版本 | 纯版本信息泄露 |
| yqgx nginx/1.14.1版本 | 纯版本信息泄露 |
| CAS嵌套URL参数保留 | ehall不执行外部重定向 |
| xyh .git/HEAD 403 | 存在但被nginx拦截 |
| IDP Shibboleth元数据 | 公开标准设计 |

## 教训

1. **CAS白名单测试方法**: 不能仅检查response中是否包含"password"(错误页面模板可能包含)。必须同时检查: has_login_form AND NOT has_error("未注册"/"不允许")。
2. **ehall JSONP vs publicapp**: /jsonp/* 返回配置数据(无认证), /publicapp/* 返回业务数据(需认证)。不要混淆。
3. **CERNET防火墙**: 对202.x.x.x IP, nmap端口扫描全部filtered, 不要浪费时间。
4. **金智教育ehall appId枚举**: 搜索关键词返回的app数量可能很少(如ECUT仅2个), 不要假设所有学校都有大量app。
5. **CAS needCaptcha**: 不同学校行为不同。ECUT仅admin返回true。需要用已知有效的用户名验证。
