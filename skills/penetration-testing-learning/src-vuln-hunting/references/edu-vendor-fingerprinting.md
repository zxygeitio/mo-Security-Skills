# 教育系统供应商指纹识别方法

## 目的
大学网站的子系统(教务、一站式大厅、CAS、一卡通、迎新)通常由第三方公司开发。识别供应商可定位同源漏洞。

## 方法1: 前端框架指纹
检查 portal/ehall/CAS 系统的 JS 文件:
```bash
curl -s "https://<target>/js/main.*.js" | grep -oiP '(诚勤|树维|金智|强智|正方|青果|URP|金智教育|ycServer|SWUI|sw-ui)' | sort -u
curl -s "https://<target>/cas/deps/js/sw-ui/lib/index.js" | head -5  # 检查SWUI框架
```

## 方法2: CAS登录页指纹
```bash
# 检查CAS系统使用的UI框架和技术栈
curl -s "https://cas.<domain>/cas/login" -k | grep -oP 'src="[^"]*"' 
# sw-ui = 树维信息(CAS领域常见)
# vant = 移动端Vue组件库
```

## 方法3: 页面底部版权/技术支持
```bash
curl -s "https://<target>" | grep -iP '技术支持|copyright|©|developed|powered|诚勤|树维|金智'
```

## 方法4: 子域名发现
```bash
curl -s "https://api.hackertarget.com/hostsearch/?q=<domain>" | grep -iE "portal|oa|jw|card|ehall|yx|lx|hall|service|cas|sso"
```

## 已知供应商指纹
| 指纹 | 供应商 | 产品 |
|------|--------|------|
| SWUI / sw-ui | 树维信息 | CAS/一站式服务大厅 |
| 树维信息 | 树维信息 | 导航标题JS变量 |
| ycServer | 金智教育 | CAS SSO |
| AMP / AMPConfigure | 金智教育 | ehall网上办事大厅 |
| yunjingedu.com | 云景教育 | APM监控(嵌入ehall页面) |
| campusphere.cn | 正方软件 | CSP安全策略引用 |
| rump/c | 自定义 | 静态CMS主站服务器 |
| sudyNavi / sudy_wp | SUDY/博达 | 网站群CMS (WebPlus) |
| 强智 | 湖南强智 | 教务系统 |
| 正方 | 杭州正方 | 教务系统 |
| 青果 | 青果软件 | 教务系统 |
| URP | 金智教育 | 统一资源平台 |
| ecology_JSessionid | 泛微网络 | E-Cology OA协同办公 |
| _wev8 | 泛微网络 | JS/CSS文件后缀(如jquery_wev8.js) |
| /wui/index.html | 泛微网络 | E-Cology 9 SPA入口 |
| /cloudstore/resource/pc/ | 泛微网络 | E-Cology 9 前端资源 |
| Server: VWebServer/* | 博达软件 | Visual SiteBuilder CMS |
| CustomerNO: [hex] | 博达软件 | HTML注释中的客户编号 |
| _sitegray/_sitegray.js | 博达软件 | 博达CMS特征目录 |
| _dwr/engine.js | 博达软件 | DWR框架(博达CMS常用) |
| /system/resource/js/ajax.js | 博达软件 | 博达CMS AJAX库 |
| /system/resource/code/datainput.jsp | 博达软件 | 访问统计(历史SQLi) |
| Server: China Webber /* | 博达软件 | China Webber CMS |

## 金智教育 AMP ehall 平台指纹
```bash
# school.json配置文件(无需认证)
curl -sk 'https://ehall.<domain>/jsonp/school.json'

# school.js配置文件(无需认证)
curl -sk 'https://ehall.<domain>/portal/custom/conf/school.js'
```

### 关键泄露字段
- `schoolId`: 教育部高校代码
- `personalCenterAuthserverUrl`: CAS认证地址
- `footer.normal`: 版权信息含供应商名("江苏金智教育信息股份有限公司 苏ICP备10204514号")
- `role_data`: 角色定义(学生/教师/游客)
- 云景APM: `s.yunjingedu.com/apm/1.0/browser.min.js` 嵌入所有ehall页面

### ehall常见端点
```
/portal/custom/conf/school.js    # 学校配置(200)
/jsonp/school.json                # 学校配置JSON(200)
/new/index.html                   # 主页(200)
/publicapp/sys/emapfunauth/casValidate.do  # CAS验证(302→登录)
/publicapp/sys/publinkapp/publinkAppList.do
/publicapp/sys/common/getSchoolConfig.do
/publicapp/sys/sms/messageSmsApi/sendMessage.do  # SMS接口
```

### CORS特征
ehall返回 `Access-Control-Allow-Credentials: true` 但不反射任意Origin(安全)。
允许Headers含 `token` 表示使用Token认证。

## 金智教育 CAS 指纹
```bash
# 检测JS文件名
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'login-wisedu[^"]*\.js'

# 检测密码加密密钥
curl -sk 'https://authserver.<domain>/authserver/login' | grep -oP 'pwdDefaultEncryptSalt\s*=\s*"\K[^"]+'

# 检测Ticket注册表
curl -sk 'https://authserver.<domain>/authserver/status' | grep -oP 'Ticket registry \K[^\s]+'
```

### 关键指纹
- JS文件: `login-wisedu_v1.0.js`
- 变量: `pwdDefaultEncryptSalt`, `dynamicPwdEncryptSalt`
- 路径: `/authserver/login` (标准Apereo CAS路径)
- Ticket注册表: `com.wisedu.authserver.ticket.registry.CacheTicketRegistry`
- 表单字段: `dllt=userNamePasswordLogin|dynamicLogin|qrLogin`

## 南京诚勤教育科技有限公司
- 官网: chengqinedu.com (无法访问)
- 产品: 教育管理系统(具体产品名待确认)
- 关联: 可能与树维信息有关联(待验证)
- 已知客户: 巴音郭楞职业技术学院(portal.xjbyxy.cn)、中国科学院大学、中国地质大学(待确认)

## BladeX框架指纹识别 (2026-06 tsinghua.edu.cn)

BladeX是中国企业级Java快速开发框架，常见于高校管理系统。

### 指纹特征
```bash
# Vue.js SPA页面底部版权
curl -sk 'https://target/' | grep -i "bladex.vip"

# JS中window._CONFIG对象
curl -sk 'https://target/' | grep -o "window._CONFIG"

# API端点模式 /api/blade-*
curl -sk 'https://target/api/blade-auth/oauth/token' -o /dev/null -w '%{http_code}'
# 返回401 = BladeX确认

# CSS/JS文件命名模式
curl -sk 'https://target/' | grep -oP 'src="[^"]*chunk-[^"]*\.js"'
```

### 关键端点
```
/api/blade-auth/oauth/token        # OAuth2 Token (POST)
/api/blade-auth/oauth/token-key    # Token公钥 (GET, 可能404)
/api/blade-auth/oauth/captcha      # 验证码 (GET, 无需认证, 返回key+base64图片)
/api/blade-auth/oauth/user-info    # 用户信息 (需认证)
/api/blade-system/menu/list        # 菜单列表 (需认证)
/api/blade-system/dict/list        # 字典列表 (需认证)
/api/blade-system/dept/list        # 部门列表 (需认证)
/api/blade-system/tenant/list      # 租户列表 (需认证)
/api/blade-develop/code/list       # 代码生成 (需认证, 开发功能)
/api/blade-develop/datasource/list # 数据源 (需认证, 高危)
/api/blade-resource/oss/endpoint/put-file  # 文件上传
/doc.html                          # Swagger文档 (可能暴露)
/swagger-ui.html                   # Swagger UI (可能暴露)
```

### 认证机制
- OAuth2 Password Grant: POST /api/blade-auth/oauth/token
- Token存储: Cookie `saber-access-token` 和 `saber-refresh-token`
- 验证码: /api/blade-auth/oauth/captcha 返回 `{key, image(base64)}`

### 信息泄露点
- JS注释中可能包含内部IP地址 (如开发环境配置)
- window._CONFIG对象可能包含API地址、地图Key等
- Baidu Maps/Amap API Key常嵌入页面

### 已知客户
- 清华大学 dtms.civil.tsinghua.edu.cn (数字孪生基坑监测平台)

## SM2国密加密指纹 (2026-06 tsinghua.edu.cn)

部分高校SSO系统使用SM2国密算法加密密码传输。

### 指纹特征
```bash
# 登录页面中SM2公钥
curl -sk 'https://sso.target/login' | grep -oP 'sm2publicKey.*?>([^<]+)<' | head -1

# SM2加密JS库
curl -sk 'https://sso.target/v2/dist/doubleauth/sm2Util.js' | head -5
```

### 关键特征
- 公钥格式: `04` + 128位十六进制 (64字节X + 64字节Y)
- 隐藏字段: `<div id="sm2publicKey">04xxxx...</div>`
- 加密流程: sm2Util.doEncryptStr(password, publicKey)
- 表单提交: `<input type="hidden" id="sm2pass" name="password">`

### 测试要点
- SM2公钥泄露本身不构成漏洞(非对称加密公钥可公开)
- 但可确认密码传输使用SM2加密，需配合CAS端点测试
- 关注验证码端点 `/do/off/ui/auth/login/captcha/{captcha}/check`

### 已知使用
- 清华大学 sso.tsinghua.edu.cn / id.tsinghua.edu.cn

## 常见教育系统子域名
- portal.<domain> - 一站式服务大厅
- cas.<domain> / sep.<domain> - CAS单点登录
- ehall.<domain> - 网上办事大厅
- card.<domain> - 一卡通系统
- jw.<domain> / jwc.<domain> - 教务系统
- oa.<domain> - OA办公系统
- fuwu.<domain> - 泛微OA服务(常见)

## SUDY WebPlus CMS 指纹识别 (2026-06 南京医科大学康达学院)

SUDY（树维/苏迪）WebPlus CMS 是高校常用建站平台，支持多站点(siteId)架构。

### 指纹特征
```bash
# JS/CSS文件含sudy关键字
curl -sk 'https://<target>/' | grep -i 'sudy'
# 匹配: sudyNavi/css/sudyNav.css, jquery.sudy.wp.visitcount.js, jquery.sudyNav.js

# siteId标识
curl -sk 'https://<target>/' | grep -oP 'sudy-wp-siteId="\K[^"]+'

# 响应头Server隐藏
curl -sk -D- 'https://<target>/' | grep -i 'Server: \*'
```

### 关键端点
```
/_web/_ids/login/api/login/create.rst     # IDS登录API (POST, 返回{"status":0})
/_web/_ids/login/api/logout/create.rst    # IDS登出API
/_web/_portal/api/user/main.psp           # Portal用户API (⚠️ 可能泄露服务器IP)
/_web/_portal/api/login/main.psp          # Portal登录API
/_web/_portal/api/config/main.psp         # Portal配置API
/_web/_portal/api/system/main.psp         # Portal系统API
/_web/_search/api/search/new.rst          # 搜索API (⚠️ 特殊字符可触发堆栈跟踪)
/_web/_upload/main.psp                    # 文件上传 (需认证)
/_admin/login.jsp                         # 后台登录 (403)
/_admin/user/main.psp                     # 用户管理 (需认证)
/_admin/config/main.psp                   # 配置管理 (需认证)
```

### 已知漏洞模式
1. **IP泄露**: `/_web/_portal/api/user/main.psp` 返回HTML含 `<input id="ipAddress" value="<真实IP>"/>`
   - 影响所有同siteId架构的子域名
   - PoC: `curl -sk "https://<target>/_web/_portal/api/user/main.psp" | grep -oP 'value="[^"]*"'`
2. **Tomcat堆栈跟踪泄露**: 搜索接口传入URL编码XSS标签触发
   - PoC: `curl -sk "https://<target>/_web/_search/api/search/new.rst?keyword=%3Cscript%3Ealert(1)%3C/script%3E" | grep -c "exception\|tomcat"`
   - 泄露: Tomcat版本、Java类名、内部路径、完整调用链
3. **多站点枚举**: 不同子域名共享同一服务器，siteId不同但IP泄露相同

### 多站点发现

### 金智ehall未认证API端点 (信息泄露)
```bash
# 站点配置 (schoolId, authserverUrl, 角色列表)
curl -sk 'http://ehall.<domain>/jsonp/school.json'

# 服务列表 (appId, appName, appKey, version)
curl -sk 'http://ehall.<domain>/jsonp/serviceCenterData.json'

# 用户信息 (站点结构, 菜单, hasLogin=false)
curl -sk 'http://ehall.<domain>/jsonp/userInfo.json'

# 推荐服务 (根据角色返回)
curl -sk 'http://ehall.<domain>/jsonp/serviceRoleApp.json?serviceRoleId=1__0'
```
**泄露内容**: schoolId, authserverUrl, appId+appKey, 角色列表, 站点ID+菜单
**注意**: 返回公开配置信息，不含用户敏感数据(低危); appKey可用于后续API探测
SUDY CMS的siteId从JS中提取，可用于关联子域名：
```bash
for sub in www kdclib kdjw kdxg kdtw kdjjjc kdgh; do
  echo -n "$sub: siteId="
  curl -sk "https://$sub.<domain>/" | grep -oP 'sudy-wp-siteId="\K[^"]+' | head -1
done
```

### 质量门禁陷阱
`src-http-probe.py` 的 control 探测会将 `/_web/_portal/api/user/main.psp` 判为 LOGIN_OR_AUTH_REQUIRED（假阴性），因为该端点在未认证时返回"提示信息"HTML页面。但实际手动curl可以获取IP泄露。验证此漏洞必须手动curl确认，不能依赖自动化probe结果。

## 泛微OA (Weaver E-Cology) 指纹识别

### 指纹特征
```bash
# Cookie特征
curl -sk -I 'https://<target>/' | grep -i 'ecology_JSessionid'

# JS文件后缀 _wev8
curl -sk 'https://<target>/' | grep -oP 'src="[^"]*_wev8[^"]*"' | head -3

# SPA入口
curl -sk 'https://<target>/wui/index.html' | head -5

# 云资源路径
curl -sk 'https://<target>/' | grep -oP '/cloudstore/resource/[^"]*'
```

### 版本识别
- **E-Cology 9**: React SPA, `/cloudstore/resource/pc/`, `_wev8` 后缀
- **E-Cology 8**: jQuery, `/wui/` 路径, `_wev8` 后缀
- **E-Weaver**: 新版微服务架构

### 常见子域名
- `fuwu.<domain>` - 泛微OA服务
- `oa.<domain>` - OA系统
- `workflow.<domain>` - 工作流系统

### API端点
```
/api/login/verifyCode        # 验证码
/api/login/checkLogin        # 登录检查
/api/hrm/ssologin            # HR SSO登录
/api/hrm/getPassword         # 密码获取
/api/ec/devMode/check        # 开发模式检查
/api/portal/login            # 门户登录
/api/workflow/               # 工作流API
/api/doc/                    # 文档API
/api/user/                   # 用户API
/api/system/info             # 系统信息
/wui/index.html#/main/portal # 门户主页
/docs/docs/DocDsp.jsp        # 文档详情
/login/Login.jsp             # 登录页(通常重定向到CAS)
```

### CAS集成
泛微OA通常集成CAS SSO认证:
```bash
curl -sk 'https://<target>/login/Login.jsp' | grep -oP 'service=[^"]*'
# 返回: service=http%3A%2F%2F<target>%2Flogin%2FLogin.jsp
```

### CORS配置
泛微OA常见CORS配置错误:
```bash
curl -sk -H 'Origin: https://evil.com' -I 'https://<target>/' | grep access-control
# 返回: access-control-allow-origin: *
#        access-control-allow-credentials: true
```

### 泛微OA漏洞参考
见 `references/weaver-oa-testing-patterns.md` — 泛微E-Cology完整漏洞测试模式。

## 网瑞达(wengine) 认证网关指纹 (2026-06-09 cust.edu.cn实战)

网瑞达(北京网瑞达科技有限公司)资源访问控制系统是中国高校常用的统一认证网关。

### 指纹特征
```bash
# Server头隐藏
curl -sk -D- 'https://<target>/' | grep 'Server: none'

# wengine_new_ticket cookie
curl -sk -D- 'https://<target>/' | grep 'wengine_new_ticket'

# 登录页面关键词
curl -sk 'https://<target>/wengine-auth/login' | grep -i '网瑞达\|WEBVPN\|资源访问控制'
```

### 认证流程
业务系统 → wengine-auth → CAS → wengine-auth callback → 业务系统

### 关键端点
```
/wengine-auth/login?id=N&path=/&from=TARGET_URL  # 登录入口
/wengine-auth-failed.png                          # 错误页面图片
```

### 子域保护模式
不同子域用不同id参数：
- id=104: ehall(办事大厅)
- id=15: 教务系统
- id=N: 其他系统

### 测试要点
1. callback参数是否有注入
2. id参数是否有越权
3. wengine-auth本身是否有未授权访问
4. CAS Open Redirect可绕过wengine-auth保护

### 已知客户
- 长春理工大学 (cust.edu.cn)
- 多个使用WebVPN的高校
