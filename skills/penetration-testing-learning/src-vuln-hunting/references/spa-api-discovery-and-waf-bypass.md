# SPA API发现 + WAF绕过技术 (MGM SRC实战)

## 核心技术: 浏览器上下文API发现

当目标SPA被WAF保护(腾讯云WAF/Tengine/阿里云WAF)导致curl直接调用API返回403/405时，使用浏览器上下文绕过。

### 方法1: performance API捕获
```javascript
// 在browser_console中执行
const entries = performance.getEntriesByType('resource');
const apiCalls = entries.filter(e => e.name.includes('api'));
apiCalls.map(e => e.name).join('\n');
```

### 方法2: 直接fetch调用(同源)
```javascript
// 浏览器已加载SPA页面，同源fetch携带正确cookies/headers
fetch('/api/endpoint', {
    method: 'POST',
    headers: {'Accept':'application/json','Content-Type':'application/json'},
    body: JSON.stringify({param: 'value'})
}).then(r => r.json()).then(d => console.log(JSON.stringify(d)));
```

### 方法3: 批量API枚举
```javascript
(async () => {
    const results = {};
    const endpoints = ['/api/v1/config', '/api/v1/users', '/api/v1/data'];
    for (const ep of endpoints) {
        const r = await fetch(ep, {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
        const d = await r.json();
        results[ep] = {status: r.status, data: JSON.stringify(d).substring(0, 200)};
    }
    return JSON.stringify(results, null, 2);
})()
```

## 腾讯云WAF绕过模式

### 路径绕过(到达后端但可能返回404)
```
/api/v1/config;          # 分号后缀
/api/v1/config;jsessionid=test  # JSESSIONID
/api/v1/config%09        # Tab字符
/api/v1/config%0d%0a     # CRLF
/api/v1/config.json      # 扩展名
/api/v1/config.xml
/api/v1/config..;/
```

### 绕过原理
- WAF做精确路径匹配，分号/扩展名/tab改变路径字符串但nginx/后端仍处理
- 绕过后请求到达后端，但后端可能不识别修改后的路径(返回404)
- 仅在后端接受这些变体路径时有效

### 无效的绕过方法
- IP欺骗(X-Forwarded-For等) — 腾讯云WAF不信任这些头
- User-Agent变换 — 不影响WAF决策
- Content-Type变换 — 不影响WAF决策
- HTTP方法变换(GET/POST/PUT/OPTIONS) — 全部拦截

## Tengine WAF CORS配置问题

### 现象
Tengine WAF对405错误页返回CORS头，反射任意Origin:
```
curl -k -H "Origin: https://evil.com" -I https://target/
# 返回: access-control-allow-origin: https://evil.com
#       access-control-allow-credentials: true
```

### 限制
- 405响应体为WAF错误页(2657B HTML)，不含敏感数据
- 浏览器不处理405响应的CORS头(无安全影响)
- 仅在实际业务端点也返回CORS头时才有安全影响

## ABP Framework (ASP.NET Boilerplate) 测试模式

### 指纹
```bash
curl -sk 'https://target/lib/abp-web-resources/Abp/Framework/scripts/abp.min.js' | head -1
# 返回: ABP框架JS文件
```

### API端点模式
```
/api/services/app/{Service}/{Method}    # 标准ABP API格式
/AbpUserConfiguration/GetAll            # 用户配置(可能未授权)
/AbpServiceProxies/GetAll               # 服务代理列表
/api/abp/application-configuration      # 应用配置
/swagger/index.html                     # Swagger文档
```

### 常见ABP服务
- ScanPay: 扫码支付(LicensePlateQuery, GetQRCodeCoupon)
- Park: 停车场(GetParkInfo, GetAll)
- Payment: 支付(CreatePayment, GetPaymentStatus)
- Session: 会话(GetCurrentLoginInformations)
- Configuration: 配置(GetAll, GetValue)
- Tenant: 租户(GetCurrentTenant)

### ABP响应格式
```json
{
    "result": null,
    "targetUrl": null,
    "success": false,
    "error": {"code": 0, "message": "...", "details": null, "validationErrors": null},
    "unAuthorizedRequest": false,
    "__abp": true
}
```
- `unAuthorizedRequest: false` = 无需认证(可访问)
- `__abp: true` = ABP Framework确认

## FourWindsIntegration 游戏忠诚度系统

### 指纹
```bash
curl -sk 'https://target/js/fwimobile.min.js' | grep -oE 'FourWindsIntegration[^"]*' | sort -u
```

### 端点格式
```
/FourWindsIntegration/GamingLoyaltySystem/{Handler}.ashx?Connection={ENV}&ModuleName={MOD}&CultureCode={LANG}
```

### 已知Handler
- GetModuleInfo.ashx — 获取模块信息(返回XML)
- RefreshSessions.ashx — 刷新会话

### Connection参数
- DEV — 开发环境(可能返回SUCCESS)
- PROD — 生产环境(可能返回FAIL)
- STAGING — 预发布环境(可能返回FAIL)

### 响应格式(XML)
```xml
<ModuleInfoResponse>
    <StatusCode>OK</StatusCode>
    <StatusId>FWI0000</StatusId>
    <StatusDescription>Success</StatusDescription>
    <StatusCookie>Module info was refreshed from data source</StatusCookie>
    <Name>["活动名"]</Name>
    <Description>["资源路径"]</Description>
    <Link>["#eventId;Id=N"]</Link>
</ModuleInfoResponse>
```

## Source Map泄露检测

### 检测方法
```bash
# 1. 获取asset-manifest.json
curl -sk 'https://target/asset-manifest.json'

# 2. 检查.map文件
curl -sk 'https://target/static/css/main.*.css.map' | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('Sources:', d.get('sources',[]))
print('Has content:', bool(d.get('sourcesContent')))
"

# 3. 检查JS sourceMappingURL
curl -sk 'https://target/static/js/main.*.js' | grep -o 'sourceMappingURL=[^*]*'
```

### 泄露内容
- `sources`: 原始文件路径(components/kioskButton.css, pages/mainPage/index.css)
- `sourcesContent`: 原始CSS/JS代码
- `names`: 变量名/函数名

## 企业代码/优惠码验证逻辑缺陷

### 测试模式
```javascript
// 测试验证端点是否接受任意输入
const tests = [{code:''}, {code:null}, {}, {code:'test'}, {code:'!@#$%'}];
for (const t of tests) {
    const r = await fetch('/api/code/check', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(t)
    });
    const d = await r.json();
    console.log(JSON.stringify(t), '→', d.success, d.data);
}
// 如果全部返回true = 验证逻辑缺陷
```

### 判断标准
- 任意输入(含空/null/缺少参数)都返回`{"success":true,"data":true}` → 验证失效
- 对比其他类似端点(如groupCode/check)是否正常工作
- 空字符串返回true是最强证据
