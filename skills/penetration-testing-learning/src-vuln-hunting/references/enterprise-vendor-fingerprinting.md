# 企业级系统供应商指纹识别方法

## ASP.NET Boilerplate (ABP Framework)
开源应用框架，常用于企业内部系统。

### 指纹特征
```bash
# JS文件
curl -sk 'https://<target>/lib/abp-web-resources/Abp/Framework/scripts/abp.min.js'

# API端点格式: /api/services/app/{Service}/{Method}
# 响应格式: {"result":null,"targetUrl":null,"success":false,"error":{...},"unAuthorizedRequest":false,"__abp":true}

# 页面中的ABP变量
curl -sk 'https://<target>/' | grep -oP 'abp\.\w+'
```

### 关键识别点
- API路径: `/api/services/app/{ModuleName}/{ServiceName}/{MethodName}`
- 响应包含 `"__abp":true` 字段
- 错误响应: `{"error":{"code":0,"message":"...","validationErrors":[...]}}`
- `unAuthorizedRequest` 字段表示是否需要认证
- `abp.min.js` 或 `abp-web-resources` 在页面中引用

### 常见ABP API端点 (无需认证时)
```
/api/services/app/Session/GetCurrentLoginInformations  # 当前登录信息
/api/services/app/Configuration/GetAll                  # 系统配置
/api/services/app/Tenant/GetCurrentTenant               # 租户信息
/api/services/app/CommonLookup/GetTimezones             # 时区列表
/api/services/app/CommonLookup/GetEditions              # 版本列表
/api/services/app/Role/GetRoles                         # 角色列表
/api/services/app/User/GetUsers                         # 用户列表
/AbpUserConfiguration/GetAll                            # 用户配置
/AbpServiceProxies/GetAll                               # 服务代理
/swagger/index.html                                     # Swagger文档
```

### 漏洞测试方法
```bash
# 1. 检查API是否需要认证
curl -sk -X POST 'https://<target>/api/services/app/{Service}/{Method}' \
  -H 'Content-Type: application/json' -d '{}'
# unAuthorizedRequest=false 表示无需认证

# 2. 检查ABP配置泄露
curl -sk 'https://<target>/api/abp/application-configuration'
curl -sk 'https://<target>/AbpUserConfiguration/GetAll'

# 3. 检查Swagger
curl -sk 'https://<target>/swagger/index.html'
curl -sk 'https://<target>/swagger/v1/swagger.json'

# 4. 枚举服务端点
# ABP API返回验证错误时会泄露字段名
curl -sk -X POST 'https://<target>/api/services/app/{Service}/{Method}' \
  -H 'Content-Type: application/json' -d '{"SearchFilter":""}'
# 响应: "The SearchFilter field is required." → 确认字段存在
```

### MGM SRC实战案例 (2026-06-05)
- carpark.mgm.mo 使用ABP Framework
- `/api/services/app/ScanPay/LicensePlateQuery` 无需认证
- `/api/services/app/ScanPay/GetQRCodeCoupon` 无需认证
- `unAuthorizedRequest:false` 确认无需授权
- 参数名大小写敏感: `ParkNo`(正确) vs `ParkNo`(不同行为)
- WAF对POST请求的JSON body中的SQL注入不拦截(ABP参数化查询保护)

## FourWindsIntegration 游戏忠诚度系统
FourWinds International公司的赌场会员忠诚度管理系统。

### 指纹特征
```bash
# ASHX端点
curl -sk 'https://<target>/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=DEV&ModuleName=slider&CultureCode=en'

# 响应格式: <?xml version="1.0"?><ModuleInfoResponse><StatusCode>OK</StatusCode><StatusId>FWI0000</StatusId>...
```

### 关键识别点
- 路径: `/FourWindsIntegration/GamingLoyaltySystem/*.ashx`
- 状态码前缀: `FWI0000`(成功), `FWI0001`(失败)
- Connection参数: DEV/PROD/STAGING
- 响应XML格式

### 常见端点
```
/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx    # 模块信息
/FourWindsIntegration/GamingLoyaltySystem/RefreshSessions.ashx  # 会话刷新
```

### 漏洞测试
```bash
# 1. 测试不同Connection值
for conn in DEV PROD STAGING TEST LOCAL; do
  curl -sk "https://<target>/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=$conn&ModuleName=slider&CultureCode=en"
done
# Connection=DEV返回SUCCESS而PROD/STAGING返回FAIL → DEV环境暴露

# 2. 枚举ModuleName
for mod in slider home main member loyalty gaming casino hotel; do
  curl -sk "https://<target>/FourWindsIntegration/GamingLoyaltySystem/GetModuleInfo.ashx?Connection=DEV&ModuleName=$mod&CultureCode=en"
done

# 3. 测试RefreshSessions
curl -sk "https://<target>/FourWindsIntegration/GamingLoyaltySystem/RefreshSessions.ashx?Connection=DEV"
```

### MGM SRC实战案例 (2026-06-05)
- mlife.mo 暴露DEV环境接口
- Connection=DEV → SUCCESS, Connection=PROD/STAGING → FAIL
- slider模块返回业务数据: Name=["2049"], Link=["#ticketEvent;Id=3"]
- RefreshSessions DEV也可访问

## BeyondTrust Privileged Remote Access (PRA)
远程支持和特权访问管理平台。

### 指纹特征
```bash
# 主页标题
curl -sk 'https://<target>/' | grep -i 'Remote Support Portal\|BeyondTrust\|Bomgar'

# API端点
curl -sk 'https://<target>/api/command'
# 响应: {"message":"The resource owner or authorization server denied the request. Missing \"Authorization\" header.","error":"access_denied"}
```

### 关键识别点
- 页面标题: "Remote Support Portal"
- API使用OAuth2 Bearer token认证
- robots.txt禁止: `/appliance/`, `/login/`, `/api/`, `/files/`, `/config/`
- 错误响应JSON格式含 `message` 和 `error` 字段

### 常见端点
```
/api/command     # 命令执行API (需OAuth2)
/api/reporting   # 报告API (需OAuth2)
/api/config      # 配置API
/login           # 登录页面
/appliance       # 设备管理
```

## Tengine WAF 指纹与特征
淘宝定制版Nginx，常用于阿里云部署。

### 指纹特征
```bash
# 响应头
curl -sk -I 'https://<target>/' | grep -i 'server: Tengine'

# WAF拦截响应 (405 Method Not Allowed)
curl -sk 'https://<target>/any-path'
# 返回405, 约2657字节, 含 "data-spm" 属性
```

### 关键识别点
- Server头: `Tengine`
- 被拦截时返回405 (非403)
- 响应体含 `data-spm="a3c0e"` 属性
- 响应体约2657字节
- CORS头在405响应上也会返回(配置问题)

### WAF行为
- 拦截所有非白名单路径 → 405
- 拦截POST请求到非白名单端点 → 405
- OPTIONS请求也返回405
- 不拦截GET请求到白名单路径
- CORS配置可能反射Origin(需验证)

## 阿里云WAF指纹
```bash
# Cookie特征
curl -sk -I 'https://<target>/' | grep -i 'aliyungf_tc\|acw_tc'

# 拦截响应
curl -sk 'https://<target>/' | grep 'Request Rejected'
```

### 关键识别点
- Cookie: `aliyungf_tc`, `acw_tc` (阿里云防火墙)
- 拦截响应: "Request Rejected" + support ID
- 对SQL注入payload直接拦截
- 对路径遍历payload直接拦截

## Akamai Bot Manager指纹
```bash
# 响应状态码247 (自定义challenge)
curl -sk 'https://<target>/any-path'
# 返回247, 约437-444字节

# Challenge JS文件
curl -sk 'https://<target>/kramericaindustries.ac.lib.js'
```

### 关键识别点
- 自定义状态码247 (非标准HTTP)
- 响应体含HTML + JS challenge脚本
- JS文件名: `kramericaindustries.ac.lib.js`
- 所有路径都返回相同challenge页面
- 无法通过简单HTTP请求绕过(需浏览器执行JS)

## UmiJS前端框架API发现方法
基于React的企业级前端框架，常与Dva/Redux配合。

### JS Bundle分析
```bash
# 下载主bundle
curl -sk 'https://<target>/umi.*.js' -o /tmp/umi.js

# 提取API端点
grep -oP '"/[A-Z][a-z]+/[A-Za-z/]+"' /tmp/umi.js | sort -u

# 提取路由
grep -oP 'path:\s*"([^"]+)"' /tmp/umi.js | sort -u

# 提取配置
grep -oP 'baseURL["\s:=]+"([^"]+)"' /tmp/umi.js
grep -oP 'proxy["\s:=]+\{[^}]{10,500}\}' /tmp/umi.js
```

### 常见UmiJS路由模式
- 前端路由 ≠ 后端API
- SPA返回相同HTML for all routes (nginx配置)
- 实际API可能在不同域名或端口
- 通过proxy配置转发到后端

## Livewire (Laravel) 组件枚举方法
```bash
# 获取页面中的Livewire组件
curl -sk 'https://<target>/' | grep -oP 'wire:snapshot="[^"]*"' | while read -r line; do
  echo "$line" | python3 -c "import sys,json,html; d=json.loads(html.unescape(sys.stdin.read().split('\"')[1])); print(f'{d[\"memo\"][\"name\"]}: {list(d[\"data\"].keys())}')"
done

# Livewire更新端点
POST /livewire/update
Content-Type: application/json
X-CSRF-TOKEN: <token>
X-Livewire: true

# Livewire组件调用格式
{"components":[{"snapshot":{...},"calls":[{"method":"methodName","params":[...]}]}]}
```
