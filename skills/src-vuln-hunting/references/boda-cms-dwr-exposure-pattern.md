# 博达CMS (VWebServer) DWR框架文件暴露模式

## Trigger
Target uses VWebServer/博达CMS (common in Chinese universities). Page source loads DWR JS files.

## Fingerprint
```bash
# 博达CMS fingerprint
curl -sk "https://TARGET/" | grep -oP 'CustomerNO:[a-f0-9]+' # 博达序列号
curl -sk "https://TARGET/" | grep -oP '_sitegray/_sitegray'   # 博达特征目录
curl -sk "https://TARGET/" | grep -oP 'Announced by Visual SiteBuilder [0-9]+'
# VWebServer header
curl -sk -D- "https://TARGET/" | grep -i "server: VWebServer"

# DWR detection
curl -sk "https://TARGET/" | grep -oP '_dwr/(engine|util)\.js'
```

## DWR Exposure Test
```bash
# Client files (usually accessible, low risk)
curl -sk "https://TARGET/_dwr/engine.js" | head -5   # DWR engine
curl -sk "https://TARGET/_dwr/util.js" | head -5      # DWR utilities

# DWR test page (if accessible = high risk, exposes Java methods)
curl -sk "https://TARGET/_dwr/index.html"
curl -sk "https://TARGET/_dwr/test/"

# DWR call endpoints (if accessible = critical, allows calling Java methods)
curl -sk "https://TARGET/_dwr/call/plaincall/"
for method in UserService.getUsers SystemService.getConfig NewsService.getNews; do
  curl -sk "https://TARGET/_dwr/call/plaincall/${method}.dwr"
done
```

## Risk Levels
- **engine.js + util.js only**: LOW - Client library files exposed, reveals technology stack
- **DWR test page accessible**: MEDIUM - Exposes available Java classes and methods
- **DWR call endpoints accessible**: CRITICAL - Allows remote method invocation on server

## Common DWR Endpoints on 博达CMS
```
/_dwr/engine.js          # Client-side engine (usually present)
/_dwr/util.js            # Client-side utilities (usually present)
/_dwr/index.html         # DWR test page (lists all exposed beans)
/_dwr/test/              # Interactive test interface
/_dwr/call/plaincall/    # Direct method invocation
/_dwr/call/plaincall/ClassName.methodName.dwr  # Specific method call
```

## 博达CMS Other Known Paths
```bash
# Data input (visit statistics) - potential SQL injection
curl -sk "https://TARGET/system/resource/code/datainput.jsp?owner=CUSTOMERNO&e=1"
# Returns 200 with 0-byte GIF when working

# AJAX library
curl -sk "https://TARGET/system/resource/js/ajax.js"
# Exposes click tracking endpoints:
# /system/resource/code/news/click/clicktimes.jsp
# /system/resource/code/news/click/batchclicktimes.jsp
# /system/resource/code/news/click/addclicktimes.jsp

# System resource directory
curl -sk -D- "https://TARGET/system/resource/"  # 301 redirect = exists
```

## False Positive Check
- DWR engine.js/util.js being accessible alone is LOW risk - confirm servlet endpoints are actually exposed before escalating
- Test DWR call with actual method names from the site's functionality (search, news, user management)
- Verify 404 responses are real 404s vs SPA fallback (compare with random path)

## Report Template (DWR servlet exposed)
```
标题: [单位名称]网站DWR远程方法调用接口未授权访问
域名: [domain]
类型: 未授权访问
等级: 中/高危(取决于暴露的方法)

详情: [domain]使用博达CMS + DWR框架，/_dwr/test/页面可直接访问，
暴露了[列举Java类和方法]。攻击者可通过DWR调用这些远程方法。

复现:
curl -sk "https://[domain]/_dwr/test/"
curl -sk "https://[domain]/_dwr/call/plaincall/UserService.getUsers.dwr"
```

## Real-World Examples
- lib.cumt.edu.cn (2026-06): DWR engine.js/util.js加载，但servlet端点全部404。低危。
- 多数博达CMS站点: DWR客户端文件可访问但servlet已禁用或路径修改。
