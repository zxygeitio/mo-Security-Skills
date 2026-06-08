# Seeyon OA (致远OA) 测试模式

## 指纹识别
- URL: oa.xxx.edu.cn/seeyon/
- 登录页: /seeyon/ 或 /seeyon/index.jsp
- CSS引用: /seeyon/common/all-min.css?V=V{版本}_{日期}_{编译号}
- JS引用: /seeyon/common/all-min.js
- Cookie: JSESSIONID (Path=/seeyon)
- 标题: "xxx协同办公" 或 "xxx办公管理系统 V{版本}"
- 客开特征: 登录页JS含 `method=adminIndex`/`method=adminLogin` 客开屏蔽逻辑
- WAF: SafeLine(长亭科技)常见于致远OA前端，.jsp路径返回403"您的访问请求可能对网站造成安全威胁"

## REST API 端点 (V8/V9 均可能未授权)
GET /seeyon/rest/token          → 异常处理页面 (含版本信息)
GET /seeyon/rest/orgMember      → 401 {"code":"1010","message":"被迫下线"}
GET /seeyon/rest/organization   → 同上
GET /seeyon/rest/department     → 同上
GET /seeyon/rest/user           → 同上
GET /seeyon/rest/session        → 同上
POST /seeyon/rest/token         → 异常处理页面

### V9.0SP1 新增/变化端点 (2026-06-07 ccnu.edu.cn确认)
GET /seeyon/rest/orgDepartment  → 401 {"code":"1010",...} (V9新增)
GET /seeyon/rest/orgPost        → 401 {"code":"1010",...}
GET /seeyon/rest/orgAccount     → 401 {"code":"1010",...}
GET /seeyon/rest/token?userName=xxx → 200 异常处理页面(非真实token)
GET /seeyon/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip → 200(12B) "__LOGOUT"(需登录才有真实响应)
GET /seeyon/thirdpartyController.do → 200(0B) 空响应(V9已修补SSRF)
GET /seeyon/thirdpartyController.do?method=access&enc=... → 200(4514B) HTML页面(非SSRF)
GET /seeyon/webmail.do?method=doDownloadAtt → 200 JS "被迫下线"(需认证)
GET /seeyon/messageContent.do?method=download → 200 JS "被迫下线"(需认证)
GET /seeyon/getAjaxDataServlet?S=ajaxEdocSummaryManager&M=findById&ID=1 → 200(58B) (可能可用)
GET /seeyon/rest/authentication/ucpcLogin → 404 (V9已移除)
GET /seeyon/htmlofficeservlet → 403 (SafeLine WAF拦截)
GET /seeyon/management/status → 404 (V9未暴露)
GET /seeyon/downloadServlet → 404 (V9未暴露)
GET /seeyon/httpproxy → 404 (V9已修补)

## Token获取接口
GET /seeyon/rest/token/admin/admin      → 404 (路径不存在)
GET /seeyon/rest/token/admin/123456     → 404
POST /seeyon/rest/token                 → 500错误

## 测试/调试端点
GET /seeyon/test.do     → JS错误页面 ("被迫下线")
GET /seeyon/debug.do    → JS错误页面
GET /seeyon/main.do     → 登录页 (200 OK)

## 信息泄露点
- CSS引用泄露完整版本号: V8_0SP1_201101_29551
- /seeyon/rest/token 返回异常处理页面含版本信息
- /seeyon/common/js/V3X.js 泄露JS框架信息

## 常见漏洞
1. REST API未授权访问 (需验证是否返回真实业务数据)
2. 弱口令 (admin/123456, admin/admin等)
3. 信息泄露 (版本号、内部路径)
4. SQL注入 (登录接口)
5. 文件上传漏洞

## 报告角度
- 致远OA版本泄露 [低危]
- REST API未授权访问 [中危] (需证明可获取敏感数据)
- 弱口令 [高危] (需实际登录成功)
