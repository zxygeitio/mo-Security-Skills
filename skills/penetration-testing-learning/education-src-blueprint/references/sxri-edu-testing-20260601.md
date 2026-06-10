# 陕西铁路工程职业技术学院 (sxri.net) 测试记录 (2026-06)

## 目标概况
- 域名: sxri.net
- IP: 116.211.128.187 (加速乐CDN)
- 真实IP: 216.195.192.148 / 61.139.70.105
- 子域名: 120+个
- CDN/WAF: 加速乐 (jiasule.com)

## 技术栈
- CAS: 联创天空 lyuapServer (ly-iap-cas-ui)
- CMS: SUDY CMS (苏迪科技) — 10+子域
- 门户: Liferay 4.0.0 CE GA1 (2013年)
- OA: 泛微E-Cology (xoa.sxri.net)
- 预约: DianCMS ASP.NET 4.0 (apply.sxri.net)

## 确认漏洞

### 1. [中危] CAS用户枚举 + 密码错误计数泄露
- 端点: POST https://cas.sxri.net/lyuapServer/v1/tickets (form-data)
- 存在用户: "系统内部错误" 或 PASSERROR
- 不存在用户: NOUSER
- 密码错误计数递增: data字段为失败次数
- 无速率限制，无账号锁定
- 确认用户: admin, test

### 2. [低危] CAS网关微服务架构信息泄露
- 端点: https://cas.sxri.net/auth/login
- 响应头: X-Application-Context: ly-gateway-server-svc:1101

### 3. [低危] SUDY CMS管理页面泄露服务器真实IP
- 端点: https://jw.sxri.net/admin/login.psp (410 Gone)
- IP: 216.195.192.148 (所有SUDY子域统一)
- 影响子域: jw/jwc/zs/db/cw/email/ecshop/blog/count/it/erc/sg

### 4. [低危] Portal robots.txt泄露内网IP
- 端点: https://portal.sxri.net/robots.txt
- 泄露: Sitemap: http://192.168.2.49/sitemap.xml

### 5. [低危] 泛微OA API接口暴露
- 端点: https://xoa.sxri.net/api/ec/dev/crud/queryBySql
- 响应: {"msg":"登录信息超时","errorCode":"002","status":false}
- BshServlet: /weaver/bsh/servlet/BshServlet → 500 (存在但报错)

## SUDY CMS子域siteId映射
- jw.sxri.net: siteId=90
- jwc.sxri.net: siteId=127
- zs.sxri.net: siteId=80
- erc.sxri.net: siteId=97
- sg.sxri.net: siteId=82

## 泛微OA API端点 (均需认证)
- /api/ec/dev/crud/queryBySql
- /api/ec/dev/crud/executeSql
- /api/ec/dev/crud/getConditionFields
- /api/hrm/getUserInfo
- /api/hrm/getHrmList
- /api/workflow/getWorkflowList
- /api/doc/getDocList
- /api/system/getSystemInfo
- /weaver/bsh/servlet/BshServlet (500错误)

## 关键命令
```bash
# CAS用户枚举
curl -sk -X POST "https://cas.sxri.net/lyuapServer/v1/tickets" \
  -d "username=admin&password=wrong"

# CAS网关信息泄露
curl -sk "https://cas.sxri.net/auth/login" -D- | grep X-Application-Context

# SUDY CMS IP泄露
curl -sk "https://jw.sxri.net/admin/login.psp" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"

# Portal内网IP泄露
curl -sk "https://portal.sxri.net/robots.txt"

# 泛微OA API测试
curl -sk "https://xoa.sxri.net/api/ec/dev/crud/queryBySql"
```

## 不建议提交的发现
- SUDY CMS搜索API: 返回空JSON {}，参数异常
- Liferay JSONWS: 需要认证，返回"Authenticated access required"
- CAS SMS API: 需要有效appid，未找到
- 泛微OA BshServlet: 500错误，可能已修补
- SUDY CMS _upload/: 403 Forbidden
- DianCMS model.aspx: 302重定向到登录页
