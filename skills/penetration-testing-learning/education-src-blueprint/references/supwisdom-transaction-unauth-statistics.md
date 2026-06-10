# Supwisdom/智慧校园事务中心未授权统计接口模式

## 适用场景
教育目标使用 Supwisdom/智慧校园/融合门户/事务中心时，常见资产包括：
- `portal.<school>.edu.cn` 融合服务门户
- `admin-platform.<school>.edu.cn` 智慧校园云平台
- `transaction.<school>.edu.cn/ttc/` 事务中心
- `message-service.<school>.edu.cn/center/` 消息中心
- `authx-service.<school>.edu.cn` 安全中心/统一身份

该模式适合低影响验证“后台统计/流程配置类接口是否被错误公开”。

## 关键发现路径
1. 先访问管理平台配置文件，提取真实后端基址：
   - `https://admin-platform.<school>.edu.cn/serverConfig.json`
   - 重点字段：`BASE_TRANASACTION_API`、`EVALUATION_CENTER_BACKEND`、`MESSAGE_SERVICE_API`、`PERSONAL_CENTER_API`、`AUTH_CAS`。
2. 从融合门户/事务中心前端 JS、`remoteEntry.js`、import-map 中提取 `/ttc/`、`/api/ttc/`、`/v1/service/monitor/`、`/v1/service/analysis/` 路由。
3. 优先测试“监控/统计/分析/事务类型配置”接口，而不是一开始测试写操作或用户搜索接口。

## MDIT 实战已验证接口
目标：`transaction.mdit.edu.cn`

无需登录、无需 Cookie、无需 Authorization 即可返回真实业务数据：

```bash
curl -sk -D- 'https://transaction.mdit.edu.cn/ttc/api/ttc/transactionType/getTransactionTypeList'
curl -sk -D- 'https://transaction.mdit.edu.cn/ttc/v1/service/monitor/getHighFrequenceServiceList'
curl -sk -D- 'https://transaction.mdit.edu.cn/ttc/v1/service/monitor/getServiceApplyTimes'
curl -sk -D- 'https://transaction.mdit.edu.cn/ttc/v1/service/monitor/getServiceStatisticsInfo'
curl -sk -D- 'https://transaction.mdit.edu.cn/ttc/v1/service/analysis/getUserApplyChart'
```

典型证据：
- `transactionType/getTransactionTypeList` 返回 `code=0`、`message=获取成功`、`records`，包含 `appName`、`appId`、`name`、`id`、`transTypeCode`、`enabled`。
- `monitor/getHighFrequenceServiceList` 返回高频业务名称和申请次数，如学生请假、工单报修、学生销假、采购申请、签到、违纪处分、学籍异动审批表。
- `monitor/getServiceApplyTimes` 返回按月份统计的申请次数。
- `monitor/getServiceStatisticsInfo` 返回总服务申请量、参与流程总次数、完成率。
- `analysis/getUserApplyChart` 可能回显完整 SQL 错误：`SQLSyntaxErrorException`、`Unknown database 'user'`、`com/supwisdom/ttc/mapper/CenterListMapper.java`、表名 `TRANSACTION`、`user.TB_B_ACCOUNT`、`user.TB_B_IDENTITY_TYPE`。

## 鉴权对照，避免误报
同一系统中部分接口会正确返回鉴权错误，可用来证明上述接口不是 SPA fallback 或统一公开页：

```bash
curl -sk -D- -H 'Origin: https://evil.example' 'https://transaction.<school>.edu.cn/ttc/api/ttc/app/getAllAppList'
```

若返回如下内容，说明系统存在鉴权机制，但监控/统计接口遗漏了鉴权：

```json
{"code":401,"message":"token信息不存在","took":0}
```

同时检查响应体是否为 JSON，不能把返回同一 HTML 首页的路径当作漏洞；`admin-platform`、`portal`、`evaluation-center` 很多路径会 200 返回同一个 SPA 页面。

## CORS 解释边界
- 如果可读数据接口返回 `Access-Control-Allow-Origin: *`，可作为“扩大泄露面”的辅助证据。
- 如果接口本身只返回 `401 token信息不存在` 或 `403 Access Denied`，即使反射任意 Origin + Credentials=true，也不要单独包装为高危 CORS；没有敏感数据闭环。

## 报告角度
建议标题：`学校事务中心存在未授权访问漏洞导致业务流程配置和统计数据泄露`

可提交字段：
- 域名：`transaction.<school>.edu.cn`
- 类型：未授权访问 / 敏感信息泄露 / 错误信息泄露
- 等级：通常中危；若进一步证明可导出用户数据、流程读写或越权操作，再升级高危。
- 复现：每个接口用单行 `curl -sk -D-`，截图中同时包含命令、HTTP 200、`code=0`、关键业务字段。
- 影响：强调流程配置、业务统计、服务申请量、SQL/表名/Mapper 路径泄露对后续攻击的辅助价值；不要夸大为直接用户数据泄露，除非已实际获取 PII。

## 常见误区
- `evaluation-center/.../api/...` 在路径错误时可能 200 返回 `business-management-center` SPA 首页；这是 fallback，不是接口数据。
- `message-service`、`address-book`、`study-center` 可能存在 CORS 反射，但若返回 `401/403`，不构成可提交高危。
- `admin-platform` 的很多 API 路径会返回同一个智慧校园云平台 HTML 首页；必须用 JSON 响应和鉴权对照过滤。
