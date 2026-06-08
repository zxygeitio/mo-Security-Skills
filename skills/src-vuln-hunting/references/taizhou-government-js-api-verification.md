# 台州政务类 SRC：前端 JS 提取到低影响验证的收敛流程

适用场景：用户给出政务/企业 SRC 资产清单，前端为 Vue/webpack/RuoYi/自研后台/浙政钉 MGOP，任务要求“下载前端 JS、提取 API/密钥/上传/认证端点、低影响验证并排除 SPA/WAF 误报”。

## 关键学习

1. 前端 JS 提取阶段不能只搜 `/api/`：
   - RuoYi 常见真实前缀：`/prod-api`、`/apis`、`/dev-api`、`/common/upload`、`/captchaImage`、`/getInfo`、`/getRouters`。
   - 自研后台常见前缀：`/admin/*`、`/iext/back/*`、`/system/*`、`/login/*`。
   - 浙政钉/MGOP 常见模式：页面在 `/web/mgop/gov-open/.../index.html`，真实调用不一定是同路径 REST；JS 里可能出现 `mgop.gov.jsadapter.query`、`cloud.uploadFile`、`biz.user.getUserInfo`、`scope/info` 等桥接/封装接口。
   - 业务高价值关键词：`upload/FileController/UploadManager`、`export`、`list`、`user/list`、`resetPwd`、`roomTicket`、`companyList`、`GovEva`、`DingTalkAuth`、`getConfigurationParams`。

2. t3→t4 的转换标准：
   - t3 结束时应产出“按资产分类的候选端点清单”，包括认证、上传、导出、用户/企业/订单/配置数据接口。
   - 不要在 t3 阶段把候选接口写成漏洞；必须进入 t4 做响应对照。

3. 低影响验证必须排除四类误报：
   - SPA fallback：`/.env`、`/v2/api-docs`、随机路径等都返回同一个 HTML 首页/同一长度/同一 hash。
   - 协议错误：HTTP 访问 HTTPS 端口返回 `400 The plain HTTP request was sent to HTTPS port`，不是漏洞，应切换到 HTTPS 再测。
   - WAF/网关错误页：502/400/nginx/统一拦截页不能当成 API 暴露。
   - 业务框架“伪 200”：HTTP 200 但 JSON 内部为 `code:401`、`认证失败`、`缺少TOKEN令牌`、`未获取到token`、`无token信息`、`controller not exists`、`ip地址未授权或授权到期`，均不能当作未授权漏洞。

4. 验证脚本的运行方式：
   - 大批量目标脚本容易因慢目标超时导致整体无结果；优先“逐资产、少端点、短超时”验证。
   - 每个资产先测 3-5 个最高价值接口：未授权 list/export/user/config/upload/login/configuration。
   - 每个接口记录：status、content-type、length、body 前 500 字、随机路径对照状态、是否 JSON、是否含 auth_required 文案。
   - 只有 `JSON-like + 非 auth_required + 非随机路径同内容 + 返回实际业务字段` 才进入报告。
   - auth_required 判断要同时匹配中文、英文和 Unicode 转义后的语义；例如 `"errmsg":"\\u65e0token\\u4fe1\\u606f"` 解码后是“无token信息”，应判定为鉴权拦截。

## 台州本轮高价值候选模式

### 云上中医后台
目标：`http://39.175.127.130:8089`
候选：
- `/api/admin/Login/getPublicKey`
- `/api/admin/Login/loginSecret`
- `/api/admin/UploadManager/upload`
- `/api/admin/Admin/getList`
- `/api/admin/Menu/getMenu`
- `/api/admin/BigImage/getHospitalList`
- `/api/admin/BigImage/listRecipe`
- `/api/admin/News/getList`
- `/api/admin/Evaluate/getHospital`

验证结论：
- `getPublicKey` 返回 RSA 公钥，属于登录流程公开信息，不单独成洞。
- `loginSecret` 无账号/弱参数只返回字段校验信息。
- 菜单、医院、处方、新闻、评价、管理员列表、上传接口均返回“无token信息”；multipart 安全文本上传也被 token 拦截。
- 不要把 HTTP 200 + `errcode:2001` 当作未授权。

### 企管通
目标：`https://39.175.127.253`
候选：
- `/iext/back/AuthController/login`
- `/iext/back/DingTalkAuthController/getConfigurationParams`
- `/iext/back/FileController/uploadFile`
- `/iext/back/FileController/deleteFile?fileUrl=`
- `/iext/back/GovBigBoardController/companyList`
- `/iext/back/GovBigBoardController/companyBasicGoodList`
- `/iext/back/GovBigBoardController/companyDeclareList`
- `/iext/back/GovEvaCompanyController/listGovEvaCompany`
- `/iext/back/GovEvaGovExportUserController/listGovEvaGovUserAll`
- `/iext/back/GovEvaGovExportUserController/resetPassword?id=`

验证重点：企业/政府用户/导出/重置密码/上传删除接口。该目标容易 SPA fallback；随机路径与首页同长度时，必须以 API 实际响应为准。若候选接口返回 502 Bad Gateway，只能记为网关错误，不能提交。

### 临海房票系统
目标：`http://220.185.226.233:8989`，前端还泄露 `http://220.185.226.233:9080`，需分别验证真实 API 端口。
候选：
- `/admin/checkToken`
- `/admin/admin/info`
- `/admin/admin/list`
- `/admin/admin/resetPwd`
- `/admin/housingResources/list`
- `/admin/roomTicket/list`
- `/admin/roomTicket/info`
- `/admin/roomTicketItems/list`
- `/admin/roomTicketItems/print`
- `/admin/statistics/base`
- `/admin/sysConfig/list`
- `/admin/sysLog/list`
- `/admin/user/list`
- `/login/admin/login`

验证结论：9080 端口多个高价值接口返回 `{"code":100000,"msg":"请先登录"}`，属于统一登录拦截；`/admin/statistics/base` POST 405 仅说明方法不匹配，不是漏洞。

### 黄岩经开区/RuoYi 类后台
资产给出 HTTP，但返回 `The plain HTTP request was sent to HTTPS port` 时，改测：`https://220.185.226.191:8001`。
候选：
- `/apis/captchaImage`
- `/apis/getInfo`
- `/apis/getRouters`
- `/apis/system/user/list`
- `/apis/system/role`
- `/apis/system/config/list`
- `/apis/system/materials/list`
- `/apis/common/uploadFile`
- `/apis/common/uploadNew`

验证结论：
- `/apis/captchaImage` 返回验证码是正常公开登录接口。
- `/apis/getInfo`、`/apis/getRouters`、`/apis/system/*`、上传接口均返回 JSON 内部 `code:401`/“认证失败，无法访问系统资源”。HTTP 200 不代表未授权。

### 椒江环保全生命周期一件事系统
目标：`https://yhzw.zhoujl.com`
前端配置：`window.globle.RequestUrl = "https://yhzw.zhoujl.com/apis/"`。

高价值候选/已验证接口：
- `/apis/monitorCompanyLocationList`：未登录返回企业点位数据（实测约 99 条），包含企业名称、industryType、company/id、经纬度 location。属于真实业务数据，不是 SPA fallback。
- `/apis/monitorWarningCount`：未登录返回监控点总数、预警总数等统计（如 `monitorPointStateAll`、`monitorWarningStateAll`、`monitorWarningState10`）。
- `/apis/monitorWarningHistoryBySevenDayView`：未登录返回近七天预警统计。
- `/apis/propagandaContentCastAllList`：未登录返回环保宣传内容列表，通常偏公开内容，作为辅助证明即可。

CORS 联动：
- 上述 JSON 接口带 `Origin: https://evil.example` 请求时，响应会反射：
  - `Access-Control-Allow-Origin: https://evil.example`
  - `Access-Control-Allow-Credentials: true`
- 若接口同时返回企业点位/监管统计数据，可按“未授权访问 + CORS 任意 Origin 反射”合并报告，定级建议中危。不要单独把 CORS 包装成高危，核心危害是未登录读取监管业务数据。

验证对照：
- 随机路径如 `/apis/random_no_such_hermes_123` 返回 404 JSON（`No message available`），可排除 SPA fallback。
- 加无效 `Authorization: invalid` 访问 `monitorCompanyLocationList` 仍返回相同数据，说明不是依赖已有登录态。
- `/apis/common/upload`、`/apis/common/uploadImg`、`/apis/zlbUpload` POST 无害文件返回“没有权限”；`/apis/common/uploadMedia` 返回 401；不要报未授权上传。
- `/apis/login` 随机账号返回“用户名或密码错误”；`captchaImage` 是正常公开验证码；`getInfo`/`getRouters` 404。

报告要点：
- 标题建议：`（https://yhzw.zhoujl.com）椒江区环保全生命周期一件事系统存在未授权访问及CORS任意Origin反射漏洞`。
- 证据必须包含：前端 RequestUrl、未授权接口返回企业名称/经纬度、随机路径 404 对照、CORS 反射响应头。
- 单行 curl 优先，避免把 `python3 -m json.tool` 放在面向用户截图的主命令里；该命令需要等完整 stdin 结束后才格式化，遇到慢连接/管道缓冲时用户会误以为接口卡住。截图/报告命令优先使用 `head -c` 或 `grep -o` 提取关键字段：
  - `curl -sk --connect-timeout 8 --max-time 20 "https://yhzw.zhoujl.com/apis/monitorCompanyLocationList" | head -c 1000; echo`
  - `curl -sk --connect-timeout 8 --max-time 20 "https://yhzw.zhoujl.com/apis/monitorCompanyLocationList" | grep -o '"name":"[^"]*"\|"location":"[^"]*"\|"company":[0-9]*\|"id":[0-9]*' | head -40`
  - `curl -sk -D- "https://yhzw.zhoujl.com/apis/monitorCompanyLocationList" -H "Origin: https://evil.example" -o /tmp/yhzw_cors_body.txt | grep -i "access-control"`

### 台州数据开放平台
目标：`https://data.zjtz.gov.cn/tz/home`，真实后端 baseURL 在前端 JS 中为 `https://data.zjtz.gov.cn/athena`。

关键验证结论：
- `/tz/*` 前端路由如 `/tz/catalog/list`、`/tz/open/table/detail/1`、`/tz/login/userInfo` 多数返回同一 3922 字节 HTML，是 SPA fallback，不能作为接口暴露或漏洞证据。
- 从 `static/js/app.*.js` 中提取到的接口路径需要拼接到 `/athena`，例如 `/athena/interface/getInterfaceDataByPage`、`/athena/base/organization/listAll`、`/athena/login/userInfo`。
- `/athena/interface/getInterfaceDataByPage` 可未登录返回公开接口目录 JSON（如 `total`、`title`、`source`、`content`），`/athena/base/organization/listAll` 返回机构列表；这些偏公开数据，不应包装成敏感数据未授权。
- `/athena/login/userInfo` 未登录返回 `{"code":"9991","msg":"未登录，查询不到用户信息","data":null}`，说明没有匿名用户信息泄露。
- 上述 `/athena/*` JSON 接口带 `Origin: https://evil.example` 时会反射：
  - `Access-Control-Allow-Origin: https://evil.example`
  - `Access-Control-Allow-Credentials: true`
  - `Access-Control-Expose-Headers: access-control-allow-headers, access-control-allow-methods, access-control-allow-origin`
- 该问题可作为“CORS 任意 Origin 反射配置不当”低危/中低危提交，但当前证据仅证明公开数据接口可跨域读取和登录态接口存在 CORS 反射；未证明登录后敏感数据被跨域读取前，不要定高危。
- 若用户偏好“只要实质漏洞”或厂商不收低危配置问题，则该 CORS+公开数据证据不建议提交；明确输出“暂无新实质漏洞”，不要为了产出报告而包装公开目录数据。

复测/环境注意：
- 台州相关域名在本机 DNS 可能解析到 `198.18.0.x` 合成地址；这可能是代理/网关环境，不等于目标真实公网 IP。遇到大量 `curl code=000`、`TLS connect error: unexpected eof while reading`、`Empty reply from server` 时，先做 `example.com`、`data.zjtz.gov.cn`、目标域名三组连通性对照，再判断是否为目标接口问题。
- `curl code=000`、TLS EOF、空响应不能写入漏洞报告，也不要将其归因为 WAF/漏洞；只能作为“当前环境无法稳定复现”。
- 对曾经可复现的接口（如 `https://yhzw.zhoujl.com/apis/monitorCompanyLocationList`）如果本轮变成 TLS EOF，不能重复输出旧报告；必须以当前可复测证据为准。

复现命令模板：
- `curl -sk --connect-timeout 3 --max-time 10 -D- -o /tmp/tz_interface_body.txt -H 'Origin: https://evil.example' 'https://data.zjtz.gov.cn/athena/interface/getInterfaceDataByPage' | grep -i 'HTTP\|content-type\|access-control'`
- `curl -sk --connect-timeout 3 --max-time 10 -H 'Origin: https://evil.example' 'https://data.zjtz.gov.cn/athena/interface/getInterfaceDataByPage' | head -c 500; echo`
- `curl -sk --connect-timeout 3 --max-time 10 -D- -o /tmp/tz_login_userinfo_body.txt -H 'Origin: https://evil.example' 'https://data.zjtz.gov.cn/athena/login/userInfo' | grep -i 'HTTP\|content-type\|access-control'`

报告边界：
- 标题可用：`（https://data.zjtz.gov.cn）台州数据开放平台存在CORS任意Origin反射配置不当漏洞`。
- 等级建议低危；若平台只收实质危害漏洞，应明确“不建议作为高价值漏洞提交”。
- 必须包含 `/tz/*` SPA fallback 对照，避免把前端路由误报为 API 暴露。

### 蓝色循环 / RuoYi / 后台 SPA 类资产
目标示例：`https://lsxh.zjjxkj.top`、`https://safety.mtzx.wl.gov.cn:9011`。
验证结论：
- 蓝色循环 `/prod-api/*`、`/api/admin/*`、`/actuator/env`、`/v2/api-docs`、`/swagger-ui.html` 与随机不存在路径返回同一 HTML 首页，是 SPA fallback 假 200。
- ai 政务助手 `/prod-api/captchaImage` 是正常验证码；`/prod-api/getInfo`、`/getRouters`、`/system/user/list` 返回 `code:401` 认证失败；其他 `/api/admin/*`/actuator/swagger 为 SPA fallback。

### 云督政 / 智慧湿地 / 天台经开区 ThinkPHP/后台类资产
目标示例：`https://ydz.xj.hwen.cn`、`https://zhsd.zjtt.gov.cn`、`https://ttjjkfq.zjtt.gov.cn`。
验证结论：
- `api/admin/*` 返回“未获取到token”或“缺少TOKEN令牌”。
- `admin/login/index` 返回“ip地址未授权或授权到期”，是访问控制/白名单提示，不是漏洞。
- `controller not exists:*`、404、502 均不能当作接口暴露。

### 浙政钉/MGOP 页面
目标示例：
- `https://mapi.zjzwfw.gov.cn/web/mgop/gov-open/zj/2001831409/reserved/index.html`
- `https://ding.etz.gov.cn:8069/web/mgop/gov-open/zj/20025207/reserved/index.html`
- `https://ding.etz.gov.cn:8069/web/mgop/gov-open/zj/20022020/lastTest/index.html`

验证重点：
- 静态页面可能加载 `ZWJSBridge`、`mgop.gov.jsadapter.query`、`cloud.uploadFile`、`biz.user.getUserInfo` 等桥接能力；这些是客户端/平台能力清单，不等于后端未授权。
- JS 模块中出现 `/scope/info`、`/scope/set`、`/tgreportline/projectList` 等业务路径时，直接拼到 `ding.etz.gov.cn:8069` 往往返回 MGOP `1007 URL错误`、空正文或需要签名/桥接上下文。没有返回真实业务字段前不得报告。

## 报告门槛

不要输出候选清单当报告。只有满足以下条件才输出可提交漏洞：
- API 非 SPA/非 WAF/非协议错误页；
- 无 token/无登录态仍返回成功 JSON；
- 响应包含具体业务数据或可证明敏感操作可达；
- 有单行 curl、响应关键字段、随机路径对照；
- 上传类只用无害文件证明，不上传 shell，不覆盖/删除生产文件。

若验证被超时中断，最终只能说“未完成验证，暂无可提交漏洞”，不要把候选接口包装成漏洞。
