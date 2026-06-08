# 嘀嗒出行 Phoenix/Enterprise 类 SaaS 前端 JS/API 深挖记录

适用场景：核心资产是 Vue/webpack SPA + APISIX 网关 + SaaS 管理后台，前端暴露大量 `/phoenix/*`、`/phoenixweb/*`、`/app/enterprise/didaweb_auth.php?didaweburl=` 类接口。

## 关键流程

1. 先从首页和 chunk 中批量提取 JS，再从 JS 中提取接口路径。
   - 重点关注：`/index/login`、`/index/picCode`、`/index/smsCode`、`/driver/*`、`/driverInfo/*`、`/driverManagement/*`、`/fleetManagement/*`、`/privilegeManagement/*`、`/data/*`、`/general/*`、`/service/*`、`/phoenixweb/phoenix/upload*`、`/phoenixweb/apollo/getApolloConfigByParams`。
   - webpack chunk 中的 API 路径可能不带前缀；实际请求通常由 axios `baseURL: /phoenix` 或代理路径补齐。

2. 认证链还原要看 axios 拦截器，而不是只看页面输入框。
   - Phoenix 前端会自动附加：`orgCid`、`opFirmCid`、`firmCid`、`opRole`、`opManageOrgCid`、`opUserCid`、`cityId`。
   - 会设置 `X-Phoenix-Userkey: state.adminInfo.userKey`。
   - 登录接口可能依赖 `router-type: cp/ac` 区分公司版/协会版。

3. 低影响未授权验证矩阵。
   - 无认证直接请求业务列表/detail/export接口。
   - 伪造常见头：无 `X-Phoenix-Userkey`、`1`、`222`、`test`、`null`、`undefined`、空值。
   - 伪造前端自动参数：`orgCid=1&opFirmCid=1&firmCid=1&opRole=0&opManageOrgCid=1&opUserCid=1&cityId=1&page=1&pageSize=1`。
   - 结果判定：返回真实 JSON 数据才继续；`{"code":403,"message":"非法访问!"}` 或 `登录信息过期，请重新登录` 说明服务端鉴权有效，不能包装成漏洞。

4. 上传接口低影响验证。
   - 只上传无害 `text/plain` 文件。
   - 测 `/phoenixweb/phoenix/upload/public`、`/private`、`?bfstype=4`、无后缀。
   - 企业版还要测 `/app/uploadfile/index.php`、`/app/uploadimage/index.php`、`/app/bfsdoc/`。
   - 只有返回可访问 fileUrl/resId/genName 且无需认证访问时，才进入报告链；403/401/登录过期不报。

5. 企业版代理接口验证。
   - 常见路径：`/app/enterprise/didaweb_auth.php?didaweburl=/company/getCompanyInfo`、`/employee/getEmployeeList`、`/order/getOrderList`、`/invoice/getInvoiceList`。
   - 测无 Cookie、`X-Requested-With`、`userKey`、`X-Phoenix-Userkey`、`Cookie:userKey`、`Cookie:NODESESSID`。
   - 统一 `{"code":401,"message":"登录超时，请重新登录"}` 时不报。

## 嘀嗒出行 SRC 范围与测试纪律

适用范围：`*.didachuxing.com`、`*.didapinche.com`，均为核心资产；企业主体为北京畅行信息技术有限公司，业务为出租车/顺风车/企业出行。报告定价与等级应以补天嘀嗒出行 SRC 规则页为准：`https://www.butian.net/caption/63273`。

低影响纪律：
- 禁止高并发、自动化重扫、DoS、批量遍历用户/订单/司机/企业数据。
- 禁止生产环境文件覆盖/删除、修改真实用户数据、批量生成工单/留言/业务记录。
- 如果发现可获取服务器或应用权限，只做最小证明，不上传恶意代码、不留后门、不读源码/敏感文件、不提权、不横向。
- 对短信/验证码/注册链只做单次或极少量验证，必须避免骚扰真实用户。
- 测试记录和上传的无害证明文件在验证后清理；报告中只保留必要脱敏证据。

报告策略：嘀嗒目标是核心资产，但仍只输出已验证的实质漏洞。JS 路由、前端本地绕过、公开城市列表、登录前验证码图片、统一 401/403 鉴权响应、SPA fallback、残留测试字符串，在未证明可登录/越权/读写业务数据前不建议提交。

## 2026-05-22 嘀嗒企业版实测补充

### 续测补充：无认证矩阵收敛信号

一次继续深挖中，从本地 JS 资产重新归集约 200+ 个高价值端点，覆盖企业版订单/员工/发票/企业资料、Phoenix 下载/导出/callback、上传/文件、注册/验证码链路。结论仍是：无授权态上下文时，继续反复打无认证接口收益很低。

可复用判定规则：
- `/phoenix/index/assPicCode` 返回 `codeBase64Url` 只是图形验证码，属于登录/注册前置流程；不要当作信息泄露。
- `/phoenix/index/smsCode` 在错误图形验证码下返回“图片验证码不正确”，说明验证码校验生效；不要继续高频短信验证。
- `/phoenix/user/smsCode` 返回权限认证失败时，说明该链路需要登录态。
- 企业版 `/app/enterprise/didaweb.php?didaweburl=/companyRule/getAlpCityList` 无登录返回城市列表，属于公开低价值配置。
- 企业版 `/companyRule/*`、`/notice/*`、`/employee/*`、`/invoice/*`、`/company/*`、`/order/*` 如果无认证只返回 `403 拒绝访问`、auth 包装只返回 `401 登录超时`，不能包装成越权或未授权。
- 上传接口 `/app/uploadfile/index.php`、`/app/uploadimage/index.php` 返回 `401 登录超时`，`/phoenixweb/phoenix/upload/public|private` 返回 `403 非法访问`，说明未授权上传不成立。
- 部分请求出现 TLS EOF/连接关闭/超时只能作为网络或网关现象，不能作为漏洞证据。

`checkCompany` 坑点：
- 随机不存在企业名、泛化企业名可返回 `{"code":0,"message":""}`。
- 已注册企业名可返回 `{"code":2002,"message":"企业名称已被注册！"}`，且与手机号无关。
- 这最多说明注册流程提示企业名称是否已注册；没有管理员、手机号、订单、员工等敏感数据时，不满足用户的实质漏洞门槛，不建议提交。

后续换方向：合法授权态企业账号下做订单/员工/发票 IDOR，或移动端 App/小程序 API 逆向；无授权态 Phoenix/Enterprise 矩阵已经进入低收益区。

### 入口与路由

- 企业版有效入口是 `https://b.didachuxing.com/#/login`，不是 `/enterprise/` 或 `/enterprise/login`；后者可返回 404。
- 前端 JS 中的企业版页面路由如 `/manage`、`/userList`、`/orderList`、`/limitList` 是 hash-router 前端路由，不能直接当作后端路径漏洞。

### 公开但低价值的企业版接口

以下接口可无登录访问，但目前只属于正常登录/注册前置流程或公开配置，不足以提交：

- `/app/enterprise/didaweb.php?didaweburl=/companyRule/getAlpCityList` 返回城市列表。
- `/app/enterprise/didaweb.php?didaweburl=/login/checkCompany&phone=...&companyName=...` 返回 `{"code":0,"message":""}` 时，不能直接认定企业/手机号枚举；必须用存在与不存在企业名、手机号做稳定差异对照，并证明可枚举真实企业或管理员信息。
- `/app/enterprise/didaweb.php?didaweburl=/verifyCode/getVerifyCode&phone=...` 返回图形验证码 base64，属于登录流程前置功能。

### 前端 localStorage:userKey=222 坑点

企业版 JS 中存在前端路由守卫：登录成功后写入 `localStorage.userKey=222`，路由守卫仅检查 `userKey` 是否存在即可进入 `/manage` 等前端页面。这只能证明前端路由可本地绕过，不能证明后端权限绕过。

报告门槛：
1. 本地设置 `userKey=222` 后，必须继续抓取页面发起的后端请求；
2. 只有某些后端接口不经 `didaweb_auth.php` 或返回真实企业/员工/订单/发票数据，才可报告；
3. 如果 `/app/enterprise/didaweb_auth.php?...` 仍统一返回 `401 登录超时，请重新登录`，则不提交。

### JS 残留测试账号/手机号

`https://e.didachuxing.com/js/login.*.js` 可残留协会版账号/密码、公司版测试手机号、测试公司名等字符串。处理规则：

- 先脱敏保存证据，避免在对话或报告草稿中传播真实账号/手机号。
- 继续验证真实登录 API、`router-type: cp/ac`、图形验证码参数、短信验证码参数。
- 只有证明凭据仍可登录，或可联动接口读取业务数据、触发越权、执行业务操作，才提交。
- 如果登录接口仅返回参数错误、验证码错误、账号无效，不能把“JS 残留账号/手机号”单独包装成高危。

### 已验证为鉴权有效的典型响应

Phoenix/SaaS：
- `/phoenixweb/apollo/getApolloConfigByParams?...`、`/phoenix/apollo/getApolloConfigByParams?...` 返回 `{"code":403,"message":"非法访问!"}`。
- `/apollo/getApolloConfigByParams?...` 返回 SPA 页面时属于 fallback，非配置泄露。
- `/phoenix/common/*`、`/phoenix/firm/*`、`/phoenix/driver/*`、`/phoenix/data/*` 等业务接口在无认证、伪造 `router-type`、伪造常见参数下统一 403 时不报。

Enterprise：
- `/app/enterprise/didaweb_auth.php?didaweburl=/company/getCompanyInfo`
- `/employee/getEmployeeList`
- `/order/getOrderList`
- `/invoice/getInvoiceList`
- `/app/uploadfile/index.php`
- `/app/uploadimage/index.php`
- `/app/bfsdoc/`

上述接口若返回 `{"code":401,"message":"登录超时，请重新登录","data":null}`，表示后端鉴权生效，不要将前端路由绕过或接口路径暴露包装成漏洞。

## 后续深挖优先级

1. 企业版短信/注册链路。
   - `/verifyCode/sendSmsCode`、`/login/registerUser&method=post`。
   - 只做一次低影响验证，避免短信轰炸。
   - 重点看图形验证码是否与手机号/session 绑定、是否可复用、是否空验证码/错误验证码仍发送。

2. `checkCompany` 枚举差异。
   - 使用存在/不存在企业名与随机手机号做小样本对照。
   - 只有响应字段、状态码、长度、错误码存在稳定差异并可识别真实企业/管理员时才继续。

3. 导出/下载 callback IDOR。
   - 重点 `/data/*/download/callback`、`/asso/*/download/callback`、`/driverInfo/doc/export`、`/app/bfsdoc/`。
   - 先从 JS 还原参数名和任务 ID/文件 ID 结构；只做单条、低频、随机不存在 ID 对照。

4. Phoenix Apollo/配置接口。
   - 必须区分 `/phoenixweb/`、`/phoenix/`、无前缀三类响应。
   - 403 是鉴权生效；HTML 是 SPA fallback；只有真实 JSON 配置才继续。

## 报告门槛

- 公开 JS 中残留测试账号、测试手机号、城市/企业测试信息，只能作为线索；除非继续证明：
  1. 凭据仍可登录；或
  2. 凭据/手机号可触发越权、数据访问、业务操作；或
  3. 可联动其它接口拿到敏感数据。
- 不能把“JS 残留账号/手机号”单独包装成高危；按用户偏好，无法证明实质危害时只记录为低价值线索，不输出提交报告。
- APISIX/Phoenix 类系统中，`x-biz-code: 403`、`code:401/403/1001`、`登录信息过期` 是鉴权生效信号；后续应转向 Apollo 配置、下载 callback、导出文件、IDOR 参数，而不是反复打同一类接口。
