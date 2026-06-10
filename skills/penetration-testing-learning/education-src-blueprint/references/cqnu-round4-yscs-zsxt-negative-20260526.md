# CQNU 第四轮 yscs/zsxt CORS 与公开 API 深挖负证据（2026-05-26）

## 适用场景
教育 SRC 中，在前序已经发现招生系统或智慧校园门户存在：
- CORS 任意 Origin 回显 + `Access-Control-Allow-Credentials: true`；
- 找回密码、登录、tenant、captcha、upload/download 等公开 API 线索；
- 招生录取查询、通知书下载/模板接口；
但尚未证明真实敏感数据读取、账号枚举、验证码发送、上传成功或认证绕过。

## 本轮目标
重庆师范大学 CQNU 第四轮深挖，聚焦三条攻击假设：
1. 浏览器运行态 / JS 隐藏接口是否能发现 yscs 或 zsxt 的未授权敏感 API；
2. 招生对象枚举边界是否能从录取查询/通知书接口补到真实录取数据；
3. yscs 公开 API 差异是否能形成账号枚举、短信触发、认证绕过或上传下载入口。

## 关键结果
### yscs 找回密码配置接口
`GET https://yscs.cqnu.edu.cn/saas/gateway/fighter-middle/api/forget-password/getType`

稳定返回 200，并回显：
- `Access-Control-Allow-Origin: https://evil.example`
- `Access-Control-Allow-Credentials: true`

响应内容仅为找回方式配置：
- `securityAnswer` 安全问题找回；
- `phone` 手机验证码找回；
- `personEmail` 个人邮箱验证码找回；
- `email` 工作邮箱验证码找回；
- `requestWithEncrypt: true`；
- `needSliderImageCaptchaBeforeSend: true`；
- `needSliderImageCaptchaOnSubmit: true`；
- `sendTimeIntervalInMills: 60000`。

结论：这是公开配置 + CORS，不含账号、手机号、邮箱、token、验证码或业务数据，不建议提交。

### yscs 登录接口
`POST https://yscs.cqnu.edu.cn/saas/gateway/fighter-middle/api/login`

用随机不存在账号和错误密码测试，仅返回：
`{"code":5,"data":null,"msg":"用户名或密码错误"...}`

结论：未发现认证绕过、token 泄露或账号存在差异。

### yscs 猜测接口
以下接口低影响验证为 404 或错误分支：
- `/api/forget-password/getPublicKey`
- `/api/forget-password/captcha`
- `/api/forget-password/checkAccount`
- `/api/forget-password/sendCode`
- `/api/forget-password/validateUser`
- `/api/forget-password/submit`
- `/api/common/getPublicKey`
- `/api/captcha/get`
- `/api/tenant/listNoPermissionCheck`
- `/api/file/upload`
- `/api/file/download?id=1`

结论：未触发验证码发送、上传成功、文件下载、租户配置泄露或敏感数据读取。

### zsxt 招生系统
常见录取查询 / 通知书路径当前多为 404 或空响应：
- `/tzgl/xslqcx/lqcx`
- `/tzgl/xslqcx/getLqxx`
- `/tzgl/xslqcx/tzsdy?ksh=00000000000000`
- `/tzgl/xslqcx/lqtzsmb?mbid=1&ksh=00000000000000`

结合前序验证：公开拟录取名单样本无法命中查询，通知书接口仅壳页面/模板占位，仍不能证明真实考生数据泄露。

## 门禁结论
不建议新增提交漏洞报告。

理由：
- 未发现 RCE / SQLi / 认证绕过 / 任意用户登录；
- 未发现 IDOR 或未授权读取真实学生、教师、考生数据；
- 未发现可用上传、文件下载、短信验证码触发或账号枚举差异；
- 当前只有“CORS + 公开配置 / 404 错误”级别证据，不符合实质漏洞门槛。

## 后续投入条件
只有满足以下任一条件才值得继续：
- 拿到合法测试账号后验证 yscs/portal 登录态 IDOR、越权或敏感接口跨域读取；
- 获得真实完整低影响考生样本后验证 zsxt 录取/通知书接口；
- 从前端 JS / 小程序 / APP 包中发现新的非登录保护业务 API、上传下载入口、可用密钥或可预测对象 ID。

## 执行教训
- 对这类目标，不要把 CORS + `Credentials=true` 单独包装成漏洞；必须证明恶意 Origin 可读到登录态敏感响应或未授权业务数据。
- 找回密码接口若只返回找回方式、滑块/加密配置和发送间隔，属于公开配置，不构成账号枚举或认证绕过。
- 对猜测 API 要做小批验证并快速归类，连续 404 / 错误分支 / 空响应时停止，不进入长脚本黑洞。
