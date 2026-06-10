# 教育一卡通/Uni-app H5 校园卡系统深挖模式

## 适用场景

目标出现以下特征时使用本参考：
- 子域名类似 `yikatong.*.edu.cn`、`card.*.edu.cn`、`ecard.*.edu.cn`、`campuscard.*`。
- 页面标题/功能包含“校园卡绑定”“校园生活服务”“一卡通”“校园码”。
- 前端为 uni-app/Vue H5，入口脚本包含 `/static/js/index.*.js`、`chunk-vendors.*.js`。
- 接口统一走 `/server/*`，存在 `auth/getEncrypt`、`captcha/get`、`home/sendSms`、`user/tradeList`、`card/reportLoss` 等路径。

## 关键方法

1. 先用浏览器动态加载目标页面，提取脚本：
   - `document.scripts` 获取 JS URL。
   - 抓取主包 `index.*.js` 和 `chunk-vendors.*.js`。
   - 搜索接口关键字：`/server/`、`/auth/`、`/user/`、`/card/`、`/consume/`、`/merchant/`、`/captcha/`、`/home/sendSms`。

2. 重点搜索前端加解密逻辑：
   - `encryptDataSm4` / `decryptDataSm4`
   - `doEncryptSm2` / `doDecryptSm2`
   - `sm4` / `sm2`
   - 硬编码 key，例如 `strToString16("...")`

3. 如果 webpack 模块没有暴露到 `window`，可在浏览器环境中重新注入主包并暴露 require，复用前端自己的加解密函数：

```javascript
let js = await fetch('/static/js/index.<hash>.js').then(r => r.text());
let injected = js.replace('function n(n){', 'window.__wp_require=s;function n(n){');
let s = document.createElement('script');
s.textContent = injected;
document.documentElement.appendChild(s);
await new Promise(r => setTimeout(r, 300));
let cryptoMod = window.__wp_require('<module_id>');
```

在实战中 `<module_id>` 可能是包含 `encryptDataSm4/decryptDataSm4` 的模块，如 `46fa`；需从 JS 中搜索确认。

4. 验证硬编码 SM4 key 是否能解密后端返回：
   - 访问公开接口，如 `/server/user/info`、`/server/home/config`、`/server/auth/casConfig`。
   - 若返回形如 `{"data":"base64..."}` 且 `success` 不为 true，尝试 `decryptDataSm4(data)`。
   - 只有解出真实敏感数据/配置/用户信息，才可作为信息泄露证据；若只是失败信息，不提交。

5. 验证 `auth/getEncrypt` + SM2 请求加密链：
   - 部分系统会先调用 `/server/auth/getEncrypt` 获取 `id` 和 SM4 加密的 `publicKey`。
   - 前端使用硬编码 SM4 key 解密 `publicKey`，再用 SM2 加密业务参数为 `{id, params}`。
   - 注意：并非所有接口都走加密链。应从前端 `x=/^(?:...)/` 这类正则确认哪些方法需要加密。
   - 不要盲目把所有接口参数都包成 `{id, params}`，否则可能只得到“参数不能为空”。

6. 重点高价值接口：
   - `/server/auth/getToken`：是否可通过 `openId/orgId/schoolCode/code` 获取 accessToken。
   - `/server/user/info`：是否可未授权或伪造 token 读取用户信息。
   - `/server/user/tradeList`、`/server/user/tradeInfo`：是否可越权读取交易记录。
   - `/server/card/cardList`、`/server/card/reportLoss`、`/server/card/cancelLoss`：是否可越权操作校园卡。
   - `/server/user/password/checkIdentityNo`、`/server/user/password/resetPwd`：是否存在账号枚举/重置绕过。
   - `/server/home/sendSms`：是否可绕过图形/滑块验证码触发短信。
   - `/server/captcha/get`、`/server/captcha/check`：是否存在 token 复用、pointJson 可预测、前端 secretKey 可用于离线计算。

## 判定边界

可提交：
- 未登录/低权限获取真实用户信息、交易记录、卡列表、余额、手机号、身份证/学号等。
- 可越权挂失/解挂/改密码/换绑手机号/发起支付或退款。
- 可绕过验证码真实触发短信，且有接收或响应成功证据。
- 前端硬编码密钥 + 可解密敏感业务数据，或可伪造加密请求完成越权。

不可单独提交：
- 仅发现硬编码 SM4 key，但只能解密失败信息。
- `/auth/getEncrypt` 未授权返回临时公钥/id，但不能访问敏感接口。
- `/home/sendSms` 未登录可访问但被图形验证码阻断。
- `/captcha/get` 可获取验证码图片/secretKey，但不能通过 check 或触发业务动作。
- nginx/前端 JS 版本、接口 200 返回“失败”等弱信息。

## 复现证据建议

报告前必须形成闭环：
1. 来源：前端 JS 中接口和加密逻辑位置。
2. 构造：用前端同款 SM4/SM2 函数生成请求或解密响应。
3. 结果：接口返回真实业务数据或真实操作成功。
4. 对照：无 token/错误 token/不同用户 ID 对照，证明认证或越权问题。
5. 清理：若触发短信、挂失、绑定、支付等副作用，必须使用低影响测试账号并及时恢复。

## cdp.edu.cn 会话要点（2026-05）

`yikatong.cdp.edu.cn` 是 uni-app 校园卡系统，前端发现：
- baseUrl: `/server`
- 硬编码 SM4 key: `w687-9+3C_H&je_5`
- 加解密模块导出：`doEncryptSm2`、`decryptDataSm4`、`encryptDataSm4`
- `/server/auth/getEncrypt` 对多个 code 返回 `success:true` 和加密 publicKey。
- `/server/user/info` 未登录返回加密 data，但解密后只是失败信息。
- `/server/home/sendSms` 有图形验证码前置。
- `/server/captcha/get` 可返回 blockPuzzle/clickWord 图片、token、secretKey。

### CDP 复测补充（2026-05-22）

本轮进一步确认该类系统的“硬编码 SM4 key / getEncrypt 公开 / captcha/get 公开”不能单独作为可提交漏洞，必须闭环到真实数据或真实操作：

- 入口资源：`/static/config/index.js` 暴露 `baseUrl='/server'`；主包如 `/static/js/index.<hash>.js` 和 `chunk-vendors.<hash>.js` 可枚举 `/server/user/*`、`/server/card/*`、`/server/merchant/*`、`/server/home/sendSms`、`/server/captcha/get` 等接口。
- 硬编码 SM4 key 可用 OpenSSL 复核服务端加密响应：key 字符串 `w687-9+3C_H&je_5` 的十六进制为 `773638372d392b33435f48266a655f35`，解密命令形态：`printf '%s' '<base64-data>' | base64 -d > /tmp/enc.bin; openssl enc -d -sm4-ecb -K 773638372d392b33435f48266a655f35 -in /tmp/enc.bin`。
- 对 `GET /server/user/info -H 'Authorization: invalid'` 返回的 `data` 解密后仅为 `{"code":"","message":"失败","success":false}`，不是用户数据；这种情况不能按敏感信息泄露提交。
- `POST /server/auth/getEncrypt {"code":"10051"}` 返回 `success:true`、临时 `id/publicKey/fixed:false`，只是加密辅助流程；即使多个 code 都能返回临时公钥，也不能证明认证绕过。
- `POST /server/captcha/get {"captchaType":"blockPuzzle"}` 或 `clickWord` 可返回验证码图片和 `secretKey`，但只有进一步证明 `captcha/check` 可离线计算/复用并真实触发 `/home/sendSms` 或账号操作时，才值得报告。
- `POST /server/home/sendSms` 空参会提示手机号、orgId、imgCode、imgCodeId 必填；构造 dummy 参数返回“图形验证码不正确”。这证明验证码前置有效，不能写短信接口未授权。

后续 CDP/同类一卡通系统的投入条件：
1. 有合法测试账号后验证 `/user/tradeList`、`/card/cardList`、`/card/reportLoss`、`/card/cancelLoss`、`/user/password/resetPwd` 是否存在 IDOR/越权；
2. 证明 `captcha/check` 可绕过/复用并触发短信或账号敏感操作；
3. 用硬编码 key 解出真实用户、交易、卡片、余额等敏感业务数据。

该会话没有形成可提交漏洞，后续应继续沿 token 获取、验证码绕过、校园卡交易/挂失越权方向深挖。

### CDP 负向验证证据包（2026-05-22）

新增详细记录见 `references/cdp-yikatong-negative-20260522.md`。后续复测该目标或同类 yikatong 系统时，先对照该证据包避免重复把以下内容误报：
- `auth/getEncrypt` 公开返回临时 `id/publicKey`；
- `captcha/get` 公开返回 `token/secretKey/图片`；
- `home/sendSms` 被图形验证码阻断；
- `user/password/checkIdentityNo` 未授权返回 401；
- `user/info` 无效 token 的加密响应解密后只是失败对象。

实战提示：该目标使用 `curl --noproxy '*' --connect-timeout 3 --max-time 10` 复测关键接口更稳定；这只是该目标的证据采集模式，不应泛化为工具不可用。