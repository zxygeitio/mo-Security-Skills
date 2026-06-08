# 360 / ZGCBank 找回密码账号枚举与手机号掩码泄露

适用范围: 360 SRC 中 `pms.zgcbank.com` 北京中关村银行采购管理系统。

## 业务链
- 找回密码入口: `https://pms.zgcbank.com/pms/ananymous/zzqx/zhmm`
- 账号确认接口: `/pms/ananymous/zzqx/zhmm/confirmAccount`
- 身份验证页面: `/pms/ananymous/zzqx/zhmm/valiYzm`

## 关键结论
该问题不同于注册链验证码发送漏洞，不要合并为同一处提交。它属于找回密码流程权限控制缺失，核心影响是未登录可进入身份验证步骤并暴露绑定手机号掩码。

2026-05-20 复测修正: 不要把 `confirmAccount` 单独等同于“账号存在”。后续低频复测发现，`confirmAccount` 对明显占位登录号（如 `nosuch360test999`）也可能返回 `state=1`，并且继续 `valiYzm` 后仍显示手机号掩码。因此未来报告中若要写“账号枚举”，必须补充真实存在账号与随机不存在账号的稳定差异证据；若不存在稳定差异，应删除“账号枚举”字样，改为“找回密码流程权限控制缺失导致手机号掩码泄露/验证流程可未授权触发”。

## 复现要点
1. GET `/pms/ananymous/zzqx/zhmm` 获取普通公开会话与表单参数：`SESSION`、`_csrf`、`_ResubmitKey`、`_ResubmitToken`。
2. POST `/pms/ananymous/zzqx/zhmm/confirmAccount`，参数包含 `dlh` 与上述 token。
3. 成功响应样例：
   - `dlh=admin` -> `{"text":"操作成功！","state":1,"data":"admin","_ResubmitToken":null}`
4. 注意同一 `_ResubmitToken` 重复提交会返回：
   - `{"text":"重复提交！","state":4,"data":null,"_ResubmitToken":null}`
   这是一次性提交 token 的正常行为，不代表漏洞不存在；测试不同账号时应重新 GET 页面获得全新 token。
5. 在同一会话中 POST `/pms/ananymous/zzqx/zhmm/valiYzm` 可进入身份验证页面。
6. 页面会出现绑定手机号掩码，例如：
   - `手机验证码已发送至您的手机130****2741`
   - `id="sjhYc" class="form-control" value="130****2741"`

## 报告边界
- 可报: 找回密码流程权限控制缺失导致绑定手机号掩码泄露 / 验证流程可未授权触发。
- 谨慎表述: 不要仅凭 `confirmAccount state=1` 写“账号枚举”；必须先证明真实存在账号与随机不存在账号存在稳定差异。
- 不要夸大: 未证明短信验证码绕过或密码重置成功前，不写账号接管。
- 风险建议: 中危；若后续证明可绕过验证码重置密码，再升级为高危/严重。

## 截图建议
1. 公开找回密码页面源码中的 `confirmAccount` 与 `valiYzm`。
2. 未登录调用 `confirmAccount` 验证 `admin` 返回 `state=1,data=admin`。
3. 全新 token 下测试其他登录号/手机号返回结构化业务结果。
4. 未登录进入 `valiYzm` 页面显示绑定手机号掩码。
