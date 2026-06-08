# 360 SRC / 中关村银行注册链实战记录 (2026-05-19)

适用技能: `src-vuln-hunting`

## 目标
- 厂商: 北京中关村银行
- 业务面: 采购管理系统供应商注册链
- 主域: `pms.zgcbank.com`
- 注册页: `https://pms.zgcbank.com/pms/ananymous/jyzt/zc/gyszc`

## 已确认接口
从公开注册页源码可直接提取:
- `/pms/ananymous/jyzt/zc/checkDlh`
- `/pms/ananymous/jyzt/zc/checkZtmc`
- `/pms/ananymous/jyzt/zc/checkZtdmByZc`
- `/pms/ananymous/jyzt/zc/checkyqm`
- `/pms/ananymous/jyzt/zc/checkSjYzm`
- `/pms/ananymous/jyzt/zc/checkYzm`
- `/pms/ananymous/jyzt/zc/getEmailSession`
- `/pms/ananymous/jyzt/zc/sendEmailYzm`
- `/pms/ananymous/jyzt/zc/saveJc_ztbzt`
- `/pms/ananymous/jyzt/zc/getJc_ztbzt`
- `/pms/ananymous/jyzt/zc/viewZtxy`

## 核心发现 1: 未授权注册前校验接口开放
在访问公开注册页后，仅凭页面返回的 `SESSION` 与 `_csrf`，可未登录调用多个注册前业务校验接口:
- `checkDlh` → `{"text":"操作成功！","state":1,"data":{"flag":true}}`
- `checkZtmc` → `{"text":"操作成功！","state":1,"data":{"flag":true}}`
- `checkZtdmByZc` → `{"text":"操作成功！","state":1,"data":null}`

可用于账号/主体名称/统一社会信用代码探测。

## 核心发现 2: 伪 CSRF 防护 / 请求头 Token 未被强制校验
### 预检对照
无 Cookie、无 CSRF 参数时:
- `checkYzm` → `403 Invalid CSRF Token.`
- `checkDlh` → `403 Invalid CSRF Token.`

### 绕过验证
只带公开页拿到的 `SESSION` + 表单参数 `_csrf`，**不发送 `X-CSRF-TOKEN` 请求头** 时，以下接口仍成功处理:
- `checkDlh` → `200` + 成功 JSON
- `checkZtmc` → `200` + 成功 JSON
- `checkZtdmByZc` → `200` + 成功 JSON
- `checkyqm` → `200` + `{"text":"操作成功！","state":1,"data":false}`
- `checkSjYzm` → `200` + `false`

结论: 系统表面启用了 CSRF 防护，但核心注册前校验接口并未强制依赖请求头中的 `X-CSRF-TOKEN`，可被公开页参数组合绕过。

## 核心发现 3: 登录页短信验证码接口可未登录触发任意手机号发送
登录页 `https://pms.zgcbank.com/pms/j_form/gysloginpath` 中的“点击获取”调用 `/pms/ananymous/jyzt/zc/checkSjh`。前端要求填写账号和手机号，但后端只带公开页面的 `SESSION` + `_csrf` 即可处理 `sjh` 参数，未强制校验账号/手机号绑定关系。

验证结果:
- 无 Cookie/无 CSRF → `403 Invalid CSRF Token.`
- 有公开登录页 `SESSION` + `_csrf`，不带登录态 → `200 {"text":"操作成功！","state":1,"data":null}`
- 同会话重复调用 → `200 {"text":"短信验证码发送间隔至少2分钟","state":2,"data":null}`，证明进入真实短信发送业务逻辑。

截图位置建议:
- 【截图位置1】登录页源码中 `j_usersjh` 与 `/pms/ananymous/jyzt/zc/checkSjh` 来源
- 【截图位置2】无 Cookie/CSRF 对照返回 403
- 【截图位置3】带公开 SESSION/CSRF 调用任意手机号返回“操作成功”
- 【截图位置4】重复调用返回“短信验证码发送间隔至少2分钟”

## 核心发现 4: 忘记密码 confirmAccount 可枚举账号并泄露绑定手机号掩码
忘记密码入口 `https://pms.zgcbank.com/pms/ananymous/zzqx/zhmm` 的 `/confirmAccount` 只需公开页面 `SESSION`、`_csrf` 与 `_ResubmitToken` 即可查询任意登录号是否存在；存在账号返回 `{"text":"操作成功！","state":1,"data":"<登录号>"}`。随后 POST `/valiYzm` 可进入验证方式页面，页面直接展示绑定手机号掩码，如 `130****2741`。

验证结果:
- `dlh=admin` → `200 {"text":"操作成功！","state":1,"data":"admin"}`
- `dlh=13800138000` → `200 {"text":"操作成功！","state":1,"data":"13800138000"}`
- 进入下一步页面可看到 `手机验证码已发送至您的手机130****2741` / `id="sjhYc" value="130****2741"`

注意: 未证明可绕过短信验证码重置密码；报告应定位为“账号枚举+绑定手机号掩码泄露/找回密码流程权限控制缺失”，不要夸大为账号接管。
## 核心发现 5: 找回密码流程可账号枚举并泄露绑定手机号掩码
找回密码入口 `https://pms.zgcbank.com/pms/ananymous/zzqx/zhmm` 的流程不应与注册链验证码发送类问题重复提交；它是不同业务链（密码找回）和不同影响（账号存在性 + 绑定手机号掩码泄露）。

关键接口:
- `/pms/ananymous/zzqx/zhmm/confirmAccount`
- `/pms/ananymous/zzqx/zhmm/valiYzm`

验证要点:
1. 先 GET `/pms/ananymous/zzqx/zhmm`，提取公开会话 Cookie、`_csrf`、`_ResubmitKey`、`_ResubmitToken`。
2. `confirmAccount` 必须使用全新页面会话/ResubmitToken；同一 token 重复提交会返回 `{"text":"重复提交！","state":4}`，不要误判为不可利用。
3. 成功样例：`dlh=admin` 返回 `{"text":"操作成功！","state":1,"data":"admin","_ResubmitToken":null}`，证明未登录确认账号。
4. 继续 POST `/pms/ananymous/zzqx/zhmm/valiYzm` 可进入身份验证页面；页面显示 `手机验证码已发送至您的手机130****2741`，并包含隐藏字段 `id="sjhYc" value="130****2741"`，证明绑定手机号掩码泄露。
5. 报告定位为“账号枚举 + 绑定手机号掩码泄露/找回密码流程权限控制缺失”，不要夸大为账号接管；除非后续证明可绕过短信验证码重置密码。

截图位置建议:
- 【截图位置1】公开找回密码页面源码中的 `confirmAccount` 与 `valiYzm` 接口来源。
- 【截图位置2】未登录调用 `confirmAccount` 验证 `admin` 返回 `state=1,data=admin`。
- 【截图位置3】全新会话下测试其他登录号/手机号返回结构化业务结果，证明枚举入口。
- 【截图位置4】未登录进入 `valiYzm` 身份验证页面，显示绑定手机号掩码。

## 已排除/不要重复提交的点
- `saveJc_ztbzt`：在补齐 `_ResubmitKey/_ResubmitToken` 后返回“系统异常”，未证明跨会话写入/越权。
- `getJc_ztbzt`：返回 `{"text":"操作成功！","state":1,"data":null}`，未拿到他人草稿或敏感数据。
- `getEmailSession` / `sendEmailYzm`：返回系统异常页，未证明能实际发信或被滥用。
- 企业网银本地安全组件：未发现 loopback、本地升级链、来源校验缺失，不足以报高危。
- H5: `/isec/getServerRandom.do` 与 `/isec/keyAgreement.do` 允许 POST，但真实业务 basePath 未锁定；`/accountCheck`、`/mobileApp` 在已测路径下 404。

## 关键复现命令注意事项
- 提取 SESSION 的正则必须是:
  `SESSION=[^;]*`
- 错误写法 `SESSION=[^;]` 只会得到一个字符，例如 `SESSION=N`
- 给用户的 curl 命令必须保持**单行**，否则终端复制粘贴容易出错

## 报告写作建议
### 版本 A（较弱）
“供应商注册链未授权校验接口漏洞”

### 版本 B（更强，推荐）
“供应商注册链多处核心校验接口CSRF校验绕过漏洞”

更强原因:
1. 能证明系统确实启用过防护（403 对照）
2. 能证明防护存在稳定绕过
3. 覆盖多个真实业务接口，不是单点异常

## 截图位置建议
- 【截图位置1】公开注册页源码中提取 `_csrf` 与真实接口路径
- 【截图位置2】无 Cookie/无 CSRF 时返回 `403 Invalid CSRF Token`
- 【截图位置3】`checkDlh` 无 `X-CSRF-TOKEN` 头仍成功
- 【截图位置4】`checkZtmc` 无 `X-CSRF-TOKEN` 头仍成功
- 【截图位置5】`checkZtdmByZc` 无 `X-CSRF-TOKEN` 头仍成功
- 【截图位置6】`checkyqm` 或 `checkSjYzm` 无 `X-CSRF-TOKEN` 头仍可调用
