# BZUU Druid Monitor 登录页暴露 + CORS 负证据模式（2026-06-05）

适用范围：教育 SRC 黑盒续挖中，发现 Spring/Druid Monitor 登录页公网可访问、CORS 反射、302 泄露内网地址时的提交流程判断。

## 触发场景

目标：亳州学院 bzuu.edu.cn / oshall.bzuu.edu.cn 智慧校园 rhpt 微服务。

命中路径：

- `/zhxyApi/rhpt-system/druid/login.html`
- `/zhxyApi/rhpt-interface/druid/login.html`
- `/zhxyApi/rhpt-applets/druid/login.html`
- `/zhxyApi/rhpt-workhall/druid/login.html`

现象：

- 登录页返回 200，标题 `druid monitor`。
- 登录表单含 `loginUsername`、`loginPassword`、`submitLogin`。
- `Origin: https://evil.example` 时返回：
  - `Access-Control-Allow-Origin: https://evil.example`
  - `Access-Control-Allow-Credentials: true`
- `basic.json` / `datasource.json` / `sql.json` 返回 302 到内网地址：
  - `http://10.10.36.107:21668/druid/login.html`
  - `http://10.10.36.107:21665/druid/login.html`
  - `http://10.10.36.107:21663/druid/login.html`
  - `http://10.10.36.107:21669/druid/login.html`

## 必做验证

1. 验证登录页是否只是公开登录面：

`curl -4 --http1.1 -sk -D- 'https://TARGET/zhxyApi/rhpt-system/druid/login.html' -H 'Origin: https://evil.example'`

2. 验证监控 JSON 是否未授权可读：

`curl -4 --http1.1 -sk -D- -o /tmp/druid_basic.body 'https://TARGET/zhxyApi/rhpt-system/druid/basic.json' -H 'Origin: https://evil.example'`

`curl -4 --http1.1 -sk -D- -o /tmp/druid_datasource.body 'https://TARGET/zhxyApi/rhpt-system/druid/datasource.json' -H 'Origin: https://evil.example'`

`curl -4 --http1.1 -sk -D- -o /tmp/druid_sql.body 'https://TARGET/zhxyApi/rhpt-system/druid/sql.json' -H 'Origin: https://evil.example'`

3. 验证默认/空口令，但保持低频：

- 空用户名/空密码
- `admin/admin`
- `druid/druid`

若 POST `/submitLogin` 返回 `error` 且后续 `basic.json` 仍 302 到登录页，判定为未登录保护正常。

## 提交门槛

只有满足以下任一条件才考虑提交：

- 无需登录直接读取 `basic.json` / `datasource.json` / `sql.json`，且包含 JDBC URL、数据库用户名、连接池、SQL 统计、慢 SQL、内部接口等敏感信息。
- 发现有效弱口令或会话绕过，并能读取 Druid 监控数据。
- CORS 能跨域读取登录后的敏感 JSON（需要合法低权登录态或授权账号验证）。
- Druid 暴露可链到实际数据库、SQL、服务配置或认证绕过，而不是只有登录页/302/内网 IP。

## 不建议提交的情况

以下只作为低危线索或补充情报，不按“实质漏洞”提交：

- 只有 Druid 登录页公网可访问。
- 只有 CORS 反射登录页 + Credentials=true，但敏感 JSON 均 302 到登录页。
- 只有 `Location: http://10.x.x.x:port/druid/login.html` 内网地址泄露。
- 默认/空口令验证失败。
- `actuator/*` 返回 403，`druid/*` 返回登录页或 302。

## 报告判断话术

可记录为：

“Druid Monitor 登录面公网暴露，并在未登录访问监控 JSON 时通过 302 泄露后端内网地址；同时登录页 CORS 反射任意 Origin。但核心监控接口均需登录，默认/空口令失败，未读取到 JDBC、SQL、连接池或数据源敏感信息。因此不建议按实质漏洞提交。”

## 经验要点

- Druid 登录页暴露不等于 Druid 未授权。
- CORS 反射只有在能读敏感数据或登录态数据时才有提交价值。
- `Location` 泄露内网地址通常只是低危信息泄露，教育 SRC 通过率低。
- 同一 rhpt 微服务多个 Druid 登录页属于同根因，应合并判断，不拆多份报告。
