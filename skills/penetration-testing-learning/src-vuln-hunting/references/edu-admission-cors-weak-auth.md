# 高校招生系统：录取查询/通知书接口 CORS + 弱鉴权审计模式

适用场景：高校招生、录取查询、迎新、通知书下载、ZFSOFT/正方招生系统等目标，页面中出现 `录取结果查询`、`姓名`、`身份证号`、`考生号`、`准考证号`、`EMS单号`、`xslqcx.zf`、`lqtzsmb`、`tzsdy` 等特征。

## 关键学习

本类系统常见漏洞不是单独的“CORS配置错误”，而是组合风险：

1. 前台招生业务接口未登录可访问，进入业务逻辑而非返回 401/403 或 CAS/统一认证跳转。
2. 响应头反射任意 `Origin`，且同时设置 `Access-Control-Allow-Credentials: true`。
3. 业务对象涉及录取结果、考生姓名、证件号、考生号、准考证号、EMS 单号、通知书/模板等敏感招生信息。

这种组合可以作为候选报告，但定级和措辞必须保守：如果没有读取到真实考生数据，不能夸大为“数据泄露已发生”；应表述为“敏感业务接口弱鉴权 + CORS 任意来源信任，存在跨域读取和枚举利用风险”。

## 低影响验证流程

1. 从招生门户提取高价值入口。
   - 关注 `zsb`、`zsbxt`、`zsxt`、`yingxin` 等子域。
   - 从首页 href/JS 中搜索：`录取`、`查询`、`xslqcx`、`lqcx`、`ksh`、`sfzh`、`zkzh`、`tzs`、`lqtzs`。

2. 获取录取查询页面，确认字段和接口来源。
   - 页面出现 `姓名`、`身份证号`、`考生号`、`准考证号`、`EMS单号` 时，记录为敏感业务入口。
   - JS 中常见端点：
     - `/zsxt/tzgl/xslqcx/judgeKaptcha.zf?yzm=`
     - `/zsxt/tzgl/xslqcx/xslqxx.zf?xm=...&sfzh=...`
     - `/zsxt/tzgl/xslqcx/xslqxxNew.zf?xm=...&sfzh=...`
     - `/zsxt/tzgl/xslqcx/getSslqxxListAjax.zf`

3. 用明显测试值做非破坏性业务逻辑确认。
   - 示例：`xm=测试&sfzh=000000000000000000`。
   - 若返回“没有你的录取信息/暂未查询到录取信息”，说明进入业务查询逻辑。
   - 若返回 CAS 登录页、401、403，说明鉴权正常，不要报。

4. 检查通知书/模板相关接口是否未登录可访问。
   - 常见接口：
     - `/zsxt/xtgl/lqtzsmb/xzlqtzs.zf?ksh=00000000000000&mbid=1`
     - `/zsxt/tzgl/tzsdy/cxdymb.zf?ksh=00000000000000&zsnd=2026`
   - 只使用明显无效的测试 `ksh`，不要批量枚举真实考生号。
   - 若页面返回“录取通知书下载”“模板打印”并含模板字段如 `{model.xm}`、`姓名`、`学生，请持此通知书于`，可作为弱鉴权证据。

5. 检查 CORS 任意 Origin 回显。
   - 对业务接口加：`Origin: https://evil.example`。
   - 若响应头包含：
     - `Access-Control-Allow-Origin: https://evil.example`
     - `Access-Control-Allow-Credentials: true`
   - 则记录为组合风险证据。

## 单行 curl 模板

录取查询入口：
`curl -k -i 'https://TARGET/zsxt/tzgl/xslqcx/xslqcx.zf'`

录取查询业务逻辑：
`curl -k -i 'https://TARGET/zsxt/tzgl/xslqcx/xslqxx.zf?xm=%E6%B5%8B%E8%AF%95&sfzh=000000000000000000'`

通知书下载页：
`curl -k -i 'https://TARGET/zsxt/xtgl/lqtzsmb/xzlqtzs.zf?ksh=00000000000000&mbid=1'`

模板打印页：
`curl -k -i 'https://TARGET/zsxt/tzgl/tzsdy/cxdymb.zf?ksh=00000000000000&zsnd=2026'`

CORS 验证：
`curl -k -i -H 'Origin: https://evil.example' 'https://TARGET/zsxt/tzgl/xslqcx/xslqxx.zf?xm=%E6%B5%8B%E8%AF%95&sfzh=000000000000000000'`

通知书接口 CORS 验证：
`curl -k -i -H 'Origin: https://evil.example' 'https://TARGET/zsxt/tzgl/tzsdy/cxdymb.zf?ksh=00000000000000&zsnd=2026'`

## 报告门槛

可提交条件：
- 至少一个招生业务查询/通知书/模板接口未登录进入业务逻辑；
- 至少一个同类敏感业务接口反射任意 Origin 且 `Credentials=true`；
- 页面或响应能证明业务对象确实涉及考生录取/证件号/EMS/通知书；
- 报告中明确说明没有批量枚举真实考生，避免被认为撞库。

不建议提交：
- 只有普通 CORS 反射，没有敏感业务接口可读；
- 只有公开招生公告/录取分数线页面；
- 只有验证码接口返回 fail；
- 只有 500 栈、Tomcat 版本、登录页 DES/lt 等低价值信息；
- 业务接口虽然 200，但实际返回登录页/统一认证页/SPA 壳。

## 定级与措辞

没有真实考生数据时：中危或低危到中危之间，按平台口径选择。标题建议：
`某高校招生管理系统存在 CORS 任意来源信任叠加录取/通知书相关接口弱鉴权风险`

不要写：
- `大量考生信息泄露`（除非实际读取到真实数据且合规脱敏）
- `可任意下载录取通知书`（除非有真实 ksh/mbid 绑定绕过证据）
- `高危越权`（除非证明不同身份/对象的权限边界被绕过）

## 后续深挖方向

- 授权/合法样本下验证 `ksh`、`mbid`、`zsnd` 是否存在 IDOR；
- 验证通知书下载是否绑定当前会话/考生身份；
- 检查是否有批量查询、验证码绕过、短信/邮件通知触发接口；
- 如可获取真实数据，必须只取最小样本并脱敏，避免批量拉取。
