# 招生录取查询系统 CORS + 未授权 API 审计模式（西安明德理工学院实战）

适用场景：高校招生录取查询、录取进程查询、信息配置类前台系统，尤其是 Vue/webpack SPA 暴露 `/unauth/zsdata/*`、`/lqxx/s/api/front/*` 等接口。

## 触发指纹
- 前端入口类似：`/unauth/zsdata/lqxx/#/`
- 主 JS 中可提取：`baseURL:"https://<host>/lqxx/s"`
- API 路径包含：
  - `/api/front/infoconfig/getDqnf`
  - `/api/front/infoconfig/getMrsf`
  - `/api/front/infoconfig/getlqcxrq`
  - `/api/front/infoconfig/getTheme`
  - `/api/front/lqxx/lqjc`
  - `/api/front/lqxx/lqcx`

## 验证流程

1. 从前端 JS 提取 baseURL 和接口路径：

```bash
curl -sk "https://TARGET/unauth/zsdata/lqxx/js/app.HASH.js" | grep -aoE 'baseURL.{0,120}|/api/front/[A-Za-z0-9_/]+' | head -30
```

2. 测试录取进程接口是否未授权，并验证 CORS 是否反射任意 Origin：

```bash
curl -sk -D- -X POST "https://TARGET/lqxx/s/api/front/lqxx/lqjc" -H "Content-Type: application/json" -H "Origin: https://evil.example" -d "{}"
```

成立证据：HTTP 200 + JSON 业务数据 + `Access-Control-Allow-Origin: https://evil.example` + `Access-Control-Allow-Credentials: true`。

3. 测试配置接口：

```bash
curl -sk -D- -X POST "https://TARGET/lqxx/s/api/front/infoconfig/getTheme" -H "Content-Type: application/json" -H "Origin: https://evil.example" -d "{}"
curl -sk -X POST "https://TARGET/lqxx/s/api/front/infoconfig/getDqnf" -H "Content-Type: application/json" -H "Origin: https://evil.example" -d "{}"
curl -sk -X POST "https://TARGET/lqxx/s/api/front/infoconfig/getMrsf" -H "Content-Type: application/json" -H "Origin: https://evil.example" -d "{}"
curl -sk -X POST "https://TARGET/lqxx/s/api/front/infoconfig/getlqcxrq" -H "Content-Type: application/json" -H "Origin: https://evil.example" -d "{}"
```

常见敏感字段：当前招生年份、默认省份、查询开放时间、Logo/Banner/资源路径、录取批次、省份、校区、招生类别、层次、科类、发布状态、发布时间。

4. 测试录取查询接口校验逻辑：

```bash
curl -sk -D- -X POST "https://TARGET/lqxx/s/api/front/lqxx/lqcx" -H "Content-Type: application/json" -H "Origin: https://evil.example" -d '{"xm":"张三","sfzh":"610000200001010000"}'
curl -sk -X POST "https://TARGET/lqxx/s/api/front/lqxx/lqcx" -H "Content-Type: application/json" -d '{}'
```

若任意姓名+身份证号返回 `success:true`，但空参数返回“未填写必填信息”，可作为“后端会检查必填字段但未正确校验姓名/证件组合”的逻辑异常证据。

## 定级与报告边界

- 仅能读取录取进程、配置、开放时间等公共/半公开数据时，通常按中危或低中危表述，不要包装成真实考生数据泄露。
- 如果能枚举真实考生录取结果、身份证、手机号、通知书号、考生号等个人信息，可升级为高危未授权访问/IDOR。
- CORS 必须同时证明：任意 Origin 反射 + 可读取业务 JSON；若只是非法/失效 ACAO 值，不应按高危 CORS 写。
- `lqcx` 对任意输入返回 `success:true` 是业务逻辑异常，但必须谨慎表述为“查询流程可信度受影响/后端校验不足”，除非证明后续状态可展示真实录取信息。

## 报告写法要点

- 标题建议：`XXX学院招生录取查询系统存在跨域配置不当及未授权访问导致招生录取进程数据泄露`
- 截图位置：
  1. JS 中 baseURL 与 `/api/front/*` 接口路径同屏
  2. `lqjc` 请求、CORS 响应头、录取进程字段同屏
  3. `getTheme` 配置与 CORS 响应头同屏
  4. `getDqnf/getMrsf/getlqcxrq` 返回当前年份、默认省份、开放时间
  5. `lqcx` 任意姓名/身份证 success=true 与空参数失败对照
- 影响描述聚焦精准招生诈骗、伪造录取通知、冒充招生办社工，以及查询流程可信度受影响。

## 深挖方向

1. 搜索旧 JS / source map / 历史 hash，找后台接口、admin/manage/sys 路径或 token。
2. 检查 `/tdlqxxuserfiles/` 资源目录是否存在目录遍历、任意文件读取、上传接口或可执行文件渲染。
3. 枚举同套系统其他学校资产，确认是否通用供应商漏洞。
4. 对 `lqcx` 做低影响差异测试：字段缺失、身份证格式错误、年份/省份/批次参数组合，观察是否能触发真实结果字段，但不要批量枚举真实身份信息。
5. 若发现真实个人信息或录取结果，另起高危报告；否则将 CORS、未授权配置、逻辑异常合并一份，避免重复提交。
