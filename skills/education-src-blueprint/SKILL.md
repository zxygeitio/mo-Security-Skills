---
name: education-src-blueprint
description: "教育SRC漏洞挖掘蓝图 — 目标筛选→漏洞类型优先级→利用验证→报告质量门禁→提交决策树。详细历史案例已拆到 references。"
tags: [education, src, butian, cas, ehall, wisedu, lyuap, report-gate]
---

# 教育 SRC 蓝图轻量入口

## 适用场景

- 目标是高校、学院、教育集团、教育局、智慧校园、CAS/统一身份认证、办事大厅、教务、OA、招生、邮箱、VPN/WebVPN。
- 用户要求提高教育 SRC 通过率、减少低价值报告、定位可提交实质漏洞。
- 需要把教育目标的大量子域快速分流为值得深挖的业务系统。

## 核心判断

教育 SRC 最常见失败原因不是“没扫到东西”，而是把低价值信息泄露当漏洞提交。必须优先找能证明业务影响的漏洞：账号/身份/学生或教职工数据、办事流程、成绩/课程/缴费/一卡通、后台管理、文件上传下载、CAS ticket/service、API Key 可用性。

## 优先级矩阵

- P0/P1：CAS 认证绕过、CAS Open Redirect 可窃 ticket、越权读取学生/教职工数据、未授权管理 API、SQLi/RCE、文件上传可访问、AppSecret/API Key 可调用敏感接口。
- P1/P2：CORS 读取登录态敏感接口、验证码/找回密码逻辑缺陷、用户枚举带稳定差异、Swagger/Actuator 暴露且可调用敏感功能、OA API 未授权。
- P3/不报：安全头缺失、jQuery/中间件版本、robots、普通登录页、盐值/JSESSIONID 单独泄露、无敏感数据 CORS、SUDY 后台 IP、站点地图/通知公告、SPA fallback 假 200。

## 教育目标分流

1. 先看核心入口：`auth`/`authserver`/`cas`/`sso`/`ids`/`one`/`ehall`/`portal`/`jw`/`oa`/`webvpn`/`vpn`/`mail`/`ecard`/`pay`。
2. 识别供应商：金智/Wisedu、联奕/Lianyi、Apereo CAS、泛微、致远、SUDY、VSB、强智、正方、青果。
3. 对高价值入口生成小批 URL，交给 `src-http-probe.py --control --dedupe`，再由 `src-quality-gate.py` 过滤假阳性。
4. 5 分钟内没有 P0/P1 候选则换入口；不要在新闻站、静态站、纯门户上耗时。

## 标准执行

```bash
/usr/bin/python3 /root/.hermes/scripts/src-fast-assess.py example.edu.cn --out /tmp/src_assess_example
/usr/bin/python3 /root/.hermes/scripts/src-practical-next.py /tmp/src_assess_example --out /tmp/src_assess_example/next.md --json-out /tmp/src_assess_example/next.json
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py /tmp/src_assess_example /tmp/src_assess_example/urls.txt --timeout 8 --control --dedupe
/usr/bin/python3 /root/.hermes/scripts/src-quality-gate.py /tmp/src_assess_example/probe_results.tsv --out /tmp/src_assess_example/quality_gate.md --json-out /tmp/src_assess_example/quality_gate.json
```

说明：命令是模板，正式目标根据 `next.md` 选 5-20 个高价值 URL 建 `urls.txt`，不要全量盲打。

## CAS 专项门禁

- Open Redirect：必须证明 `service` 接受外域/危险 scheme，并说明 ticket 风险；最好用安全接收域演示跳转链。
- 用户枚举：必须有存在/不存在账号稳定差异，且低频验证；不要爆破。
- 验证码缺陷：证明服务端未校验或验证码明文可复用；客户端校验本身不一定可提交。
- 盐值泄露：单独低价值；必须链到密码加密绕过、撞库增益或其他实质影响。
- CORS：必须证明浏览器可读登录态敏感接口；只有预检反射但无敏感读取通常低危或不报。

## 报告质量门禁

提交前必须满足：

- 重新执行 PoC 成功，响应内容与报告一致。
- 有对照组：无效 token、随机路径、不存在 ID、未登录态、不同 Origin 或不同账号。
- 有证据落盘：headers/body/curl/截图位置。
- 无历史重复：查 `session_search` 与 `/tmp/vuln_reports`。
- 字段完整：标题/域名/类型/等级/行业/精确到区地址/URL/详情/复现/影响/修复。
- 不能夸大：无法证明数据访问、越权或攻击结果时，写“不建议提交”。

## 常见反驳清单

- 这是公开信息还是敏感业务数据？
- 是否只是登录页、错误页、WAF 页、SPA fallback？
- 是否有随机不存在路径对照？
- 是否有鉴权对照或不同账号对照？
- 是否只是版本/CVE 猜测，未验证适用？
- 是否同根因已提交？
- 是否超出教育 SRC 授权范围？

## Reference 路由

- 完整旧版技能全文：`references/legacy-full-skill-2026-06-08.md`
- 教育供应商指纹和专项案例：见 `src-vuln-hunting` skill 的 `references/edu-vendor-fingerprinting.md`
- CAS 专项：见 `src-vuln-hunting` skill 的 `references/cas-vuln-testing-patterns.md`、`references/wisedu-cas-testing-patterns.md`
- 低价值不提交：见 `src-vuln-hunting` skill 的 `references/education-portal-api-no-submit-gate.md`
- 高危利用：见 `src-vuln-hunting` skill 的 `references/high-severity-exploitation-patterns.md`

## 相关技能

- `global-control`：系统总控与工具健康检查。
- `src-vuln-hunting`：SRC 通用流程、证据门禁和报告规范。
- `web-pentest-fast`：外网 Web 快速测试入口。
- `exploit-chain`：从低价值线索升级为业务攻击链。
