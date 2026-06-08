---
name: src-vuln-hunting
description: >-
  SRC(Security Response Center)公益漏洞挖掘全流程入口 — 目标快筛、攻击假设、证据门禁、实质漏洞报告。详细历史案例和 payload 已拆到 references。
domain: cybersecurity
subdomain: vulnerability-management
tags:
- src
- butian
- cors
- idor
- apisix
- recon
- vulnerability
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1190
- T1078
- T1552
nist_csf:
- ID.RA-01
- DE.CM-01
---
# SRC 漏洞挖掘轻量入口

## 触发条件

- 用户要求 SRC、补天、漏洞盒子、企业/教育目标漏洞挖掘。
- 需要从域名/URL/JS/API/报告草稿中判断是否存在可提交漏洞。
- 需要把扫描候选转成可复现、可截图、可提交的实质漏洞证据。

## 硬原则

1. 只报告真实可利用漏洞：RCE、SQLi、认证绕过、越权、未授权敏感数据、可用密钥、上传闭环。
2. 扫描结果只是候选：Nuclei、Burp、HexStrike、脚本命中必须经过 the agent orchestrator复核。
3. 先建攻击假设：角色、数据对象、权限边界、业务流程、可控参数，再小批验证。
4. 每批最多 5-20 个高价值接口；请求/响应/header/body/curl/control 全部落盘。
5. WAF/SPA fallback/登录页/统一错误页/公开设计/同根因重复不能包装成报告。
6. CVE 必须确认版本适用性和最小 PoC，不得只列编号。
7. 报告前重新执行 PoC，确认当前仍可复现。

### 外部安全技能语料补强

当目标涉及 API/BOLA/IDOR/JWT/OAuth/SAML/CVE/KEV/云身份/供应链等主题，先用 Anthropic Cybersecurity Skills 外部索引召回 5-12 个相关程序素材，再回到 the AI agent 证据门禁验证：

```bash
/usr/bin/python3 /root/.the agent/scripts/anthropic-cyber-skills-router.py \
  --query '<target + attack hypothesis + tech stack>' \
  --limit 10
```

优先参考的外部模式：`testing-api-for-broken-object-level-authorization`、`testing-api-authentication-weaknesses`、`testing-jwt-token-security`、`exploiting-jwt-algorithm-confusion-attack`、`testing-api-security-with-owasp-top-10`、`performing-cve-prioritization-with-kev-catalog`、`analyzing-api-gateway-access-logs`。外部技能只补方法论和检查清单；是否可报仍由 `src-http-probe --control`、`src-quality-gate.py`、`src-think.py`、`src-evidence-gate.py` 的实证结果决定。


1. 基线和工具：先按 `global-control` 运行健康检查；需要扫描工具时跑 `/usr/bin/python3 /root/.the agent/scripts/pentest-control-plane.py health`。
2. 快筛资产：`/usr/bin/python3 /root/.the agent/scripts/src-fast-assess.py <domain> --out /tmp/src_assess_<domain>`。
3. 生成下一步：`/usr/bin/python3 /root/.the agent/scripts/src-practical-next.py <alive.txt|probe_results.tsv|src-fast-assess-outdir> --out /tmp/next.md --json-out /tmp/next.json`。
4. 推理假设：`/usr/bin/python3 /root/.the agent/scripts/src-think.py <workspace-or-artifacts> --out /tmp/src-think.md --json-out /tmp/src-think.json`，把 URL/API/JS/Burp/MITM 证据合成为业务对象、攻击假设、缺口、A/B 对照和≤20条验证命令；检查 `submit_readiness`：`READY_TO_VALIDATE` 才能小批验证，`NEED_MORE_EVIDENCE` 只补证，`NO_REPORT` 禁止写报告。
5. JS/API 提取：`/usr/bin/python3 /root/.the agent/scripts/src-js-api-extract.py <url-or-file> --out <workspace>`，只把高价值 API 投入验证。
6. 小批探测：`/usr/bin/python3 /root/.the agent/scripts/src-http-probe.py <workspace> urls.txt --timeout 8 --control --dedupe`。
7. 质量门禁：`/usr/bin/python3 /root/.the agent/scripts/src-quality-gate.py <workspace>/probe_results.tsv --out quality_gate.md --json-out quality_gate.json`。
8. 候选深挖：只有 `HAS_REPORTABLE_CANDIDATES` 或明确可补证的 `NEED_MORE_EVIDENCE` 继续；否则换目标/换假设。
9. 报告门禁：报告前执行去重、重放 PoC、截图标注、格式检查；历史报告查 `/tmp/vuln_reports` 和 `session_search`。

## 高价值优先级

- P0/P1：RCE、SQLi、认证绕过、IDOR/BOLA、任意文件上传、SSRF 到内网/云元数据、AppSecret/API Key 可调用敏感接口。
- P1/P2：未授权业务数据、CORS 读取登录态敏感接口、Swagger/Actuator 可调用敏感功能、找回密码/验证码逻辑缺陷。
- 低价值或不报：安全头缺失、版本号、robots、普通登录页、公开新闻/通知、盐值/JSESSIONID 单独泄露、无敏感数据的 CORS、SPA fallback 假 200。

## 真实性门禁

候选必须至少满足其中一类：

- 未授权 API：返回真实敏感业务数据，并有无效 token/随机 ID/不存在 ID 对照。
- IDOR：改 ID 返回不同归属对象，证明当前身份不应访问。
- 文件上传：返回 `fileUrl/resId/genName`，文件可访问，并证明实际业务影响。
- 密钥泄露：密钥/API Key/AppSecret 能调真实接口或换 token；修复时确认密钥轮换。
- CORS：浏览器可从攻击者 Origin 读取登录态敏感接口。
- Swagger/Actuator：证明敏感数据泄露或敏感接口可调用。

## 常用脚本入口

- `/root/.the agent/scripts/src-hypothesis-builder.py TARGET --scope <education|ai|hotel|iot|default> --outdir OUTDIR`
- `/root/.the agent/scripts/src-workspace-init.py`
- `/root/.the agent/scripts/src-fast-assess.py <domain>`
- `/root/.the agent/scripts/src-practical-next.py <artifact> --out next.md --json-out next.json`
- `/root/.the agent/scripts/src-think.py <workspace-or-artifacts> --out src-think.md --json-out src-think.json`
- `/root/.the agent/scripts/src-js-api-extract.py`
- `/root/.the agent/scripts/src-http-probe.py WORKSPACE urls.txt --timeout 8 --control --dedupe`
- `/root/.the agent/scripts/src-quality-gate.py WORKSPACE/probe_results.tsv --out quality_gate.md --json-out quality_gate.json`
- `/root/.the agent/scripts/src-evidence-gate.py CANDIDATE_DIR --out evidence_gate.md`
- `/root/.the agent/scripts/src-report-format-gate.py REPORT.txt`
- `/root/.the agent/scripts/the agent-ensure-tools.sh --status|--burp|--hexstrike|--gateway`

## 报告格式

用户偏好：纯文本，报告间 `===` 分隔，单行 curl，复现命令汇总，`【截图位置N】` 标注。补天字段必须含标题、域名、类型、等级、行业、精确到区地址、URL、详情、复现、影响、修复。

## Reference 路由

- 完整旧版技能全文：`references/legacy-full-skill-2026-06-08.md`
- 教育供应商指纹：`references/edu-vendor-fingerprinting.md`
- CAS 测试：`references/cas-vuln-testing-patterns.md`、`references/wisedu-cas-testing-patterns.md`、`references/pac4j-cas-open-redirect-pattern.md`
- 泛微 OA：`references/weaver-oa-testing-patterns.md`
- 高危利用模式：`references/high-severity-exploitation-patterns.md`
- 效率/WAF 策略：`references/src-efficiency-waf-strategy-20260601.md`
- 低影响不提交门禁：`references/education-portal-api-no-submit-gate.md`
- 目标专项历史案例：按 `references/*src*`、`references/*testing*`、`references/*verification*` 查找。

## 相关技能

- `global-control`：总控、MCP/Gateway/Burp/HexStrike 健康检查。
- `pentest-unified-engine`：目标图谱、攻击路由、PoC/报告管道。
- `education-src-blueprint`：教育 SRC 专项优先级和审核门禁。
- `web-pentest-fast`：外网 Web 快速入口。
- `exploit-chain`：把低价值线索升级为攻击链。
