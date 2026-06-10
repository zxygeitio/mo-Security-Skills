---
name: src-vuln-hunting
description: "SRC(Security Response Center)公益漏洞挖掘全流程入口 — 目标快筛、攻击假设、证据门禁、实质漏洞报告。详细历史案例和 payload 已拆到 references。"
tags: [src, butian, cors, idor, apisix, recon, vulnerability]
---

# SRC 漏洞挖掘轻量入口

## 触发条件

- 用户要求 SRC、补天、漏洞盒子、企业/教育目标漏洞挖掘。
- 需要从域名/URL/JS/API/报告草稿中判断是否存在可提交漏洞。
- 需要把扫描候选转成可复现、可截图、可提交的实质漏洞证据。

## 硬原则
## 硬原则

1. 只报告真实可利用漏洞：RCE、SQLi、认证绕过、越权、未授权敏感数据、可用密钥、上传闭环。
2. 扫描结果只是候选：Nuclei、Burp、HexStrike、脚本命中必须经过 Hermes 主控复核。
3. 先建攻击假设：角色、数据对象、权限边界、业务流程、可控参数，再小批验证。
4. 每批最多 5-20 个高价值接口；请求/响应/header/body/curl/control 全部落盘。
5. WAF/SPA fallback/登录页/统一错误页/公开设计/同根因重复不能包装成报告。
6. CVE 必须确认版本适用性和最小 PoC，不得只列编号。
7. 报告前重新执行 PoC，确认当前仍可复现。
8. **可复现门禁强制**: 提交前必须运行 `src-reproducibility-gate.py <workspace>`，只有 PoC 能跑通、输出一致、有实际利用价值的发现才通过。低价值发现（Server头/IP泄露/堆栈跟踪/登录页/默认页/健康检查/CAS白名单拦截）自动 REJECT。用户明确要求"不报告那些没有实际利用价值的漏洞，要能复刻出来的漏洞才算"。
8. **CAS Open Redirect 不单独报告**（2026-06 实测多个教育SRC审核拒绝，视为预期行为）。仅当 Open Redirect 可链式利用（如窃取 ticket 后证明可访问敏感数据）时才作为攻击链一环报告。
- grep 正则必须用量词：`grep -oP 'value="[^"]*"'` 正确，`grep -o 'value="[0-9.]"'` 错误（少了 `*` 只匹配单字符）。

### 外部安全技能语料补强

当目标涉及 API/BOLA/IDOR/JWT/OAuth/SAML/CVE/KEV/云身份/供应链等主题，先用 Anthropic Cybersecurity Skills 外部索引召回 5-12 个相关程序素材，再回到 Hermes 证据门禁验证：

```bash
/usr/bin/python3 /root/.hermes/scripts/anthropic-cyber-skills-router.py \
  --query '<target + attack hypothesis + tech stack>' \
  --limit 10
```

优先参考的外部模式：`testing-api-for-broken-object-level-authorization`、`testing-api-authentication-weaknesses`、`testing-jwt-token-security`、`exploiting-jwt-algorithm-confusion-attack`、`testing-api-security-with-owasp-top-10`、`performing-cve-prioritization-with-kev-catalog`、`analyzing-api-gateway-access-logs`。外部技能只补方法论和检查清单；是否可报仍由 `src-http-probe --control`、`src-quality-gate.py`、`src-think.py`、`src-evidence-gate.py` 的实证结果决定。


1. 基线和工具：先按 `global-control` 运行健康检查；需要扫描工具时跑 `/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py health`。
2. 快筛资产：`/usr/bin/python3 /root/.hermes/scripts/src-fast-assess.py <domain> --out /tmp/src_assess_<domain>`。
3. 生成下一步：`/usr/bin/python3 /root/.hermes/scripts/src-practical-next.py <alive.txt|probe_results.tsv|src-fast-assess-outdir> --out /tmp/next.md --json-out /tmp/next.json --tiers --show-skipped`。
4. 推理假设：`/usr/bin/python3 /root/.hermes/scripts/src-think.py <workspace-or-artifacts> --out /tmp/src-think.md --json-out /tmp/src-think.json`，把 URL/API/JS/Burp/MITM 证据合成为业务对象、攻击假设、缺口、A/B 对照和≤20条验证命令；检查 `submit_readiness`：`READY_TO_VALIDATE` 才能小批验证，`NEED_MORE_EVIDENCE` 只补证，`NO_REPORT` 禁止写报告。
5. JS/API 提取：`/usr/bin/python3 /root/.hermes/scripts/src-js-api-extract.py <url-or-file> --out <workspace>`，只把高价值 API 投入验证。
6. 小批探测：`/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py <workspace> urls.txt --timeout 8 --control --dedupe`。
7. 质量门禁：`/usr/bin/python3 /root/.hermes/scripts/src-quality-gate.py <workspace>/probe_results.tsv --out quality_gate.md --json-out quality_gate.json`。
8. 候选深挖：只有 `HAS_REPORTABLE_CANDIDATES` 或明确可补证的 `NEED_MORE_EVIDENCE` 继续；否则换目标/换假设。
9. **自治审计门禁**：`/usr/bin/python3 /root/.hermes/scripts/src-autonomy-audit-gate.py <workspace> --out /tmp/autonomy-audit.md --json-out /tmp/autonomy-audit.json --manifest-out /tmp/evidence-manifest.json`。报告提交前检查 APTS 风格范围/安全/审计/报告治理、POPPER 风格假设证伪与 A/B 对照、Shannon 风格 PoC-backed findings only，并生成 evidence manifest（路径/大小/sha256）供人工复核。`BLOCK_REPORT`/`DO_NOT_SUBMIT` 禁止提交；`NEEDS_MORE_EVIDENCE` 只补证；`READY_FOR_HUMAN_REVIEW` 才进入人工复核/报告。
10. 报告门禁：报告前执行去重、重放 PoC、截图标注、格式检查；历史报告查 `/tmp/vuln_reports` 和 `session_search`。

## 已加固目标处置

当全部攻击面（SQLi/文件上传/LFI/RCE/认证绕过/SSRF/XXE/目录遍历/.git泄露/CORS/数据库未授权）均测试通过且无中高危发现时：
1. 不要反复重测同一攻击面——浪费工具预算且用户会不满（Loop Guard v2.0 的语义循环检测会强制停止）
2. 明确告知用户"无中高危可利用漏洞"，不包装低危为高危
3. 建议用户换目标或接受信息泄露报告
4. 记录已加固状态到技能references，避免下次重复测试

**已知加固组合**（测试5分钟内无P0/P1候选直接换目标）：
- SUDY WebPlus CMS + 金智教育 CAS + 网易企业邮箱 + Sangfor EasyConnect VPN
- 金智教育 CAS 有 service 白名单，Open Redirect 不可利用
- ehall 全部端点 302 到 CAS，无绕过
- SUDY CMS 版本较新，已知CVE已修复

## IP泄露价值评估

IP泄露发现后，必须验证IP身份：
- `ping IP` 检查可达性和TTL
- `nslookup domain` 对比解析IP和泄露IP
- `curl -sk http://ip-api.com/json/IP` 查ISP和地理位置
- 若泄露IP是CDN/WAF的DNS服务器（如198.18.x.x网段），而非origin server，漏洞价值显著降低
- 此时应告知用户"泄露的是CDN/WAF IP，非真实服务器IP"

## 高价值优先级

- P0/P1：RCE、SQLi、认证绕过、IDOR/BOLA、任意文件上传、SSRF 到内网/云元数据、AppSecret/API Key 可调用敏感接口。
- P1/P2：未授权业务数据、CORS 读取登录态敏感接口、Swagger/Actuator 可调用敏感功能、找回密码/验证码逻辑缺陷。
- 低价值或不报：安全头缺失、版本号、robots、普通登录页、公开新闻/通知、盐值/JSESSIONID 单独泄露、无敏感数据的 CORS、SPA fallback 假 200、**CAS Open Redirect（补天审核视为配置问题，2026-06-09实战被拒收，需配合完整Ticket窃取利用链才可能通过）**、CORS wildcard(*)+credentials（几乎所有学校都这样配置，不被接受为漏洞）。

## 真实性门禁

候选必须至少满足其中一类：

- 未授权 API：返回真实敏感业务数据，并有无效 token/随机 ID/不存在 ID 对照。
- IDOR：改 ID 返回不同归属对象，证明当前身份不应访问。
- 文件上传：返回 `fileUrl/resId/genName`，文件可访问，并证明实际业务影响。
- 密钥泄露：密钥/API Key/AppSecret 能调真实接口或换 token；修复时确认密钥轮换。
- CORS：浏览器可从攻击者 Origin 读取登录态敏感接口。
- Swagger/Actuator：证明敏感数据泄露或敏感接口可调用。

## PoC命令陷阱

- grep正则必须用量词：`value="[0-9.]*"` 而非 `value="[0-9.]"`（少了`*`只匹配单个字符）
- curl输出管道到grep时，用 `grep -oP 'value="[^"]*"'` 更稳健
- Authorization: Basic 后面必须有空格（用户曾因此调试失败）

## IP泄露验证陷阱 (2026-06-09新增)

发现IP泄露漏洞后，必须验证泄露的IP是真实服务器IP还是CDN/WAF/DNS服务器IP：
1. `nslookup <domain>` 对比泄露IP和域名解析IP
2. `dig @<leaked_ip> <domain>` 测试泄露IP是否是DNS服务器
3. `curl -sk http://<leaked_ip>/` 测试Web服务是否可达
4. `whois <leaked_ip>` 查看ISP/组织，是否是CDN/云服务商
5. 如果泄露IP是CDN/WAF/DNS的IP，漏洞等级降为低危或不报

案例：njmu.edu.cn泄露IP 109.122.3.227，实测是香港Alice Networks LTD的DNS服务器，
域名解析到198.18.x.x（CDN网段），泄露IP不是真实服务器IP。

## IP泄露验证门禁

发现IP地址泄露时，**必须验证是否为真实服务器IP**后再报告。CDN/WAF基础设施IP泄露的报告通常会被拒。

验证步骤：
1. `nslookup <domain>` 对比泄露IP与解析IP是否在同一网段
2. `curl -sk "http://ip-api.com/json/<IP>"` 查询ISP/地理位置
3. `curl -sk -H "Host: <domain>" http://<IP>/` 直接访问看是否返回真实内容
4. `dig @<泄露IP> <domain>` 检查是否为DNS服务器
5. 检查泄露IP是否有代理端口(1080/3128/8080/8118/9050)

CDN/WAF IP特征（非真实服务器）：
- 域名解析到198.18.x.x/198.19.x.x等网段
- 泄露IP位于香港/海外，ISP为CDN提供商(Alice Networks/Cloudflare等)
- 泄露IP开放DNS(53)、代理(1080/3128)等端口
- dig查询返回域名解析到CDN网段

降级处理：如确认为CDN IP，报告等级应从"中危"降为"低危"或"信息"，并注明"非真实服务器IP"。

## 常用脚本入口

- `/root/.hermes/scripts/src-hypothesis-builder.py TARGET --scope <education|ai|hotel|iot|default> --outdir OUTDIR`
- `/root/.hermes/scripts/src-workspace-init.py`
- `/root/.hermes/scripts/src-fast-assess.py <domain>`
- `/root/.hermes/scripts/src-practical-next.py <artifact> --out next.md --json-out next.json --tiers --show-skipped`
- `/root/.hermes/scripts/src-think.py <workspace-or-artifacts> --out src-think.md --json-out src-think.json`
- `/root/.hermes/scripts/src-js-api-extract.py`
- `/root/.hermes/scripts/src-http-probe.py WORKSPACE urls.txt --timeout 8 --control --dedupe`
- `/root/.hermes/scripts/src-quality-gate.py WORKSPACE/probe_results.tsv --out quality_gate.md --json-out quality_gate.json`
- `/root/.hermes/scripts/src-evidence-gate.py CANDIDATE_DIR --out evidence_gate.md`
- `/root/.hermes/scripts/src-reproducibility-gate.py WORKSPACE [--dry-run] [--out report.md] [--min-severity medium]` — 可复现门禁
- `/root/.hermes/scripts/src-report-format-gate.py REPORT.txt`
- `/root/.hermes/scripts/hermes-ensure-tools.sh --status|--burp|--hexstrike|--gateway`

## PoC 命令常见陷阱

### grep 正则遗漏量词
给用户的 PoC 中 `grep -o 'value="[0-9.]"'` 匹配不到结果，因为字符类 `[0-9.]` 只匹配**单个字符**。
正确写法必须加量词：`grep -o 'value="[0-9.]*"'`。
**防御性写法**：优先用 `-oP 'value="[^"]*"'`（Perl正则匹配任意非引号字符），不依赖量词，不易出错。
**经验法则**：凡是 PoC 中 grep 涉及多位数字/字母/路径的字符类，交付前检查是否缺 `+` 或 `*` 量词。

### 自动化探测假阴性
`src-http-probe.py` 的 control 探测会将需要特定参数/请求才能返回敏感数据的端点误判为 `LOGIN_OR_AUTH_REQUIRED`（假阴性）。
例如 SUDY CMS 的 `/_web/_portal/api/user/main.psp` 在 probe 中被判为需要登录，但手动 curl 可正常获取 IP 泄露。
**规则**：对信息泄露类漏洞，必须手动 curl 复现验证，不能仅依赖自动化 probe 的 decision 字段作为最终判断。

## 报告格式

用户偏好：纯文本，报告间 `===` 分隔，单行 curl，复现命令汇总，`【截图位置N】` 标注。补天字段必须含标题、域名、类型、等级、行业、精确到区地址、URL、详情、复现、影响、修复。

## Reference 路由

- IP泄露验证方法论：`references/ip-leakage-validation.md`
- 完整旧版技能全文：`references/legacy-full-skill-2026-06-08.md`
- 教育供应商指纹：`references/edu-vendor-fingerprinting.md`
- ehall 金智教育 JSONP API 未授权访问：`references/ehall-wisedu-jsonp-api-patterns.md` — /jsonp/appInfo.json 泄露 appKey/domainId/deployPrefix，无需认证
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
