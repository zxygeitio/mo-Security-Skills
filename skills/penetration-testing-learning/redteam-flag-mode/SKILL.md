---
name: redteam-flag-mode
description: 授权红队攻防/CTF夺旗模式 — 范围约束、按需工具启动、Flag工作区、证据链、提交格式与降级策略
category: penetration-testing-learning
created_by: agent
---

# Red-Team Flag Mode / 红队夺旗模式

## 触发条件

用户提到：
- 红队攻防战、攻防演练、夺旗、flag、CTF-like、靶场、演练平台。
- 需要在对抗中持续推进，不因为 Burp/MCP/VPN/Cron/工具限制卡住。

先加载：
- `global-control`
- `pentest-ops`
- `vuln-intel`
- `web-pentest-fast` 或目标专项技能
- 需要攻击链时加载 `exploit-chain`
- CTF知识库和自动化脚本: `ctf-playbook`

## 安全边界

只在授权范围内执行。开始前必须明确或从规则文件中解析：

1. 目标范围：IP 段、域名、系统、账号、VPN、时间窗口。
2. 允许动作：扫描、利用、横向、社工、DoS、数据访问、是否允许写文件。
3. 禁止动作：默认禁止破坏数据、持久化后门、清痕、超范围横向、批量拖库。
4. Flag 规则：格式、提交接口、计分方式、证据要求。

若规则不明，先只做被动/低风险侦察和本机准备，不做越权或破坏性利用。

## 本机入口

配置与 runbook：

```bash
/root/.hermes/redteam-flag-mode/config.yaml
/root/.hermes/redteam-flag-mode/RUNBOOK.md
```

初始化工作区：

```bash
/root/.hermes/scripts/hermes-flag-mode.sh init --case CASE_NAME --target TARGET
```

记录 flag：

```bash
/root/.hermes/scripts/hermes-flag-mode.sh add-flag --case CASE_NAME --target TARGET --flag 'flag{...}' --note 'vuln/path summary'
```

记录证据：

```bash
/root/.hermes/scripts/hermes-flag-mode.sh add-evidence --case CASE_NAME --file /tmp/evidence.txt --note 'HTTP response proving flag access'
```

查看 ledger：

```bash
/root/.hermes/scripts/hermes-flag-mode.sh ledger --case CASE_NAME
```

## 作业流

1. Intake：读规则、确认范围、flag 格式、提交方式和时间窗口。
2. Baseline：运行总控巡检；按需启动 Burp/HexStrike/MCP/VPN；创建 case 工作区。
3. Recon：先被动和低噪声，后主动扫描；保存资产、指纹、路径、JS/API。
4. Triage：优先能直接出 flag 的路径。
5. Verify：非破坏性验证漏洞，保存请求/响应和命令。
6. Capture：只读取 flag 或最小证明，不扩大数据访问。
7. Submit：按规则提交 flag；输出 flag ledger、命令、证据和修复建议。

## 工具策略

按需启动，不等用户手动打开：

```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --gateway --hexstrike
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
```

漏洞情报按需查询：

```bash
/root/.hermes/scripts/hermes-vuln-query.sh --refresh --keyword 'PRODUCT_OR_CVE' --days 30 --github-limit 10
```

MCP 仅执行，Hermes 主控负责判断和复核。

## Flag 优先级

高优先级：
- 未授权 API / IDOR / 权限绕过可读 flag。
- 文件读取读 `/flag`、`/root/flag.txt`、应用目录 flag。
- RCE 后最小命令验证并读取 flag。
- SSRF 访问内部 flag 服务或云 metadata。
- Git/CI/CD/对象存储泄露 flag artifact。
- Actuator/heapdump/config 泄露凭证后可读 flag。

慎用或默认不做：
- 大规模密码喷洒。
- 持久化、后门、清痕。
- 破坏性写入、服务中断、批量脱库。

## 证据标准

每个 flag 至少记录：

- Target / scope 状态。
- Flag 值或 hash+preview（按规则决定是否输出原文）。
- Capture path：漏洞路径或利用链。
- One-line command：可复现命令。
- Evidence file：原始响应、截图或日志路径。
- Timestamp。
- 风险和修复建议。

## 降级策略

- Burp GUI 不可用：curl/httpx 保存原始 HTTP 证据。
- HexStrike 不可用：nmap/nuclei/sqlmap/ffuf 原生命令。
- VPN 影响模型 API：停止，改 split tunnel，验证 API 连通后继续。
- WAF 封禁：停止主动探测，转离线 JS/API 分析和证据整理。
- NVD/GitHub rate limit：减小 github-limit，使用 searchsploit/nuclei templates/本地缓存。

## 输出模板

```text
=== FLAG N ===
Target:
Scope:
Flag:
Flag SHA256:
Capture path:
One-line command:
Evidence file:
Timestamp:
Risk:
Remediation:
```
