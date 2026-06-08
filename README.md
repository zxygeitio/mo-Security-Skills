# Hermes Security Skills

> The largest open-source **offensive cybersecurity skills library** for [Hermes Agent](https://hermes-agent.nousresearch.com) — giving AI agents the structured knowledge of a senior penetration tester and SRC vulnerability hunter.

**40 production-grade skills** spanning **15 security domains**, built from real-world SRC (Security Response Center) vulnerability hunting across 50+ Chinese and international targets including MGM, Huazhu, T3出行, 萤石, 教育行业, and more.

Each skill is a battle-tested playbook — not theoretical checklists, but procedures that produced verified, submitted vulnerabilities.

## Why This Library?

> A junior pentester knows which Nuclei template catches a Spring Boot Actuator exposure, how to chain CORS misconfiguration with IDOR for account takeover, and when a CAS Open Redirect becomes a ticket theft vector. **Your AI agent doesn't — unless you give it these skills.**

Unlike general-purpose security knowledge bases, this library is:
- **AI-native**: Written as Hermes Agent skills with YAML frontmatter (~30 token scanning)
- **Battle-tested**: Every skill was forged from real SRC engagements
- **Chinese + English**: Covers both Chinese education/enterprise SRC and international targets
- **Chain-oriented**: Skills compose into end-to-end attack chains (recon → fingerprint → exploit → report)

## Repository Structure

```
Hermes-Security-Skills/
├── README.md
├── LICENSE                          # Apache 2.0
├── SECURITY.md
├── index.json                       # Machine-readable skill index
├── ATTACK_COVERAGE.md               # MITRE ATT&CK coverage analysis
└── skills/
    ├── exploit-chain/
    │   ├── SKILL.md                 # Skill definition (YAML frontmatter + Markdown)
    │   ├── references/              # Deep technical references
    │   │   └── business-logic-chain-framework-20260602.md
    │   └── scripts/                 # Working helper scripts
    ├── pentest-recon-driven/
    │   ├── SKILL.md
    │   ├── references/
    │   │   ├── mgm-src-testing-patterns.md
    │   │   └── ...
    │   ├── scripts/
    │   └── templates/
    └── ... (40 skills total)
```

## Skill Anatomy

Each skill follows the [agentskills.io](https://agentskills.io) standard:

```yaml
---
name: exploit-chain
description: 端到端攻击链 — 从漏洞发现到RCE到数据提取的完整利用流程
category: penetration-testing-learning
tags: [exploit, rce, chain, offensive, post-exploitation]
---
```

YAML frontmatter enables ~30 token scanning for fast skill discovery. The Markdown body contains the actual playbook.

## Skill Categories

### 🔍 Reconnaissance & Information Gathering (8 skills)
| Skill | Description |
|-------|-------------|
| `pentest-recon-driven` | 信息收集驱动渗透测试入口 — 被动侦察→指纹→API/JS 逆向→精准验证 |
| `auto-recon-lowhanging` | 自动化初始侦察与低垂果实采集 — 模块化服务探测 + SQLi盲注验证 |
| `rot-proxy-behind-discovery` | 通过证书O字段指纹识别ROT Proxy背后真实业务系统 |
| `openvpn-split-tunnel` | Configure OpenVPN split tunnel for pentest engagements |
| `burp-suite-setup` | Burp Suite proxy setup with HTTPS certificate configuration |
| `hexstrike-usage` | How to use HexStrike MCP — tools first, HTTP API as fallback |
| `hexstrike-api-fallback` | HexStrike MCP bridge HTTP API fallback |
| `pentagi-cli-conversion` | 将 PentAGI 项目改造为纯 CLI 工具 |

### 🎯 Vulnerability Hunting & Exploitation (12 skills)
| Skill | Description |
|-------|-------------|
| `src-vuln-hunting` | SRC公益漏洞挖掘全流程 — 目标快筛、攻击假设、证据门禁 |
| `exploit-chain` | 端到端攻击链 — SQLi/文件上传/SSRF/反序列化/认证绕过/API滥用 |
| `web-pentest-fast` | 外网Web渗透快速流程 — 轻量决策树、低噪声加载 |
| `exploit-db-integration` | Exploit-DB 深度集成 — 47K+漏洞库、指纹→exploit自动映射 |
| `spring-boot-actuator-httptrace-exploitation` | Spring Boot Actuator httptrace 渗透方法论 |
| `lianyi-cas-exploitation-patterns` | 联奕CAS统一身份认证平台渗透模式 |
| `nginx-cve-database` | Nginx CVE漏洞数据库 (2024-2026) |
| `nginx-spa-fallback-false-positive` | Detect nginx SPA fallback false positives |
| `script-analysis-invisible-code` | 高级脚本分析与隐形代码检测 — Unicode零宽字符混淆 |
| `vuln-intel` | 漏洞情报聚合 — 实时CVE搜索、指纹→漏洞→利用映射 |
| `vuln-intel-2025-2026` | 2025-2026漏洞情报库 — 最新CVE PoC/攻击链 |
| `smart-vuln-detector` | 智能漏洞检测框架 — 基于指纹的漏洞特征匹配 |

### 🏢 SRC-Specific Patterns (6 skills)
| Skill | Description |
|-------|-------------|
| `education-src-blueprint` | 教育SRC漏洞挖掘蓝图 — 目标筛选→漏洞类型优先级→报告质量门禁 |
| `mgm-src-testing-patterns` | MGM美高梅SRC — FWI CMS/booking/ADFS/F5 BIG-IP |
| `qssrc-testing-patterns` | 轻松筹SRC — API未授权/IDOR/Passport认证/Actuator |
| `shein-src-recon` | SHEIN SRC — 子域名枚举+内网探测+GSRM WAF识别 |
| `nisp-pentest-fusion` | NISP知识体系与SRC实战融合 |
| `edu-auto-scanner` | 教育SRC全自动化扫描工具集 — 批量探测+指纹→漏洞映射 |

### 🔗 Post-Exploitation & Lateral Movement (4 skills)
| Skill | Description |
|-------|-------------|
| `pentest-lateral` | 横向移动与内网渗透工具手册 |
| `post-exploit-pwncat` | 自动化后渗透 — Dumb Shell→稳定PTY→提权→持久化 |
| `pentest-ops` | 渗透测试一体化作业流 — VPN→内网探测→ROT识别→漏洞验证→报告 |
| `pentest-tool-mastery` | 渗透测试工具精通 — 20+工具选型决策树、组合技、自动化模式 |

### 🤖 Agent & Automation (6 skills)
| Skill | Description |
|-------|-------------|
| `pentest-unified-engine` | 统一渗透引擎 — 目标图谱+智能路由+PoC生成+报告管道 |
| `pentest-multiagent-system` | 多智能体渗透测试工作流系统 |
| `agent-execution-monitor` | Agent执行监控与Loop Guard — 防止无效循环、请求预算管理 |
| `agent-task-planner` | 智能任务规划器 — 复杂任务自动分解为3-7步结构化计划 |
| `pentest-control-plane` | 渗透测试控制平面 — 统一调度所有渗透工具 |
| `pentest-agent-build` | Lightweight CLI pentest agent — Go项目构建笔记 |

### 🏴 CTF & Red Team (3 skills)
| Skill | Description |
|-------|-------------|
| `ctf-playbook` | CTF竞赛知识库 — Web/Crypto/PWN/Misc/Reverse解题思路、payload速查 |
| `redteam-flag-mode` | 授权红队攻防/CTF夺旗模式 — 范围约束、证据链、提交格式 |
| `local-pentest-practice-lab` | Docker靶场搭建与漏洞利用完整工作流 |

### 🛡️ Defense & CI/CD (1 skill)
| Skill | Description |
|-------|-------------|
| `cicd-pipeline-poisoning` | CI/CD基础设施滥用与流水线投毒 — GitHub Actions/GitLab CI/Jenkins |

## MITRE ATT&CK Coverage

See [ATTACK_COVERAGE.md](ATTACK_COVERAGE.md) for detailed framework mapping.

Key coverage areas:
- **Reconnaissance (TA0043)**: T1592, T1589, T1590, T1591, T1595, T1596, T1593, T1594
- **Resource Development (TA0042)**: T1583, T1584, T1585, T1586, T1587, T1588
- **Initial Access (TA0001)**: T1190, T1133, T1078, T1566
- **Execution (TA0002)**: T1059, T1203
- **Persistence (TA0003)**: T1078, T1136, T1505
- **Privilege Escalation (TA0004)**: T1068, T1078
- **Credential Access (TA0006)**: T1110, T1557
- **Discovery (TA0007)**: T1046, T1087, T1083
- **Lateral Movement (TA0008)**: T1021, T1550
- **Collection (TA0009)**: T1213, T1530
- **Exfiltration (TA0010)**: T1041, T1567

## Quick Start

### For Hermes Agent Users
```bash
# Clone the repo
git clone https://github.com/zxygeitio/Hermes-Security-Skills.git

# Copy skills to your Hermes skills directory
cp -r Hermes-Security-Skills/skills/* ~/.hermes/skills/penetration-testing-learning/
```

### For Other AI Agents
Each skill's `SKILL.md` is self-contained. Read the YAML frontmatter for fast scanning, then load the full Markdown body for execution context.

```python
import yaml, re

def scan_skill(path):
    with open(path) as f:
        content = f.read()
    m = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
    if m:
        return yaml.safe_load(m.group(1))
    return None
```

## Real-World Results

Skills in this library have been used to discover and report:

| Target | Vulns Found | Severity | Skill Used |
|--------|-------------|----------|------------|
| MGM 美高梅 | 8 new findings | High | `mgm-src-testing-patterns` |
| 华住集团 | 15 vulns (5H/7M/3L) | Critical | `exploit-chain`, `src-vuln-hunting` |
| T3出行 | 6+ vulnerabilities | High | `src-vuln-hunting` |
| 教育行业 (多所高校) | 20+ vulnerabilities | High | `education-src-blueprint`, `lianyi-cas-exploitation-patterns` |
| 萤石 | 6 reports | Medium | `pentest-recon-driven` |
| 轻松筹 | Multiple findings | High | `qssrc-testing-patterns` |

## Contributing

1. Fork the repository
2. Create a new skill directory under `skills/`
3. Add `SKILL.md` with proper YAML frontmatter
4. Add `references/`, `scripts/`, `assets/` as needed
5. Submit a Pull Request

### Skill Naming Convention
- Use **kebab-case** (e.g., `exploit-chain`, not `exploitChain`)
- Be descriptive: `spring-boot-actuator-httptrace-exploitation` > `spring-exploit`
- Target-specific patterns: `<target>-src-testing-patterns`

### Skill Quality Standards
- ✅ Must have real-world testing evidence
- ✅ Must include concrete commands, not just concepts
- ✅ Must document pitfalls and false positives
- ✅ Must include verification steps
- ❌ No theoretical-only content
- ❌ No untested CVE claims

## License

Apache License 2.0 — see [LICENSE](LICENSE)

## Disclaimer

⚠️ **This is an offensive security toolkit for authorized testing only.**

All skills in this library are designed for:
- Authorized SRC (Security Response Center) vulnerability disclosure
- CTF (Capture The Flag) competitions
- Authorized red team engagements
- Security research in controlled environments

Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before using any technique described in these skills.

---

Built with [Hermes Agent](https://hermes-agent.nousresearch.com) — the autonomous AI agent framework by Nous Research.
