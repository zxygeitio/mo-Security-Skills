<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:ff6b35,100:ff2d2d&height=220&section=header&text=mo-Security-Skills&fontSize=50&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Universal%20Offensive%20Security%20Skills%20for%20AI%20Agents&descSize=16&descAlignY=55&descAlign=50" width="100%">
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/🛡️_Skills-63-orange?style=for-the-badge&logo=shield&logoColor=white" alt="Skills"></a>
  <a href="#"><img src="https://img.shields.io/badge/🎯_Subdomains-11-red?style=for-the-badge&logo=target&logoColor=white" alt="Subdomains"></a>
  <a href="#"><img src="https://img.shields.io/badge/📁_Files-1300+-blue?style=for-the-badge&logo=files&logoColor=white" alt="Files"></a>
  <a href="#"><img src="https://img.shields.io/badge/⚔️_ATT%26CK-45+_Techniques-green?style=for-the-badge&logo=mitre&logoColor=white" alt="ATT&CK"></a>
  <a href="https://agentskills.io"><img src="https://img.shields.io/badge/📐_Standard-agentskills.io-purple?style=for-the-badge" alt="agentskills.io"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/📜_License-Apache_2.0-purple?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <b>🔥 Battle-tested offensive security skills — works with ANY AI agent 🔥</b><br>
  <i>63 production-grade skills · 11 security subdomains · agentskills.io standard</i><br>
  <i>Compatible with Claude · GPT · Gemini · Llama · Hermes · LangChain · CrewAI · any agent</i>
</p>

---

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-agent-compatibility">Agent Compatibility</a> •
  <a href="#-skill-universe">Skills</a> •
  <a href="#-attack-chain-map">Attack Chain</a> •
  <a href="#-real-world-results">Results</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 🤖 Agent Compatibility

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    WORKS WITH EVERY AI AGENT                       │
  │                                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
  │  │  Claude   │  │   GPT    │  │  Gemini  │  │  Llama   │           │
  │  │  (Anthropic)  │  (OpenAI)  │  (Google)  │  │  (Meta)  │           │
  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
  │                                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
  │  │  Hermes  │  │LangChain │  │  CrewAI  │  │  AutoGPT │           │
  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
  │                                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
  │  │ MetaGPT  │  │  Cursor  │  │ Windsurf │  │   Cline  │           │
  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
  │                                                                     │
  │  Any agent that reads YAML frontmatter + Markdown body              │
  └─────────────────────────────────────────────────────────────────────┘
```

**How it works:** Each skill is a self-contained Markdown file with YAML frontmatter. The frontmatter enables ~30 token fast scanning for skill discovery. The body contains step-by-step instructions with real commands. No framework-specific runtime, no SDK, no dependencies.

```yaml
# YAML frontmatter — read by any agent for fast discovery
---
name: exploiting-sql-injection-with-sqlmap
description: >-
  Detect and exploit SQL injection using sqlmap for
  authorized penetration tests and CTF challenges.
domain: cybersecurity
subdomain: web-application-security
tags:
- sqlmap
- sqli
- owasp
- web-security
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1190
- T1059.007
nist_csf:
- DE.CM-01
- ID.RA-01
---

# Markdown body — self-contained playbook for any agent
## When to Use
- During authorized penetration testing
- To validate SQLi findings from scanners
...
```

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/zxygeitio/mo-Security-Skills.git

# Use with any agent — just point to the skills directory
# Claude: attach SKILL.md as context
# GPT: include in system prompt
# LangChain: load as Document objects
# Custom: parse YAML frontmatter for discovery, load body for execution
```

<details>
<summary>🐍 <b>Python — Universal Skill Loader</b></summary>

```python
import yaml, re, glob

def discover_skills(path="skills/*/SKILL.md"):
    """Fast discovery via YAML frontmatter (~30 tokens per skill)"""
    skills = []
    for f in glob.glob(path):
        with open(f) as fh:
            content = fh.read()
            m = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
            if m:
                meta = yaml.safe_load(m.group(1))
                meta['_file'] = f
                skills.append(meta)
    return skills

def load_skill(name, path="skills/*/SKILL.md"):
    """Load full skill body by name"""
    for f in glob.glob(path):
        with open(f) as fh:
            content = fh.read()
            m = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
            if m:
                meta = yaml.safe_load(m.group(1))
                if meta.get('name') == name:
                    return {'meta': meta, 'body': content[m.end():]}
    return None

# Discover all skills
for skill in discover_skills():
    print(f"  [{skill.get('subdomain','?')}] {skill['name']}: {skill['description'][:70]}")

# Load specific skill
s = load_skill('exploit-chain')
print(s['body'][:500])
```

</details>

<details>
<summary>🔗 <b>LangChain — Load as Documents</b></summary>

```python
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter

loader = DirectoryLoader("skills/", glob="**/SKILL.md", loader_cls=TextLoader)
docs = loader.load()

# Each doc is a skill — split or use as-is
splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=200)
chunks = splitter.split_documents(docs)
```

</details>

<details>
<summary>🦙 <b>LlamaIndex — Build Skill Index</b></summary>

```python
from llama_index.core import SimpleDirectoryReader, VectorStoreIndex

documents = SimpleDirectoryReader("skills/", recursive=True).load_data()
index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

# Ask: "What skills help with SQL injection?"
response = query_engine.query("SQL injection exploitation skills")
print(response)
```

</details>

---

## 🌌 Skill Universe

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=22&pause=1000&color=FF6B35&center=true&vCenter=true&multiline=true&repeat=true&width=600&height=100&lines=🔍+Recon+%7C+🎯+Exploit+%7C+🔗+Chain;🏢+SRC+%7C+🤖+Agent+%7C+🏴+CTF" alt="Typing SVG">
</p>

### 🔍 Reconnaissance & Intelligence Gathering

```
  ┌──────────────────────────────────────────────────────────────┐
  │  PASSIVE RECON → ACTIVE SCAN → FINGERPRINT → JS/API REVERSE │
  │       ↓              ↓            ↓              ↓           │
  │  CT/Wayback     Port Scan    Tech Stack      API Endpoint   │
  │  Shodan/DB      Subdomain    WAF Detect      Key Extract    │
  │  DNS/WHOIS      Alive Probe  Version Map     Auth Bypass    │
  └──────────────────────────────────────────────────────────────┘
```

| Skill | What It Does | ATT&CK |
|:------|:-------------|:------:|
| 📡 `pentest-recon-driven` | 被动侦察→指纹→API/JS 逆向→精准验证 | T1595 T1592 T1590 |
| 🎣 `auto-recon-lowhanging` | 模块化服务探测 + SQLi盲注验证 + 协议枚举 | T1595 T1046 T1190 |
| 🔎 `rot-proxy-behind-discovery` | 证书O字段指纹识别ROT Proxy背后真实系统 | T1595 T1046 |
| 🌐 `openvpn-split-tunnel` | Split tunnel配置,保持本地+VPN双通 | T1133 |
| 🔧 `burp-suite-setup` | Burp Suite代理+HTTPS证书配置 | T1190 |
| ⚡ `hexstrike-usage` | HexStrike工具优先,HTTP API fallback | T1046 T1190 |
| 🔄 `hexstrike-api-fallback` | HexStrike bridge降级方案 | T1046 |
| 🛠️ `pentagi-cli-conversion` | PentAGI → 纯CLI工具改造 | — |

### 🎯 Vulnerability Hunting & Exploitation

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                    VULNERABILITY EXPLOITATION PIPELINE          │
  │                                                                 │
  │  Target ──→ Fingerprint ──→ CVE Match ──→ PoC Build ──→ Verify │
  │    │           │              │              │             │     │
  │    ▼           ▼              ▼              ▼             ▼     │
  │  Domain    Tech Stack    Sploitus/      Minimal        Evidence  │
  │  IP/URL    Version       Exploit-DB     Safe PoC       Capture  │
  │                                                                 │
  │  ┌─── Chains ─────────────────────────────────────────────┐     │
  │  │ SQLi→RCE │ SSRF→Internal │ CORS+IDOR→Takeover │ CAS→  │     │
  │  │ FileUpload→Shell │ AuthBypass→Admin │ JWT→Forge      │     │
  │  └────────────────────────────────────────────────────────┘     │
  └─────────────────────────────────────────────────────────────────┘
```

| Skill | What It Does | ATT&CK |
|:------|:-------------|:------:|
| 💀 `exploit-chain` | 端到端攻击链: SQLi/上传/SSRF/反序列化/认证绕过 | T1190 T1059 T1078 |
| 🎯 `src-vuln-hunting` | SRC漏洞挖掘全流程: 目标快筛→攻击假设→证据门禁 | T1190 T1078 T1552 |
| ⚡ `web-pentest-fast` | 外网Web渗透快速流程: 轻量决策树、低噪声 | T1190 T1071 T1059 |
| 🗄️ `exploit-db-integration` | 47K+漏洞库 + 指纹→exploit自动映射 | T1190 T1588 |
| 🍃 `spring-boot-actuator-httptrace-exploitation` | Actuator httptrace敏感信息泄露 | T1190 T1213 |
| 🔐 `lianyi-cas-exploitation-patterns` | 统一身份认证CAS: Open Redirect→Ticket窃取 | T1078 T1133 |
| 📦 `nginx-cve-database` | Nginx CVE漏洞库 (2024-2026) | T1190 |
| 🎭 `nginx-spa-fallback-false-positive` | SPA fallback误报检测 | T1190 |
| 👻 `script-analysis-invisible-code` | Unicode零宽字符+隐形代码检测 | T1027 T1059 |
| 📊 `vuln-intel` | 漏洞情报: 实时CVE + 指纹→漏洞→利用映射 | T1588 T1592 |
| 📚 `vuln-intel-2025-2026` | 2025-2026最新漏洞情报库 | T1588 T1592 |
| 🧠 `smart-vuln-detector` | 智能漏洞检测: 基于指纹的特征匹配 | T1190 T1595 |

### 🏢 SRC-Specific Playbooks

```
  ┌────────────────────────────────────────────────────────────┐
  │              SRC VULNERABILITY HUNTING MODE                │
  │                                                            │
  │   Target ──→ Subdomain ──→ Fingerprint ──→ Pattern Match  │
  │     │            │             │                │          │
  │     ▼            ▼             ▼                ▼          │
  │   Scope      Asset Map    CAS/WAF/CMS     Known Exploits  │
  │   Verify     Alive Check  Version Lock    Chain Building  │
  │                                                            │
  │   ┌─────────────────────────────────────────────────┐      │
  │   │  🎓 教育  │  🏨 酒店  │  🎰 博彩  │  🚗 出行  │  🛒 电商  │
  │   └─────────────────────────────────────────────────┘      │
  └────────────────────────────────────────────────────────────┘
```

| Skill | Industry | Key Findings |
|:------|:---------|:-------------|
| 🎓 `education-src-blueprint` | 教育行业 | 统一身份认证 + Liferay + 统一认证攻击面 |
| 🎰 `mgm-src-testing-patterns` | 某博彩集团 | CMS系统 + ADFS + CORS泄露 + API密钥 |
| 💰 `qssrc-testing-patterns` | 某众筹平台 | API未授权 + IDOR + Passport认证绕过 |
| 👗 `shein-src-recon` | 某跨境电商 | 子域名枚举 + WAF识别 |
| 📖 `nisp-pentest-fusion` | 通用 | NISP知识体系 + SRC实战融合 |
| 🏫 `edu-auto-scanner` | 教育批量 | 批量探测 + 指纹→漏洞映射 + JS分析 |

### 🔗 Post-Exploitation & Lateral Movement

| Skill | ATT&CK | Description |
|:------|:------:|:------------|
| 🕸️ `pentest-lateral` | T1021 T1550 | 横向移动与内网渗透工具手册 |
| 🐚 `post-exploit-pwncat` | T1059 T1068 | Dumb Shell→PTY→提权→持久化 |
| 🔄 `pentest-ops` | T1190 T1021 | VPN→内网→ROT→漏洞→报告 |
| 🧰 `pentest-tool-mastery` | T1046 T1190 | 20+工具选型决策树 + 组合技 |

### 🤖 Agent & Automation

| Skill | Purpose | ATT&CK |
|:------|:--------|:------:|
| 🏗️ `pentest-unified-engine` | 统一渗透引擎: 目标图谱+智能路由+PoC+报告 | T1595 T1190 |
| 👥 `pentest-multiagent-system` | 多智能体并行渗透工作流 | T1595 T1190 |
| 📊 `agent-execution-monitor` | Loop Guard + 请求预算 + 工具调用审计 | T1059 |
| 📋 `agent-task-planner` | 复杂任务→3-7步结构化计划 | T1595 |
| 🎛️ `pentest-control-plane` | 统一调度所有渗透工具 | T1046 T1190 |
| 🤖 `pentest-agent-build` | Go语言CLI渗透Agent | T1059 |

### 🏴 CTF & Red Team

| Skill | Mode | ATT&CK |
|:------|:-----|:------:|
| 🏁 `ctf-playbook` | CTF | T1190 T1059 T1078 |
| ⚔️ `redteam-flag-mode` | Red Team | T1190 T1078 T1021 |
| 🧪 `local-pentest-practice-lab` | Practice | T1190 |

### 🛡️ CI/CD & DevSecOps

| Skill | ATT&CK |
|:------|:------:|
| 🔧 `cicd-pipeline-poisoning` | T1195 T1505 T1552 |

---

## 🗺️ Attack Chain Map

```mermaid
graph TD
    A[🔍 Recon] --> B[🎯 Fingerprint]
    B --> C{Service Type?}
    C -->|Web App| D[🌐 Web Exploit]
    C -->|API| E[📡 API Abuse]
    C -->|CAS/SSO| F[🔐 Auth Bypass]
    C -->|Cloud| G[☁️ Cloud Attack]
    
    D --> D1[SQLi]
    D --> D2[XSS/SSRF]
    D --> D3[File Upload]
    D --> D4[Deserialization]
    
    E --> E1[IDOR/BOLA]
    E --> E2[CORS Misconfig]
    E --> E3[API Key Leak]
    
    F --> F1[Open Redirect]
    F --> F2[Ticket Theft]
    F --> F3[Account Takeover]
    
    D1 --> H[💀 RCE / Data Access]
    D3 --> H
    E1 --> I[📊 Data Breach]
    E3 --> I
    F3 --> I
    
    H --> J[📝 Evidence + Report]
    I --> J
    
    style A fill:#ff6b35,stroke:#ff2d2d,color:#fff
    style B fill:#ff6b35,stroke:#ff2d2d,color:#fff
    style H fill:#ff2d2d,stroke:#ff0000,color:#fff
    style I fill:#ff2d2d,stroke:#ff0000,color:#fff
    style J fill:#00d4aa,stroke:#00b894,color:#fff
```

<p align="center">
  <b>MITRE ATT&CK Coverage: 11 Tactics · 45+ Techniques</b>
</p>

| Tactic | Techniques | Key Skills |
|:-------|:----------:|:-----------|
| 📡 Reconnaissance (TA0043) | 8 | `pentest-recon-driven`, `auto-recon-lowhanging` |
| 🏗️ Resource Development (TA0042) | 5 | `local-pentest-practice-lab`, `exploit-db-integration` |
| 🚪 Initial Access (TA0001) | 4 | `exploit-chain`, `lianyi-cas-exploitation-patterns` |
| ⚡ Execution (TA0002) | 2 | `exploit-chain`, `post-exploit-pwncat` |
| 🔒 Persistence (TA0003) | 3 | `cicd-pipeline-poisoning` |
| ⬆️ Privilege Escalation (TA0004) | 2 | `exploit-chain`, `pentest-lateral` |
| 🛡️ Defense Evasion (TA0005) | 1 | `nginx-spa-fallback-false-positive` |
| 🔑 Credential Access (TA0006) | 2 | `lianyi-cas-exploitation-patterns` |
| 🔍 Discovery (TA0007) | 3 | `auto-recon-lowhanging`, `pentest-recon-driven` |
| ↔️ Lateral Movement (TA0008) | 2 | `pentest-lateral`, `pentest-ops` |
| 📦 Collection (TA0009) | 2 | `exploit-chain`, `src-vuln-hunting` |
| 📤 Exfiltration (TA0010) | 2 | `exploit-chain` |

> 📖 Full mapping: [ATTACK_COVERAGE.md](ATTACK_COVERAGE.md)

---

## 🏆 Real-World Results

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=18&pause=1000&color=00D4AA&center=true&vCenter=true&multiline=true&repeat=true&width=500&height=60&lines=Real+vulnerabilities.+Real+impact.+No+theories." alt="Typing SVG">
</p>

<table>
<tr>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/🎰_某博彩集团-8_Findings-critical?style=for-the-badge" width="180"><br>
<b>High</b><br>
<sub>CORS泄露 + API数据<br>WAF绕过 + 企业代码缺陷</sub>
</td>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/🏨_某酒店集团-15_Vulns-critical?style=for-the-badge" width="180"><br>
<b>Critical: 5H / 7M / 3L</b><br>
<sub>AppSecret→敏感数据<br>未授权+IDOR(多品牌)</sub>
</td>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/🚗_某出行平台-6+_Vulns-orange?style=for-the-badge" width="180"><br>
<b>High</b><br>
<sub>Kong OAuth双斜杠绕过<br>VIP API 120端点</sub>
</td>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/🎓_某教育集群-20+_Vulns-orange?style=for-the-badge" width="180"><br>
<b>High</b><br>
<sub>CAS Open Redirect<br>统一认证攻击面</sub>
</td>
</tr>
<tr>
<td align="center">
<img src="https://img.shields.io/badge/📹_某IoT厂商-6_Reports-yellow?style=for-the-badge" width="180"><br>
<b>Medium</b><br>
<sub>Config.js泄露<br>__NEXT_DATA__泄露</sub>
</td>
<td align="center">
<img src="https://img.shields.io/badge/💰_某众筹平台-Multiple-orange?style=for-the-badge" width="180"><br>
<b>High</b><br>
<sub>API未授权/IDOR<br>Passport认证绕过</sub>
</td>
<td align="center">
<img src="https://img.shields.io/badge/🌐_某综合性高校-200+_Subs-blue?style=for-the-badge" width="180"><br>
<b>Medium</b><br>
<sub>CORS修复验证<br>OA V9.0SP1</sub>
</td>
<td align="center">
<img src="https://img.shields.io/badge/🏫_某教育机构-CAS_Chains-orange?style=for-the-badge" width="180"><br>
<b>High</b><br>
<sub>统一认证全线CORS<br>Open Redirect窃取Ticket</sub>
</td>
</tr>
</table>

---

## 🏗️ Architecture

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                    UNIVERSAL SKILL ARCHITECTURE                      │
  │                   (agentskills.io v2.0 Standard)                    │
  │                                                                     │
  │   ┌─────────────────────────────────────────────────────────────┐   │
  │   │                    YAML FRONTMATTER                         │   │
  │   │   name · description · domain · subdomain · tags · version  │   │
  │   │   author · license · mitre_attack · nist_csf                │   │
  │   │                                                             │   │
  │   │   ┌─────────────────────────────────────────────────────┐   │   │
  │   │   │         ~30 TOKEN FAST DISCOVERY                    │   │   │
  │   │   │   Any agent scans frontmatter → matches skill       │   │   │
  │   │   └─────────────────────────────────────────────────────┘   │   │
  │   └─────────────────────────────────────────────────────────────┘   │
  │                           │                                         │
  │                           ▼                                         │
  │   ┌─────────────────────────────────────────────────────────────┐   │
  │   │                    MARKDOWN BODY                            │   │
  │   │   ## When to Use    — Trigger conditions                   │   │
  │   │   ## Prerequisites  — Tools, access, environment           │   │
  │   │   ## Steps          — Numbered workflow with commands       │   │
  │   │   ## Key Concepts   — Reference tables                    │   │
  │   │   ## Expected Output — What agent should produce           │   │
  │   └─────────────────────────────────────────────────────────────┘   │
  │                           │                                         │
  │                           ▼                                         │
  │   ┌─────────────────────────────────────────────────────────────┐   │
  │   │                    SUPPORTING FILES                        │   │
  │   │   references/  — Standards, CVE refs, deep procedures     │   │
  │   │   scripts/     — Working helper scripts                   │   │
  │   │   assets/      — Templates, checklists                    │   │
  │   │   LICENSE       — Apache 2.0                              │   │
  │   └─────────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────────┘
```

### Subdomain Distribution

```
penetration-testing    ████████████████████░░  21 skills
web-application-security ████░░░░░░░░░░░░░░░░   4 skills
vulnerability-management ████░░░░░░░░░░░░░░░░   4 skills
threat-intelligence    ██░░░░░░░░░░░░░░░░░░░░   2 skills
soc-operations         ██░░░░░░░░░░░░░░░░░░░░   2 skills
red-teaming            ██░░░░░░░░░░░░░░░░░░░░   2 skills
api-security           █░░░░░░░░░░░░░░░░░░░░░   1 skill
devsecops              █░░░░░░░░░░░░░░░░░░░░░   1 skill
identity-access-mgmt   █░░░░░░░░░░░░░░░░░░░░░   1 skill
malware-analysis       █░░░░░░░░░░░░░░░░░░░░░   1 skill
network-security       █░░░░░░░░░░░░░░░░░░░░░   1 skill
```

---

## 🧬 Skill Anatomy

```
skills/exploit-chain/
├── SKILL.md              ← YAML frontmatter + Markdown playbook
├── references/           ← Deep technical references
├── scripts/              ← Working helper scripts
├── assets/               ← Templates & checklists
└── LICENSE               ← Apache 2.0
```

<details>
<summary>📄 <b>Full SKILL.md Example</b></summary>

```yaml
---
name: exploiting-sql-injection-with-sqlmap
description: >-
  Detect and exploit SQL injection using sqlmap for
  authorized penetration tests and CTF challenges.
domain: cybersecurity
subdomain: web-application-security
tags:
- sqlmap
- sqli
- owasp
- web-security
- penetration-testing
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1190
- T1059.007
nist_csf:
- DE.CM-01
- ID.RA-01
---

# SQL Injection Exploitation with sqlmap

## When to Use
- During authorized penetration testing engagements
- To validate SQLi findings from scanners
- For CTF challenges involving SQL injection

## Prerequisites
- Authorization: Written Rules of Engagement
- Tools: sqlmap, Python 3.6+, Burp Suite
- Access: Network connectivity to target

## Steps
1. Identify injection points...
2. Run sqlmap basic detection...
3. Enumerate database structure...
...

## Expected Output
JSON report with findings, evidence, and MITRE ATT&CK mapping.
```

</details>

---

## 📊 Repository Stats

<p align="center">
<table>
<tr>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-63-ff6b35?style=flat" width="80"><br><b>Skills</b>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-11-ff2d2d?style=flat" width="80"><br><b>Subdomains</b>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-1300+-00d4aa?style=flat" width="80"><br><b>Files</b>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-45+-5b86e5?style=flat" width="80"><br><b>ATT&CK</b>
</td>
<td align="center" width="20%">
<img src="https://img.shields.io/badge/-50+-9b59b6?style=flat" width="80"><br><b>Targets</b>
</td>
</tr>
</table>
</p>

---

## 🛠️ Tools Covered

<p align="center">
<a href="https://nmap.org"><img src="https://img.shields.io/badge/Nmap-📡-4a90d9?style=for-the-badge" alt="Nmap"></a>
<a href="https://nuclei.projectdiscovery.io"><img src="https://img.shields.io/badge/Nuclei-🎯-ff6b35?style=for-the-badge" alt="Nuclei"></a>
<a href="https://portswigger.net/burp"><img src="https://img.shields.io/badge/Burp_Suite-🔧-ff4444?style=for-the-badge" alt="Burp Suite"></a>
<a href="https://sqlmap.org"><img src="https://img.shields.io/badge/sqlmap-🗄️-00d4aa?style=for-the-badge" alt="sqlmap"></a>
<a href="https://github.com/projectdiscovery/httpx"><img src="https://img.shields.io/badge/httpx-🌐-5b86e5?style=for-the-badge" alt="httpx"></a>
<a href="https://exploit-db.com"><img src="https://img.shields.io/badge/Exploit--DB-💀-ff2d2d?style=for-the-badge" alt="Exploit-DB"></a>
<a href="https://sploitus.com"><img src="https://img.shields.io/badge/Sploitus-🔎-9b59b6?style=for-the-badge" alt="Sploitus"></a>
<a href="https://github.com"><img src="https://img.shields.io/badge/20+_More_Tools-🧰-666?style=for-the-badge" alt="More"></a>
</p>

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

**Maintenance tooling** (`scripts/`, requires `pip install pyyaml`):

| Command | Purpose |
|:--------|:--------|
| `python scripts/build_index.py` | Regenerate `index.json` from every top-level SKILL.md frontmatter (never hand-edit the index) |
| `python scripts/build_index.py --check` | CI gate — fail if `index.json` is stale |
| `python scripts/validate_skills.py` | Validate the frontmatter contract (name ↔ directory, real descriptions, no leaked private IPs); warns on missing discovery tags |

Both checks run automatically on every push and PR via GitHub Actions.

```
  ┌──────────────────────────────────────────────┐
  │         CONTRIBUTING WORKFLOW                │
  │                                              │
  │  1. 🍴 Fork the repo                        │
  │  2. 📁 Create skills/<your-skill>/SKILL.md  │
  │  3. 📝 Add references/ + scripts/ + assets/ │
  │  4. ✅ Security scan (no hardcoded secrets) │
  │  5. 🚀 Submit Pull Request                  │
  │                                              │
  └──────────────────────────────────────────────┘
```

---

## 📜 License

<p align="center">
<a href="LICENSE"><img src="https://img.shields.io/badge/📜_License-Apache_2.0-blue?style=for-the-badge" alt="License"></a>
</p>

---

## ⚠️ Disclaimer

> 🛡️ **This is an offensive security toolkit for authorized testing only.**
>
> All skills are designed for: authorized SRC vulnerability disclosure · CTF competitions · authorized red team engagements · security research in controlled environments.
>
> **Unauthorized access to computer systems is illegal.** Users are responsible for ensuring proper authorization.

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:ff6b35,100:ff2d2d&height=120&section=footer" width="100%">
</p>

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/zxygeitio">zxygeitio</a> · Follows <a href="https://agentskills.io">agentskills.io</a> standard</sub>
</p>
