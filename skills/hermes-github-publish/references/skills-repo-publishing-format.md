# 技能库发布到 GitHub 格式 (agentskills.io 标准)

## 目录结构

```
<repo-name>/
├── README.md              # 炫酷介绍 + 分类表格 + 使用示例 + 成果展示
├── index.json             # 机器可读索引
├── LICENSE                # Apache 2.0 推荐
├── SECURITY.md            # 安全策略 + 敏感数据报告流程
├── ATTACK_COVERAGE.md     # (安全库专用) MITRE ATT&CK 映射
├── .gitignore
└── skills/
    ├── <skill-name>/      # kebab-case 命名
    │   ├── SKILL.md       # YAML frontmatter + Markdown body
    │   ├── references/    # 深度技术参考
    │   ├── scripts/       # 可执行脚本
    │   └── assets/        # 模板、清单
    └── ...
```

## SKILL.md YAML Frontmatter (agentskills.io v2.0)

```yaml
---
name: exploit-chain                    # kebab-case, 1-64字符, 必须
description: >-                        # 多行描述, 含关键词, 必须
  端到端攻击链 — 从漏洞发现到RCE到数据提取
  的完整利用流程，覆盖SQL注入/文件上传/SSRF
domain: cybersecurity                  # 固定值, 必须
subdomain: penetration-testing         # 子域分类, 必须 (见下方列表)
tags:                                  # 多行数组, 必须
- exploit
- rce
- chain
- offensive
- post-exploitation
version: '1.0'                         # 版本号, 必须
author: github-username                # 作者, 必须
license: Apache-2.0                    # 许可证, 必须
mitre_attack:                          # ATT&CK technique IDs, 推荐
- T1190
- T1059
- T1078
nist_csf:                              # NIST CSF categories, 推荐
- DE.CM-01
- ID.RA-01
---
```

**标准 subdomain 列表 (按频率排序):**

| Subdomain | 领域 |
|:----------|:-----|
| penetration-testing | 通用渗透测试方法论、侦察、利用 |
| web-application-security | OWASP Top 10, XSS, SQLi, SSRF |
| api-security | REST/GraphQL, BOLA, IDOR |
| vulnerability-management | 扫描、优先级、CVE 追踪 |
| threat-intelligence | IOC, CTI, 威胁情报 |
| red-teaming | 对抗模拟、C2、横向移动 |
| soc-operations | SIEM、告警分类、检测工程 |
| identity-access-management | IAM, PAM, SSO, SAML, OAuth, CAS |
| network-security | IDS/IPS, 防火墙, 流量分析 |
| malware-analysis | 静态/动态分析、逆向工程 |
| devsecops | CI/CD 安全, SAST, DAST, 供应链 |
| cloud-security | AWS, Azure, GCP |
| container-security | Docker, Kubernetes |
| digital-forensics | 磁盘、内存、网络取证 |
| incident-response | 事件响应、遏制、恢复 |
| threat-hunting | 假设驱动狩猎、行为分析 |

**Markdown body 标准章节:**
- `## When to Use` — 触发条件
- `## Prerequisites` — 工具、权限、环境
- `## Steps` — 编号步骤 + 真实命令
- `## Key Concepts` — 参考表格
- `## Expected Output` — agent 应产出什么

~30 token 扫描 frontmatter 即可判断技能是否相关。Markdown body 自包含，不依赖特定框架。

## 每个技能目录需要 LICENSE 文件

```bash
# 复制根 LICENSE 到每个技能目录
for d in skills/*/; do cp LICENSE "$d"; done
```

## index.json 生成 (v2.0)

```python
import json, re, os, glob

index = {
    "version": "2.0.0",
    "standard": "agentskills.io",
    "domain": "cybersecurity",
    "skills": []
}
for path in sorted(glob.glob("skills/*/SKILL.md")):
    with open(path) as f:
        m = re.match(r'^---\s*\n(.*?)\n---', f.read(), re.DOTALL)
    if not m: continue
    entry = {"path": os.path.dirname(path)}
    # Parse key-value fields
    for line in m.group(1).split("\n"):
        stripped = line.strip()
        for key in ["name", "description", "domain", "subdomain", "version", "license"]:
            if stripped.startswith(f"{key}:"):
                entry[key] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
    # Parse multi-line lists (tags, mitre_attack, nist_csf)
    current_list = None
    list_items = []
    for line in m.group(1).split("\n"):
        stripped = line.strip()
        if stripped in ("tags:", "mitre_attack:", "nist_csf:"):
            if current_list and list_items:
                entry[current_list] = list_items
            current_list = stripped.rstrip(":")
            list_items = []
            continue
        if current_list and stripped.startswith("- "):
            list_items.append(stripped[2:].strip().strip('"').strip("'"))
        elif current_list and stripped and not stripped.startswith("-"):
            entry[current_list] = list_items
            current_list = None
            list_items = []
    if current_list and list_items:
        entry[current_list] = list_items
    index["skills"].append(entry)
index["total_skills"] = len(index["skills"])
with open("index.json", "w") as f:
    json.dump(index, f, indent=2, ensure_ascii=False)
```

## Agent 无关化检查

公开发布前确保技能中无框架特定引用:
```bash
# 检查路径引用
grep -rn '/root/.hermes' skills/ --include='*.md' --include='*.py'
# 检查框架导入
grep -rn 'from hermes_tools' skills/ --include='*.py'
# 检查框架术语（排除 README 兼容性列表）
grep -rni 'hermes' skills/ --include='*.md' --include='*.py' | grep -vi 'compatible'
```

## 完整检查清单

- [ ] `.env` / `auth.json` / `config.yaml` 不在 git 中
- [ ] `memories/` / `sessions/` / `state.db` 不在 git 中
- [ ] Skills 中无硬编码密钥（Python 正则扫描真实格式）
- [ ] 无目标公司名（用匿名化规则扫描）
- [ ] 无框架特定路径引用（/root/.hermes 等）
- [ ] 无框架特定导入（hermes_tools 等）
- [ ] 每个技能目录有 LICENSE 文件
- [ ] YAML frontmatter 符合 v2.0 标准（含 domain/subdomain/mitre_attack）
- [ ] `.gitignore` + `README.md` + `LICENSE` + `SECURITY.md` + `CONTRIBUTING.md` 已创建
- [ ] `index.json` 已生成且含 v2.0 字段
- [ ] （安全库）`ATTACK_COVERAGE.md` 已创建

## README 最佳实践

- 渐变 header + badges + 打字机动画 (见 github-readme-visual-design.md)
- 分类表格: 每类一个 emoji 标题 + 技能列表 + 描述
- 真实成果展示: 目标 + 发现数量 + 严重级别
- MITRE ATT&CK 覆盖映射表
- Quick Start 代码块
- Contributing 指南 + 命名规范 + 质量标准
