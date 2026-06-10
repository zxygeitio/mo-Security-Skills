# Skills Repository Publishing — agentskills.io 格式

## 适用场景

将 Hermes 技能发布为公开的技能库仓库（如 [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) 格式）。

## 仓库结构

```
<repo-name>/
├── README.md              # 项目介绍 + 技能分类表 + 快速开始
├── LICENSE                # Apache 2.0 推荐
├── SECURITY.md            # 安全政策 + 漏洞报告指引
├── ATTACK_COVERAGE.md     # MITRE ATT&CK 映射（安全类必须）
├── index.json             # 机器可读技能索引
├── .gitignore
└── skills/
    ├── <skill-name>/
    │   ├── SKILL.md       # YAML frontmatter + Markdown body
    │   ├── references/    # 深度技术参考
    │   ├── scripts/       # 辅助脚本
    │   └── assets/        # 模板/检查清单
    └── ...
```

## SKILL.md YAML Frontmatter 格式

```yaml
---
name: kebab-case-skill-name
description: 一行简洁描述
domain: cybersecurity          # 可选
category: penetration-testing  # 可选
tags: [tag1, tag2, tag3]
---
```

YAML frontmatter 用于 ~30 token 快速扫描发现。

## 构建步骤

### Step 1: 准备技能目录

```bash
# 按类别复制技能到临时目录
mkdir -p /tmp/publish-repo/skills
cp -r ~/.hermes/skills/<category>/* /tmp/publish-repo/skills/

# 重组织为 skills/ 子目录结构（如果不是）
cd /tmp/publish-repo
mkdir -p skills
for d in */; do
  [ "$d" = "skills/" ] && continue
  mv "$d" skills/
done

# 移除顶层 SKILL.md（分类文件不是技能）
rm -f skills/SKILL.md
```

### Step 2: 安全审计（关键！）

技能仓库的审计比普通项目更复杂：技能文档中**自然包含** secret/api_key/password 等词（描述漏洞模式），但不能有真实密钥值。

**用 Python 而非 grep 做审计**（grep 的 shell 转义在多层嵌套时极易出错）：

```python
import os, re

scan_dir = "/tmp/publish-repo/skills"
real_secrets = []
for root, dirs, files in os.walk(scan_dir):
    for fname in files:
        if not fname.endswith(('.md', '.py', '.sh', '.yaml')):
            continue
        with open(os.path.join(root, fname)) as f:
            content = f.read()
        if re.search(r'ghp_[a-zA-Z0-9]{36}', content):
            real_secrets.append(f"{fname}: GitHub PAT")
        if re.search(r'github_pat_[a-zA-Z0-9_]{50,}', content):
            real_secrets.append(f"{fname}: fine-grained PAT")
        if re.search(r'sk-[a-zA-Z0-9]{20,}', content):
            real_secrets.append(f"{fname}: OpenAI key")
        if re.search(r'AKIA[0-9A-Z]{16}', content):
            real_secrets.append(f"{fname}: AWS key")
```

**区分文档引用 vs 真实泄露：**
- ✅ 安全：`grep -oP 'appkey|appsecret'` — 描述漏洞搜索模式
- ✅ 安全：`AppSecret泄露→未授权数据访问` — 描述攻击链
- ✅ 安全：`clientIp=10.32.32.16` — 目标漏洞证据（目标自己泄露的）
- 🚨 危险：`app_secret="a1b2c3d4e5f6..."` — 真实密钥值

**内部 IP 检查：** SRC 技能中常包含目标内部 IP（漏洞证据），不是你的内网 IP，可安全发布。

### Step 3: 构建 index.json

```python
import json, re, os

index = {
    "version": "1.0.0",
    "generated": "2026-06-08T00:00:00Z",
    "repository": "https://github.com/OWNER/REPO",
    "domain": "cybersecurity",
    "total_skills": 0,
    "skills": []
}

for path in sorted(glob.glob("skills/*/SKILL.md")):
    with open(path) as f:
        content = f.read()
    m = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
    if not m:
        continue
    # Parse YAML frontmatter manually (avoid yaml dependency)
    yaml_text = m.group(1)
    entry = {"domain": "cybersecurity"}
    for line in yaml_text.split("\n"):
        line = line.strip()
        for key in ["name", "description", "category"]:
            if line.startswith(f"{key}:"):
                entry[key] = line.split(":", 1)[1].strip().strip('"').strip("'")
        if line.startswith("tags:"):
            tags_str = line.split(":", 1)[1].strip()
            if tags_str.startswith("["):
                entry["tags"] = [t.strip().strip('"').strip("'") for t in tags_str.strip("[]").split(",")]
    entry["path"] = os.path.dirname(path)
    index["skills"].append(entry)

index["total_skills"] = len(index["skills"])
```

### Step 4: 创建 README.md

README 应包含：
1. 一句话介绍 + 技能数量
2. 仓库结构图
3. SKILL.md 格式说明
4. **按类别分组的技能表**（名称 + 一行描述）
5. MITRE ATT&CK 覆盖概述
6. 快速开始（给 Hermes 用户和其他 AI agent 用户）
7. 真实成果展示（可选，增加可信度）
8. 贡献指南 + 命名规范
9. License + Disclaimer

### Step 5: 创建辅助文件

- `ATTACK_COVERAGE.md` — 按 ATT&CK tactic 分组，每个 technique 列出对应的 skill
- `SECURITY.md` — 漏洞报告指引 + 技能安全准则
- `LICENSE` — Apache 2.0 推荐
- `.gitignore` — 排除 .env, config.yaml, memories/, sessions/, state.db 等

### Step 6: Git 初始化 + 推送

```bash
cd /tmp/publish-repo
git init
git config user.name "username"
git config user.email "username@users.noreply.github.com"
git add -A
git commit -m "Initial commit: N skills"
git remote add origin https://x-access-token:TOKEN@github.com/OWNER/REPO.git
git branch -M main
git push -u origin main
```

## 命名建议

仓库名应体现：框架名 + 领域。示例：
- `Hermes-Security-Skills` — 安全技能库
- `Hermes-Pentest-Skills` — 渗透测试专项
- `Hermes-CTF-Skills` — CTF 专项

## Pitfalls

1. **grep 审计误报率极高** — 技能文档中大量出现 secret/key/password 等词（描述漏洞模式）。用 Python 正则匹配**真实密钥格式**（ghp_*, sk-*, AKIA*），不要用 grep 匹配关键词。

2. **references/ 中的漏洞证据 vs 真实数据** — SRC 技能的 references/ 常包含真实目标的漏洞证据（内部 IP、泄露的配置）。这些是**目标自己泄露的**，不是你的敏感数据，可以发布。但要确认没有你自己的 VPN 凭证、API key 混在其中。

3. **分类文件不是技能** — `skills/penetration-testing-learning/SKILL.md` 是分类描述文件，不应作为独立技能发布。只发布子目录中的实际技能。

4. **嵌套目录处理** — 有些技能的 references/ 下还有子目录（如 `references/ctf-automation-engine/`），`cp -r` 会正确处理，但要确认 git 也跟踪了这些嵌套目录。

5. **index.json 不要依赖 PyYAML** — 用正则解析 YAML frontmatter 即可，避免在构建环境中安装额外依赖。

6. **ATTACK_COVERAGE.md 不需要 100% 精确** — 这是概述性文档，按 tactic 大类分组即可。重点是展示技能覆盖面，不是精确到每个 sub-technique。

7. **gh CLI 在 Kali 上常不可用** — 用 git + REST API 替代。创建仓库用 `POST /user/repos`，推送用 git push。
