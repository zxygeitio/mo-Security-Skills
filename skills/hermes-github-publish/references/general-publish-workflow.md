# 通用项目发布到 GitHub 流程

## 1. 准备阶段

```bash
cd /path/to/project

# 扫描敏感文件
grep -rnE '(api_key|apikey|token|secret|password|GITHUB_TOKEN)[[:space:]]*[:=][[:space:]]*["'"'"'][^${]' . \
  --include="*.py" --include="*.sh" --include="*.yaml" --include="*.json" \
  | grep -vE '(example|placeholder|your_|xxx|TODO|test|flag\{|CTF\{)'

# 检查大文件
find . -type f -size +1M -not -path './.git/*'
```

## 2. 创建 .gitignore

标准排除项：
- `__pycache__/`, `*.pyc`, `*.pyo` — Python 字节码
- `.env`, `*.key`, `*.pem` — 凭证文件
- `loot/`, `output/`, `results/` — 运行时输出
- `.git/` 嵌套仓库
- `*.log`, `*.db` — 日志和数据库

## 3. 初始化和提交

```bash
git init
git config user.name "USERNAME"
git config user.email "USERNAME@users.noreply.github.com"
git branch -M main
git add -A
git status --short  # 确认无敏感文件
git commit -m "feat: 项目描述"
```

## 4. 创建远程仓库（三种方式）

### 方式A: curl + GitHub REST API（最通用）
```bash
TOKEN="github_pat_... 或 ghp_..."
curl -s -X POST -H "Authorization: token $TOKEN" \
  -H "Content-Type: application/json" \
  https://api.github.com/user/repos \
  -d '{"name":"repo-name","description":"...","auto_init":false,"private":false}'
```

### 方式B: gh CLI（最简洁）
```bash
gh auth login
gh repo create repo-name --public --source=. --push
```

### 方式C: 网页手动创建
https://github.com/new → 不勾选 "Initialize this repository"

## 5. 推送

```bash
# 经典 token (ghp_) — URL 内嵌
git remote add origin https://USERNAME:ghp_TOKEN@github.com/USERNAME/REPO.git
git push -u origin main

# fine-grained token (github_pat_) — 用 credential helper
git config credential.helper store
echo "https://USERNAME:github_pat_TOKEN@github.com" >> ~/.git-credentials
git remote add origin https://github.com/USERNAME/REPO.git
git push -u origin main
```

## 5b. Fallback: API 文件上传

当 git push 持续返回 403（fine-grained PAT 常见问题），用 Contents API 逐文件上传：

```python
# 在 execute_code 中运行
import urllib.request, json, base64, os

with open("/tmp/.gh_token.txt") as fh:
    secret = fh.readlines()[0].strip()

REPO = "OWNER/REPO"
REPO_DIR = "/path/to/project"

def api(method, path, data=None):
    headers = {"Authorization": f"token {secret}", "Content-Type": "application/json",
               "Accept": "application/vnd.github.v3+json"}
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(f"https://api.github.com{path}", data=body, headers=headers, method=method)
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())

# 获取文件列表
result = terminal("cd {} && git ls-files".format(REPO_DIR))
files = [f.strip() for f in result['output'].strip().split('\n') if f.strip()]

for filepath in files:
    full_path = os.path.join(REPO_DIR, filepath)
    if not os.path.isfile(full_path): continue
    with open(full_path, 'rb') as fh:
        content_b64 = base64.b64encode(fh.read()).decode()
    payload = {"message": f"feat: add {filepath}", "content": content_b64, "branch": "main"}
    try:
        existing = api("GET", f"/repos/{REPO}/contents/{filepath}")
        payload["sha"] = existing["sha"]
    except: pass
    api("PUT", f"/repos/{REPO}/contents/{filepath}", payload)
```

完整脚本见 `scripts/github-api-upload.py`。

## 6. 推送后验证

```bash
curl -s "https://api.github.com/repos/OWNER/REPO" | python -c "
import sys,json; d=json.load(sys.stdin)
print(f'仓库: {d[\"full_name\"]}')
print(f'文件数: {d.get(\"size\",\"N/A\")}KB')
print(f'可见性: {\"私有\" if d[\"private\"] else \"公开\"}')
"
```
