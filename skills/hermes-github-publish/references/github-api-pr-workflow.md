# GitHub API-based PR Contribution Workflow

## When to Use

- git clone 超时（大仓库如 pentagi 17k+ stars）
- Token 只有 fine-grained PAT，git push 返回 403
- 只需要修改少量文件，不需要本地完整仓库
- Hermes token 自动脱敏导致 git 认证失败

## Prerequisites

- Fine-grained PAT with:
  - **Fork 仓库**: Contents: Read and write
  - **Upstream 仓库**: Pull requests: Read and write（常被遗漏！）
- Token 存储在 `/tmp/.gh_token.txt`（用完必须清理）

## Step-by-Step

### 1. Fork

```python
api("POST", "/repos/{upstream}/forks", {})
# 等待 3-5 秒让 fork 创建完成
import time; time.sleep(5)
```

### 2. Sync Fork with Upstream

```python
# Get upstream main SHA
upstream_ref = api("GET", "/repos/{upstream}/git/refs/heads/main")
main_sha = upstream_ref["object"]["sha"]

# Update fork's main
api("PATCH", "/repos/{fork}/git/refs/heads/main", {"sha": main_sha, "force": True})
```

### 3. Create Branch

```python
api("POST", "/repos/{fork}/git/refs", {
    "ref": "refs/heads/{branch_name}",
    "sha": main_sha
})
```

### 4. Commit Files

```python
# Get current file
data = api("GET", "/repos/{fork}/contents/{path}?ref={branch}")
content = base64.b64decode(data["content"]).decode()
sha = data["sha"]

# Modify content
content = content.replace(old, new)

# Commit
api("PUT", "/repos/{fork}/contents/{path}", {
    "message": "fix: description",
    "content": base64.b64encode(content.encode()).decode(),
    "sha": sha,
    "branch": branch
})
```

### 5. Create PR

```python
api("POST", "/repos/{upstream}/pulls", {
    "title": "fix(security): description (#issue)",
    "body": "## Problem\n...\n## Fix\n...\nFixes #issue",
    "head": "{fork_user}:{branch}",
    "base": "main",
    "maintainer_can_modify": True
})
```

### 6. Fallback: Manual PR Link

If PR creation returns 403 (missing Pull requests permission):

```
https://github.com/{upstream}/compare/main...{fork_user}:{branch}?expand=1
```

用户点击此链接即可在浏览器中创建 PR。

## Common Pitfalls

1. **base64.b644encode** — 反复出现的拼写错误，正确是 `base64.b64encode`（两个 4 不是三个）

2. **File SHA must match** — 每次 PUT 文件必须传当前文件的 SHA，否则返回 409 Conflict

3. **Pattern matching with whitespace** — Go 代码中的 struct 字段有对齐空格（如 `\tinside   bool`），替换时必须匹配精确的空白。用 `repr(line)` 调试。

4. **Indentation in Go** — Go 用 tab 缩进。多层嵌套时确认 `\t\t` 数量正确。

5. **Token file cleanup** — 推送完成后必须 `rm -f /tmp/.gh_token.txt`

6. **Fork creation is async** — POST forks 返回 202 后需要等待几秒

7. **Multiple commits in one PR** — 可以在同一个 branch 上多次 PUT 不同文件，每个 PUT 一个 commit

## Verification Checklist

提交 PR 前验证：
- [ ] 所有目标文件在 branch 上有正确内容
- [ ] Go 代码语法正确（检查缩进）
- [ ] 环境变量/配置项命名与项目风格一致
- [ ] PR body 包含 Problem/Fix/Files Changed 结构
- [ ] 引用了相关 Issue 编号
