---
name: agent-execution-monitor
description: "Agent执行监控与Loop Guard v2.1 — 语义循环+时间门限+负面记忆+停滞检测+workspace隔离。借鉴PentAGI v2.0。"
category: ai-development
created_by: agent
---

# Agent Execution Monitor / Loop Guard v2.1

## 触发条件
- SRC/渗透长任务、自动化扫描、多工具编排
- agent 需要反复调用工具的复杂任务
- 用户要求"深挖""持续""自主"的高自主性任务

## v2.0 升级 (2026-06-09, 基于NJMU测试教训)

### 新增机制

#### 1. 语义循环检测（Semantic Loop Detection）
不仅追踪单个 tool+target 重复，还检测"相同测试方案"的序列级重复：
- 计算最近 10 步操作序列的哈希签名
- 相同签名出现 ≥3 次 → 警告
- 相同签名出现 ≥5 次 → 强制停止
- **解决NJMU问题**: agent 重复"curl→SQLi→ehall→CAS→WebVPN→子域→评估"同一方案 10+ 轮

#### 2. 时间门限（Staleness Gate）
自上次确认发现后的时间追踪：
- ≥10 分钟无确认发现 → 警告
- ≥20 分钟 → 建议切换目标/报告已有发现
- 仅在首次确认发现后激活，避免新任务误报

#### 3. 负面记忆（Rejected Finding Memory）
记录被用户拒绝的发现类型：
- `reject <tool> <target> <finding_type> [feedback]`
- 未来产出相同类型发现时自动警告
- **解决NJMU问题**: 用户说"这些没有用"后，agent 仍继续产出同类 SUDY IP泄露

#### 4. 进展停滞检测（Stagnation Detection）
连续工具调用无新证据检测：
- 连续 8 次调用无 new_evidence 标记 → 警告
- 连续 12 次 → 强制停止
- 区分"有证据但不确认"和"完全没有新信息"

## v2.1 升级 (2026-06-09, GPT审计修复)

#### 5. Workspace 隔离（--workspace）
按目标/workspace 隔离监控状态，避免跨目标污染：
```bash
agent-exec-monitor.py --workspace njmu health
agent-exec-monitor.py --workspace njmu log curl "kdc.njmu.edu.cn" "ip_leak"
agent-exec-monitor.py --workspace mgm reset
```
状态文件存 `/tmp/hermes-monitor-<name>/`。不指定 --workspace 时使用全局 `/tmp/hermes-exec-*.jsonl`。
**适用场景**: 同时测试多个目标，或中断后恢复时需要干净状态。

#### 6. 证据截断修复
log 命令的 evidence/hypothesis 参数不再截断多词：
```bash
# 旧: evidence 只取 args[2]，多词被丢弃
# 新: args[2:] join，用 || 分隔 evidence 和 hypothesis
agent-exec-monitor.py log curl "target.com" "found SQL error in login endpoint" || "possible SQLi via username param"
```

#### 7. 确认记录计为进展
confirm 命令设置 `new_evidence=True`，不再触发假停滞。

### 原有机制（仍有效）

#### 5. 同工具循环检测（Same-Tool Limit）
- 同一工具连续调用 ≥ 5 次 → 警告
- 同一工具连续调用 ≥ 8 次 → 强制中断

#### 6. 总工具调用预算（Total Tool Budget）
| 任务模式 | 默认预算 |
|----------|----------|
| `quick-scan` | 30 |
| `standard` | 80 |
| `deep-hunt` | 150 |
| `unlimited` | ∞ |

#### 7. Evidence→Hypothesis→Validation 因果图
每次工具调用自动归类到因果链。

```
[Evidence] 工具输出 → 提取关键发现
    ↓
[Hypothesis] 发现 → 生成可验证假设
    ↓
[Validation] 假设 → 选择验证工具 → 执行 → 确认/否定
```

**存储格式** (JSONL):
```json
{
  "ts": "2026-06-07T21:30:00Z",
  "tool": "nuclei",
  "target": "example.com",
  "evidence": "CVE-2024-1234 matched",
  "hypothesis": "RCE via deserialization",
  "validation_tool": "curl",
  "validation_result": "confirmed",
  "severity": "high"
}
```

### 4. Scope Guard — 范围守护

防止 agent 偏离授权范围：

- 目标域名/IP 白名单检查
- 禁止访问未授权的内网段
- 禁止执行破坏性命令（rm -rf / DROP TABLE 等）
- WAF 触发后自动暂停该目标 5 分钟

### 5. Critic Gate — 结果质量门

在输出报告/提交发现前，自动执行质量检查：

- 漏洞是否有完整复现步骤？
- 是否有截取的响应证据？
- 严重级别是否匹配实际影响？
- 是否误报（SPA fallback / WAF 403 / 默认页面）？

## 实现脚本

本技能包含 3 个脚本（`scripts/` 目录），同时部署到 `/root/.hermes/scripts/`：

| 脚本 | 功能 | 用法 |
|------|------|------|
| `agent-exec-monitor.py` | Loop Guard v2.1 + 因果图 + 预算 + 负面记忆 + workspace隔离 | `stats`, `alerts`, `graph`, `log`, `confirm`, `reject`, `budget`, `summary`, `health`, `reset`, `--workspace NAME` |
| `sploitus-search.py` | Sploitus 漏洞搜索 | `<query> [--type exploits\|tools] [--limit N]` |
| `tool-memory.py` | 工具成功率记忆 | `record`, `recommend <fingerprint>`, `stats`, `history` |

```bash
# v2.1 快速健康检查（所有守卫一目了然）
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py health

# v2.1 按目标隔离监控（多目标并行测试时）
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py --workspace njmu health
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py --workspace njmu log curl "kdc.njmu.edu.cn" "ip_leak"

# 记录被用户拒绝的发现类型（防止重复产出）
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py reject curl "kdc.njmu.edu.cn" "ip_leak" "user says no value"

# 查看当前会话统计
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py stats

# 查看循环检测告警
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py alerts

# 重置计数器
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py reset

# 查看因果图
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py graph
```

## 与 Hermes 集成

在 `global-control` 技能的 SRC/渗透任务流程中自动加载本技能。

在 SOUL.md 的执行风格中引用：
> Loop Guard v2.1 自动生效：语义循环检测(方案级重复≥5次强制停止)、时间门限(≥20min无确认发现警告)、负面记忆(被拒绝发现类型自动告警)、进展停滞(连续12次无证据强制停止)、workspace隔离(--workspace NAME)。

## Pitfalls

1. **误判循环**：合法的批量扫描（如对 100 个子域各跑一次 nuclei）不应触发循环告警。判定条件需区分"同一目标重复调用"和"不同目标批量调用"。
2. **预算过紧**：复杂 SRC 任务 30 次工具调用远远不够。`quick-scan` 预算仅用于初始评估，正式任务用 `standard` 或 `deep-hunt`。
3. **因果图膨胀**：长任务的 JSONL 可能很大。只保留最近 200 条 + 所有 confirmed 发现。
4. **v2.0 语义循环误判**：合法的"侦察→指纹→攻击→验证"循环可能被误判为重复方案。解决方案：当 evidence 字段有实质内容时，方案签名应包含 evidence 差异。
5. **v2.0 时间门限冷启动**：新任务开始时无 confirmed finding，应以 session 开始时间为准，而非 999 分钟。
6. **v2.0 负面记忆粒度**：reject 记录的是 tool+target+finding_type 三元组，过于精确可能漏匹配，过于宽泛可能误匹配。建议 finding_type 用通用类别（如 "ip_leak" 而非具体 IP 地址）。

## 参考文件

- `references/usage-patterns.md` — 典型工作流和命令示例
- `references/gpt-audit-methodology.md` — Python脚本安全审计方法论、常见发现模式、修复优先级
