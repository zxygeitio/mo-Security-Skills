---
name: agent-execution-monitor
description: "Agent执行监控与Loop Guard — 防止无效循环、请求预算管理、工具调用审计。借鉴PentAGI v2.0的Execution Monitor机制。"
category: ai-development
created_by: agent
---

# Agent Execution Monitor / Loop Guard

## 触发条件
- SRC/渗透长任务、自动化扫描、多工具编排
- agent 需要反复调用工具的复杂任务
- 用户要求"深挖""持续""自主"的高自主性任务

## 核心机制

### 1. 同工具循环检测（Same-Tool Limit）

当 agent 连续调用同一工具 N 次且结果无实质变化时，触发干预：

**检测规则：**
- 同一工具连续调用 ≥ 5 次 → 警告，建议切换策略
- 同一工具连续调用 ≥ 8 次 → 强制中断，输出原因和替代方案
- "结果无实质变化"判定：输出长度差 < 10% 且无新发现关键词

**干预动作：**
1. 记录循环原因到 `/tmp/hermes-exec-monitor.jsonl`
2. 输出诊断：哪些工具卡住了、为什么
3. 建议替代策略（换工具/换角度/跳过/报告已有发现）
4. 若用户设置了 `auto_mode=true`，自动切换到备选方案

### 2. 总工具调用预算（Total Tool Budget）

不同任务模式有不同的工具调用预算：

| 任务模式 | 默认预算 | 说明 |
|----------|----------|------|
| `quick-scan` | 30 | 快速扫描，超限即停 |
| `standard` | 80 | 标准SRC任务 |
| `deep-hunt` | 150 | 深度挖掘 |
| `unlimited` | ∞ | 用户明确要求不限制 |

**预算耗尽处理：**
- 剩余 20% 时提醒："预算即将耗尽，建议优先验证已发现的候选"
- 耗尽时输出：已完成的发现列表、未完成的候选、建议下一步
- 用户可随时 `extend budget +50` 追加

### 3. Evidence→Hypothesis→Validation 因果图

每次工具调用自动归类：

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
| `agent-exec-monitor.py` | Loop Guard + 因果图 + 预算管理 | `stats`, `alerts`, `graph`, `log`, `confirm`, `budget`, `summary`, `reset` |
| `sploitus-search.py` | Sploitus 漏洞搜索 | `<query> [--type exploits\|tools] [--limit N]` |
| `tool-memory.py` | 工具成功率记忆 | `record`, `recommend <fingerprint>`, `stats`, `history` |

```bash
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
> 长任务自动启用 Loop Guard：同工具连续 ≥5 次触发策略切换，总工具预算按任务模式分配，Evidence→Hypothesis→Validation 因果链全程记录。

## Pitfalls

1. **误判循环**：合法的批量扫描（如对 100 个子域各跑一次 nuclei）不应触发循环告警。判定条件需区分"同一目标重复调用"和"不同目标批量调用"。
2. **预算过紧**：复杂 SRC 任务 30 次工具调用远远不够。`quick-scan` 预算仅用于初始评估，正式任务用 `standard` 或 `deep-hunt`。
3. **因果图膨胀**：长任务的 JSONL 可能很大。只保留最近 200 条 + 所有 confirmed 发现。

## 参考文件

- `references/usage-patterns.md` — 典型工作流和命令示例
