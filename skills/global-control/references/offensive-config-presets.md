# Offensive Config Presets

SRC/渗透测试"进攻性"配置预设 — 减少摩擦、放宽限制、延长超时，让工具链全速运转。

## 何时使用

用户说"进攻性强一点""少点拦截""优化框架让SRC更快"时，应用此预设。

## 安全注意

off 模式 = 零人工确认。仅在用户明确要求进攻性优化时应用。
操作完成后提醒用户下次 `/new` 新会话生效。

## 配置清单

### 1. 审批模式 (解决 python -c 拦截)

```yaml
approvals:
  mode: off          # smart→off: python -c 不再被拦截，无需写临时文件绕过
  cron_mode: deny    # cron 任务仍拒绝（安全）
```

**根因**: `approvals.mode: smart` 会拦截 `python -c '...'` 模式，即使 `subagent_auto_approve: true` 也无法绕过（这是 approvals 系统，不是 delegation 系统）。改为 `off` 彻底消除。

### 2. 终端超时

```yaml
terminal:
  timeout: 300       # 180→300: 慢目标(CERNET/海外/WAF背后)不易超时
```

### 3. 压缩 (保持更多上下文)

```yaml
compression:
  threshold: 0.6     # 0.5→0.6: 推迟压缩触发，前期发现不丢失
  target_ratio: 0.3  # 0.2→0.3: 压缩后保留更多内容
```

**权衡**: 消耗更多 token，但 SRC 长任务中前期侦察信息丢失代价更大。

### 4. 委托子代理

```yaml
delegation:
  max_iterations: 100        # 80→100: 复杂渗透链不中断
  child_timeout_seconds: 1200 # 900→1200: CERNET等慢目标不再全线超时
```

**经验**: 900s 超时在教育SRC目标（VPN-gated、国际、WAF限速）下仍频繁超时。1200s 为安全余量。

### 5. MCP 超时

```yaml
mcp_servers:
  hexstrike:
    timeout: 300     # 180→300: 大范围扫描不中断
  burpsuite:
    timeout: 240     # 120→240: 复杂抓包链路不超时
```

### 6. 安全开关

```yaml
security:
  allow_private_urls: true    # false→true: 内网目标直接访问
  tirith_enabled: false       # true→false: 去掉安全策略拦截
```

**说明**: `tirith` 是安全策略检查器，在进攻性场景下会拦截部分工具调用。关闭后工具链无阻塞。

### 7. 工具循环防护

```yaml
tool_loop_guardrails:
  warnings_enabled: false     # 静默模式，不打断进攻节奏
  warn_after:
    exact_failure: 3          # 2→3
    same_tool_failure: 5      # 3→5
    idempotent_no_progress: 3 # 2→3
  hard_stop_after:
    exact_failure: 8          # 5→8
    same_tool_failure: 12     # 8→12
    idempotent_no_progress: 8 # 5→8
```

**策略**: 放宽约 50-60%，允许更多重试。SRC 任务中目标不稳定是常态，不应过早中断。

## 恢复为保守模式

```yaml
approvals:
  mode: smart
terminal:
  timeout: 180
compression:
  threshold: 0.5
  target_ratio: 0.2
delegation:
  max_iterations: 80
  child_timeout_seconds: 900
security:
  allow_private_urls: false
  tirith_enabled: true
tool_loop_guardrails:
  warnings_enabled: true
```
