# Agent Execution Monitor — 使用模式

## 脚本位置
`/root/.hermes/scripts/agent-exec-monitor.py`

## 典型工作流

### SRC 任务开始
```bash
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py reset
```

### 每次工具调用后
```bash
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py log nuclei example.com "CVE-2024-1234 matched" "RCE via deserialization"
```

### 确认漏洞后
```bash
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py confirm nuclei example.com confirmed high
```

### 检查预算
```bash
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py budget standard
```

### 任务结束/上下文交接
```bash
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py summary
```

## 循环检测行为

- ≥5 次同工具同目标 → ⚠️ 警告输出 + 记录到 alerts.jsonl
- ≥8 次同工具同目标 → 🚨 强制中断 (exit code 2)
- "同目标"判定：tool + target 完全匹配
- 批量扫描不同目标不会触发（每个 target 独立计数）

## 数据保留

- 默认保留最近 500 条记录
- alerts.jsonl 永久保留
- reset 清空所有数据
