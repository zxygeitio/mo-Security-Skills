# GPT 审计方法论 — Python 脚本安全审查

## 用途
委托外部模型 (GPT/Claude) 对 Python 脚本做系统性安全和质量审查。适用于 SRC 框架、自动化工具、agent 脚本。

## 审计 prompt 模板

```
Review the following Python scripts and identify concrete bugs, design flaws, 
missing edge cases, and improvement opportunities. Be harsh and specific.

Review these files:
1. <file1>
2. <file2>
...

For each file, provide:
- SPECIFIC bugs (not vague suggestions)
- Edge cases that will cause crashes or wrong behavior
- Logic flaws in detection/filtering
- Missing error handling
- Performance issues
- Security issues in the scripts themselves

Output format: numbered list, each item with 
[FILE] [SEVERITY: critical/high/medium/low] [BUG/DESIGN/EDGE/PERF] 
followed by the specific issue and recommended fix.
```

## 常见发现模式 (2026-06-09 审计结果)

### CRITICAL 类
| 模式 | 修复 |
|------|------|
| `#!/usr/bin/env python3` 在 python3 被劫持的环境 | 改为 `#!/usr/bin/python3` |
| `subprocess.run(cmd, shell=True)` + 未校验输入 | `shlex.split` + `shell=False` + FQDN 校验 |
| 外部数据(crt.sh/API)直接用于 shell 命令 | 严格正则校验 + `shlex.quote()` |

### HIGH 类
| 模式 | 修复 |
|------|------|
| 全局状态文件不隔离 | `--workspace` 参数隔离到子目录 |
| 多词 CLI 参数截断 (`args[2]` 只取一个) | `args[2:]` join + delimiter 分隔 |
| TSV 写入用 `\t`.join() 嵌入制表符破坏格式 | `csv.writer(delimiter="\t")` |
| 生成的 shell 命令无转义 | `shlex.quote()` 包裹所有动态值 |
| HTTP 方法被降级 (PUT/PATCH→POST) | 保留原始方法，state-changing 加 WARNING |
| 403/404 一刀切拒绝 | 检查 strong hits (stack trace/CORS/PII) 后再拒绝 |
| dedup 过激 (仅按 URL) | 改为 `(method, url)` 元组 |
| test/dev/staging 被标记为低价值 | SRC 中是高价值攻击面，改为 P1 |

### MEDIUM 类
| 模式 | 修复 |
|------|------|
| NEGATIVE_HINT 包含 "login" 导致 auth API 被降分 | 拆分 FALLBACK_NEGATIVE vs LOGIN_FORM |
| CORS 评分太低 (12分) | +credentials=true 时额外 +25 分 |
| 文件名直接拼接 host (含 `:` 等特殊字符) | `re.sub(r'[^a-zA-Z0-9.-]', '_', host)` |
| sort 按字符串而非数值 | `int(x[2]) if x[2].isdigit() else 999` |
| 死代码 (定义但未使用的模式列表) | 标注用途或删除 |

## 修复优先级

1. **先修 shebang** — 全局影响，一行修复
2. **再修 shell 注入** — 安全关键
3. **然后修逻辑误杀** — 影响漏洞发现率
4. **最后修 schema/格式** — 数据完整性

## 验证清单

每个修复后必须:
1. `py_compile.compile(file, doraise=True)` — 语法检查
2. `head -1 file` — 确认 shebang
3. 关键功能 smoke test (help/health/reset)
4. 端到端: 生成数据 → 消费数据 → 检查输出
