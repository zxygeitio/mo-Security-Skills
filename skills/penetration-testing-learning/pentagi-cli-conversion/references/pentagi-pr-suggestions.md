# PentAGI PR 建议 — 经代码级验证

分析日期: 2026-06-07
上游: https://github.com/vxcontrol/pentagi (v2.1.0, 17.5k stars, 2.4k forks, 29 open issues, 16 open PRs, 141 merged PRs)
验证方法: 逐文件检查源码、.env.example、config.go、CONTRIBUTORS.md、open/closed issues、open/merged PRs

## ⚠️ 已被占用的方向（不要重复提）

| 方向 | 状态 | 详情 |
|------|------|------|
| ZIP Streaming Fix | **PR #339 已存在** | mason5052 已提交 "stream ZIP downloads without buffering archives"，正在 review |
| Sploitus 集成 | **PR#133 已合并** | CONTRIBUTORS.md 记录 "Implemented better exploit finding capabilities by Sploitus (PR#133)"。config.go 有 `SPLOITUS_ENABLED`。是搜索引擎集成形式（类似 DuckDuckGo），不是独立 `sploitus.go` 工具文件 |
| XSStrike flags | **PR #343 已存在** | mason5052 "avoid unsupported XSStrike flags in pentester prompt" |
| Profile 页面 | **PR #340 已存在** | Akalanka1337 "Replace Change Password with My Profile" |

## ✅ 验证后的可提 PR 方向

### PR 1: Execution Monitor 实现（高价值，config 空壳）

**验证依据：**
- `config.go` 有 `ExecutionMonitorEnabled bool`、`ExecutionMonitorSameToolLimit int`、`ExecutionMonitorTotalToolLimit int`
- `.env.example` 有完整文档：`EXECUTION_MONITOR_ENABLED`、`EXECUTION_MONITOR_SAME_TOOL_LIMIT`、`EXECUTION_MONITOR_TOTAL_TOOL_LIMIT`
- README 说是 "Beta" 功能，"Best for: models <32B parameters"
- **但 `backend/pkg/tools/` 目录下搜索 `execution_monitor`、`same_tool_limit`、`total_tool_limit` 无任何 Go 实现代码**
- `executor.go` 的 `Execute()` 方法中没有同工具计数逻辑
- `registry.go` 中无 execution_monitor 相关工具注册

**PR 内容：**
- 新增 `backend/pkg/tools/execution_monitor.go`
- 实现 `ExecutionMonitor` 结构体：per-flow 工具调用计数器 + 同工具连续调用检测
- 在 `executor.go` 的 `Execute()` 中注入检查：handler 执行前检查计数，超限注入 warning message
- 输出相似度检测：比较最近 N 次同工具输出的 hash/长度
- 在 `flow_manager.go` 的 `get_flow_status` 中暴露 monitor 状态

代码量: ~200行 Go
接受概率: 高（config 已定义好，只缺实现，是"填空题"式 PR）

### PR 2: Container Escape 修复（安全 Issue #337）

**验证依据：**
- Issue #337 已确认：`backend/pkg/docker/client.go:282-284` 在 `DOCKER_INSIDE=true` 时挂载 host Docker socket
- `docker-compose.yml` 默认 `DOCKER_INSIDE=true`
- 影响：prompt 注入 → agent 可执行 `docker run --privileged -v /:/host` → 完全控制 host
- **目前无 PR 修复**

**方案 A（最小改动）：**
- `docker-compose.yml` 中 `DOCKER_INSIDE` 默认改 `false`
- 文档明确警告启用风险
- 新增 `DOCKER_SOCKET_READONLY` 选项

**方案 B（更安全）：**
- 实现 Docker socket proxy（tecnativa/docker-socket-proxy 模式）
- agent 只能 create/start/stop/logs，不能 exec 到 host

代码量: ~30行（方案 A）
接受概率: 高（安全漏洞，维护者优先处理）

### PR 3: Language Bug 修复（Issue #285）

**验证依据：**
- Issue #285 已确认：`args.go` 中 `jsonschema_description` 用 `"in user's language only"` 导致 LLM 输出俄语
- 用 `"in English"` 的字段稳定输出英文
- 根因：`"user's language"` 对 LLM 是歧义指令
- **目前无 PR 修复**

**PR 内容：**
- 将 `backend/pkg/tools/args.go` 中所有 `"in user's language only"` 替换为 `"in English"`
- 或更精确：从 flow 的 `language` 字段注入实际语言

代码量: ~10行 sed 替换
接受概率: 很高（已确认 bug，改动明确）

### PR 4: Vector Store 去重（优化）

**验证依据：**
- `executor.go` 的 `storeToolResult()` 无 content hash 去重
- 同一 nuclei 扫描结果被多次存储，向量库膨胀
- `MergeAndDeduplicateDocs` 只按 score 去重，不按 content hash

**PR 内容：**
- `storeToolResult()` 增加 content hash 检查
- 存储前查询 `flow_id + tool_name + content_hash`，已存在则跳过
- `VECTOR_STORE_DEDUP_ENABLED` 环境变量（默认 true）

代码量: ~50行
接受概率: 高

### PR 5: Evidence Chain 原型推进（PR #279 是 Draft）

**验证依据：**
- PR #279 "add evidence receipt hash chain prototype" 是 Draft，2026-04-22 创建后未更新
- `examples/proposals/evidence_chain.md` 有完整 RFC
- 主要作者 mason5052 同时在做多个 PR

**PR 内容：**
- 将 Draft PR #279 推进到可合并状态
- 或独立提简化版：只签名 toolcall 摘要 + 最终报告 hash
- sidecar JSON 文件存储 receipt

代码量: ~200行
接受概率: 中（需与 mason5052 协调）

### PR 6: Browser 公私网路由增强

**验证依据：**
- `browser.go` 已有 `scPrvURL`/`scPubURL` + `localZones` 定义
- 但 CIDR 检查不够全面，缺少用户自定义内网段
- Issue #342 请求 BrowserOS MCP 集成（更重的方案）

**PR 内容：**
- `BROWSER_PRIVATE_NETWORKS` 环境变量追加自定义内网域名后缀
- 二进制 URL 检测扩展（增加 `.wasm`, `.avif`）
- 同 URL 同 flow 请求去重

代码量: ~80行
接受概率: 中高

### PR 7: Tool Success Memory（新功能，Issue #341 相关）

**验证依据：**
- Issue #341 请求 "Configurable fallback when tools fail"
- 现有 memory 系统（`memory.go`）只存通用知识
- `ToolCallLogProvider` 记录了每次调用但没有按 fingerprint 聚合成功率

**PR 内容：**
- 新增 `backend/pkg/tools/tool_recommend.go`
- 从 toolcall 日志聚合 `tool_name + target_fingerprint + success`
- `recommend_tools` 工具：输入 fingerprint 返回历史最佳工具

代码量: ~400行
接受概率: 中低（新功能，需要更多设计讨论）

## 提交顺序建议

1. **PR #3 Language Bug** — 10行，已确认 bug，最高接受率
2. **PR #1 Execution Monitor** — config 空壳，填空题式 PR
3. **PR #2 Container Escape** — 安全漏洞，维护者优先
4. **PR #4 Vector Dedup** — 简单优化
5. **PR #6 Browser Routing** — 增强
6. **PR #5 Evidence Chain** — 需协调
7. **PR #7 Tool Memory** — 新功能

## 贡献者画像

- **mason5052** — 最活跃，同时开 11 个 PR，主要做 docs/fix/RFC
- **asdek** — 项目维护者，合并 PR
- **mrigankad** — bug 修复
- **Akalanka1337** — 功能增强
- PR 模板要求：type(scope): description，需通过 CI 检查
