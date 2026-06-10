---
name: pentagi-cli-conversion
description: 将 PentAGI 项目改造为纯 CLI 工具的方法论 — 绕过 FlowWorker/DB/GraphQL/Docker 依赖，直接复用 Provider + Tools 核心
---

# PentAGI CLI 化改造方法论

## 参考文件

- `references/pentagi-v2.1-analysis.md` — PentAGI v2.1.0 完整可复用能力分析（7个高价值模块 + CLI化方案）
- `references/pentagi-pr-suggestions.md` — 可提 PR 的 7 个方向（含代码改动点、接受概率、提交顺序）

## 2026-06-07 上游 v2.1.0 新增可复用能力

PentAGI v2.1.0 (2026-05-29) 新增了以下 CLI 化时值得保留的能力：

### Execution Monitor（执行监控/Loop Guard）
- `EXECUTION_MONITOR_SAME_TOOL_LIMIT` — 同一工具连续调用上限（默认5次）
- `EXECUTION_MONITOR_TOTAL_TOOL_LIMIT` — 总工具调用上限（默认10次）
- 超限触发 mentor 干预，切换策略
- 对小模型（<32B）效果提升 2x，代价 2-3x 执行时间
- **CLI 化建议**：直接在 `callWithTools()` 循环中加计数器，超限返回错误提示

### Task Planning（任务规划）
- `AGENT_PLANNING_STEP_ENABLED` — 执行前自动分解为 3-7 步
- **CLI 化建议**：可选 pre-execution prompt，让 LLM 先输出步骤再执行

### Sploitus 漏洞搜索
- 聚合 ExploitDB + Packet Storm + GitHub Security Advisories
- `SPLOITUS_ENABLED` 开关
- **CLI 化建议**：作为 `search` 工具的新 provider，类似 duckduckgo/google

### Chain Summarization（链式摘要）
- 保留最近 QA 段落（不摘要），旧段落压缩
- 可配置字节数上限（50KB-75KB）
- **CLI 化建议**：在 chat history 超限时自动摘要旧消息

### File Management
- `/work/uploads`, `/work/resources` + 容器同步
- **CLI 化建议**：用本地目录映射替代容器同步

### Knowledge Base + 向量搜索
- pgvector 语义搜索 + 匿名化
- **CLI 化建议**：SQLite + 简单 TF-IDF 替代 pgvector，或跳过

### 多 Agent 角色（12种 Executor）
新增 `EnricherExecutor`（结果丰富化）和 `ReporterExecutor`（报告生成）
- **CLI 化建议**：保留 pentester/searcher/coder/reporter 四个核心角色

## 2026-06-07 深度验证补充

已对 main 分支代码做逐文件验证（`args.go`、`config.go`、`templates/`、`tools/`、`docker/client.go`）。关键纠正：

- **Execution Monitor 不是空壳** — 通过 `question_execution_monitor.tmpl` 实现 prompt-based adviser consultation，不是代码级计数器。
- **Language Bug (#285) 已修复** — `args.go` 采用 "Technical-channel" (英文) + "Engagement-log" (用户语言) 双通道设计。
- **Sploitus 已实现** — PR#133 已合并，是搜索引擎集成（不是独立工具文件）。`SPLOITUS_ENABLED` 默认 false。
- **Container Escape (#337)** — `docker/client.go:282-284` 确认挂载 host socket，`.env.example` 原默认 `DOCKER_INSIDE=true`。

架构深度分析见 `references/pentagi-architecture-deep-dive.md`。

已读取 `vxcontrol/pentagi` main 分支（本地快照 `/tmp/pentagi-src`）：HEAD `879e87c`，最新 release tag `v2.1.0`（2026-05-29）。当前 PentAGI 重点已经从“能跑的早期自动化”扩展为：多 Provider（含 Qwen/Kimi/GLM/DeepSeek/Gemini 新模型配置和 Qwen thinking control）、工具调用日志、assistant flow 管理、pgvector knowledge 管理、Graphiti 可选知识图、Langfuse/Grafana observability、flow-scoped files/resources、anonymization、chain summarizer 配置。`examples/proposals/mcp_client_integration.md` 仍是 RFC/design-only，不是 runtime MCP 实现；核心原则是显式配置、allowlist、`mcp.<server>.<tool>` 命名空间、审计、超时/响应大小限制和故障隔离。

CLI 化思路仍然成立：不要直接复用 `FlowWorker` 重依赖链；优先保留 Provider + Tool schema + agent loop。但如果继续改造 CLI，应补入上游 v2.1 的两个关键能力：
- 工具调用日志/loop guard：记录每次 tool call，限制同工具重复和总工具次数，避免 agent 卡在无效扫描。
- Flow evidence schema：用轻量 JSONL/SQLite 保存 flow/task/subtask/action/artifact，替代完整 PostgreSQL/GraphQL，但保留可审计性。

## 背景
PentAGI 是一个 AI 驱动的自动化渗透测试多智能体平台，架构重（PostgreSQL + pgvector + GraphQL + Docker），但核心逻辑（Provider 调用 + Tools 执行）是干净的。

目标：提取核心逻辑，绕过重型依赖，变成纯 CLI 交互工具。

## 核心依赖分析

### 必须保留的组件（可直接复用）
- `backend/pkg/providers/` — Provider 层，支持 OpenAI/Anthropic/Ollama/DeepSeek/Qwen/GLM/Kimi/Bedrock/Custom HTTP
- `backend/pkg/tools/` — ToolsExecutor，35个工具（terminal/search/done 等）
- `backend/pkg/providers/provider/provider.go` — `Provider.Call()` 和 `Provider.CallWithTools()` 接口
- `backend/pkg/providers/pconfig/config.go` — YAML 配置解析
- `langchaingo/llms` — 底层 LLM 抽象

### 必须绕过的组件（强依赖链）
- `FlowWorker` → 强依赖 `DB() database.Querier`（100+ 方法）+ GraphQL Subscribers + Docker + pgvector
- `FlowProvider` → 要求 `DB()` 接口注入，无法直接实例化
- `GraphQL Subscriptions` → 实时推送，CLI 用 stdout print 替代
- `PostgreSQL` → Flow/Task 状态全改为内存
- `pgvector` → 向量搜索 stubbed
- `Docker` → 工具执行改用 host shell `os/exec`

## 关键决策：裸 Call() 而非 FlowWorker

### 错误路线（走不通）
```
CLIRunner → FlowWorker → FlowProvider → DB() → PostgreSQL
```
FlowWorker 初始化时就会因为 DB 不存在而 panic。

### 正确路线
```
CLIRunner → Provider.Call() / Provider.CallWithTools() → langchaingo
```

`Provider.Call()` 只需要 `llms.Model` 接口，不依赖 DB。
`Provider.CallWithTools()` 额外需要 `[]llms.Tool`，可直接构造。

### Provider 实例化路径（无 DB）
```
config.Config → ProviderController → buildProvider() → openai.New() / anthropic.New() / custom.New()
```

绕过了 `ProviderController.GetProvider()`（它要求 DB），改为直接调用各 provider 的 `New()` 构造函数。

## CLI 架构设计

```
backend/cmd/cli/main.go         CLI 入口
├── buildConfig()              读取 env + flag → config.Config
├── buildProvider(provider)     按类型实例化 provider（openai/anthropic/custom/ollama/deepseek...）
├── registerTools()             注册 tool name → handler func
└── cli.CLIRunner.Run()         交互循环

backend/pkg/cli/cli.go          核心引擎
├── CLIRunner                   管理 chat history + tool handlers
├── buildPrompt()               组装 system prompt
├── callWithTools()             provider.CallWithTools() + 工具调用循环
├── executeToolCalls()          根据工具名分发到具体 handler
└── extractResponseText()       从 llms.ContentResponse 提取文本
```

## 已实现的 Provider 工厂模式

```go
func buildProvider(cfg *config.Config) (llms.Model, error) {
    switch cfg.ProviderConfig.Type {
    case "openai":
        return openai.New(openai.WithAPIKey(cfg.ProviderConfig.APIKey),
            openai.WithBaseURL(cfg.ProviderConfig.ServerURL+"/v1"))
    case "anthropic":
        return anthropic.New(anthropic.WithAPIKey(cfg.ProviderConfig.APIKey),
            anthropic.WithBaseURL(cfg.ProviderConfig.ServerURL+"/v1"))
    case "custom":
        // 从 YAML 读 model 等参数
        return custom.NewHTTP(cfg.ProviderConfig.ServerURL, cfg.ProviderConfig.APIKey, model)
    case "ollama":
        return ollama.New(cfg.ProviderConfig.ServerURL)
    case "deepseek":
        return deepseek.New(cfg.ProviderConfig.ServerURL, cfg.ProviderConfig.APIKey)
    // ... 其他 provider
    }
}
```

## 工具注册模式

```go
func (r *CLIRunner) RegisterTool(name string, handler func(ctx context.Context, input string) (string, error)) {
    r.toolHandlers[name] = handler
}
```

由于 `tools` 包常量未导出（大写），CLI 层用字符串字面量注册：
```go
runner.RegisterTool("terminal", terminalHandler)
runner.RegisterTool("search", searchHandler)
runner.RegisterTool("done", doneHandler)
```

## callWithTools 核心模式

```go
func (r *CLIRunner) callWithTools(ctx context.Context, msgs []llms.MessageContent,
    tools []llms.Tool) (*llms.ContentResponse, error) {

    resp, err := r.provider.CallWithTools(ctx, msgs, tools,
        llms.WithMaxTokens(maxTokens),
        llms.WithTemperature(temperature),
    )
    if err != nil {
        return nil, err
    }

    // 遍历 ToolCall，执行 handler，追加结果到 msgs
    for _, tc := range toolCalls {
        result, err := r.toolHandlers[tc.Function.Name](ctx, tc.Function.Arguments)
        msgs = append(msgs, llms.MessageContent{
            Role: "tool",
            Content: result,
        })
    }

    // 递归调用直到无 ToolCall
    return r.callWithTools(ctx, msgs, tools)
}
```

## 已知问题和限制

1. **Build 超时**：首次 `go build` 需要下载 langchaingo 及其传递依赖，在网络慢的环境下可能超时。解决方案：分开 `go mod download` 再 `go build`。

2. **tools 包常量未导出**：PentAGI 的 `tools.go` 中工具名常量（如 `BarrierToolType`）是大写开头但未在包级别导出，CLI 用字符串字面量代替。

3. **ToolsExecutor 未直接复用**：`pkg/tools/tools.go` 的 `ToolsExecutor` 接口需要 DB 注入，CLI 只复用了工具**定义**（`llms.Tool` 构造方式），工具执行逻辑自行实现。

4. **pgvector 记忆缺失**：CLI 无持久记忆，每次对话独立。后续可接入轻量 pgvector 连接实现 RAG 记忆。

5. **RunSingle 工具反馈未完成**：`RunSingle()` 目前在 LLM 返回后直接输出，尚未把工具调用结果反馈给 LLM 做二次推理（完整的 agent loop 需要这个）。

## 文件清单

- `backend/cmd/cli/main.go` — 447行，CLI 入口
- `backend/pkg/cli/cli.go` — 318行，CLIRunner 核心引擎
- 需创建：`providers.yaml`（custom provider 配置格式参考）
- 需验证：各 provider 的 `New()` 构造函数具体签名（openai 在 `openai.New()` 第65行附近）

## 验证步骤

```bash
# 1. 语法检查
cd /tmp/pentagi/backend
gofmt -e ./pkg/cli/cli.go ./cmd/cli/main.go

# 2. 依赖下载（单独运行，防止超时）
go mod download

# 3. 编译
go build -trimpath -o pentagi-cli ./cmd/cli/

# 4. 运行
./pentagi-cli --provider openai --api-key sk-... --model gpt-4o
```

## Pitfalls

1. **声称某功能"不存在"前必须验证** — 用户纠正过："再严谨一下"。分析开源项目时，功能可能以搜索引擎集成形式存在（如 Sploitus 作为 DuckDuckGo 类型的 search provider），而不是独立工具文件。必须检查：`.env.example` 中的配置变量、`config.go` 中的 struct 字段、`CONTRIBUTORS.md` 中的 PR 记录、open/closed PRs。config 存在 ≠ 实现存在（如 Execution Monitor），但也别把已实现的说成缺失。

2. **PR 重复提交** — 提 PR 前必须检查 open PRs 列表。本 session 中 ZIP fix（#339）和 XSStrike fix（#343）已被 mason5052 占了。

3. **代码级验证标准** — 声称"X 没有实现"需要：在 `backend/pkg/tools/` 目录搜索相关函数名/常量名，确认无匹配。声称"Y 有 bug"需要：定位具体文件和行号。声称"Z 可以优化"需要：确认当前实现确实有该问题。

## 参考代码位置

- Provider 接口：`backend/pkg/providers/provider/provider.go`
- OpenAI 实现：`backend/pkg/providers/openai/openai.go`（New 在第65行，Call 在第138行）
- Anthropic 实现：`backend/pkg/providers/anthropic/`
- Custom HTTP：`backend/pkg/providers/custom/`
- Tools 定义：`backend/pkg/tools/tools.go`
- ProviderConfig：`backend/pkg/providers/pconfig/config.go`
- HTTPClient：`backend/pkg/system/utils.go` 第70行
