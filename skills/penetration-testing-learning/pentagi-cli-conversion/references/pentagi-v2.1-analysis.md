# PentAGI v2.1.0 — 可复用能力详细分析

分析日期: 2026-06-07
上游: https://github.com/vxcontrol/pentagi (v2.1.0, 2026-05-29, 357 commits)

## 高价值可复用模块

### 1. Execution Monitor（Loop Guard）

配置: `EXECUTION_MONITOR_SAME_TOOL_LIMIT=5`, `EXECUTION_MONITOR_TOTAL_TOOL_LIMIT=10`
效果: 小模型结果质量提升 2x，代价 2-3x 执行时间
CLI化: 在 tool call 循环中加计数器，超限切换策略

### 2. Task Planning

配置: `AGENT_PLANNING_STEP_ENABLED=true`
机制: 执行前 LLM 输出 3-7 步，逐步执行并追踪
CLI化: 可选 pre-execution prompt

### 3. Sploitus 漏洞搜索

聚合: ExploitDB + Packet Storm + GitHub Security Advisories
CLI化: search 工具的新 provider

### 4. Chain Summarization

配置: `SUMMARIZER_LAST_SEC_BYTES=51200`, `SUMMARIZER_MAX_QA_SECTIONS=10`
CLI化: chat history 超限时 LLM 摘要旧消息

### 5. Browser 公私网路由

内网后缀: .local/.lan/.htb/.dev/.test/.corp/.internal
双 scraper: scPrvURL + scPubURL
二进制检测: .pdf/.zip/.exe → 拒绝渲染

### 6. Tool Registry 模式

ToolType: Barrier/Environment/SearchNetwork/SearchVectorDb/Agent/StoreAgentResult/StoreVectorDb
CLI化: map[string]ToolHandler 注册

### 7. 多 Agent 角色

核心4角色: pentester/searcher/coder/reporter
扩展: installer/memorist/enricher/generator/refiner

## 不适合 CLI 化

Graphiti/Neo4j(太重), Langfuse/Grafana(企业级), Docker隔离(host shell即可), PostgreSQL+pgvector(SQLite替代), GraphQL(stdin/stdout)
