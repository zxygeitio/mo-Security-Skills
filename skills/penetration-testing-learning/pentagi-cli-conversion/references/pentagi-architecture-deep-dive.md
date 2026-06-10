# PentAGI Architecture Deep Dive (2026-06-07 验证)

## Execution Monitor — 不是代码级计数器

之前误判为 "config 空壳"，实际实现方式是 **prompt-based adviser consultation**：

- `question_execution_monitor.tmpl` (2459 bytes) — 向 adviser 提交完整执行历史
- adviser 分析：是否在循环、是否卡住、是否需要切换策略
- 触发条件由 config 控制：`EXECUTION_MONITOR_ENABLED`、`EXECUTION_MONITOR_SAME_TOOL_LIMIT`、`EXECUTION_MONITOR_TOTAL_TOOL_LIMIT`

**代码位置**: `backend/pkg/templates/prompts/question_execution_monitor.tmpl`

**工作原理**: 不是硬编码的工具调用计数器，而是 LLM 判断的"软"监控。agent 把所有 tool calls 的 name/args/result 发给 adviser，adviser 回答 6 个关键问题：
1. 是否有实质进展？
2. 是否在重复相同操作？
3. 是否卡在循环？
4. 是否需要换策略？
5. 任务是否不可能完成？
6. 最关键的下一步是什么？

**优势**: 灵活，能理解语义级的"卡住"（不只是同工具重复）
**劣势**: 依赖 LLM 判断质量，小模型可能误判

## Language Bug (#285) — 已修复

`args.go` 中采用双通道设计：
- **"Technical-channel payload"** — 始终英文，用于技术内容（查询、代码、结果）
- **"Engagement-log entry"** — 使用 flow 设置的语言，用于用户可见的评论

所有 `jsonschema_description` 都遵循这个模式。Issue #285 的 `"in user's language only"` 歧义已被消除。

## Sploitus — 已实现

PR#133 已合并。实现为搜索引擎集成（类似 DuckDuckGo/Tavily），不是独立工具文件。
- Config: `SPLOITUS_ENABLED` (default: false)
- 工具名: `sploitus`（在 `registry.go` 中注册）
- 参数: query, type (exploits/tools), sort, limit

## Tool Registry 完整清单

| 类型 | 工具 |
|------|------|
| Barrier | done, ask |
| Agent | maintenance, coder, pentester, advice, memorist, search |
| Store Agent Result | maintenance_result, code_result, hack_result, memorist_result, search_result, enricher_result, report_result |
| Search Network | browser, google, duckduckgo, tavily, traversaal, perplexity, searxng, sploitus |
| Search Vector DB | search_in_memory, search_guide, search_answer, search_code, graphiti_search |
| Store Vector DB | store_guide, store_answer, store_code |
| Environment | terminal, file, get_flow_status, stop_flow, submit_flow_input, patch_flow_subtasks, wait_flow_completion |

## Agent Roles (12 Executor Types)

| Executor | 角色 | 主要工具 |
|----------|------|----------|
| Primary | 主协调器 | 所有工具 |
| Assistant | 交互助手 | terminal, file, browser, search |
| Adviser | 导师/顾问 | search_in_memory, search_guide |
| Pentester | 渗透测试 | terminal, browser, sploitus |
| Coder | 代码开发 | terminal, file |
| Installer | 环境维护 | terminal |
| Searcher | 情报收集 | browser, google, duckduckgo, tavily, sploitus |
| Generator | 子任务生成 | subtask_list |
| Refiner | 结果优化 | subtask_patch |
| Memorist | 记忆检索 | search_in_memory, search_guide, search_answer, search_code |
| Enricher | 结果丰富化 | search, graphiti_search |
| Reporter | 报告生成 | terminal, file |

## Evidence Chain (RFC, PR #279 Draft)

- `examples/proposals/evidence_chain.md` — 完整 RFC
- PR #279 "add evidence receipt hash chain prototype" — Draft 状态，4月后未更新
- 设计: Ed25519 签名的 receipt 链，sidecar JSON 存储
- 状态: 可以推进或独立提简化版
