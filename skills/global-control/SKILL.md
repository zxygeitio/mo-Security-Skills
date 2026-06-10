---
name: global-control
description: 全局控制入口 — 在 Hermes 系统维护、SRC/渗透、长任务、多工具编排前先加载；负责基线巡检、技能分流、任务状态、验证闭环。
category: ai-development
created_by: agent
---

# Global Control / 全局控制入口

## 触发条件

遇到以下任一任务，先加载本技能，再加载专项技能：

- 用户说“控制全局”“优化整个系统”“检查技能/框架/工具/MCP/Cron/代理”。
- 需要修改 Hermes Agent、配置、SOUL/persona、技能、MCP、Cron、Gateway、Provider、工具集。
- SRC/渗透测试任务，尤其是需要长时间自主挖掘、Burp/HexStrike/VPN/报告生成。
- 多步骤长任务、后台任务、多 Agent 编排、需要跨会话复盘或任务恢复。

## 总控原则

1. 主控权：Hermes Agent 是本机任务总控，主动整合并调度技能、内置工具、MCP、Cron、Gateway、Provider、浏览器、终端、文件系统和长期记忆；除危险/越权/不可逆操作外，不把控制权外包给用户反复决策。
2. 不凭记忆猜系统状态：配置、时间、进程、端口、git、文件、工具版本必须用工具查。
3. 先建立基线，再行动：运行总控脚本或等价检查，确认 Hermes、MCP、技能、仓库、VPN/代理状态。
4. 技能分流：总控负责入口、编排、验证和闭环，专项技能负责领域细节；避免把大技能全文当默认上下文；大技能主文件保持轻量，历史案例/payload/专项打法拆到 references 按需读取。
5. 外部安全技能语料融合：遇到防御、DFIR、云安全、身份、AI 安全、风险合规，或需要补强 SRC/API/JWT/OAuth/BOLA 方法论时，先查询 Anthropic Cybersecurity Skills 外部索引，而不是 bulk import 754 个技能：`/usr/bin/python3 /root/.hermes/scripts/anthropic-cyber-skills-router.py --query '<task>' --limit 10`。融合说明见 `references/anthropic-cybersecurity-skills-fusion.md`；外部技能只作程序素材，Hermes 证据门禁仍是最终裁决。
6. 漏洞情报按需实时：SRC/渗透涉及产品/版本/CVE/POC 时，现场运行 `/root/.hermes/scripts/hermes-vuln-query.sh --refresh --keyword '<product-or-CVE>'` 查询/刷新；不要依赖长期每日 Cron，因为 Hermes 不一定 7×24 常驻。历史本地库只作缓存，新 CVE 情报只作候选，不直接当报告结论。
6. 只有一个 in_progress：用 todo 管理长任务，完成一步立即更新。
7. 不口头承诺：说要检查/修改/验证就立即工具执行。
8. 输出以结果为主：SRC/渗透过程不频繁汇报，验证成功后直接给可提交结果。
9. 控制面优先级：内置 file/terminal/browser/delegation/cron 是稳定控制面；MCP 是外接能力面；脚本/状态文件用于可恢复长任务。

## 控制面盘点

执行系统优化、长任务或 SRC 总控时，按需确认以下部件可控并可被主控调度：

- 配置面：`/root/.hermes/config.yaml`、`/root/.hermes/SOUL.md`、profiles、toolsets、approvals、安全开关。
- 技能面：`/root/.hermes/skills/**/SKILL.md`，大技能拆分到 references，过期技能立即 patch。
- 执行面：terminal、file、browser、vision、code_execution、delegate_task、cronjob、kanban/workspace（如启用）。
- MCP 面：`hermes mcp list/test`、MCP server 进程、背后真实服务端口、工具级健康检查。
- 服务面：Gateway、Cron scheduler、Burp、HexStrike、VPN、代理、数据库/资产库等外部依赖。
- 证据面：会话检索、memory、/tmp 证据、/tmp/vuln_reports 报告、日志文件。

控制要求：发现部件未启动或不可用时，先判断是否当前任务必需；必需则主动启动、健康检查、修复或降级替代，不必需则标注为外部服务状态，不扩大为系统故障。需要 Burp/HexStrike/MCP/Gateway/VPN/代理等专项工具时，不等待用户手动打开；在授权和安全范围明确时由 Hermes 自行执行启动脚本、端口检查和功能验证。

Burp 实战就绪要求：开始依赖 BP/Burp 的 SRC/渗透任务前，优先执行 `/root/.hermes/scripts/hermes-burp-ready.sh --quiet`，而不是只看进程。该脚本会启动/确认 Burp、验证 `127.0.0.1:8080`、`hermes mcp test burpsuite`、HTTP/HTTPS curl 代理、Burp MCP 请求/日志/分析闭环、CA/NSS/Android 证书材料，并输出 `/tmp/hermes-burp-ready/summary.json`。需要给 Windows/手机抓包时加 `--expose-lan`。若要保留当前 MCP 日志用于目标分析，加 `--no-clear`。

按需启动入口：

```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --status
/root/.hermes/scripts/hermes-ensure-tools.sh --gateway --hexstrike
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
/root/.hermes/scripts/hermes-ensure-tools.sh --all
```

说明：`--burp` 会尝试启动 Burp Suite GUI 与 Burp MCP/Gateway，并等待 `127.0.0.1:8080`；`--hexstrike` 会确保 `127.0.0.1:8888` 与 MCP bridge；`--gateway` 会确保 Cron/MCP 所需 Gateway 服务。若显示 Burp 代理未监听但当前任务不需要抓包，只记录状态，不作为故障。

7. PentAGI/现代攻防 Agent 经验：长渗透/SRC 系统强化可参考 `pentest-multiagent-system` skill 的 `references/pentagi-expert-system-strengthening.md` 与 `references/ai-pentest-agent-projects-strengthening-20260602.md`。优先吸收轻量模式：Flow/Task/SubTask/Action 证据模型、Chain Workspace(JSONL/SQLite)、Evidence→Hypothesis→Validation 因果图、工具调用日志、同工具重复/请求预算 loop guard、scope guard、Critic gate、cleanup registry、Tavily→专家方法/文档搜索、Sploitus/searchsploit/nuclei→PoC 情报、Graphiti 风格轻量实体关系记忆、MCP allowlist/namespace/审计/故障隔离。不要照搬 PentAGI/Blacksmith/Pentest-Swarm-AI 的重型 PostgreSQL/Redis/GraphQL/Neo4j/LangGraph/Web UI 栈，除非任务明确需要。
8. **执行监控/Loop Guard v2.1（v2026.06 升级）**：SRC/渗透长任务自动加载 `agent-execution-monitor` 技能。同工具连续调用 ≥5 次触发策略切换，≥8 次强制中断。工具调用预算按任务模式分配（quick-scan:30/standard:80/deep-hunt:150）。监控脚本：`/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py`。v2.1新增：workspace隔离(`--workspace NAME`避免跨目标状态污染)、语义循环检测(方案级重复≥5次强制停止)、时间门限(≥20min无确认发现警告)、负面记忆(reject命令记录被拒发现类型)、进展停滞(连续12次无证据强制停止)、证据截断修复、confirm计为进展。健康检查：`agent-exec-monitor.py health`。多目标并行时必须用`--workspace`隔离。
9. **智能任务规划（v2026.06 升级）**：复杂 SRC 任务开始前加载 `agent-task-planner` 技能，自动分解为 3-7 步结构化计划。模板：Web SRC 5步(RECON→FINGERPRINT→ATTACK-SURFACE→EXPLOIT→REPORT)、教育SRC 3步(QUICK-RECON→LOW-HANGING-FRUIT→DEEP-HUNT)、内网5步(NETWORK-MAP→CREDENTIAL-HUNT→LATERAL-MOVE→PRIVILEGE-ESC→PERSIST)。
10. **Sploitus 漏洞情报（v2026.06 升级）**：搜索 CVE/PoC/攻击工具时，优先使用 Sploitus（聚合 ExploitDB+Packet Storm+GitHub Advisories）。脚本：`/usr/bin/python3 /root/.hermes/scripts/sploitus-search.py <query>`。与现有 exploit-db-integration 和 vuln-intel 技能互补。
11. **工具成功率记忆（v2026.06 升级）**：每次渗透工具执行后记录成功率到 SQLite（`/root/.hermes/data/tool_success.db`）。对已知指纹的工具推荐历史最佳工具。脚本：`/usr/bin/python3 /root/.hermes/scripts/tool-memory.py recommend <fingerprint>`。记录：`tool-memory.py record <tool> <target> <fingerprint> <0|1>`。
12. **Chain Summarization / 上下文管理**：长任务中自动关注上下文压缩。Hermes 内置 compression 配置（`compression.enabled`/`threshold`/`target_ratio`），结合 `/compress` 手动触发。关键：保留最近发现和活跃假设，压缩已完成步骤的历史。
13. **子域价值分级（v2026.06 升级）**：SRC 快筛后用 `src-practical-next.py --tiers --show-skipped` 做子域价值分级。自动过滤 CDN/static/www/news/test 等低价值目标，按 P0(api/auth/actuator) > P1(ehall/cas/oa) > P2(app/mobile) 分级。避免在低价值目标上浪费工具调用预算。
14. **加固目标快速退出（v2026.06 教训）**：对加固良好的目标（SUDY+金智CAS+网易邮箱+EasyConnect），5 分钟内无 P0/P1 候选应换目标或报告已有发现。已知加固组合：SUDY WebPlus CMS + 金智教育 CAS + 网易企业邮箱 + Sangfor EasyConnect。信息泄露(IP/堆栈)单独不值得深挖——除非能证明泄露的是真实 origin server IP 而非 CDN/WAF。

## 技能神经路由 / Skill Neural Network

系统维护、SRC/渗透、MCP、长任务或跨领域任务开始前，优先用技能神经路由把相关技能连接成加载顺序，而不是只凭记忆手选技能。详细流程、产物说明、坑点和验证命令见 `references/skill-neural-network-routing.md`。

```bash
/usr/bin/python3 /root/.hermes/scripts/skill-neural-router.py \
  --out-dir /root/.hermes/data/skill-network \
  --query '<用户任务/目标/关键词>'
```

产物：
- `/root/.hermes/data/skill-network/skill-scan.json`：全部技能元数据、引用、脚本、缺失本地引用。
- `/root/.hermes/data/skill-network/skill-graph.json`：技能节点、领域节点、带权连接和连接理由。
- `/root/.hermes/data/skill-network/route-index.json`：固定领域路由，如 `global-control`、`src-pentest`、`hermes-system`、`mcp-tools`、`long-task`、`mlops-training`。
- `/root/.hermes/data/skill-network/last-query-route.json`：当前任务文本对应的推荐加载顺序。
- `/root/.hermes/data/skill-network/skill-network-report.md`：可读审计报告。

使用规则：
1. 先加载 `global-control`，再运行 `skill-neural-router.py --query` 获取 `load_order`。
2. 对 `mandatory_first` 中的技能必须先加载；其余技能按 `load_order` 取前 3-8 个，避免一次加载全库导致上下文膨胀。
3. 如果路由结果包含 MCP/Burp/HexStrike/Cron/Provider 类技能，必须再做对应服务健康检查；图谱只决定“该用什么”，不替代可用性验证。
4. 如果报告出现 `missing local references`，非归档技能应优先补齐或改成跨技能引用；归档技能只作为历史告警，不阻塞当前任务。
5. 复杂任务结束后，若发现新的稳定组合关系，patch 对应领域技能和 `global-control`，再重新运行路由器刷新图谱。

## 会话复盘与技能维护

当用户评价表现、纠正控制方式、调整 MCP/自控边界、或要求“记住/以后都这样”时，不只写 memory；还要主动更新当前在用的 class-level 技能，让同类任务下次自动采用新流程。

## 任务模式选择器

先判断任务模式，再决定工具强度；不要把所有任务都套成重型巡检或 SRC 流程。

- `discussion`：用户在讨论方案、偏好、架构取舍时，优先给判断和可执行建议；只在涉及当前系统状态、配置、进程、版本时做轻量查询，避免无谓重型工具链。
- `offensive-tune`：用户要求"进攻性强""少拦截""SRC更快"时，加载 `references/offensive-config-presets.md` 按清单逐项应用；操作后提醒 `/new` 生效。
- `boundary-escalation`：用户要求“打破边界”“去掉限制”“全面战争机器”等安全边界突破时，不把系统改成无授权约束的攻击代理；应主动把控制权定义清楚：用户掌握目标、授权范围、风险阈值、停止/继续/回滚，Hermes 负责授权范围内的高进攻性、链式假设驱动、低噪声验证、证据闭环和可审计执行。可修改 SOUL/persona 来强化“用户控制权 + 授权红队/SRC/CTF/靶场高进攻性”，但必须保留禁止未授权入侵、持久化、横向移动、真实数据窃取、破坏和规避法律/平台边界的硬规则。
- `legal-extreme-depth`：用户明确声明合法授权并要求“能力极限/深度”时，进入合法极限深度模式：不解除硬安全边界，不做无授权攻击；实际落地 Chain Workspace、Evidence→Hypothesis→Validation、A/B authz matrix、critic gate、报告转换、请求预算和可审计证据落盘。优先使用 `/root/.hermes/scripts/src-chain-init.py`、`src-chain-log.py`、`src-chain-critic.py`、`src-authz-matrix.py`、`src-chain-report.py` 形成闭环；完成后用本地 self-test 或目标授权范围内最小化 PoC 验证。
- `system-audit`：Hermes/技能/MCP/Cron/Provider/Gateway/系统优化任务，必须先基线巡检，再修改，最后验证。
- `mcp-diagnostic`：排查 MCP 时分层确认：Hermes MCP 配置、MCP server 进程、背后真实服务、目标服务连通性；不要把“后端服务未开”误报成“MCP 配置失败”。
- `src-hunt`：SRC/渗透长任务低频汇报，只输出验证通过的实质漏洞；候选、WAF 拦截、弱信息泄露、SPA fallback 不包装成报告。**加固目标快速退出**：5 分钟内无 P0/P1 候选则换目标。信息泄露(IP/堆栈)单独不值得深挖——除非能证明泄露的是真实 origin server IP 而非 CDN/WAF。对已知加固组合(SUDY+金智CAS+网易邮箱+EasyConnect)直接跳过低价值攻击面测试。
- `report-fix`：报告修复任务优先满足用户格式、截图位置、单行 curl、复现命令汇总和平台字段要求。
- `system-upgrade`：系统包升级任务。Kali Rolling 常有 1000+ 包升级，`apt full-upgrade` 前台 600s 超时会中断安装导致包损坏。200+ 包必须用 `terminal(background=true, notify_on_complete=true)` + 日志文件 `/tmp/apt-upgrade.log`；完成后跑 `dpkg --configure -a` 和关键工具验证（nmap/nuclei/sqlmap/python/node/hermes）。详见 `references/system-audit-checklist.md` 的 System Upgrade 章节。
- `coding`：代码/配置修改任务走 read/patch/test/verify 闭环，避免只给计划。

## 自控与 MCP 边界

默认由 Hermes 主控做决策、编排和验证；MCP 只作为专项执行器，不作为任务大脑。

- Hermes 主控适合：任务分解、路线切换、漏洞价值判断、报告生成、技能/记忆/会话整合、跨工具验证、长任务编排。
- MCP 适合：Burp 抓包/HTTP history、HexStrike 扫描工具、外部 API/数据库/资产库/GitHub 等结构化能力接入。
- MCP 工具结果必须由主控复核；扫描结果、代理日志、自动判断不能直接当最终漏洞结论。
- Burp MCP 可用不等于 Burp 代理已开；每次抓包前检查 `127.0.0.1:8080`。
- HexStrike MCP 可用不等于每次任务都要调用；仅在扫描、枚举、漏洞情报或工具化验证明确有价值时使用。
- 避免接入与 Hermes 内置能力重复且更不稳定的泛用 MCP（如普通 filesystem），优先用内置 file/terminal/browser 工具。

## 一键基线巡检

快速参考：`references/system-audit-checklist.md` 包含磁盘、版本、安全工具、安全加固、性能调优、Docker、网络暴露的检查命令和常见问题表。

首选脚本：

```bash
/root/.hermes/scripts/hermes-global-control.py --skip-hermes --deep
```

说明：
- 默认脚本是只读巡检，不会修改系统。
- `--skip-hermes` 用于当前环境中 Hermes CLI 健康检查较慢或可能阻塞时；需要完整检查时去掉该参数。
- 脚本使用 `/usr/bin/python3`，避免当前 shell 的 `python3` shim 卡住。

- Gateway/Cron 依赖：Hermes Cron 任务依赖 Gateway 调度器；若 `hermes cron status` 显示 `Gateway is not running — cron jobs will NOT fire`，这不是 Cron job 配置坏，而是 Gateway 服务未运行。可安全修复流程见 `references/gateway-cron-recovery.md`。
- No-agent Cron 静默原则：脚本型 Cron 正常成功时应尽量 stdout/stderr 为空；rate limit、可降级外部源失败等非致命 warning 应在 `--quiet` 模式静默或合并，避免每日噪声。

完整 Hermes 基线（必要时单独跑，避免整脚本被慢检查拖住）：

```bash
hermes --version
hermes status --all
hermes doctor
hermes tools list
hermes mcp list
hermes cron list
```

仓库验证使用 Hermes venv Python：

```bash
cd /root/.hermes/hermes-agent
/root/.hermes/hermes-agent/venv/bin/python -m pytest tests/tools/test_skill_manager_tool.py tests/tools/test_skills_tool.py -q -o addopts=
```

## 技能路由

### Hermes/系统配置

加载：
- `hermes-agent`
- `native-mcp`（涉及 MCP）
- `hermes-agent-self-evolution`（整体优化/审计）
- `task-persistence` 或 `workspace-dispatch`（长任务/多任务）

行动顺序：
1. 读 `/root/.hermes/config.yaml`、`/root/.hermes/SOUL.md`、相关技能文件。
2. 运行总控脚本和必要的 Hermes CLI 检查。
3. 修改用 `patch`/`write_file`/`skill_manage`，不要用 sed/echo 覆盖。
4. 框架迭代若用户要求“每次提交到 GitHub”，先检查仓库是否有历史脏改动；默认只 `git add` 本轮明确修改且已验证/脱敏的文件，不夹带技能大重写、SRC历史案例、会话/数据目录或未审计产物。提交前做高置信 secret 扫描，推送后用 `git ls-remote origin refs/heads/main` 与 `git rev-parse HEAD` 核对远端 SHA。
5. 验证：脚本、`skill_view`、`hermes doctor/status`、相关 pytest。
6. 新脚本验证闭环：语法检查→导入检查→help→逐子命令功能测试→边界测试→集成测试。详见 `pentest-unified-engine` skill 的 `references/new-script-testing-methodology.md`。常见陷阱：datetime.utcnow()弃用、SQLite CASE缺THEN、argparse子命令缺参数、关键词映射比精确匹配更鲁棒。

API key / Web provider 配置补充：
- 用户提供 Tavily 等 Web provider API key 时，优先写入 `hermes config env-path` 指向的 `.env`，不要写进 `config.yaml`；Tavily 的必需变量是 `TAVILY_API_KEY`（可兼容额外写 `TAVILY_KEY`，但 Hermes 插件实际读取 `TAVILY_API_KEY`）。
- 写入后将 `.env` 权限设为 `0600`，读回时必须遮蔽 key，只显示前后几位。
- 验证闭环至少包括：shell source `.env` 后确认变量可读、`hermes status --all` 显示对应 provider 为 ✓、必要时用 provider 的低成本接口做一次 smoke test（例如 Tavily `/search` max_results=1）。
- 告知生效边界：当前已运行的 CLI/Gateway 进程通常不会自动继承新 `.env`；CLI 用 `/reload` 或新会话，Gateway/后台服务需要 restart。

### SRC / 渗透测试 / 红队夺旗

加载：
- `pentest-unified-engine`（**v2026.06 新增** - 统一渗透引擎：目标图谱+智能路由+PoC生成+报告管道一体化）
- `pentest-control-plane`（渗透测试控制平面，单模块工具箱）
- `src-vuln-hunting`
- `education-src-blueprint`（教育目标）
- `web-pentest-fast`
- `exploit-chain`（需要从低价值信息泄露升级为业务逻辑/授权范围内链式漏洞验证时，优先读取 `references/business-logic-chain-framework-20260602.md`）
- `pentest-ops`
- `hexstrike-usage` / `hexstrike-api-fallback`
- `burp-suite-setup`（抓包/代理）
- `redteam-flag-mode`（授权攻防演练/夺旗/flag/CTF-like 任务）
- 目标专项技能（如 qssrc、education、shein、cpic 等）

**渗透测试控制平面**：
- 控制平面脚本：`/root/.hermes/scripts/pentest-control-plane.py`
- 自动化脚本：`/root/.hermes/scripts/pentest-automation.sh`
- 健康检查：`/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py health`
- 工作流列表：`/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py list-workflows`
- 运行工作流：`/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py workflow <name> --args <key>=<value>`
- 运行工具：`/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py run <category> <tool> --args <key>=<value>`

高危漏洞挖掘工具链：
- `pentest-orchestrator.py full <domain>` — 一键完整渗透(图谱+路由+PoC+报告)
- `pentest-orchestrator.py recon <domain>` — 一键侦察(子域+端口+指纹+图谱)
- `target-graph-engine.py init/from-nmap/from-nuclei/priority/stats` — 目标图谱引擎
- `attack-router.py fingerprint/waf-adapt/route/execute` — 智能攻击路由(含WAF自适应)
- `auto-poc-report.py generate/verify/chain/report/quality-gate` — 自动PoC+报告管道
- `src-fast-assess.py <domain>` — 一键目标快筛(60秒)
- `src-sqli-hunter.py <url> --param id` — SQL注入快速检测
- `src-rce-scanner.py <url> --param cmd` — 命令注入/SSTI/XXE/LFI
- `src-idor-fuzzer.py <url> --cookie 's=x' --range 1-100` — IDOR枚举
- `src-cors-batch-test.py <url> --auth` — 批量CORS+认证绕过
- 详细模式: `src-vuln-hunting/references/high-severity-exploitation-patterns.md`

行动顺序：
1. 确认授权范围和目标；如果已有明确目标，直接开始，不反复问。
2. **健康检查**: 运行 `/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py health` 确认工具状态。
3. **一键快筛**: `src-fast-assess.py <domain>` 60秒内判断值不值得深挖。
4. **指纹→漏洞映射**: 按 `src-vuln-hunting/references/cms-vuln-fingerprint-map.md` 直接执行对应测试命令。
5. **高危漏洞扫描**: 对P0/P1目标依次运行 SQLi→RCE→IDOR 测试。
6. **自动化工作流**: 使用控制平面运行完整渗透测试工作流。
7. 检查 VPN split tunnel，防止默认路由断模型 API。
8. **效率优先**: 参考 `src-vuln-hunting` 的 `references/src-efficiency-waf-strategy-20260601.md`，用请求预算管理策略在WAF封禁前完成高价值测试。
9. **低价值过滤**: 教育目标直接跳过黑名单模式(SUDY IP泄露/CAS盐值/JSESSIONID/jQuery版本/TRACE/robots.txt内网IP)。
10. **快速跳过**: 5分钟内无P0/P1候选则换目标，不在低价值目标上花30+分钟。
11. 区分 MCP 服务可用性和后端服务状态：Burp MCP 进程存在不代表 127.0.0.1:8080 代理已开。
12. 只认实质漏洞：RCE/SQLi/越权/认证绕过/未授权数据/API 密钥能导致真实数据访问。
13. WAF/假 200/SPA fallback 必须验证响应内容、长度、Content-Type、随机不存在路径对照。
14. 报告遵循用户偏好：纯文本、报告间 `===`、单行 curl、复现命令汇总、【截图位置N】。

### 长任务/多 Agent

- 3 步以上必须 todo。
- 需要持续运行用 `terminal(background=true, notify_on_complete=true)`、`cronjob` 或 Kanban，不要留口头计划。
- 子任务独立且不需要用户交互时可 `delegate_task` 并行。
- 可恢复任务要落盘状态，优先使用 `task-persistence`。

## 巡检结果解读

- `oversized skills >80KB`：不是立即故障，但说明技能需要拆分 references 或压缩；优先处理频繁加载的大技能。
- `Burp proxy 127.0.0.1:8080 FAIL`：表示 Burp 代理监听未开；若 Burp MCP 进程在，MCP 配置仍可能正常。
- `VPN tun0 FAIL`：当前未连 VPN；只有任务需要内网时才连接，并且必须 split tunnel。
- `/tmp/vuln_reports missing`：报告目录不存在；开始 SRC 报告任务前创建。
- `git working tree dirty`：修改 Hermes 源码前先确认/备份，不要在脏树上直接 pull。

## 验证闭环

完成任何优化后至少验证三项：

1. 产物存在：脚本/技能/SOUL/config 文件能读回。
2. 可执行：脚本能跑，技能能 `skill_view` 加载。
3. 系统未破坏：相关 `hermes doctor/status` 或 pytest 通过；若有外部服务未运行，明确标注为服务状态而非配置失败。
4. 技能引用完整性：对本轮加载/修改过的技能，检查 `SKILL.md` 中反引号引用的 `references/` 与 `scripts/` 是否真实存在。**注意区分跨skill引用和本地引用**：格式为"见 `other-skill` skill 的 `references/xxx.md`"的是跨skill引用，不是缺失文件。glob模式（含`*`）也不检查存在性。详见 `references/skill-library-integrity-selftest.md` 的跨skill-aware检查脚本。跨技能复用的reference要么复制/转发到当前技能目录（forwarding stub），要么在当前技能新增明确的"见xxx skill"引用，避免留下看似本技能本地文件但实际不存在的路径。
5. SRC 框架脚本回归：至少跑一次 `src-workspace-init.py` → `src-http-probe.py` → `src-quality-gate.py` → `src-js-api-extract.py` 的离线/低噪声 self-test；`src-http-probe.py` 应能自动创建不存在的 workspace 目录，避免新工作区首次探测失败。重复运行同一 workspace 时注意 `probe_results.tsv` 是追加写入：self-test/一次性验证应使用新的临时 root、清理旧 TSV，或显式采用 fresh/dedupe 模式，避免 quality gate 对重复行重复计数；正式长任务则保留追加写入以支持中断恢复。
6. 支持脚本权限/语法：对技能 `scripts/*.sh` 跑 `bash -n`，并确认被文档当作可执行入口的脚本有 `+x` 权限。
7. 技能引用完整性：检查 `SKILL.md` 中反引号引用的 `references/`、`scripts/`、`templates/`、`assets/` 是否真实存在。若引用的是其他技能的文件，必须写成“见 `<skill>` skill 的 `<path>`”，或在当前技能增加 forwarding reference；不要留下看似本技能本地文件但实际不存在的路径。通配符示例（如 `references/*src*patterns*.md`）应标注为 glob/示例，避免被完整性自测误报。

- 当前本机关键路径

- SRC 框架脚本：`/root/.hermes/scripts/src-workspace-init.py`、`/root/.hermes/scripts/src-http-probe.py`、`/root/.hermes/scripts/src-quality-gate.py`、`/root/.hermes/scripts/src-practical-next.py`、`/root/.hermes/scripts/src-think.py`；使用方法见 `references/hermes-src-framework-scripts.md`
- SRC 证据门禁：`src-http-probe.py --control` 产出的 `decision/fp_class` 必须交给 `src-quality-gate.py` 复核；门禁会过滤 SPA fallback/WAF/login/统一错误页，按 rce/upload/sql_error/pii/auth/business 等强度给候选打分。只有 `HAS_REPORTABLE_CANDIDATES` 或明确可补证的 `NEED_MORE_EVIDENCE` 继续深挖；`DO_NOT_SUBMIT` 不包装成报告。
- **可复现门禁（v2.1 新增）**：提交报告前必须运行 `/usr/bin/python3 /root/.hermes/scripts/src-reproducibility-gate.py <workspace>`。只有 PoC 能跑通、输出一致、有实际利用价值（密钥泄露/PII批量/SQL注入/CORS+creds/文件上传执行/未授权数据）的发现才通过。低价值发现（Server头/IP泄露/堆栈跟踪/登录页/默认页/健康检查）自动 REJECT。
- SRC 实战下一步排序：已有 `alive.txt`、`probe_results.tsv` 或 `src-fast-assess.py` 输出目录时，运行 `/usr/bin/python3 /root/.hermes/scripts/src-practical-next.py <artifact> --out /tmp/next.md --json-out /tmp/next.json --tiers --show-skipped`，优先攻击 api/auth/cas/ehall/oa/pay/upload/admin/actuator/swagger 等面，自动过滤 0 分静态/cdn/news 面，并输出可复制单行 curl。注意：test/dev/jenkins/gitlab 在 SRC 中是高价值攻击面(P1)，不应被跳过。
- 假设推理层：机械排序后、报告前必须运行 `/usr/bin/python3 /root/.hermes/scripts/src-think.py <workspace-or-artifacts> --out /tmp/src-think.md --json-out /tmp/src-think.json`。它把 probe/API/JS/Burp/MITM 证据合成为业务对象、攻击假设、缺失证据、A/B 对照和≤20条验证命令；输出 `evidence_graph`、`rigor`、`submit_readiness` 三类审计字段。只允许 `READY_TO_VALIDATE` 进入小批验证，`NEED_MORE_EVIDENCE` 只补证，`NO_REPORT` 禁止写报告；优先验证 IDOR/BOLA、租户/角色边界、文件链、密钥到数据、状态机，而不是继续按模板扫静态面。
- **自治审计门禁（v2026.06 新增）**：提交报告前在可复现门禁之后运行 `/usr/bin/python3 /root/.hermes/scripts/src-autonomy-audit-gate.py <workspace> --out /tmp/autonomy-audit.md --json-out /tmp/autonomy-audit.json --manifest-out /tmp/evidence-manifest.json`。该脚本吸收 OWASP APTS（范围/安全/审计/报告治理）、POPPER（假设证伪/A-B对照）、Shannon Lite（只报告 PoC-backed verified findings）模式，并生成 evidence manifest（路径/大小/sha256）用于提交前人工复核；`BLOCK_REPORT`/`DO_NOT_SUBMIT` 禁止提交，`NEEDS_MORE_EVIDENCE` 只补证，`READY_FOR_HUMAN_REVIEW` 才进入报告复核。
- SRC self-test 注意：同一 workspace 重复 probe 会追加 `probe_results.tsv`；巡检用新临时 root 或 fresh/dedupe，正式长任务才依赖追加恢复。
- 总控脚本：`/root/.hermes/scripts/hermes-global-control.py`
- 快筛脚本：`/root/.hermes/scripts/src-fast-assess.py`（60秒目标评估：子域名+指纹+优先攻击面+推荐命令）
- 批量CORS脚本：`/root/.hermes/scripts/src-cors-batch-test.py`（JS端点提取+批量CORS+认证绕过测试）
- 指纹→漏洞映射：见 `src-vuln-hunting` skill 的 `references/cms-vuln-fingerprint-map.md`
- Exploit-DB 深度集成：见 `exploit-db-integration` skill（47K+漏洞库引擎 + 指纹→exploit管道 + 攻击脚本生成）
- 引擎入口：`/usr/bin/python3 /root/.hermes/scripts/exploitdb_engine.py {stats|search|cve|product|rce|nmap|fingerprint}`
- 管道入口：`/usr/bin/python3 /root/.hermes/scripts/edb-pipeline.py --nmap/--nuclei/--product --target HOST --script /tmp/attack.sh`
- SRC效率策略：见 `src-vuln-hunting` skill 的 `references/src-efficiency-waf-strategy-20260601.md`
- 按需启动脚本模板：`scripts/hermes-ensure-tools.sh`，当前本机实例：`/root/.hermes/scripts/hermes-ensure-tools.sh`
- 安全脚本审计清单：见 `pentest-unified-engine` skill 的 `references/python-security-script-audit-checklist.md`（GPT审计发现的类级模式：shell注入/域名验证/403误杀/dedup键/方法降级等）
- GPT审计方法论：见 `agent-execution-monitor` skill 的 `references/gpt-audit-methodology.md`
- Scope enforcement：`src-http-probe.py --scope-domain example.edu.cn` 自动跳过超范围URL
- 大技能拆分方法：`references/large-skill-decomposition.md`
- 技能库完整性自测：`references/skill-library-integrity-selftest.md`
- Gateway/Cron 恢复：`references/gateway-cron-recovery.md`
- 按需启动 Burp/MCP/HexStrike/Gateway：`references/on-demand-tool-startup.md`
- Burp 实战就绪脚本：`/root/.hermes/scripts/hermes-burp-ready.sh`；验证产物：`/tmp/hermes-burp-ready/summary.json`
- 进攻性配置预设(YOLO/超时/压缩/MCP)：`references/offensive-config-presets.md`
- 大型技能文件维护模式(100K限制/重复清理/Python脚本)：`references/large-skill-maintenance.md`
- 漏洞情报按需查询：见 `vuln-intel` 的 `references/on-demand-vuln-query.md`
- Persona：`/root/.hermes/SOUL.md`
- Hermes 仓库：`/root/.hermes/hermes-agent`
- 技能目录：`/root/.hermes/skills`
- 报告目录：`/tmp/vuln_reports`
- HexStrike 服务常见端口：`127.0.0.1:8888`
- Burp 代理常见端口：`127.0.0.1:8080`
