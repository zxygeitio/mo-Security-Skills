# Skill Neural Network Routing

## Purpose

Use this pattern when the user asks to connect/fuse Hermes skills, optimize the whole system, or make cross-domain task routing tighter.

The goal is not to load every skill. The goal is to build a deterministic control-plane graph, then load only the small set of skills that match the current task.

## Durable Workflow

1. Load `global-control` first for any system-wide optimization task.
2. Run the router with the task text:

```bash
/usr/bin/python3 /root/.hermes/scripts/skill-neural-router.py \
  --out-dir /root/.hermes/data/skill-network \
  --query '<task text>'
```

3. Read `/root/.hermes/data/skill-network/last-query-route.json`.
4. Load all `mandatory_first` skills, then the top 3-8 entries from `load_order`.
5. If selected skills mention MCP, Burp, HexStrike, Gateway, Cron, Provider, or VPN, run the corresponding health check before relying on the tool.
6. If `skill-network-report.md` shows non-archive missing local references, patch the affected skill or convert the path into an explicit cross-skill reference.
7. Re-run the router after patching so the graph reflects the current library.

## Current Router Outputs

- `skill-scan.json`: skill metadata, local references, scripts, missing references, keywords.
- `skill-graph.json`: skill/domain nodes and weighted edges with reasons.
- `route-index.json`: stable domain routes such as `global-control`, `src-pentest`, `hermes-system`, `mcp-tools`, `long-task`, `mlops-training`.
- `last-query-route.json`: task-specific selected domain and skill load order.
- `skill-network-report.md`: human-readable audit report.

## Pitfalls

- Do not treat the graph as a service-health verdict. It only decides what knowledge/tools are relevant.
- Do not load the whole skill library just because the graph is connected; that defeats context control.
- Archive-only missing references are historical warnings unless the current task explicitly depends on that archived skill.
- If a skill path points to a directory such as `templates/`, the directory must exist; a missing directory is still a valid integrity issue.

## Verification

Minimum verification after changes:

```bash
/usr/bin/python3 -m py_compile /root/.hermes/scripts/skill-neural-router.py
/usr/bin/python3 /root/.hermes/scripts/skill-neural-router.py --query 'Hermes MCP Gateway Cron Provider 技能 全局优化'
/usr/bin/python3 /root/.hermes/scripts/skill-neural-router.py --query 'SRC 渗透 Burp HexStrike 漏洞情报 IDOR 越权 报告'
/usr/bin/python3 /root/.hermes/scripts/skill-neural-router.py --query '长任务 多Agent cron persistence retry execution monitor'
```

Expected behavior: each query returns a domain-specific `query_domain` and a compact `query_load_order`, with no non-archive missing local references.
