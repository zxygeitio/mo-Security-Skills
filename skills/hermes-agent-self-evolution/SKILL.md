---
name: hermes-agent-self-evolution
description: |
  Evolutionary self-improvement for Hermes Agent using DSPy + GEPA (Genetic-Pareto Prompt Evolution).
  Automatically evolves and optimizes skills, tool descriptions, system prompts, and code through
  reflective evolutionary search. No GPU training required — operates via API calls.
category: ai-development
---

# Hermes Agent Self-Evolution

Evolutionary self-improvement using DSPy + GEPA (Genetic-Pareto Prompt Architecture).

## Source
https://github.com/NousResearch/hermes-agent-self-evolution

## Quick Start

```bash
cd /tmp/hermes-agent-self-evolution
pip install -e ".[dev]"

# Point at your hermes-agent repo
export HERMES_AGENT_REPO=~/.hermes/hermes-agent

# Evolve a skill (synthetic eval data)
python -m evolution.skills.evolve_skill \
    --skill github-code-review \
    --iterations 10 \
    --eval-source synthetic

# Or use real session history
python -m evolution.skills.evolve_skill \
    --skill github-code-review \
    --iterations 10 \
    --eval-source sessiondb
```

## System Optimization Audit

When the user asks to inspect or optimize the whole Hermes Agent system, use the reusable audit pattern in `references/system-optimization-audit.md`. It covers baseline discovery, skill dedupe, MCP health separation, cron hygiene, repo update safety, and the important rule to run repo tests with the Hermes venv Python rather than system Python.


                                      │
                                      ▼
                                 GEPA Optimizer ◄── Execution traces
                                      │                    ▲
                                      ▼                    │
                                 Candidate variants ──► Evaluate
                                      │
                                 Constraint gates (tests, size limits, benchmarks)
                                      │
                                      ▼
                                 Best variant ──► PR against hermes-agent
```

## Key Files

- `evolution/skills/evolve_skill.py` — Main skill evolution script
- `generate_report.py` — Evolution report generator
- `datasets/` — Eval datasets
- `tests/` — Test suites

## GPT-Audit-Driven Upgrade (2026-06-09)

An alternative to DSPy/GEPA evolution: use a strong external model (GPT-5.5, Claude) to statically audit framework scripts, then fix the issues systematically.

### Workflow
1. Delegate code review to a GPT model via `delegate_task(goal="Review these scripts for bugs/flaws", toolsets=["terminal","file"])`
2. GPT reads all scripts and returns numbered findings with `[FILE] [SEVERITY] [TYPE]` tags
3. Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
4. Fix in batches: shebangs first, then shell injection, then logic flaws
5. Verify each fix: syntax check + functional test
6. Capture class-level patterns as `references/python-security-script-audit-checklist.md`

### What GPT found (75 issues across 7 scripts)
- 6x shebang `env python3` (all scripts)
- 3x `shell=True` with unsanitized input
- 4x generated commands without `shlex.quote()`
- 2x 403/404 false rejection (quality gate)
- 1x method downgrade (PUT/PATCH/DELETE → POST)
- 1x dedup too aggressive (URL-only, loses different methods)
- 1x test/dev targets classified as low-value (actually P1 in SRC)

### Lessons
- External audit catches patterns the author misses (tunnel vision)
- Fix by category, not by file (shebangs all at once, injection all at once)
- Always verify after fixing (syntax + functional)
- Capture class-level patterns, not session-specific fixes
- `pentest-unified-engine` skill has the full checklist: `references/python-security-script-audit-checklist.md`
