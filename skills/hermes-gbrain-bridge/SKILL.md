---
name: hermes-gbrain-bridge
description: |
  Bridge that converts scattered agent memory (Hermes, Claude Code, Codex, OpenClaw) into clean
  markdown for gBrain to ingest. Produces canonical markdown from JSONL event streams and various
  agent memory formats. Dependency-free, uses Bun runtime.
category: ai-development
---

# Hermes-gBrain Bridge

Converts scattered agent memory into gBrain-ingestible markdown.

## Source
https://github.com/howardpen9/hermes-gbrain-bridge

## Install

```bash
cd /tmp/hermes-gbrain-bridge
bun install
```

## Supported Sources

| Tool | Location | Format |
|------|----------|--------|
| Hermes | `~/.hermes/sessions/*.jsonl` + `memories/*.md` | JSONL + markdown |
| Claude Code | `~/.claude/projects/<path-hash>/*.jsonl` | Event stream JSONL |
| Codex CLI | `~/.codex/sessions/**/*.jsonl` | JSONL with session_meta |
| OpenClaw | `~/.openclaw.pre-migration/workspace/**/*.md` | Markdown |

## Usage

```bash
# Discover what's available
bun run src/cli.ts discover --days 30

# Dry-run export
bun run src/cli.ts export --source=claude-code --dry-run --days 30

# Export to staging
bun run src/cli.ts export --source=all --out=/tmp/gbrain-staging --days 30

# Then import to gBrain
gbrain import /tmp/gbrain-staging --no-embed
gbrain embed --stale
```

## Architecture

The bridge reads from various agent memory locations, adapts formats to canonical event format,
redacts secrets, and outputs clean markdown files to a staging directory. gBrain handles ingestion
and storage. The bridge never touches the database directly.
