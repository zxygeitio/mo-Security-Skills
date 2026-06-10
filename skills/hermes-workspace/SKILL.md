---
name: hermes-workspace
description: |
  Complete Hermes-native workspace with chat, terminal, skills manager, and multi-agent orchestration.
  Docker-based deployment with hot-reload. 500+ stars, actively maintained.
category: ai-development
---

# Hermes Workspace

Complete development environment for Hermes Agent with Docker-based deployment.

## Source
https://github.com/outsourc-e/hermes-workspace

## Quick Start

```bash
cd /tmp/hermes-workspace
./install.sh
# or
docker-compose up -d
```

## Features

- Chat interface with streaming support
- Integrated terminal (WebSocket)
- Skills manager
- Multi-agent task dispatch
- Cron job scheduling
- Gateway management (Telegram, Discord, Slack, etc.)
- Usage analytics
- Profile management (multi-instance)

## Built-in Skills

- `workspace-dispatch` — Single-agent mission orchestrator with task decomposition

## Files

- `install.sh` — Installation script
- `docker-compose.yml` — Docker deployment
- `skills/` — Built-in skills
- `FEATURES-INVENTORY.md` — Full feature list
