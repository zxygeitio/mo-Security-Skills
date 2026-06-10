---
name: hermes-web-ui
description: |
  Web dashboard for Hermes Agent. Provides session management, scheduled jobs, usage analytics,
  model configuration, channel management (Telegram, Discord, Slack, WhatsApp, etc.), integrated
  terminal, and streaming chat interface. Vue 3 + Koa 2 + TypeScript.
category: ai-development
---

# Hermes Web UI

Web dashboard for Hermes Agent — multi-platform AI chat system with session management,
scheduled jobs, usage analytics, and channel integration.

## Source
https://github.com/EKKOLearnAI/hermes-web-ui

## Tech Stack

- **Frontend:** Vue 3 (Composition API), Naive UI, Pinia, vue-router, vue-i18n, SCSS, Vite
- **Backend:** Koa 2, @koa/router v15+, node-pty (WebSocket terminal)
- **Language:** TypeScript (strict mode)

## Dev Commands

```bash
cd /tmp/hermes-web-ui
npm install

npm run dev           # Start both server and client
npm run dev:client    # Vite dev server only
npm run dev:server    # nodemon + ts-node for server only
npm run build         # Type-check -> Vite build -> esbuild
npm run preview       # Preview production build
npm run test          # Run tests (vitest)
```

- **Dev port:** 8648
- **Prerequisite:** `hermes` CLI must be installed and on `$PATH`

## Features

- Session management with streaming chat
- Scheduled jobs CRUD
- Usage analytics with daily trends
- Model provider configuration
- Channel management (Telegram, Discord, Slack, WhatsApp, WeChat, etc.)
- Integrated WebSocket terminal
- Multi-language support (en, zh, de, es, fr, ja, ko, pt)

## Project Structure

```
packages/client/src/
  ├── api/hermes/       # Gateway proxy & local BFF
  ├── components/hermes/ # Chat, jobs, models, settings, skills, usage
  ├── stores/hermes/    # Pinia stores
  └── views/hermes/     # Page components

packages/server/src/
  ├── controllers/hermes/ # Request handlers
  ├── routes/hermes/      # Route modules
  └── services/           # Auth, config
```
