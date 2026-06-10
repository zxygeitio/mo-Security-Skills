---
name: feishu-websocket-bot
description: Feishu WebSocket bot key gotchas — WS client can't send, P2P vs group, locale floods.
category: productivity
---

# Feishu WebSocket Bot — Critical Gotchas

## 1. WS Client Cannot Send Messages
`lark.ws.Client` only receives. The `.im` namespace doesn't exist on it. Sending requires raw HTTP requests to the REST API, NOT `cli.im.v1.message.create()`.

Fix: use `requests.post` with Bearer token to the messages endpoint.

Working script at `/root/feishu_ws_bot.py`.

## 2. Group Chat = @mention Only
`im.message.receive_v1` in groups only fires when bot is **@mentioned**. Use **P2P private chat** for all-message delivery.

## 3. Locale Flood
`LC_ALL=en_US.UTF-8` causes massive warnings. Run with:
```
env -i PATH=/usr/bin:/bin HOME=/root LANG=zh_CN.UTF-8 python3 bot.py
```

## 4. DEBUG for Incoming
Default INFO level suppresses incoming event logs. Use `log_level=lark.LogLevel.DEBUG` to see raw payloads.
