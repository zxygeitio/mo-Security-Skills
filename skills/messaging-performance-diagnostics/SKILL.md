---
name: messaging-performance-diagnostics
description: "Diagnose slow response times on messaging platform gateways (Feishu, Telegram, Discord, etc.). Covers system resource checks, model provider latency benchmarking, WebSocket stability, and runaway process detection."
version: 1.0.0
author: hermes-agent
metadata:
  hermes:
    tags: [gateway, feishu, telegram, discord, performance, troubleshooting, diagnostics]
---

# Messaging Performance Diagnostics

Systematic troubleshooting when the Hermes gateway is slow to respond on any messaging platform.

## Trigger Conditions

- User reports messages take too long to get a reply
- Gateway logs show high `time=` values in `response ready` entries
- Feishu/Telegram/Discord feels sluggish compared to CLI

## Diagnosis Workflow

Follow this sequence — each step narrows the cause.

### Step 1: Check Gateway Status & Recent Logs

```bash
hermes gateway status
grep "response ready\|inbound message" ~/.hermes/logs/gateway.log | tail -20
```

Key metric: the `time=` field in `response ready` log lines. Normal is 3-8s for a simple message. >15s is suspicious.

### Step 2: Check System Resources (CPU/Memory)

```bash
top -bn1 | head -20
```

**Pitfall: Runaway processes.** Subagents, MCP bridges, or pentest tools can spin up processes that consume 100% CPU indefinitely. A single runaway `python3` process pegging one core will slow the entire gateway.

If a suspicious process is found:
```bash
# Identify it
ps -p <PID> -o pid,ppid,cmd,%cpu,%mem,etime
cat /proc/<PID>/cmdline | tr '\0' ' '
# Kill it
kill <PID>
```

### Step 3: Benchmark Model Provider API Latency

Test the configured model provider independently to isolate gateway-vs-provider:

```bash
# Extract base_url and api_key from config
grep -E "base_url|api_key" ~/.hermes/config.yaml

# Test models endpoint
time curl -s -o /dev/null -w "%{http_code} %{time_total}" \
  "<base_url>/models" \
  -H "Authorization: Bearer <api_key>"

# Test actual chat completion (minimal request)
time curl -s -X POST "<base_url>/chat/completions" \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"model": "<model_name>", "messages": [{"role": "user", "content": "Hi"}], "max_tokens": 10}'
```

Baseline expectations:
- Models endpoint: <1s
- Chat completion (simple): 2-5s is normal, >8s is slow
- If provider latency is fine but gateway is slow, the bottleneck is local (CPU, memory, or processing)

### Step 4: Check WebSocket Connection Stability

```bash
grep -i "keepalive\|reconnect\|disconnect\|timeout" ~/.hermes/logs/gateway.log | tail -10
```

Feishu/Lark uses WebSocket with keepalive pings. Timeout → disconnect → reconnect cycles add latency. Causes:
- Network instability (VPN, firewall)
- Server-side rate limiting
- Long-running tool calls blocking the event loop

### Step 5: Check for Unauthorized User Warnings

```bash
grep "Unauthorized user" ~/.hermes/logs/gateway.log | tail -5
```

These warnings don't block message processing but indicate the user may not be in the allowlist. Configure if needed:
```
FEISHU_ALLOW_ALL_USERS=true   # or
FEISHU_ALLOWED_USERS=user_id1,user_id2
```

## Common Root Causes (ranked by frequency)

1. **Runaway process consuming CPU** — most common and easiest to miss. Always check `top` first.
2. **Model provider latency** — some providers (especially free tier or region-specific) are inherently slow. Test independently.
3. **Large context/skills loading** — sessions with heavy skill loads or long conversation history increase processing time.
4. **WebSocket reconnection storms** — network issues causing repeated disconnect/reconnect cycles.
5. **Memory pressure** — gateway process using >800MB, system swapping.

## Quick One-Liner Health Check

```bash
echo "=== CPU ===" && top -bn1 | head -5 && echo "=== GW ===" && hermes gateway status 2>&1 | grep -E "Active|Memory|CPU" && echo "=== Recent ===" && grep "response ready" ~/.hermes/logs/gateway.log | tail -3 && echo "=== Provider ===" && time curl -s -o /dev/null -w "%{http_code} %{time_total}" "$(grep base_url ~/.hermes/config.yaml | head -1 | awk '{print $2}' | tr -d '\"')/models" -H "Authorization: Bearer $(grep api_key ~/.hermes/config.yaml | head -1 | awk '{print $2}' | tr -d '\"')"
```

## Notes

- Gateway restart from inside the gateway process is blocked (`Refusing to restart the gateway from inside the gateway process`). Use an external shell.
- `hermes gateway status` shows memory/CPU of the gateway process itself — useful for spotting memory leaks.
- The `time=` in gateway logs includes model API call time + local processing. Subtract the provider benchmark to estimate local overhead.
