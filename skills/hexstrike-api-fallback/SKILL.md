---
name: hexstrike-api-fallback
description: >-
  HexStrike MCP bridge 不稳定时的 HTTP API fallback 调用方案
domain: cybersecurity
subdomain: penetration-testing
tags:
- security
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1046
nist_csf:
- ID.RA-01
---
# HexStrike API Fallback — MCP bridge 不稳定时的替代方案

## Problem
HexStrike bridge (`/root/hexstrike-mcp-bridge.py`) 通过 stdio transport 连接 the AI agent 时，进程频繁退出或报 `ClosedResourceError`。原因：FastMCP 1.27.0 + Python 3.13 在无 tty 环境下 stdio 兼容性不稳定。

但 HexStrike HTTP API (`http://127.0.0.1:8888`) 本身完全稳定。

## Solution
所有 58+ 安全工具都可通过 `curl` 直接调用 HTTP API，不依赖 MCP bridge。

## HexStrike HTTP API 调用方式

### 1. 有独立端点的工具

**端点：`/api/tools/<工具名>`，POST JSON body**

```bash
# waf detection
curl -s http://127.0.0.1:8888/api/tools/wafw00f \
  -X POST -H "Content-Type: application/json" \
  -d '{"target":"https://example.com"}'

# nmap scan
curl -s http://127.0.0.1:8888/api/tools/nmap \
  -X POST -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1", "scan_type":"-sV"}'

# theHarvester
curl -s http://127.0.0.1:8888/api/tools/theHarvester \
  -X POST -H "Content-Type: application/json" \
  -d '{"domain":"example.com", "source":"all"}'

# searchsploit
curl -s http://127.0.0.1:8888/api/tools/searchsploit \
  -X POST -H "Content-Type: application/json" \
  -d '{"term":"apache 2.4"}'
```

**常用端点速查：**
```
nmap / nikto / sqlmap / ffuf / gobuster / dirb / masscan
hydra / john / hashcat / netexec / enum4linux / responder
wafw00f / httpx / wpscan / subfinder / amass / nuclei
```

### 2. 无独立端点的工具 → 走通用 command 端点

```bash
curl -s http://127.0.0.1:8888/api/command \
  -X POST -H "Content-Type: application/json" \
  -d '{"command":"whatweb -a 3 https://TARGET --colour=never", "use_cache":false}'
```

**适用：** whatweb, theHarvester, searchsploit, recon-ng, dnsenum, radare2, evil-winrm 等

## 工具参数对照

| 工具 | 端点 | 主要参数 |
|------|------|----------|
| nmap | /api/tools/nmap | target, scan_type (-sV), ports |
| masscan | /api/tools/masscan | target, ports |
| nikto | /api/tools/nikto | target |
| sqlmap | /api/tools/sqlmap | url |
| ffuf | /api/tools/ffuf | url, wordlist, mode (u/d/s/w) |
| gobuster | /api/tools/gobuster | url, mode (dir/dns/fuzz), wordlist |
| dirb | /api/tools/dirb | url, wordlist |
| wafw00f | /api/tools/wafw00f | **target** (不是 url!) |
| httpx | /api/tools/httpx | **target** (不是 url!) |
| hydra | /api/tools/hydra | target, service, user, passlist |
| john | /api/tools/john | hash_file, wordlist, format |
| hashcat | /api/tools/hashcat | hash_file, wordlist, mode |
| netexec | /api/tools/netexec | target, module (smb/ssh/winrm/rdp) |
| nuclei | /api/tools/nuclei | target, severity, tags |
| subfinder | /api/tools/subfinder | domain |
| amass | /api/tools/amass | domain, mode (passive/active) |

## 验证 API 健康
```bash
curl -s http://127.0.0.1:8888/health
```

## MCP Bridge 参数映射 (已修复于 /root/hexstrike-mcp-bridge.py)
- `wafw00f`: 传入 `url` → 映射为 `target`
- `httpx`: 传入 `url` → 映射为 `target`
- `whatweb/theHarvester/searchsploit/recon-ng`: 改用 `/api/command` 而非 `/api/tools/<tool>`

## MCP Bridge 自动拉起 HTTP API
`/root/hexstrike-mcp-bridge.py` 已加入 `ensure_hexstrike_server()`：
- `the agent mcp test hexstrike` / `/reload-mcp` 时如果 `127.0.0.1:8888` 未运行，会自动执行 `/root/hexstrike-ai/hexstrike-env/bin/python /root/hexstrike-ai/hexstrike_server.py --port 8888`
- stdout/stderr 追加到 `/root/hexstrike-ai/hexstrike.log`
- 可用环境变量覆盖路径：`HEXSTRIKE_ROOT`, `HEXSTRIKE_PYTHON`, `HEXSTRIKE_SERVER`, `HEXSTRIKE_LOG`
- 验证命令：先 `pkill -f '/root/hexstrike-ai/hexstrike_server.py --port 8888'`，再 `the agent mcp test hexstrike`，应显示 connected/tools discovered，随后 `curl http://127.0.0.1:8888/health` 应恢复 healthy
