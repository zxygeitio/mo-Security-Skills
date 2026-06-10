#!/usr/bin/env bash
# Hermes on-demand tool starter / health checker.
# Intended to be copied to /root/.hermes/scripts/hermes-ensure-tools.sh or run as reference.
set -u

WANT_BURP=0
WANT_HEX=0
WANT_GATEWAY=0
STATUS_ONLY=0
WAIT_SECS=45
DISPLAY_VALUE="${DISPLAY:-:0.0}"
LOG_DIR="/root/.hermes/logs"
mkdir -p "$LOG_DIR"

log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
exists(){ command -v "$1" >/dev/null 2>&1; }
port_open(){ ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$1$"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --all) WANT_BURP=1; WANT_HEX=1; WANT_GATEWAY=1 ;;
    --burp) WANT_BURP=1 ;;
    --hexstrike) WANT_HEX=1 ;;
    --gateway) WANT_GATEWAY=1 ;;
    --status) STATUS_ONLY=1 ;;
    --wait) shift; WAIT_SECS="${1:-45}" ;;
    --display) shift; DISPLAY_VALUE="${1:-:0.0}" ;;
    -h|--help) sed -n '1,12p' "$0"; exit 0 ;;
    *) log "unknown arg: $1"; exit 2 ;;
  esac
  shift
 done

status(){
  log "Gateway: $(hermes gateway status 2>&1 | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-220)"
  if port_open 8888; then log "HexStrike API: OK 127.0.0.1:8888"; else log "HexStrike API: DOWN 127.0.0.1:8888"; fi
  if pgrep -f 'hexstrike-mcp-bridge.py' >/dev/null 2>&1; then log "HexStrike MCP bridge: OK"; else log "HexStrike MCP bridge: DOWN"; fi
  if pgrep -f 'burp_mcp_server.py' >/dev/null 2>&1; then log "Burp MCP server: OK"; else log "Burp MCP server: DOWN"; fi
  if port_open 8080; then log "Burp proxy: OK 127.0.0.1:8080"; else log "Burp proxy: DOWN 127.0.0.1:8080"; fi
}

start_gateway(){
  if hermes gateway status 2>&1 | grep -q 'gateway service is running\|Gateway is running'; then log "Gateway already running"; return 0; fi
  log "Starting Hermes gateway service"
  hermes gateway start >/tmp/hermes_gateway_start.log 2>&1 || true
  if ! hermes gateway status 2>&1 | grep -q 'gateway service is running\|Gateway is running'; then
    log "Gateway start failed; installing user service"
    yes y | hermes gateway install --force >/tmp/hermes_gateway_install.log 2>&1 || true
  fi
  hermes gateway status 2>&1 | head -30
}

start_hexstrike(){
  if port_open 8888; then
    log "HexStrike API already listening on 8888"
  elif [ -f /root/hexstrike-ai/hexstrike_server.py ]; then
    log "Starting HexStrike API on 127.0.0.1:8888"
    nohup /root/hexstrike-ai/hexstrike-env/bin/python /root/hexstrike-ai/hexstrike_server.py --port 8888 > "$LOG_DIR/hexstrike-api.log" 2>&1 &
  else
    log "HexStrike server file missing: /root/hexstrike-ai/hexstrike_server.py"
  fi
  if ! pgrep -f 'hexstrike-mcp-bridge.py' >/dev/null 2>&1 && [ -f /root/hexstrike-mcp-bridge.py ]; then
    log "Starting HexStrike MCP bridge"
    nohup /root/hexstrike-ai/hexstrike-env/bin/python /root/hexstrike-mcp-bridge.py > "$LOG_DIR/hexstrike-mcp-bridge.log" 2>&1 &
  fi
  for i in $(seq 1 "$WAIT_SECS"); do port_open 8888 && break; sleep 1; done
  if port_open 8888; then log "HexStrike API ready"; else log "HexStrike API not ready after ${WAIT_SECS}s"; return 1; fi
}

start_burp(){
  if ! pgrep -f 'burp_mcp_server.py' >/dev/null 2>&1; then
    log "Burp MCP server not running; starting/restarting gateway so MCP servers load"
    start_gateway
  fi
  if port_open 8080; then
    log "Burp proxy already listening on 127.0.0.1:8080"
  elif exists burpsuite; then
    log "Starting Burp Suite GUI with DISPLAY=${DISPLAY_VALUE}"
    DISPLAY="$DISPLAY_VALUE" nohup burpsuite --use-defaults > "$LOG_DIR/burpsuite.log" 2>&1 &
    for i in $(seq 1 "$WAIT_SECS"); do
      port_open 8080 && break
      if exists xdotool; then
        WID=$(DISPLAY="$DISPLAY_VALUE" xdotool search --name 'Burp Suite Community Edition\|Burp Suite' 2>/dev/null | head -1 || true)
        if [ -n "${WID:-}" ]; then
          DISPLAY="$DISPLAY_VALUE" xdotool windowactivate "$WID" >/dev/null 2>&1 || true
          DISPLAY="$DISPLAY_VALUE" xdotool key Tab Return >/dev/null 2>&1 || true
        fi
      fi
      sleep 1
    done
  else
    log "burpsuite command not found"
  fi
  if port_open 8080; then log "Burp proxy ready"; else log "Burp proxy not ready after ${WAIT_SECS}s"; return 1; fi
}

if [ "$STATUS_ONLY" = 1 ]; then status; exit 0; fi
if [ "$WANT_GATEWAY" = 1 ]; then start_gateway; fi
if [ "$WANT_HEX" = 1 ]; then start_hexstrike; fi
if [ "$WANT_BURP" = 1 ]; then start_burp; fi
status
