#!/usr/bin/env bash
set -euo pipefail

PORT="${MITM_PORT:-8081}"
HOST="${MITM_HOST:-127.0.0.1}"
BASE_DIR="${MITM_DIR:-/tmp/hermes-mitm-fallback}"
PID_FILE="$BASE_DIR/mitmdump.pid"
LOG_FILE="$BASE_DIR/mitmdump.log"
FLOW_FILE="$BASE_DIR/flows.mitm"
JSONL_FILE="$BASE_DIR/traffic.jsonl"
ADDON_FILE="$BASE_DIR/hermes_mitm_logger.py"

mkdir -p "$BASE_DIR"

write_addon() {
  cat > "$ADDON_FILE" <<'PY'
import json
import os
import time
from mitmproxy import http

OUT = None
OUT_PATH = os.environ.get('HERMES_MITM_JSONL', '/tmp/hermes-mitm-fallback/traffic.jsonl')

def load(loader):
    global OUT
    OUT = open(OUT_PATH, 'a', encoding='utf-8')

def done():
    global OUT
    if OUT:
        OUT.close()

def response(flow: http.HTTPFlow):
    req = flow.request
    resp = flow.response
    if not resp or not OUT:
        return
    try:
        preview = resp.get_text(strict=False)[:1000]
    except Exception:
        preview = ''
    item = {
        'ts': int(time.time()),
        'method': req.method,
        'url': req.pretty_url,
        'host': req.host,
        'status_code': resp.status_code,
        'request_headers': dict(req.headers),
        'response_headers': dict(resp.headers),
        'request_body_len': len(req.raw_content or b''),
        'response_body_len': len(resp.raw_content or b''),
        'response_preview': preview,
    }
    OUT.write(json.dumps(item, ensure_ascii=False) + '\n')
    OUT.flush()
PY
}

is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

status() {
  echo "base_dir=$BASE_DIR"
  echo "proxy=http://$HOST:$PORT"
  if is_running; then
    echo "status=running pid=$(cat "$PID_FILE")"
  else
    echo "status=stopped"
  fi
  ss -tlnp | grep ":$PORT" || true
  [[ -f "$JSONL_FILE" ]] && echo "traffic_lines=$(wc -l < "$JSONL_FILE")" || echo "traffic_lines=0"
}

start() {
  if is_running; then
    status
    return 0
  fi
  command -v mitmdump >/dev/null || { echo "mitmdump not found" >&2; return 1; }
  write_addon
  : > "$LOG_FILE"
  : > "$JSONL_FILE"
  HERMES_MITM_JSONL="$JSONL_FILE" nohup mitmdump --mode regular --listen-host "$HOST" --listen-port "$PORT" --set block_global=false --set connection_strategy=lazy --set ssl_insecure=true -w "$FLOW_FILE" -s "$ADDON_FILE" >"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  for _ in $(seq 1 30); do
    ss -tlnp | grep -q ":$PORT" && { status; return 0; }
    sleep 1
  done
  echo "mitmdump failed to listen on $HOST:$PORT" >&2
  tail -80 "$LOG_FILE" >&2 || true
  return 1
}

stop() {
  if is_running; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
  status
}

verify() {
  start >/dev/null
  curl -sS -m 20 -x "http://$HOST:$PORT" -o "$BASE_DIR/verify-http.body" -D "$BASE_DIR/verify-http.headers" "http://httpbin.org/get?hermes_mitm_fallback=1"
  curl -skS -m 30 -x "http://$HOST:$PORT" -o "$BASE_DIR/verify-https.body" -D "$BASE_DIR/verify-https.headers" "https://httpbin.org/get?hermes_mitm_fallback_https=1"
  sleep 1
  echo "verified_proxy=http://$HOST:$PORT"
  echo "http_status=$(awk '/^HTTP\//{print $2; exit}' "$BASE_DIR/verify-http.headers")"
  echo "https_status=$(awk '/^HTTP\//{s=$2} END{print s}' "$BASE_DIR/verify-https.headers")"
  echo "traffic_lines=$(wc -l < "$JSONL_FILE")"
  echo "jsonl=$JSONL_FILE"
  echo "flows=$FLOW_FILE"
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop >/dev/null; start ;;
  status) status ;;
  verify) verify ;;
  *) echo "Usage: $0 {start|stop|restart|status|verify}" >&2; exit 2 ;;
esac
