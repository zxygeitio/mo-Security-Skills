#!/usr/bin/env bash
set -euo pipefail

PORT="${HEXSTRIKE_PORT:-8888}"
ROOT="${HEXSTRIKE_ROOT:-/root/hexstrike-ai}"
PY="$ROOT/hexstrike-env/bin/python"
SERVER="$ROOT/hexstrike_server.py"
LOG="$ROOT/hexstrike.log"

if curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/health" >/dev/null; then
  echo "HexStrike API healthy on 127.0.0.1:${PORT}"
  exit 0
fi

if [[ ! -x "$PY" ]]; then
  echo "Missing HexStrike Python: $PY" >&2
  exit 1
fi
if [[ ! -f "$SERVER" ]]; then
  echo "Missing HexStrike server: $SERVER" >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG")"
nohup "$PY" "$SERVER" --port "$PORT" >>"$LOG" 2>&1 &
pid=$!
echo "Started HexStrike API pid=$pid port=$PORT log=$LOG"

for i in {1..20}; do
  if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/health" >/dev/null; then
    echo "HexStrike API healthy on 127.0.0.1:${PORT}"
    exit 0
  fi
  sleep 1
done

echo "HexStrike API did not become healthy; recent log:" >&2
tail -80 "$LOG" >&2 || true
exit 1
