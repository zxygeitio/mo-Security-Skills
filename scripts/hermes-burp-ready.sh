#!/usr/bin/env bash
# Hermes Burp Suite readiness guard for SRC/pentest work.
# It makes Burp usable from Hermes in practice: starts Burp/Gateway if needed,
# verifies proxy + MCP discovery + HTTP/HTTPS through Burp + local evidence log,
# and keeps CA material available for curl/browser/mobile workflows.
#
# Usage:
#   /root/.hermes/scripts/hermes-burp-ready.sh
#   /root/.hermes/scripts/hermes-burp-ready.sh --quiet
#   /root/.hermes/scripts/hermes-burp-ready.sh --no-clear
#   /root/.hermes/scripts/hermes-burp-ready.sh --expose-lan
set -u

QUIET=0
CLEAR_LOGS=1
EXPOSE_LAN=0
WAIT_SECS=60
DISPLAY_VALUE="${DISPLAY:-:0.0}"
LOG_DIR="/root/.hermes/logs"
STATE_DIR="/root/.hermes/burp_mcp"
EVIDENCE_DIR="/tmp/hermes-burp-ready"
ENSURE="/root/.hermes/scripts/hermes-ensure-tools.sh"
MCP_LOG="$STATE_DIR/traffic.jsonl"
CA_PEM="/tmp/burp_ca.pem"
SYS_CA="/usr/local/share/ca-certificates/burp_ca.crt"
SUMMARY_JSON="$EVIDENCE_DIR/summary.json"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$EVIDENCE_DIR"

log(){ [ "$QUIET" = 1 ] || printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
fail(){ printf '[%s] ERROR: %s\n' "$(date '+%F %T')" "$*" >&2; exit 1; }
exists(){ command -v "$1" >/dev/null 2>&1; }
port_open(){ ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$1$"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --no-clear) CLEAR_LOGS=0 ;;
    --expose-lan) EXPOSE_LAN=1 ;;
    --wait) shift; WAIT_SECS="${1:-60}" ;;
    --display) shift; DISPLAY_VALUE="${1:-:0.0}" ;;
    -h|--help) sed -n '1,16p' "$0"; exit 0 ;;
    *) fail "unknown arg: $1" ;;
  esac
  shift
done

log "Ensuring Burp Suite + Hermes Burp MCP are running"
[ -x "$ENSURE" ] || fail "missing ensure script: $ENSURE"
"$ENSURE" --burp --wait "$WAIT_SECS" --display "$DISPLAY_VALUE" > "$EVIDENCE_DIR/ensure.log" 2>&1 || {
  tail -80 "$EVIDENCE_DIR/ensure.log" >&2 || true
  fail "ensure Burp failed"
}
[ "$QUIET" = 1 ] || tail -20 "$EVIDENCE_DIR/ensure.log"

port_open 8080 || fail "Burp proxy is not listening on 127.0.0.1:8080"
pgrep -f 'burp_mcp_server.py' >/dev/null 2>&1 || fail "Burp MCP server process is not running"

# Try to keep intercept off. This is best-effort because Community GUI state is visual.
if exists xdotool; then
  WID=$(DISPLAY="$DISPLAY_VALUE" xdotool search --name 'Burp Suite Community Edition\|Burp Suite' 2>/dev/null | head -1 || true)
  if [ -n "${WID:-}" ]; then
    DISPLAY="$DISPLAY_VALUE" xdotool windowactivate "$WID" >/dev/null 2>&1 || true
    DISPLAY="$DISPLAY_VALUE" xdotool key ctrl+shift+P >/dev/null 2>&1 || true
    sleep 0.3
    # Do not blindly toggle Intercept here: Ctrl+T is stateful and may turn it ON.
    # The HTTP/HTTPS curl + MCP checks below are the authoritative proof that requests pass.
  fi
fi

log "Checking Burp package/version"
{
  echo '=== burpsuite --version ==='
  burpsuite --version 2>&1 | head -5 || true
  echo '=== apt-cache policy burpsuite ==='
  apt-cache policy burpsuite 2>/dev/null || true
} > "$EVIDENCE_DIR/version.txt"

log "Ensuring Burp CA is available and trusted by system/NSS when possible"
if [ ! -s "$SYS_CA" ]; then
  echo "" | timeout 15 openssl s_client -proxy 127.0.0.1:8080 -connect example.com:443 -servername example.com -showcerts 2>&1 \
    | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > /tmp/burp_cert_chain.pem || true
  /usr/bin/python3 - <<'PY' || true
import re
from pathlib import Path
chain=Path('/tmp/burp_cert_chain.pem').read_text(errors='replace') if Path('/tmp/burp_cert_chain.pem').exists() else ''
certs=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', chain, re.S)
if certs:
    Path('/tmp/burp_ca.pem').write_text(certs[-1].strip()+'\n')
PY
  if [ -s "$CA_PEM" ]; then
    cp "$CA_PEM" "$SYS_CA"
    update-ca-certificates >/tmp/hermes_burp_update_ca.log 2>&1 || true
  fi
else
  cp "$SYS_CA" "$CA_PEM" 2>/dev/null || true
fi
if [ -s "$SYS_CA" ]; then
  openssl x509 -in "$SYS_CA" -noout -subject -issuer -dates -fingerprint -sha256 > "$EVIDENCE_DIR/ca.txt" 2>&1 || true
  HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$SYS_CA" 2>/dev/null | head -1 || true)
  if [ -n "${HASH:-}" ]; then
    cp "$SYS_CA" "/tmp/${HASH}.0" 2>/dev/null || true
    echo "/tmp/${HASH}.0" > "$EVIDENCE_DIR/android_ca_path.txt"
  fi
  if exists certutil; then
    mkdir -p /root/.pki/nssdb
    timeout 10 certutil -N -d sql:/root/.pki/nssdb --empty-password >/dev/null 2>&1 || true
    timeout 10 certutil -A -d sql:/root/.pki/nssdb -t "CT,," -n "Burp Suite CA" -i "$SYS_CA" >/dev/null 2>&1 || true
    timeout 10 certutil -L -d sql:/root/.pki/nssdb > "$EVIDENCE_DIR/nss.txt" 2>&1 || true
  fi
else
  log "WARNING: Burp CA file still unavailable; HTTPS via MCP works with verify=false, but browser/mobile trust may need manual CA setup"
fi

log "Testing Hermes MCP discovery"
hermes mcp test burpsuite > "$EVIDENCE_DIR/hermes_mcp_test.txt" 2>&1 || {
  tail -80 "$EVIDENCE_DIR/hermes_mcp_test.txt" >&2 || true
  fail "hermes mcp test burpsuite failed"
}
grep -q 'Tools discovered' "$EVIDENCE_DIR/hermes_mcp_test.txt" || fail "MCP test did not discover tools"

if [ "$CLEAR_LOGS" = 1 ]; then
  : > "$MCP_LOG"
fi

log "Testing direct curl through Burp proxy"
curl -sS -m 30 -x http://127.0.0.1:8080 'http://httpbin.org/get?hermes_burp_ready_curl_http=1' -o "$EVIDENCE_DIR/curl_http.json" || fail "curl HTTP through Burp failed"
curl -k -sS -m 30 -x http://127.0.0.1:8080 'https://httpbin.org/get?hermes_burp_ready_curl_https=1' -o "$EVIDENCE_DIR/curl_https.json" || fail "curl HTTPS through Burp failed"
grep -q 'hermes_burp_ready_curl_http' "$EVIDENCE_DIR/curl_http.json" || fail "curl HTTP response marker missing"
grep -q 'hermes_burp_ready_curl_https' "$EVIDENCE_DIR/curl_https.json" || fail "curl HTTPS response marker missing"

log "Testing Burp MCP request/log pipeline"
/root/.hermes/hermes-agent/venv/bin/python3 - <<'PY' > /tmp/hermes_burp_mcp_direct.json
import asyncio, importlib.util, json, sys
p='/root/tools/burp-mcp-hermes/burp_mcp_server.py'
spec=importlib.util.spec_from_file_location('burp_mcp_server_direct', p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
results=[]
results.append(mod.burp_health())
results.append(mod.burp_proxy_request('http://httpbin.org/get?hermes_burp_ready_mcp_http=1', headers={'User-Agent':'Hermes-Burp-Ready/1.0'}, timeout=30))
results.append(mod.burp_proxy_request('https://httpbin.org/get?hermes_burp_ready_mcp_https=1', headers={'User-Agent':'Hermes-Burp-Ready/1.0'}, timeout=30))
results.append(mod.burp_logs(search='hermes_burp_ready_mcp', limit=5))
results.append(mod.burp_analyze_logs(limit=100))
print(json.dumps(results, ensure_ascii=False, indent=2, default=str))
PY
mv /tmp/hermes_burp_mcp_direct.json "$EVIDENCE_DIR/mcp_direct.json"
/usr/bin/python3 - <<'PY'
import json, sys
from pathlib import Path
p=Path('/tmp/hermes-burp-ready/mcp_direct.json')
obj=json.loads(p.read_text())
health=obj[0]
if not health.get('reachable'):
    raise SystemExit('MCP health reachable=false: '+str(health.get('error')))
for idx in (1,2):
    if obj[idx].get('status_code') != 200:
        raise SystemExit(f'MCP request {idx} status not 200: {obj[idx]}')
if obj[3].get('count',0) < 2:
    raise SystemExit('MCP logs did not contain both ready markers')
PY

if [ "$EXPOSE_LAN" = 1 ]; then
  KALI_IP=$(ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
  if [ -n "${KALI_IP:-}" ]; then
    if ! ss -ltn | awk '{print $4}' | grep -q "${KALI_IP}:8080$"; then
      pkill -f "socat TCP-LISTEN:8080,bind=${KALI_IP}" 2>/dev/null || true
      nohup socat TCP-LISTEN:8080,bind="$KALI_IP",fork,reuseaddr TCP:127.0.0.1:8080 > "$LOG_DIR/burp-socat-${KALI_IP}.log" 2>&1 &
      sleep 1
    fi
    echo "$KALI_IP:8080" > "$EVIDENCE_DIR/lan_proxy.txt"
    log "LAN proxy exposed at $KALI_IP:8080"
  else
    log "WARNING: could not determine eth0 IPv4 for --expose-lan"
  fi
fi

/usr/bin/python3 - <<'PY'
import json, os, subprocess
from pathlib import Path
base=Path('/tmp/hermes-burp-ready')
summary={
  'ok': True,
  'burp_proxy': '127.0.0.1:8080',
  'mcp_log': '/root/.hermes/burp_mcp/traffic.jsonl',
  'evidence_dir': str(base),
  'system_ca': '/usr/local/share/ca-certificates/burp_ca.crt' if Path('/usr/local/share/ca-certificates/burp_ca.crt').exists() else '',
  'android_ca': Path(base/'android_ca_path.txt').read_text().strip() if (base/'android_ca_path.txt').exists() else '',
  'lan_proxy': Path(base/'lan_proxy.txt').read_text().strip() if (base/'lan_proxy.txt').exists() else '',
}
try:
    m=json.loads((base/'mcp_direct.json').read_text())
    summary['mcp_health']=m[0]
    summary['mcp_analyze']=m[-1]
except Exception as e:
    summary['mcp_parse_error']=str(e)
(base/'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

log "Burp is ready for Hermes-controlled practical work"
