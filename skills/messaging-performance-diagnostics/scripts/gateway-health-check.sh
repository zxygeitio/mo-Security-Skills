#!/usr/bin/env bash
# Quick gateway health check — run from any shell
# Usage: bash gateway-health-check.sh

echo "=== System Resources ==="
top -bn1 | head -5

echo ""
echo "=== Gateway Process ==="
systemctl --user status hermes-gateway --no-pager 2>/dev/null | grep -E "Active|Memory|CPU|Tasks" || echo "(not running as systemd service)"

echo ""
echo "=== Top CPU Consumers ==="
ps aux --sort=-%cpu | head -6

echo ""
echo "=== Recent Response Times ==="
grep "response ready" ~/.hermes/logs/gateway.log 2>/dev/null | tail -5 || echo "(no gateway log found)"

echo ""
echo "=== Recent Errors/Reconnects ==="
grep -iE "error|timeout|reconnect|disconnect|keepalive" ~/.hermes/logs/gateway.log 2>/dev/null | tail -5 || echo "(no issues found)"

echo ""
echo "=== Unauthorized User Warnings ==="
grep "Unauthorized user" ~/.hermes/logs/gateway.log 2>/dev/null | tail -3 || echo "(none)"

echo ""
echo "=== Model Provider Latency ==="
BASE_URL=$(grep 'base_url:' ~/.hermes/config.yaml 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' | tr -d "'")
API_KEY=$(grep 'api_key:' ~/.hermes/config.yaml 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' | tr -d "'")
if [ -n "$BASE_URL" ] && [ -n "$API_KEY" ]; then
    echo -n "  Models endpoint: "
    curl -s -o /dev/null -w "%{http_code} %{time_total}s" "$BASE_URL/models" -H "Authorization: Bearer $API_KEY"
    echo ""
else
    echo "  (could not extract base_url/api_key from config)"
fi
