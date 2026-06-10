#!/bin/bash
# CTF Web快速检查脚本
# 用法: ctf-web-recon.sh <URL>

URL="$1"
echo "=========================================="
echo "CTF Web快速侦察: $URL"
echo "=========================================="

echo ""
echo "[1/8] 响应头检查..."
echo "------------------------------------------"
curl -skI "$URL" 2>/dev/null | head -20

echo ""
echo "[2/8] robots.txt..."
echo "------------------------------------------"
curl -sk "$URL/robots.txt" 2>/dev/null | head -10

echo ""
echo "[3/8] 常见敏感文件..."
echo "------------------------------------------"
for path in /.git/HEAD /.env /.DS_Store /www.zip /backup.zip /flag /flag.txt /flag.php /admin /robots.txt /sitemap.xml /index.php.bak /index.html.bak /www.tar.gz /web.zip /backup.tar.gz; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL$path" 2>/dev/null)
    size=$(curl -sk -o /dev/null -w "%{size_download}" "$URL$path" 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        echo "$path → $code ($size bytes)"
    fi
done

echo ""
echo "[4/8] 源代码关键信息..."
echo "------------------------------------------"
curl -sk "$URL" 2>/dev/null | grep -iE "(flag|password|secret|key|token|admin|source|<!--)" | head -10

echo ""
echo "[5/8] JS文件分析..."
echo "------------------------------------------"
curl -sk "$URL" 2>/dev/null | grep -oP 'src="[^"]*\.js[^"]*"' | head -5 | while read js; do
    jsurl=$(echo "$js" | grep -oP '"[^"]*"' | tr -d '"')
    if [[ "$jsurl" == http* ]]; then
        echo "JS: $jsurl"
    else
        echo "JS: $URL$jsurl"
    fi
done

echo ""
echo "[6/8] 注释信息..."
echo "------------------------------------------"
curl -sk "$URL" 2>/dev/null | grep -oP '<!--[^>]*-->' | head -5

echo ""
echo "[7/8] 常见参数FUZZ..."
echo "------------------------------------------"
for param in id page file cmd debug admin user name action view source; do
    resp=$(curl -sk "$URL?$param=test" 2>/dev/null | head -c 200)
    if [ ${#resp} -gt 50 ]; then
        echo "?$param=test → 响应长度: ${#resp}"
    fi
done

echo ""
echo "[8/8] 子目录扫描..."
echo "------------------------------------------"
for dir in admin login api upload files images css js static assets backup config data db debug test dev staging; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL/$dir/" 2>/dev/null)
    if [ "$code" == "200" ] || [ "$code" == "301" ] || [ "$code" == "302" ]; then
        echo "/$dir/ → $code"
    fi
done

echo ""
echo "=========================================="
echo "侦察完成!"
echo "=========================================="
