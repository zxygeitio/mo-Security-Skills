#!/bin/bash
# edu-target-preflight.sh — 教育目标可达性预检
# 用法: ./edu-target-preflight.sh domain.edu.cn
# 输出: 可达性报告 + 是否值得测试的建议

DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
    echo "用法: $0 <domain.edu.cn>"
    exit 1
fi

echo "=========================================="
echo " 教育目标可达性预检: $DOMAIN"
echo "=========================================="

# 1. DNS解析
echo ""
echo "[1/6] DNS解析..."
IP=$(dig +short "$DOMAIN" A 2>/dev/null | head -1)
if [ -z "$IP" ]; then
    echo "  [FAIL] DNS解析失败"
    echo "  建议: 跳过此目标"
    exit 1
fi
echo "  IP: $IP"

# 2. CERNET检测
echo ""
echo "[2/6] CERNET教育网检测..."
WHOIS_INFO=$(whois "$IP" 2>/dev/null | head -20)
if echo "$WHOIS_INFO" | grep -qi "cernet\|education.*network\|edu.*cn"; then
    echo "  [WARN] 疑似CERNET教育网IP"
    echo "  影响: 外网可能不可达"
    CERNET=true
else
    echo "  [OK] 非CERNET IP"
    CERNET=false
fi

# 3. HTTP可达性
echo ""
echo "[3/6] HTTP可达性..."
HTTP_OK=false
for proto in https http; do
    CODE=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$proto://$DOMAIN/" 2>/dev/null)
    SIZE=$(curl -sk --max-time 10 -o /dev/null -w "%{size_download}" "$proto://$DOMAIN/" 2>/dev/null)
    if [ "$CODE" != "000" ]; then
        echo "  [OK] $proto://$DOMAIN → HTTP $CODE (${SIZE} bytes)"
        HTTP_OK=true
        PROTO=$proto
        break
    fi
done

if [ "$HTTP_OK" = false ]; then
    echo "  [FAIL] HTTP不可达"
    if [ "$CERNET" = true ]; then
        echo "  原因: CERNET教育网限制，外网无法访问"
        echo "  建议: 转向邮件/DNS/云资产攻击面"
    else
        echo "  原因: 网络不可达或防火墙拦截"
    fi
    echo ""
    echo "=========================================="
    echo " 结论: 主站不可达，需转向其他攻击面"
    echo "=========================================="
    exit 1
fi

# 4. WAF检测
echo ""
echo "[4/6] WAF检测..."
HEADERS=$(curl -skI --max-time 10 "$PROTO://$DOMAIN/" 2>/dev/null)
WAF_TYPE="none"

if echo "$HEADERS" | grep -qi "acw_tc\|yunzhongjun"; then
    WAF_TYPE="阿里云WAF"
    echo "  [WARN] 检测到阿里云WAF (acw_tc cookie)"
elif echo "$HEADERS" | grep -qi "x-protected-by.*openrasp"; then
    WAF_TYPE="OpenRASP"
    echo "  [WARN] 检测到OpenRASP"
elif echo "$HEADERS" | grep -qi "x-waf\|x-cdn-waf"; then
    WAF_TYPE="通用WAF"
    echo "  [WARN] 检测到WAF"
elif echo "$HEADERS" | grep -qi "cloudflare"; then
    WAF_TYPE="Cloudflare"
    echo "  [WARN] 检测到Cloudflare"
else
    echo "  [OK] 未检测到WAF"
fi

# 5. SPA Fallback检测
echo ""
echo "[5/6] SPA Fallback检测..."
BODY1=$(curl -sk --max-time 5 "$PROTO://$DOMAIN/" 2>/dev/null | md5sum | awk '{print $1}')
BODY2=$(curl -sk --max-time 5 "$PROTO://$DOMAIN/nonexistent$(date +%s)" 2>/dev/null | md5sum | awk '{print $1}')
BODY3=$(curl -sk --max-time 5 "$PROTO://$DOMAIN/actuator" 2>/dev/null | md5sum | awk '{print $1}')

if [ "$BODY1" = "$BODY2" ] || [ "$BODY1" = "$BODY3" ]; then
    echo "  [WARN] SPA Fallback — 所有路径返回同一页面"
    SPA=true
else
    echo "  [OK] 非SPA Fallback"
    SPA=false
fi

# 6. 基础指纹
echo ""
echo "[6/6] 基础指纹..."
SERVER=$(echo "$HEADERS" | grep -i "^server:" | head -1 | tr -d '\r')
POWERED=$(echo "$HEADERS" | grep -i "^x-powered-by:" | head -1 | tr -d '\r')
TITLE=$(curl -sk --max-time 5 "$PROTO://$DOMAIN/" 2>/dev/null | grep -oP '<title>[^<]*</title>' | head -1)
echo "  Server: ${SERVER:-未知}"
echo "  Powered: ${POWERED:-未知}"
echo "  Title: ${TITLE:-未知}"

# 总结
echo ""
echo "=========================================="
echo " 预检总结"
echo "=========================================="
echo " 目标: $DOMAIN ($IP)"
echo " 可达: $([ "$HTTP_OK" = true ] && echo "是" || echo "否")"
echo " CERNET: $([ "$CERNET" = true ] && echo "是" || echo "否")"
echo " WAF: $WAF_TYPE"
echo " SPA: $([ "$SPA" = true ] && echo "是" || echo "否")"
echo ""

# 建议
echo "=========================================="
echo " 测试建议"
echo "=========================================="

if [ "$HTTP_OK" = false ]; then
    echo " [!] 主站不可达，建议:"
    echo "     1. 检查邮件系统 (dig +short $DOMAIN MX)"
    echo "     2. 检查DMARC/SPF/DKIM配置"
    echo "     3. 检查云资产 (子域名枚举)"
    echo "     4. 跳过此目标"
elif [ "$WAF_TYPE" != "none" ]; then
    echo " [!] WAF: $WAF_TYPE，建议:"
    echo "     1. 避免: actuator/.git/.env/路径遍历"
    echo "     2. 专注: API层测试、JS分析、业务逻辑"
    echo "     3. 尝试: WAF绕过技术"
elif [ "$SPA" = true ]; then
    echo " [!] SPA应用，建议:"
    echo "     1. 避免: 页面路径测试"
    echo "     2. 专注: API路由(/api/*)"
    echo "     3. 分析: JS bundle中的API端点"
else
    echo " [+] 目标可用，建议:"
    echo "     1. 执行标准Web渗透流程"
    echo "     2. 优先测试: 登录功能/API接口/文件上传"
    echo "     3. 参考 education-src-blueprint 漏洞类型优先级"
fi

echo ""
echo "=========================================="
