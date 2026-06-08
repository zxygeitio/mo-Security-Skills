#!/bin/bash
# report-quality-gate.sh — 报告提交前质量门禁检查
# 用法: ./report-quality-gate.sh <report_file.txt>
# 检查报告是否符合教育SRC提交标准

REPORT="$1"
if [ -z "$REPORT" ] || [ ! -f "$REPORT" ]; then
    echo "用法: $0 <report_file.txt>"
    exit 1
fi

echo "=========================================="
echo " 报告质量门禁检查"
echo "=========================================="
echo " 文件: $REPORT"
echo ""

CONTENT=$(cat "$REPORT")
ERRORS=0
WARNINGS=0

# 1. 标题格式检查
echo "[1/8] 标题格式..."
TITLE=$(echo "$CONTENT" | grep -i "^标题:" | head -1)
if [ -z "$TITLE" ]; then
    echo "  [ERROR] 缺少标题"
    ERRORS=$((ERRORS+1))
elif echo "$TITLE" | grep -qP "存在.*漏洞"; then
    echo "  [OK] 标题格式正确"
else
    echo "  [WARN] 标题建议格式: xxx站xxx处存在xxx漏洞"
    WARNINGS=$((WARNINGS+1))
fi

# 2. 漏洞类型检查
echo ""
echo "[2/8] 漏洞类型..."
TYPE=$(echo "$CONTENT" | grep -i "^漏洞类型:" | head -1)
if [ -z "$TYPE" ]; then
    echo "  [ERROR] 缺少漏洞类型"
    ERRORS=$((ERRORS+1))
else
    # 检查是否为已知被拒类型
    if echo "$TYPE" | grep -qi "配置缺陷\|header缺失\|版本泄露"; then
        echo "  [WARN] 漏洞类型可能被拒: $TYPE"
        echo "         教育SRC通常不收纯配置缺陷"
        WARNINGS=$((WARNINGS+1))
    else
        echo "  [OK] 漏洞类型: $TYPE"
    fi
fi

# 3. 漏洞等级检查
echo ""
echo "[3/8] 漏洞等级..."
LEVEL=$(echo "$CONTENT" | grep -i "^漏洞等级:" | head -1)
if [ -z "$LEVEL" ]; then
    echo "  [ERROR] 缺少漏洞等级"
    ERRORS=$((ERRORS+1))
else
    echo "  [OK] 等级: $LEVEL"
fi

# 4. 地址检查 (教育SRC必须精确到区)
echo ""
echo "[4/8] 地址精度..."
ADDR=$(echo "$CONTENT" | grep -i "^地址:" | head -1)
if [ -z "$ADDR" ]; then
    echo "  [ERROR] 缺少地址"
    ERRORS=$((ERRORS+1))
elif echo "$ADDR" | grep -qP "省.*市.*区"; then
    echo "  [OK] 地址精确到区"
else
    echo "  [ERROR] 地址必须精确到区 (如: 安徽省亳州市谯城区)"
    ERRORS=$((ERRORS+1))
fi

# 5. 复现步骤检查
echo ""
echo "[5/8] 复现步骤..."
if echo "$CONTENT" | grep -qi "复现步骤"; then
    # 检查是否有curl命令
    CURL_COUNT=$(echo "$CONTENT" | grep -c "curl")
    if [ "$CURL_COUNT" -gt 0 ]; then
        echo "  [OK] 包含 $CURL_COUNT 个curl命令"
    else
        echo "  [WARN] 复现步骤中未找到curl命令"
        echo "         建议: 每步都提供可执行的curl命令"
        WARNINGS=$((WARNINGS+1))
    fi
    
    # 检查是否有HTTP响应
    if echo "$CONTENT" | grep -qiP "HTTP/[12]\.\d|200 OK|302|403|500"; then
        echo "  [OK] 包含HTTP响应信息"
    else
        echo "  [WARN] 未找到HTTP响应信息"
        echo "         建议: 使用 curl -sk -D- 获取完整响应"
        WARNINGS=$((WARNINGS+1))
    fi
else
    echo "  [ERROR] 缺少复现步骤"
    ERRORS=$((ERRORS+1))
fi

# 6. 证据检查
echo ""
echo "[6/8] 证据完整性..."
# 检查是否有实际数据
if echo "$CONTENT" | grep -qiP "返回.*数据|获取.*信息|泄露.*内容|响应.*如下"; then
    echo "  [OK] 包含数据证据描述"
else
    echo "  [WARN] 未找到数据证据描述"
    echo "         建议: 包含实际返回的敏感数据(脱敏后)"
    WARNINGS=$((WARNINGS+1))
fi

# 检查是否有危害证明
if echo "$CONTENT" | grep -qiP "影响|危害"; then
    echo "  [OK] 包含影响/危害描述"
else
    echo "  [WARN] 未找到影响/危害描述"
    WARNINGS=$((WARNINGS+1))
fi

# 7. CVSS检查
echo ""
echo "[7/8] CVSS向量..."
if echo "$CONTENT" | grep -qiP "CVSS"; then
    echo "  [OK] 包含CVSS评分"
else
    echo "  [WARN] 未找到CVSS向量"
    echo "         建议: 添加CVSS:3.1/向量字符串"
    WARNINGS=$((WARNINGS+1))
fi

# 8. 格式检查
echo ""
echo "[8/8] 格式要求..."
# 检查是否包含HTML
if echo "$CONTENT" | grep -qiP "<html|<div|<table|<br"; then
    echo "  [ERROR] 包含HTML标签，教育SRC要求纯文本"
    ERRORS=$((ERRORS+1))
else
    echo "  [OK] 纯文本格式"
fi

# 检查行业
if echo "$CONTENT" | grep -qiP "行业.*教育"; then
    echo "  [OK] 行业: 教育"
else
    echo "  [WARN] 未明确标注行业为教育"
    WARNINGS=$((WARNINGS+1))
fi

# 总结
echo ""
echo "=========================================="
echo " 检查结果"
echo "=========================================="
echo " 错误: $ERRORS"
echo " 警告: $WARNINGS"
echo ""

if [ "$ERRORS" -gt 0 ]; then
    echo " [FAIL] 存在 $ERRORS 个错误，建议修复后再提交"
    echo ""
    echo " 修复建议:"
    echo " 1. 确保所有必填字段完整"
    echo " 2. 地址精确到区"
    echo " 3. 复现步骤包含curl命令和响应"
    echo " 4. 使用纯文本格式"
    exit 1
elif [ "$WARNINGS" -gt 2 ]; then
    echo " [WARN] 存在 $WARNINGS 个警告，建议优化"
    echo ""
    echo " 优化建议:"
    echo " 1. 添加数据证据和危害证明"
    echo " 2. 确保curl命令可直接执行"
    echo " 3. 添加CVSS向量"
    exit 2
else
    echo " [PASS] 报告质量检查通过"
    echo ""
    echo " 可以提交!"
    exit 0
fi
