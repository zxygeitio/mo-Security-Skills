#!/bin/bash
# CTF Misc文件分析脚本
# 用法: ctf-misc-analyze.sh <文件>

FILE="$1"

[ -z "$FILE" ] || [ ! -f "$FILE" ] && echo "用法: $0 <文件>" && exit 1

echo "=========================================="
echo "Misc文件分析: $FILE"
echo "=========================================="

echo ""
echo "[1/8] 基本信息..."
echo "------------------------------------------"
file "$FILE"
ls -lh "$FILE"

echo ""
echo "[2/8] 文件头(hex)..."
echo "------------------------------------------"
xxd "$FILE" | head -5

echo ""
echo "[3/8] 字符串提取..."
echo "------------------------------------------"
echo "[*] 可打印字符串(长度>=6):"
strings -n 6 "$FILE" | head -30
echo ""
echo "[*] 搜索flag关键词:"
strings "$FILE" | grep -iE "(flag|ctf|key|secret|password|base64|rot13)" | head -10

echo ""
echo "[4/8] 嵌入文件检测(binwalk)..."
echo "------------------------------------------"
binwalk "$FILE"

echo ""
echo "[5/8] 元数据(exiftool)..."
echo "------------------------------------------"
exiftool "$FILE" 2>/dev/null | head -30

echo ""
echo "[6/8] 根据文件类型分析..."
echo "------------------------------------------"
FILE_TYPE=$(file -b "$FILE")

case "$FILE_TYPE" in
    *PNG*|*JPEG*|*GIF*|*BMP*)
        echo "[*] 图片文件分析..."
        
        [[ "$FILE_TYPE" == *PNG* ]] && echo "[*] PNG完整性检查:" && pngcheck "$FILE" 2>&1
        
        echo ""
        echo "[*] 隐写工具测试..."
        [[ "$FILE_TYPE" == *JPEG* ]] && {
            echo "[*] steghide检测(无密码):"
            steghide extract -sf "$FILE" -p "" -f 2>/dev/null && echo "[+] 发现隐藏内容!"
        }
        
        echo ""
        echo "[*] 建议: stegsolve / zbarimg(二维码) / 修改PNG高度"
        ;;
    
    *ELF*|*executable*)
        echo "[*] 可执行文件分析..."
        strings -n 8 "$FILE" | head -50
        echo ""
        checksec --file="$FILE" 2>/dev/null
        ;;
    
    *PDF*)
        echo "[*] PDF分析..."
        pdfinfo "$FILE" 2>/dev/null
        pdftotext "$FILE" /tmp/pdf_text.txt 2>/dev/null && head -30 /tmp/pdf_text.txt
        ;;
    
    *Zip*|*archive*)
        echo "[*] 压缩文件分析..."
        unzip -l "$FILE" 2>/dev/null
        echo ""
        echo "[*] 提取尝试:"
        mkdir -p /tmp/ctf_extract
        unzip -o -P "" "$FILE" -d /tmp/ctf_extract 2>/dev/null && echo "[+] 提取成功!" && ls -la /tmp/ctf_extract/
        ;;
    
    *ASCII*|*text*)
        echo "[*] 文本文件..."
        head -50 "$FILE"
        echo ""
        echo "[*] 编码检测: Base64(=填充) / Hex(0-9a-f) / URL编码(%) / Brainfuck(+-><.[])"
        ;;
    
    *data*)
        echo "[*] 未知数据文件..."
        xxd "$FILE" | head -10
        echo ""
        echo "[*] 尝试解压..."
        file "$FILE" | grep -q "gzip" && gzip -dk "$FILE" 2>/dev/null
        file "$FILE" | grep -q "bzip2" && bzip2 -dk "$FILE" 2>/dev/null
        ;;
esac

echo ""
echo "[7/8] 磁盘/分区检测..."
echo "------------------------------------------"
file "$FILE" | grep -qE "(disk|partition|filesystem|MBR)" && {
    echo "[*] 检测到磁盘镜像!"
    fdisk -l "$FILE" 2>/dev/null
}

echo ""
echo "[8/8] 网络流量检测..."
echo "------------------------------------------"
file "$FILE" | grep -qE "(pcap|capture)" && {
    echo "[*] 检测到网络流量!"
    tshark -r "$FILE" -q -z io,phs 2>/dev/null | head -20
    echo ""
    echo "[*] HTTP请求:"
    tshark -r "$FILE" -Y "http.request" 2>/dev/null | head -10
}

echo ""
echo "=========================================="
echo "分析完成! 根据类型使用对应工具深入分析"
echo "=========================================="
