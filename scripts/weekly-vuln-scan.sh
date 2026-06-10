#!/bin/bash
# 每周漏洞扫描包装脚本

# 创建目标文件（如果不存在）
if [ ! -f "/tmp/targets.txt" ]; then
    echo "example.com" > /tmp/targets.txt
fi

/root/.hermes/scripts/pentest-automation.sh vuln-scan /tmp/targets.txt
