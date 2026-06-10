#!/usr/bin/env python3
"""简单测试工作流"""

import subprocess
import sys

def main():
    print("测试工作流开始")
    
    # 测试1: 列出工具
    print("\n1. 列出工具:")
    result = subprocess.run(
        "/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py list",
        shell=True,
        capture_output=True,
        text=True
    )
    print(result.stdout[:500])
    
    # 测试2: 健康检查
    print("\n2. 健康检查:")
    result = subprocess.run(
        "/usr/bin/python3 /root/.hermes/scripts/pentest-control-plane.py health",
        shell=True,
        capture_output=True,
        text=True
    )
    print(result.stdout[:500])
    
    print("\n测试工作流完成")

if __name__ == '__main__':
    main()
