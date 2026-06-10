#!/usr/bin/env python3
"""
自定义工作流模板 - 可根据需求修改
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

class CustomWorkflow:
    """自定义工作流"""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.steps = []
    
    def add_step(self, name, command, description=""):
        """添加工作流步骤"""
        self.steps.append({
            'name': name,
            'command': command,
            'description': description
        })
    
    def run(self, **kwargs):
        """运行工作流"""
        print(f"开始执行工作流: {self.name}")
        print(f"描述: {self.description}")
        print(f"步骤数量: {len(self.steps)}")
        print("")
        
        # 创建输出目录
        output_dir = Path(f'/tmp/workflow_{self.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        output_dir.mkdir(exist_ok=True)
        
        results = []
        for i, step in enumerate(self.steps, 1):
            print(f"[{i}/{len(self.steps)}] {step['name']}")
            if step['description']:
                print(f"  描述: {step['description']}")
            
            # 替换命令中的变量
            command = step['command']
            for key, value in kwargs.items():
                command = command.replace(f'{{{key}}}', str(value))
            
            # 执行命令
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                # 保存结果
                step_result = {
                    'step': step['name'],
                    'command': command,
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                results.append(step_result)
                
                # 保存到文件
                output_file = output_dir / f"step_{i}_{step['name'].replace(' ', '_')}.txt"
                with open(output_file, 'w') as f:
                    f.write(f"步骤: {step['name']}\n")
                    f.write(f"命令: {command}\n")
                    f.write(f"返回码: {result.returncode}\n")
                    f.write(f"标准输出:\n{result.stdout}\n")
                    f.write(f"标准错误:\n{result.stderr}\n")
                
                if result.returncode == 0:
                    print(f"  ✓ 成功")
                else:
                    print(f"  ✗ 失败 (返回码: {result.returncode})")
            
            except subprocess.TimeoutExpired:
                print(f"  ✗ 超时")
                results.append({
                    'step': step['name'],
                    'command': command,
                    'error': '超时'
                })
            except Exception as e:
                print(f"  ✗ 错误: {e}")
                results.append({
                    'step': step['name'],
                    'command': command,
                    'error': str(e)
                })
        
        # 生成报告
        report_file = output_dir / "report.md"
        with open(report_file, 'w') as f:
            f.write(f"# 工作流报告: {self.name}\n\n")
            f.write(f"**执行时间**: {datetime.now()}\n")
            f.write(f"**输出目录**: {output_dir}\n\n")
            f.write(f"## 步骤结果\n\n")
            for i, result in enumerate(results, 1):
                f.write(f"### 步骤 {i}: {result.get('step', '未知')}\n\n")
                f.write(f"- 命令: `{result.get('command', '')}`\n")
                if 'error' in result:
                    f.write(f"- 错误: {result['error']}\n")
                else:
                    f.write(f"- 返回码: {result.get('returncode', '未知')}\n")
                f.write("\n")
        
        print(f"\n工作流执行完成")
        print(f"输出目录: {output_dir}")
        print(f"报告文件: {report_file}")
        
        return {
            'workflow': self.name,
            'output_dir': str(output_dir),
            'report_file': str(report_file),
            'results': results
        }

# 示例工作流定义
def create_web_pentest_workflow():
    """创建Web渗透测试工作流"""
    workflow = CustomWorkflow(
        name="web-pentest",
        description="Web应用渗透测试工作流"
    )
    
    workflow.add_step(
        name="信息收集",
        command="subfinder -d {domain} -silent > /tmp/subs.txt",
        description="子域名枚举"
    )
    
    workflow.add_step(
        name="HTTP探活",
        command="cat /tmp/subs.txt | httpx -silent > /tmp/alive.txt",
        description="HTTP服务探活"
    )
    
    workflow.add_step(
        name="端口扫描",
        command="nmap -Pn -sT -T4 --top-ports 100 -iL /tmp/alive.txt -oN /tmp/nmap.txt",
        description="端口扫描"
    )
    
    workflow.add_step(
        name="漏洞扫描",
        command="nuclei -l /tmp/alive.txt -t cves/ -severity critical,high -o /tmp/nuclei.txt",
        description="漏洞扫描"
    )
    
    workflow.add_step(
        name="目录爆破",
        command="gobuster dir -u {url} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -o /tmp/gobuster.txt",
        description="目录爆破"
    )
    
    return workflow

def create_internal_pentest_workflow():
    """创建内网渗透测试工作流"""
    workflow = CustomWorkflow(
        name="internal-pentest",
        description="内网渗透测试工作流"
    )
    
    workflow.add_step(
        name="SMB枚举",
        command="python3 /opt/enum4linux-ng/enum4linux-ng.py -a {target} > /tmp/enum4linux.txt",
        description="SMB枚举"
    )
    
    workflow.add_step(
        name="Kerberos爆破",
        command="kerbrute userenum -d {domain} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt > /tmp/kerbrute.txt",
        description="Kerberos用户枚举"
    )
    
    workflow.add_step(
        name="Responder",
        command="timeout 300 python3 /opt/responder/Responder.py -I eth0 -wrf > /tmp/responder.txt",
        description="LLMNR/NBT-NS投毒"
    )
    
    return workflow

# 主函数
def main():
    if len(sys.argv) < 2:
        print("用法: python3 custom-workflows.py <workflow_name> [key=value ...]")
        print("")
        print("可用工作流:")
        print("  web-pentest      - Web应用渗透测试")
        print("  internal-pentest - 内网渗透测试")
        sys.exit(1)
    
    workflow_name = sys.argv[1]
    
    # 解析参数
    kwargs = {}
    for arg in sys.argv[2:]:
        if '=' in arg:
            key, value = arg.split('=', 1)
            kwargs[key] = value
    
    # 创建工作流
    if workflow_name == "web-pentest":
        workflow = create_web_pentest_workflow()
    elif workflow_name == "internal-pentest":
        workflow = create_internal_pentest_workflow()
    else:
        print(f"未知工作流: {workflow_name}")
        sys.exit(1)
    
    # 执行工作流
    result = workflow.run(**kwargs)
    
    # 输出结果
    print("\n" + "="*50)
    print("工作流执行结果:")
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
