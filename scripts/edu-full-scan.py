import os
#!/usr/bin/python3
"""
edu-full-scan.py - 教育SRC全自动化扫描主控脚本
串联: 子域枚举→批量探测→指纹识别→漏洞扫描→报告生成

用法:
  python3 edu-full-scan.py cuit.edu.cn                    # 完整扫描
  python3 edu-full-scan.py cuit.edu.cn --fast             # 快速模式(跳过深挖)
  python3 edu-full-scan.py cuit.edu.cn --resume           # 断点续扫
  python3 edu-full-scan.py cuit.edu.cn --phase recon      # 只执行特定阶段
  python3 edu-full-scan.py cuit.edu.cn --timeout 8        # 自定义超时

阶段:
  1. recon        - 子域枚举 + DNS过滤 + HTTP探活
  2. fingerprint  - 技术栈指纹识别
  3. vuln_scan    - 自动漏洞扫描
  4. js_scan      - JS安全分析(SPA目标)
  5. deep_dive    - 深挖高价值目标
  6. report       - 生成报告
"""

import subprocess
import sys
import json
import time
import argparse
from datetime import datetime

PYTHON = os.environ.get('PYTHON_BIN', '/usr/bin/python3')
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_BASE = os.environ.get('PENTEST_WORKSPACE', '/tmp/vuln_reports')


def run_script(script, args, timeout=300):
    """运行子脚本"""
    cmd = [PYTHON, os.path.join(SCRIPTS_DIR, script)] + args
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.stdout:
            print(r.stdout)
        if r.stderr:
            print(r.stderr, file=sys.stderr)
        return r.returncode == 0, r.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] Script timed out: {script}")
        return False, ''
    except Exception as e:
        print(f"[!] Script error: {e}")
        return False, ''


def run_cmd(cmd, timeout=60):
    """运行shell命令"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ''


def phase_recon(domain, timeout=4, batch=20):
    """Phase 1: 子域枚举 + 探活"""
    ws = os.path.join(WORKSPACE_BASE, domain)
    os.makedirs(ws, exist_ok=True)
    subs_file = os.path.join(ws, 'subs.txt')
    alive_file = os.path.join(ws, 'alive.txt')

    # 子域枚举
    print(f"\n{'='*60}")
    print(f"[*] Phase 1: Recon - {domain}")
    print(f"{'='*60}")

    # subfinder
    print("[*] Running subfinder...")
    result = run_cmd(f'subfinder -silent -d {domain} 2>/dev/null', timeout=60)
    subs = set(result.split('\n')) if result else set()

    # 补充常见子域
    common_subs = [
        'www', 'mail', 'oa', 'sso', 'cas', 'vpn', 'webvpn', 'sslvpn',
        'idp', 'auth', 'login', 'ywtb', 'notice', 'news', 'email',
        'lib', 'jwc', 'jwb', 'rsc', 'dag', 'hqc', 'zs', 'xsc',
        'ef', 'pan', 'ftp', 'dns', 'ns1', 'ns2', 'smtp', 'pop', 'imap',
        'admin', 'api', 'app', 'm', 'mobile', 'wap', 'static', 'img',
        'cjypt', 'zkypt', 'exam', 'jwgl', 'jxgl', 'klas', 'security',
        'ceshi', 'user', 'iwm', 'ztb', 'cxcy', 'acm', 'cyber',
    ]
    for sub in common_subs:
        subs.add(f'{sub}.{domain}')

    subs = sorted(subs)
    with open(subs_file, 'w') as f:
        f.write('\n'.join(subs) + '\n')
    print(f"[+] {len(subs)} subdomains collected")

    # 批量探测
    print("[*] Running batch probe...")
    ok, output = run_script('edu-batch-probe.py', [
        subs_file, '--timeout', str(timeout), '--batch', str(batch),
        '--dns', '-f', '-o', alive_file,
        '--filter-code', '200,301,302,403',
    ], timeout=600)

    # 更新workspace
    if os.path.exists(alive_file):
        with open(alive_file) as f:
            alive_count = len([l for l in f if l.strip()])
    else:
        alive_count = 0

    run_script('src-workspace.py', [
        'update', domain, '--phase', 'recon'
    ])

    # 更新统计
    ws_data = load_ws(domain)
    if ws_data:
        ws_data['stats']['subs_total'] = len(subs)
        ws_data['stats']['subs_alive'] = alive_count
        save_ws(domain, ws_data)

    return alive_count


def phase_fingerprint(domain, timeout=6):
    """Phase 2: 指纹识别"""
    ws = os.path.join(WORKSPACE_BASE, domain)
    alive_file = os.path.join(ws, 'alive.txt')

    print(f"\n{'='*60}")
    print(f"[*] Phase 2: Fingerprint - {domain}")
    print(f"{'='*60}")

    if not os.path.exists(alive_file):
        print("[-] No alive.txt found, run recon first")
        return

    # 对存活子域做指纹识别
    ok, output = run_script('edu-batch-probe.py', [
        alive_file, '--timeout', str(timeout), '--fingerprint',
        '-o', os.path.join(ws, 'fingerprints.txt'),
    ], timeout=300)

    run_script('src-workspace.py', [
        'update', domain, '--phase', 'fingerprint'
    ])


def phase_vuln_scan(domain, timeout=6):
    """Phase 3: 自动漏洞扫描"""
    ws = os.path.join(WORKSPACE_BASE, domain)
    alive_file = os.path.join(ws, 'alive.txt')

    print(f"\n{'='*60}")
    print(f"[*] Phase 3: Vulnerability Scan - {domain}")
    print(f"{'='*60}")

    if not os.path.exists(alive_file):
        print("[-] No alive.txt found, run recon first")
        return

    # 提取存活URL
    urls = []
    with open(alive_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                # 格式: CODE SIZE PROTO://DOMAIN
                url = parts[2]
                urls.append(url)
            elif '|' in line:
                # 格式: CODE|PROTO://DOMAIN
                url = line.split('|')[1]
                urls.append(url)

    if not urls:
        print("[-] No URLs to scan")
        return

    # 写入URL列表
    urls_file = os.path.join(ws, 'urls.txt')
    with open(urls_file, 'w') as f:
        f.write('\n'.join(urls) + '\n')

    # 运行漏洞扫描
    ok, output = run_script('auto-vuln-scan.py', [
        urls_file, '--timeout', str(timeout), '--enum',
        '-o', os.path.join(ws, 'vulns.json'), '--json',
    ], timeout=600)

    run_script('src-workspace.py', [
        'update', domain, '--phase', 'vuln_scan'
    ])


def phase_js_scan(domain):
    """Phase 4: JS安全分析"""
    ws = os.path.join(WORKSPACE_BASE, domain)

    print(f"\n{'='*60}")
    print(f"[*] Phase 4: JS Security Scan - {domain}")
    print(f"{'='*60}")

    # 找SPA目标
    alive_file = os.path.join(ws, 'alive.txt')
    if not os.path.exists(alive_file):
        return

    js_targets = []
    with open(alive_file) as f:
        for line in f:
            if '1761' in line or '1761B' in line or 'vite' in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    js_targets.append(parts[2])

    for url in js_targets[:3]:  # 只扫描前3个SPA目标
        print(f"[*] Scanning JS: {url}")
        # 获取HTML中的JS链接
        html = run_cmd(f'curl -sk --max-time 8 {url} 2>/dev/null', timeout=15)
        import re
        js_files = re.findall(r'src="([^"]*\.js[^"]*)"', html)
        for js_url in js_files[:3]:
            if not js_url.startswith('http'):
                js_url = url.rstrip('/') + '/' + js_url.lstrip('/')
            print(f"[*] Analyzing: {js_url}")
            run_script('js-secrets-scanner.py', [
                js_url, '--url', '--severity', 'medium',
            ], timeout=30)

    run_script('src-workspace.py', [
        'update', domain, '--phase', 'js_scan'
    ])


def phase_report(domain):
    """Phase 6: 生成报告"""
    ws = os.path.join(WORKSPACE_BASE, domain)

    print(f"\n{'='*60}")
    print(f"[*] Phase 6: Report Generation - {domain}")
    print(f"{'='*60}")

    run_script('src-workspace.py', [
        'export', domain,
    ])

    run_script('src-workspace.py', [
        'update', domain, '--phase', 'report'
    ])


def load_ws(domain):
    """加载workspace"""
    ws_file = os.path.join(WORKSPACE_BASE, domain, 'workspace.json')
    if os.path.exists(ws_file):
        with open(ws_file) as f:
            return json.load(f)
    return None


def save_ws(domain, data):
    """保存workspace"""
    ws_file = os.path.join(WORKSPACE_BASE, domain, 'workspace.json')
    data['last_scan'] = datetime.now().isoformat()
    with open(ws_file, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description='Full edu SRC scanner')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--fast', action='store_true', help='Fast mode (skip deep dive)')
    parser.add_argument('--resume', action='store_true', help='Resume from last phase')
    parser.add_argument('--phase', help='Run specific phase only')
    parser.add_argument('--timeout', type=int, default=4, help='Request timeout')
    parser.add_argument('--batch', type=int, default=20, help='Concurrent batch size')
    args = parser.parse_args()

    domain = args.domain.replace('https://', '').replace('http://', '').rstrip('/')
    start_time = time.time()

    print(f"{'='*60}")
    print(f"  edu-full-scan: {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode: {'fast' if args.fast else 'full'}")
    print(f"{'='*60}")

    # 初始化workspace
    run_script('src-workspace.py', ['init', domain])

    # 确定起始阶段
    if args.phase:
        start_phase = args.phase
    elif args.resume:
        ws_data = load_ws(domain)
        start_phase = ws_data.get('phase', 'recon') if ws_data else 'recon'
        print(f"[*] Resuming from phase: {start_phase}")
    else:
        start_phase = 'recon'

    phases = ['recon', 'fingerprint', 'vuln_scan', 'js_scan', 'deep_dive', 'report']
    start_idx = phases.index(start_phase) if start_phase in phases else 0

    # 执行各阶段
    try:
        if 'recon' in phases[start_idx:]:
            phase_recon(domain, args.timeout, args.batch)

        if 'fingerprint' in phases[start_idx:]:
            phase_fingerprint(domain, args.timeout)

        if 'vuln_scan' in phases[start_idx:]:
            phase_vuln_scan(domain, args.timeout)

        if 'js_scan' in phases[start_idx:] and not args.fast:
            phase_js_scan(domain)

        if 'deep_dive' in phases[start_idx:] and not args.fast:
            print("\n[*] Deep dive phase requires manual Hermes agent intervention")
            print("    Run: python3 auto-vuln-scan.py <high-value-url> --all --enum")

        if 'report' in phases[start_idx:]:
            phase_report(domain)

    except KeyboardInterrupt:
        print("\n[!] Interrupted. Use --resume to continue.")

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[*] Scan complete: {domain}")
    print(f"[*] Total time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print(f"{'='*60}")

    # 显示workspace状态
    run_script('src-workspace.py', ['status', domain])


if __name__ == '__main__':
    main()
