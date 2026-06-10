#!/usr/bin/python3
"""
src-workspace.py - 扫描状态持久化管理
支持断点续扫、状态查询、增量更新

用法:
  python3 src-workspace.py init cuit.edu.cn              # 初始化工作区
  python3 src-workspace.py status cuit.edu.cn            # 查看状态
  python3 src-workspace.py resume cuit.edu.cn            # 显示续扫建议
  python3 src-workspace.py update cuit.edu.cn --phase deep_scan
  python3 src-workspace.py add-vuln cuit.edu.cn --json '{"url":"...","severity":"medium"}'
  python3 src-workspace.py list                          # 列出所有工作区
  python3 src-workspace.py export cuit.edu.cn            # 导出完整报告

工作区结构:
  /tmp/vuln_reports/<domain>/
    workspace.json      # 扫描状态
    subs.txt            # 子域列表
    alive.txt           # 存活子域
    fingerprints.json   # 指纹缓存
    vulns.json          # 发现的漏洞
    endpoints-tested.json  # 已测试端点
    reports/            # 报告
    evidence/           # 证据文件
"""

import os
import json
import argparse
from datetime import datetime


WORKSPACE_BASE = os.environ.get('PENTEST_WORKSPACE', '/tmp/vuln_reports')


def get_workspace(domain):
    """获取工作区路径"""
    # 去掉协议前缀
    domain = domain.replace('https://', '').replace('http://', '').rstrip('/')
    return os.path.join(WORKSPACE_BASE, domain)


def init_workspace(domain):
    """初始化工作区"""
    ws = get_workspace(domain)
    os.makedirs(ws, exist_ok=True)
    os.makedirs(os.path.join(ws, 'reports'), exist_ok=True)
    os.makedirs(os.path.join(ws, 'evidence'), exist_ok=True)

    workspace_file = os.path.join(ws, 'workspace.json')
    if os.path.exists(workspace_file):
        print(f"[!] Workspace already exists: {ws}")
        with open(workspace_file) as f:
            data = json.load(f)
        print(f"    Domain: {data['domain']}")
        print(f"    Created: {data['created']}")
        print(f"    Phase: {data.get('phase', 'unknown')}")
        print(f"    Vulns: {len(data.get('vulns', []))}")
        return data

    data = {
        'domain': domain,
        'created': datetime.now().isoformat(),
        'last_scan': datetime.now().isoformat(),
        'phase': 'init',
        'stats': {
            'subs_total': 0,
            'subs_alive': 0,
            'endpoints_tested': 0,
            'vulns_found': 0,
        },
        'vulns': [],
        'tested_endpoints': [],
        'skipped_subdomains': [],
        'notes': [],
    }

    with open(workspace_file, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[+] Workspace initialized: {ws}")
    print(f"    Domain: {domain}")
    return data


def load_workspace(domain):
    """加载工作区"""
    ws = get_workspace(domain)
    workspace_file = os.path.join(ws, 'workspace.json')
    if not os.path.exists(workspace_file):
        print(f"[-] No workspace found for {domain}")
        print(f"    Run: python3 src-workspace.py init {domain}")
        return None

    with open(workspace_file) as f:
        return json.load(f)


def save_workspace(domain, data):
    """保存工作区"""
    ws = get_workspace(domain)
    data['last_scan'] = datetime.now().isoformat()
    with open(os.path.join(ws, 'workspace.json'), 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def status(domain):
    """显示工作区状态"""
    data = load_workspace(domain)
    if not data:
        return

    ws = get_workspace(domain)
    print(f"\n{'='*50}")
    print(f"Workspace: {domain}")
    print(f"{'='*50}")
    print(f"Created:    {data['created']}")
    print(f"Last scan:  {data['last_scan']}")
    print(f"Phase:      {data.get('phase', 'unknown')}")

    stats = data.get('stats', {})
    print("\nStats:")
    print(f"  Subdomains:   {stats.get('subs_alive', 0)}/{stats.get('subs_total', 0)}")
    print(f"  Endpoints:    {stats.get('endpoints_tested', 0)}")
    print(f"  Vulns found:  {stats.get('vulns_found', 0)}")

    # 文件状态
    print("\nFiles:")
    for fname in ['subs.txt', 'alive.txt', 'fingerprints.json', 'vulns.json',
                  'endpoints-tested.json']:
        fpath = os.path.join(ws, fname)
        if os.path.exists(fpath):
            size = os.path.getsize(fpath)
            print(f"  {fname}: {size} bytes")
        else:
            print(f"  {fname}: (not created)")

    # 漏洞摘要
    vulns = data.get('vulns', [])
    if vulns:
        print("\nVulnerabilities:")
        severity_count = {}
        for v in vulns:
            sev = v.get('severity', 'unknown')
            severity_count[sev] = severity_count.get(sev, 0) + 1
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in severity_count:
                print(f"  [{sev.upper()}] {severity_count[sev]}")

        print("\nDetails:")
        for v in vulns:
            print(f"  [{v.get('severity', '?').upper():8s}] {v.get('description', 'N/A')}")
            print(f"           {v.get('url', 'N/A')}")

    # 备注
    notes = data.get('notes', [])
    if notes:
        print("\nNotes:")
        for note in notes[-5:]:
            print(f"  - {note}")


def resume(domain):
    """显示续扫建议"""
    data = load_workspace(domain)
    if not data:
        return

    phase = data.get('phase', 'init')
    ws = get_workspace(domain)

    print(f"\n[*] Resume suggestions for {domain} (current phase: {phase})")
    print(f"{'='*50}")

    phase_next = {
        'init': ('recon', 'Run subdomain enumeration and HTTP probing'),
        'recon': ('fingerprint', 'Run fingerprint detection on alive subdomains'),
        'fingerprint': ('vuln_scan', 'Run auto vulnerability scanning'),
        'vuln_scan': ('deep_dive', 'Deep dive into high-value targets'),
        'deep_dive': ('report', 'Generate reports'),
        'report': ('done', 'All phases complete'),
    }

    if phase in phase_next:
        next_phase, suggestion = phase_next[phase]
        print(f"  Next phase: {next_phase}")
        print(f"  Suggestion: {suggestion}")

    # 检查未测试的子域
    alive_file = os.path.join(ws, 'alive.txt')
    if os.path.exists(alive_file):
        with open(alive_file) as f:
            alive = {l.strip().split('|')[0] if '|' in l else l.strip()
                    for l in f if l.strip()}
        tested = set(data.get('tested_endpoints', []))
        untested = [a for a in alive if not any(a in t for t in tested)]
        if untested:
            print(f"\n  Untested subdomains ({len(untested)}):")
            for s in untested[:10]:
                print(f"    - {s}")
            if len(untested) > 10:
                print(f"    ... and {len(untested)-10} more")

    # 未修复的漏洞
    vulns = data.get('vulns', [])
    if vulns:
        print(f"\n  Pending vulns ({len(vulns)}):")
        for v in vulns:
            print(f"    [{v.get('severity','?').upper()}] {v.get('description','N/A')}")


def add_vuln(domain, vuln_json):
    """添加漏洞"""
    data = load_workspace(domain)
    if not data:
        data = init_workspace(domain)

    vuln = json.loads(vuln_json)
    vuln['discovered'] = datetime.now().isoformat()
    data['vulns'].append(vuln)
    data['stats']['vulns_found'] = len(data['vulns'])
    save_workspace(domain, data)
    print(f"[+] Vuln added: {vuln.get('description', 'N/A')}")


def update_phase(domain, phase):
    """更新阶段"""
    data = load_workspace(domain)
    if not data:
        return
    data['phase'] = phase
    save_workspace(domain, data)
    print(f"[+] Phase updated to: {phase}")


def update_stats(domain, **kwargs):
    """更新统计"""
    data = load_workspace(domain)
    if not data:
        return
    for k, v in kwargs.items():
        data['stats'][k] = v
    save_workspace(domain, data)


def add_note(domain, note):
    """添加备注"""
    data = load_workspace(domain)
    if not data:
        return
    data['notes'].append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}")
    save_workspace(domain, data)


def add_tested_endpoint(domain, endpoint):
    """记录已测试端点"""
    data = load_workspace(domain)
    if not data:
        return
    if endpoint not in data['tested_endpoints']:
        data['tested_endpoints'].append(endpoint)
        data['stats']['endpoints_tested'] = len(data['tested_endpoints'])
        save_workspace(domain, data)


def list_workspaces():
    """列出所有工作区"""
    if not os.path.exists(WORKSPACE_BASE):
        print("[-] No workspaces found")
        return

    for d in sorted(os.listdir(WORKSPACE_BASE)):
        ws_file = os.path.join(WORKSPACE_BASE, d, 'workspace.json')
        if os.path.exists(ws_file):
            with open(ws_file) as f:
                data = json.load(f)
            stats = data.get('stats', {})
            print(f"  {d}")
            print(f"    Phase: {data.get('phase', '?')}, "
                  f"Vulns: {stats.get('vulns_found', 0)}, "
                  f"Last: {data.get('last_scan', '?')[:19]}")


def export_workspace(domain):
    """导出完整报告"""
    data = load_workspace(domain)
    if not data:
        return

    ws = get_workspace(domain)
    report_file = os.path.join(ws, 'reports', f'full-report-{datetime.now().strftime("%Y%m%d")}.txt')

    lines = []
    lines.append(f"SRC漏洞报告: {domain}")
    lines.append(f"{'='*60}")
    lines.append(f"扫描时间: {data['created']} ~ {data['last_scan']}")
    lines.append(f"扫描阶段: {data.get('phase', 'unknown')}")
    lines.append("")

    stats = data.get('stats', {})
    lines.append("统计:")
    lines.append(f"  子域总数: {stats.get('subs_total', 0)}")
    lines.append(f"  存活子域: {stats.get('subs_alive', 0)}")
    lines.append(f"  测试端点: {stats.get('endpoints_tested', 0)}")
    lines.append(f"  发现漏洞: {stats.get('vulns_found', 0)}")
    lines.append("")

    vulns = data.get('vulns', [])
    if vulns:
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'info'), 5))

        for i, v in enumerate(vulns, 1):
            lines.append(f"漏洞{i}: {v.get('description', 'N/A')}")
            lines.append(f"  严重性: {v.get('severity', 'unknown').upper()}")
            lines.append(f"  URL: {v.get('url', 'N/A')}")
            lines.append(f"  产品: {v.get('product', 'N/A')}")
            if 'body_preview' in v:
                lines.append(f"  响应预览: {v['body_preview'][:200]}")
            lines.append("")

    report = '\n'.join(lines)
    with open(report_file, 'w') as f:
        f.write(report)

    print(f"[+] Report exported to: {report_file}")
    print(report)


def main():
    parser = argparse.ArgumentParser(description='SRC workspace manager')
    sub = parser.add_subparsers(dest='command')

    # init
    p = sub.add_parser('init', help='Initialize workspace')
    p.add_argument('domain')

    # status
    p = sub.add_parser('status', help='Show workspace status')
    p.add_argument('domain')

    # resume
    p = sub.add_parser('resume', help='Show resume suggestions')
    p.add_argument('domain')

    # update
    p = sub.add_parser('update', help='Update workspace')
    p.add_argument('domain')
    p.add_argument('--phase', help='Set scan phase')

    # add-vuln
    p = sub.add_parser('add-vuln', help='Add vulnerability')
    p.add_argument('domain')
    p.add_argument('--json', required=True, help='Vulnerability JSON')

    # add-note
    p = sub.add_parser('add-note', help='Add note')
    p.add_argument('domain')
    p.add_argument('note')

    # mark-tested
    p = sub.add_parser('mark-tested', help='Mark endpoint as tested')
    p.add_argument('domain')
    p.add_argument('endpoint')

    # list
    sub.add_parser('list', help='List all workspaces')

    # export
    p = sub.add_parser('export', help='Export full report')
    p.add_argument('domain')

    args = parser.parse_args()

    if args.command == 'init':
        init_workspace(args.domain)
    elif args.command == 'status':
        status(args.domain)
    elif args.command == 'resume':
        resume(args.domain)
    elif args.command == 'update':
        update_phase(args.domain, args.phase)
    elif args.command == 'add-vuln':
        add_vuln(args.domain, args.json)
    elif args.command == 'add-note':
        add_note(args.domain, args.note)
    elif args.command == 'mark-tested':
        add_tested_endpoint(args.domain, args.endpoint)
    elif args.command == 'list':
        list_workspaces()
    elif args.command == 'export':
        export_workspace(args.domain)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
