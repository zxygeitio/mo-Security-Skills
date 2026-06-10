#!/usr/bin/python3
"""
edu-batch-probe.py - 批量子域探测脚本
解决CERNET/慢网络下串行curl超时问题

用法:
  python3 edu-batch-probe.py subs.txt                    # 默认: 4秒超时, 20并发, 分批
  python3 edu-batch-probe.py subs.txt --timeout 6        # 6秒超时
  python3 edu-batch-probe.py subs.txt --batch 30 --dns   # DNS预过滤 + 30并发
  python3 edu-batch-probe.py subs.txt -o alive.txt       # 输出到文件
  python3 edu-batch-probe.py subs.txt --fingerprint      # 同时做指纹识别

输出格式: CODE SIZE PROTO://DOMAIN [REDIRECT] [TECH]
"""

import subprocess
import sys
import time
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def dns_filter(subs, timeout=2, workers=10):
    """DNS预过滤: 只保留能解析的域名(并行)"""
    alive = []

    def check_dns(sub):
        try:
            r = subprocess.run(
                ['dig', '+short', sub, 'A'],
                capture_output=True, text=True, timeout=timeout + 1
            )
            if r.stdout.strip():
                ip = r.stdout.strip().split('\n')[0]
                return (sub, ip)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_dns, s): s for s in subs}
        for f in as_completed(futures):
            r = f.result()
            if r:
                alive.append(r)

    return alive


def probe(sub, timeout=4, fingerprint=False):
    """HTTP探活: 返回(code, size, proto, redirect, tech)"""
    for proto in ['https', 'http']:
        try:
            cmd = [
                'curl', '-sk', '--max-time', str(timeout),
                '-D', '/dev/stderr',
                '-o', '/dev/null',
                '-w', '%{http_code}|%{size_download}|%{redirect_url}',
                f'{proto}://{sub}/'
            ]
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 2
            )
            parts = r.stdout.strip().split('|')
            code = parts[0] if parts else '000'
            if code in ('', '000'):
                continue

            size = parts[1] if len(parts) > 1 else '0'
            redir = parts[2] if len(parts) > 2 else ''

            tech = ''
            if fingerprint:
                headers = r.stderr
                tech = extract_tech(headers, sub)

            return (sub, proto, code, size, redir, tech)
        except Exception:
            pass
    return None


def extract_tech(headers, sub):
    """从响应头提取技术栈"""
    techs = []
    h = headers.lower()

    # Server
    for line in h.split('\n'):
        if 'server:' in line:
            srv = line.split('server:')[1].strip()
            if srv and srv != '*********' and srv != 'server':
                techs.append(f'S:{srv}')
        if 'x-powered-by:' in line:
            xpb = line.split('x-powered-by:')[1].strip()
            techs.append(f'XPB:{xpb}')

    # Cookie指纹
    if 'jsessionid' in h:
        techs.append('Java')
    if 'phpsessid' in h:
        techs.append('PHP')
    if 'asp.net' in h:
        techs.append('ASP.NET')
    if 'route=' in h:
        techs.append('CAS-Route')

    # 特定产品
    if 'seeyon' in h or 'V10_' in h:
        techs.append('SeeyonOA')
    if 'authserver' in h:
        techs.append('CAS')
    if 'webvpn' in sub:
        techs.append('WebVPN')

    return '|'.join(techs) if techs else ''


def probe_with_headers(sub, timeout=4):
    """带完整响应头的探活"""
    for proto in ['https', 'http']:
        try:
            cmd = [
                'curl', '-sk', '--max-time', str(timeout),
                '-i',  # include headers in output
                '-o', '/dev/null',
                '-w', '\n__STATUS__%{http_code}|%{size_download}|%{redirect_url}',
                f'{proto}://{sub}/'
            ]
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 2
            )
            output = r.stdout
            status_marker = output.rfind('__STATUS__')
            if status_marker == -1:
                continue

            headers_part = output[:status_marker]
            status_part = output[status_marker + 10:]
            parts = status_part.strip().split('|')
            code = parts[0] if parts else '000'
            if code in ('', '000'):
                continue

            size = parts[1] if len(parts) > 1 else '0'
            redir = parts[2] if len(parts) > 2 else ''
            tech = extract_tech(headers_part, sub)

            return (sub, proto, code, size, redir, tech, headers_part)
        except Exception:
            pass
    return None


def main():
    parser = argparse.ArgumentParser(description='Batch subdomain probe')
    parser.add_argument('subs_file', help='Subdomain list file')
    parser.add_argument('--timeout', type=int, default=4, help='Per-request timeout (default: 4)')
    parser.add_argument('--batch', type=int, default=20, help='Concurrent batch size (default: 20)')
    parser.add_argument('--dns', action='store_true', help='DNS pre-filter')
    parser.add_argument('--dns-timeout', type=int, default=2, help='DNS timeout (default: 2)')
    parser.add_argument('--fingerprint', '-f', action='store_true', help='Extract tech stack')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--filter-code', default='200,301,302,403',
                        help='Show only these status codes (comma-separated)')
    parser.add_argument('--min-size', type=int, default=0,
                        help='Min response size in bytes')
    args = parser.parse_args()

    # 读取子域列表
    with open(args.subs_file) as f:
        subs = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    
    print(f"[*] Loaded {len(subs)} subdomains")

    # DNS预过滤
    if args.dns:
        print(f"[*] DNS filtering (timeout={args.dns_timeout}s)...")
        t0 = time.time()
        dns_alive = dns_filter(subs, args.dns_timeout)
        print(f"[+] {len(dns_alive)}/{len(subs)} DNS alive ({time.time()-t0:.1f}s)")
        subs = [s for s, ip in dns_alive]

    # 批量HTTP探活
    print(f"[*] HTTP probing (timeout={args.timeout}s, batch={args.batch})...")
    t0 = time.time()
    results = []
    total = len(subs)

    for i in range(0, total, args.batch):
        batch = subs[i:i + args.batch]
        batch_num = i // args.batch + 1
        total_batches = (total + args.batch - 1) // args.batch

        with ThreadPoolExecutor(max_workers=args.batch) as ex:
            futures = {
                ex.submit(probe, s, args.timeout, args.fingerprint): s
                for s in batch
            }
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)

        done = min(i + args.batch, total)
        sys.stderr.write(f"\r[*] Progress: {done}/{total} ({batch_num}/{total_batches} batches)")
        sys.stderr.flush()

    elapsed = time.time() - t0
    print(f"\n[+] {len(results)}/{total} alive ({elapsed:.1f}s)")

    # 过滤
    allowed_codes = set(args.filter_code.split(','))
    filtered = [
        r for r in results
        if r[2] in allowed_codes and int(r[3]) >= args.min_size
    ]

    # 输出
    output_lines = []
    for sub, proto, code, size, redir, tech in sorted(filtered, key=lambda x: x[2]):
        line = f"{code} {size:>8}B {proto}://{sub}"
        if redir:
            line += f" -> {redir}"
        if tech:
            line += f" [{tech}]"
        output_lines.append(line)
        print(line)

    # 写入文件
    if args.output:
        with open(args.output, 'w') as f:
            if args.json:
                json.dump([{
                    'subdomain': r[0], 'proto': r[1], 'code': r[2],
                    'size': r[3], 'redirect': r[4], 'tech': r[5]
                } for r in filtered], f, indent=2, ensure_ascii=False)
            else:
                f.write('\n'.join(output_lines) + '\n')
        print(f"[+] Results written to {args.output}")

    # 统计
    codes = {}
    for r in filtered:
        codes[r[2]] = codes.get(r[2], 0) + 1
    print("\n[*] Status code distribution:")
    for code in sorted(codes.keys()):
        print(f"    {code}: {codes[code]}")


if __name__ == '__main__':
    main()
