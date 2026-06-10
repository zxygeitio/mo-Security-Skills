#!/usr/bin/env python3
"""
SRC Batch CORS Test - 批量CORS/API测试
自动从JS提取API端点，批量测CORS和认证绕过

用法:
  src-cors-batch-test.py <url>
  src-cors-batch-test.py <url> --js <js_url>   # 指定JS文件
  src-cors-batch-test.py <url> --endpoints <file>  # 从文件读取端点

输出:
  cors_results.txt - CORS测试结果
  auth_results.txt - 认证绕过测试结果
"""

import argparse
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def extract_endpoints_from_js(base_url, js_urls=None):
    """Extract API endpoints from JS files."""
    endpoints = set()

    # Default: try to find JS files from the page
    if not js_urls:
        page = run_cmd(f"curl -sk --max-time 10 '{base_url}/' 2>/dev/null", timeout=15)
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', page)
        js_urls = [u if u.startswith('http') else f"{base_url.rstrip('/')}/{u.lstrip('/')}" for u in js_urls]

    for js_url in js_urls[:10]:  # Limit to 10 JS files
        js_content = run_cmd(f"curl -sk --max-time 10 '{js_url}' 2>/dev/null", timeout=15)

        # Extract API paths
        patterns = [
            r'["\']/(api|v[123]|rest|service|graphql|auth|user|admin|upload|download|search|login|register|captcha)[/\w\-\.]*["\']',
            r'["\'](/[a-zA-Z]+/[a-zA-Z]+(?:/[a-zA-Z]+)*)["\']',
            r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
            r'API_BASE\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pat in patterns:
            matches = re.findall(pat, js_content, re.I)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                if len(m) > 3 and len(m) < 200:
                    endpoints.add(m)

    return list(endpoints)


def test_cors(url, endpoint, origins=None):
    """Test CORS on a single endpoint."""
    if not origins:
        origins = ["https://evil.com", "https://attacker.com", "null"]

    results = []
    full_url = f"{url.rstrip('/')}{endpoint}" if endpoint.startswith('/') else endpoint

    for origin in origins:
        r = run_cmd(f"curl -sk --max-time 8 -D- '{full_url}' -H 'Origin: {origin}' 2>/dev/null", timeout=12)

        acao = ""
        acac = ""
        aceh = ""
        status = ""

        for line in r.split('\n'):
            line_lower = line.lower().strip()
            if line_lower.startswith('access-control-allow-origin'):
                acao = line.split(':', 1)[1].strip()
            elif line_lower.startswith('access-control-allow-credentials'):
                acac = line.split(':', 1)[1].strip()
            elif line_lower.startswith('access-control-expose-headers'):
                aceh = line.split(':', 1)[1].strip()
            elif line_lower.startswith('http/'):
                status = line.strip()

        if acao:
            vuln = False
            severity = ""

            if acao == origin and acac.lower() == "true":
                vuln = True
                severity = "HIGH"
            elif acao == "*":
                vuln = True
                severity = "MEDIUM"
            elif acao == origin:
                vuln = True
                severity = "MEDIUM"

            results.append({
                "endpoint": endpoint,
                "origin": origin,
                "acao": acao,
                "acac": acac,
                "aceh": aceh,
                "status": status,
                "vuln": vuln,
                "severity": severity,
            })

    return results


def test_auth_bypass(url, endpoint):
    """Test if endpoint requires authentication."""
    full_url = f"{url.rstrip('/')}{endpoint}" if endpoint.startswith('/') else endpoint

    # Test without any auth
    r = run_cmd(f"curl -sk --max-time 8 -D- '{full_url}' 2>/dev/null", timeout=12)

    status = ""
    body = ""
    for i, line in enumerate(r.split('\n')):
        if line.lower().startswith('http/'):
            status = line.strip()
        if i > 5:  # Skip headers
            body += line

    # Determine if endpoint is open
    is_open = False
    if "200" in status and len(body.strip()) > 50:
        # Check if it's not a login redirect or error
        body_lower = body.lower()
        if not any(x in body_lower for x in ['login', 'unauthorized', 'token失效', '未授权', '401', '403']):
            is_open = True

    return {
        "endpoint": endpoint,
        "status": status,
        "body_len": len(body.strip()),
        "is_open": is_open,
    }


def main():
    parser = argparse.ArgumentParser(description="SRC Batch CORS Test")
    parser.add_argument("url", help="目标URL (如 https://target.com)")
    parser.add_argument("--js", nargs="*", help="JS文件URL列表")
    parser.add_argument("--endpoints", help="端点列表文件(每行一个)")
    parser.add_argument("--origins", nargs="*", default=["https://evil.com", "https://attacker.com", "null"],
                        help="测试的Origin列表")
    parser.add_argument("--auth", action="store_true", help="同时测试认证绕过")
    args = parser.parse_args()

    url = args.url.rstrip('/')

    # Get endpoints
    if args.endpoints:
        with open(args.endpoints) as f:
            endpoints = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        print("[*] 从JS提取API端点...")
        endpoints = extract_endpoints_from_js(url, args.js)
        print(f"    发现 {len(endpoints)} 个端点")

    if not endpoints:
        print("[!] 未发现API端点")
        sys.exit(1)

    # Test CORS
    print(f"[*] 批量CORS测试 ({len(endpoints)} 端点 × {len(args.origins)} Origin)...")
    cors_vulns = []
    all_cors = []

    def batch_cors(ep):
        return test_cors(url, ep, args.origins)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(batch_cors, ep): ep for ep in endpoints}
        for f in as_completed(futures):
            results = f.result()
            all_cors.extend(results)
            for r in results:
                if r['vuln']:
                    cors_vulns.append(r)

    # Test auth bypass
    auth_vulns = []
    if args.auth:
        print("[*] 批量认证绕过测试...")
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(test_auth_bypass, url, ep): ep for ep in endpoints}
            for f in as_completed(futures):
                result = f.result()
                if result['is_open']:
                    auth_vulns.append(result)

    # Output results
    print()
    print("=" * 60)

    if cors_vulns:
        print(f"\n[!] CORS漏洞: {len(cors_vulns)} 个")
        for v in cors_vulns:
            print(f"  [{v['severity']}] {v['endpoint']}")
            print(f"       Origin: {v['origin']} → ACAO: {v['acao']}, ACAC: {v['acac']}")
    else:
        print("\n[*] 未发现CORS漏洞")

    if auth_vulns:
        print(f"\n[!] 可能未授权端点: {len(auth_vulns)} 个")
        for v in auth_vulns:
            print(f"  {v['endpoint']} → {v['status']} ({v['body_len']}B)")
    elif args.auth:
        print("\n[*] 未发现未授权端点")

    print()
    print("=" * 60)

    # Save results
    outdir = f"/tmp/cors_test_{url.replace('https://','').replace('http://','').replace('/','_')}"
    os.makedirs(outdir, exist_ok=True)

    with open(f"{outdir}/cors_results.txt", 'w') as f:
        for r in all_cors:
            f.write(f"{r['endpoint']} | {r['origin']} | ACAO={r['acao']} | ACAC={r['acac']} | {'VULN' if r['vuln'] else 'OK'}\n")

    if auth_vulns:
        with open(f"{outdir}/auth_results.txt", 'w') as f:
            for v in auth_vulns:
                f.write(f"{v['endpoint']} | {v['status']} | {v['body_len']}B\n")

    print(f"[*] 结果保存: {outdir}/")


if __name__ == "__main__":
    main()
