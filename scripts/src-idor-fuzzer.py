#!/usr/bin/env python3
"""
IDOR Fuzzer - IDOR/越权系统化枚举
对比已认证和未认证请求，发现水平/垂直越权

用法:
  src-idor-fuzzer.py <url> --cookie 'session=xxx'           # 带认证态测试
  src-idor-fuzzer.py <url> --cookie 's=xxx' --token 'Bearer xxx'
  src-idor-fuzzer.py <url> --param id --range 1-100         # 枚举ID范围
  src-idor-fuzzer.py <url> --param id --range 1-100 --cookie 's=xxx'
  src-idor-fuzzer.py <url> --file endpoints.txt             # 从文件读取端点

原理:
  1. 用认证态请求获取基准响应
  2. 修改关键参数(userId/id/fileId/orderId等)测试越权
  3. 对比响应差异判断是否越权成功
"""

import argparse
import hashlib
import re
import subprocess
import sys
import urllib.parse


def req(url, method="GET", data=None, cookie=None, token=None, headers=None, timeout=10):
    """Send HTTP request and return (status, headers, body, time)."""
    cmd = f"curl -sk --max-time {timeout} -D /tmp/idor_hdr.txt -o /tmp/idor_body.txt -w '%{{http_code}}|%{{time_total}}|%{{size_download}}' "
    if method == "POST" and data:
        cmd += f"-X POST -d '{data}' "
    if cookie:
        cmd += f"-b '{cookie}' "
    if token:
        cmd += f"-H 'Authorization: {token}' "
    if headers:
        for h in headers:
            cmd += f"-H '{h}' "
    cmd += f"'{url}'"

    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout+5)
        output = r.stdout.strip()
        parts = output.split('|')
        status = parts[0] if parts else ''
        resp_time = float(parts[1]) if len(parts) > 1 else 0
        size = int(float(parts[2])) if len(parts) > 2 else 0

        with open('/tmp/idor_hdr.txt', 'r') as f:
            hdr = f.read()
        with open('/tmp/idor_body.txt', 'r') as f:
            body = f.read()

        return status, hdr, body, size
    except Exception:
        return '', '', '', 0


def detect_id_params(url, method="GET", data=None):
    """Detect ID-like parameters."""
    id_patterns = re.compile(r'(id|uid|userId|user_id|accountId|orderId|fileId|docId|resId|appId|tenantId|orgId|memberId|studentId|no|number|sn|code|token|key)$', re.I)

    params = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for p in qs:
        if id_patterns.search(p):
            params.append((p, qs[p][0]))

    if data:
        post_params = urllib.parse.parse_qs(data)
        for p in post_params:
            if id_patterns.search(p):
                params.append((p, post_params[p][0]))

    return params


def test_idor_param(url, param, original_value, method="GET", data=None, cookie=None, token=None, id_range=None):
    """Test a single parameter for IDOR."""
    results = []

    # Get authenticated baseline
    _, _, auth_body, auth_size = req(url, method, data, cookie, token)
    auth_hash = hashlib.md5(auth_body.encode()).hexdigest()[:16]

    # Determine test values
    test_values = []
    if id_range:
        start, end = id_range.split('-')
        test_values = list(range(int(start), min(int(start) + 20, int(end) + 1)))  # Limit to 20
    else:
        # Try adjacent IDs and common values
        try:
            orig_int = int(original_value)
            test_values = [orig_int + 1, orig_int - 1, orig_int + 2, orig_int - 2,
                          1, 2, 100, 1000, 0, -1]
        except ValueError:
            # Non-numeric ID, try common values
            test_values = ["admin", "test", "1", "0", "null", "undefined"]

    for test_val in test_values:
        # Inject test value
        if method == "GET":
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [str(test_val)]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            test_data = None
        else:
            test_url = url
            params = urllib.parse.parse_qs(data or '', keep_blank_values=True)
            params[param] = [str(test_val)]
            test_data = urllib.parse.urlencode(params, doseq=True)

        # Test without auth
        _, _, noauth_body, noauth_size = req(test_url, method, test_data)
        noauth_hash = hashlib.md5(noauth_body.encode()).hexdigest()[:16]

        # Test with auth (different ID)
        _, _, diffauth_body, diffauth_size = req(test_url, method, test_data, cookie, token)
        diffauth_hash = hashlib.md5(diffauth_body.encode()).hexdigest()[:16]

        # Analysis
        is_different_id = str(test_val) != str(original_value)
        has_data = noauth_size > 100 or diffauth_size > 100
        noauth_differs = noauth_hash != auth_hash
        diffauth_differs = diffauth_hash != auth_hash
        noauth_returns_data = noauth_size > 100 and noauth_hash != hashlib.md5(b'').hexdigest()[:16]
        diffauth_returns_data = diffauth_size > 100 and diffauth_hash != hashlib.md5(b'').hexdigest()[:16]

        # IDOR without auth (most critical)
        if is_different_id and has_data and noauth_returns_data and noauth_differs:
            # Check if response looks like real data (not error)
            if not any(x in noauth_body.lower() for x in ['error', 'unauthorized', 'forbidden', 'not found', '401', '403', 'login']):
                results.append({
                    "type": "IDOR_NOAUTH",
                    "param": param,
                    "original": original_value,
                    "tested": test_val,
                    "status": "VULN",
                    "noauth_size": noauth_size,
                    "diffauth_size": diffauth_size,
                    "severity": "CRITICAL",
                    "desc": f"无需认证即可访问 {param}={test_val} 的数据({noauth_size}B)"
                })

        # IDOR with auth (horizontal privilege escalation)
        elif is_different_id and has_data and diffauth_returns_data:
            if not any(x in diffauth_body.lower() for x in ['error', 'unauthorized', 'forbidden', 'not found', '401', '403']):
                results.append({
                    "type": "IDOR_AUTH",
                    "param": param,
                    "original": original_value,
                    "tested": test_val,
                    "status": "VULN",
                    "auth_size": diffauth_size,
                    "severity": "HIGH",
                    "desc": f"认证用户可访问 {param}={test_val} 的数据({diffauth_size}B)"
                })

    return results


def test_horizontal_escalation(url, param, original_value, method="GET", data=None,
                                cookie_a=None, cookie_b=None, token_a=None, token_b=None):
    """Test horizontal privilege escalation between two accounts."""
    results = []

    # Account A requests its own resource
    _, _, body_a, size_a = req(url, method, data, cookie_a, token_a)
    hash_a = hashlib.md5(body_a.encode()).hexdigest()[:16]

    # Account B requests Account A's resource
    _, _, body_b, size_b = req(url, method, data, cookie_b, token_b)
    hash_b = hashlib.md5(body_b.encode()).hexdigest()[:16]

    if hash_a == hash_b and size_a > 100:
        results.append({
            "type": "HORIZONTAL_ESCALATION",
            "param": param,
            "severity": "CRITICAL",
            "desc": f"账号B可访问账号A的数据({size_a}B)",
            "evidence_size_a": size_a,
            "evidence_size_b": size_b,
        })

    return results


def main():
    parser = argparse.ArgumentParser(description="IDOR Fuzzer - IDOR/越权系统化枚举")
    parser.add_argument("url", help="目标URL (含参数)")
    parser.add_argument("--param", "-p", help="指定ID参数")
    parser.add_argument("--range", "-r", help="ID范围(如 1-100)")
    parser.add_argument("--method", "-m", default="GET", help="HTTP方法")
    parser.add_argument("--data", "-d", help="POST数据")
    parser.add_argument("--cookie", "-c", help="认证Cookie")
    parser.add_argument("--token", "-t", help="认证Token(Bearer)")
    parser.add_argument("--file", "-f", help="端点列表文件")
    parser.add_argument("--cookie-b", help="第二个账号Cookie(水平越权测试)")
    parser.add_argument("--token-b", help="第二个账号Token")
    args = parser.parse_args()

    url = args.url
    method = args.method.upper()
    data = args.data

    print("[*] IDOR Fuzzer")
    print(f"[*] 目标: {url}")
    print()

    # Detect ID parameters
    if args.param:
        # Get current value from URL/data
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        orig_val = qs.get(args.param, ['1'])[0]
        id_params = [(args.param, orig_val)]
    else:
        id_params = detect_id_params(url, method, data)
        if not id_params:
            print("[!] 未发现ID类参数，请用 --param 指定")
            print("[*] 常见ID参数: id, userId, fileId, orderId, docId, studentId, appId")
            sys.exit(1)
        print(f"[*] 自动检测到ID参数: {', '.join(p for p, v in id_params)}")

    all_findings = []

    for param, orig_value in id_params:
        print(f"\n[*] 测试参数: {param} (当前值: {orig_value})")

        # IDOR enumeration
        findings = test_idor_param(url, param, orig_value, method, data,
                                    args.cookie, args.token, args.range)

        if findings:
            for f in findings:
                print(f"  [!] {f['type']}: {f['desc']}")
                all_findings.extend(findings)
        else:
            print("  [-] 未检测到IDOR")

        # Horizontal escalation (if two accounts provided)
        if args.cookie_b or args.token_b:
            print("  [水平越权测试]...")
            findings = test_horizontal_escalation(url, param, orig_value, method, data,
                                                    args.cookie, args.cookie_b,
                                                    args.token, args.token_b)
            if findings:
                for f in findings:
                    print(f"  [!] {f['type']}: {f['desc']}")
                    all_findings.extend(findings)
            else:
                print("  [-] 未检测到水平越权")

    # Summary
    print()
    print("=" * 60)
    if all_findings:
        print(f"[!] 发现 {len(all_findings)} 个越权漏洞!")
        for f in all_findings:
            print(f"\n  类型: {f['type']}")
            print(f"  参数: {f['param']}")
            print(f"  严重程度: {f['severity']}")
            print(f"  描述: {f['desc']}")
    else:
        print("[*] 未检测到IDOR/越权")
        print("[*] 建议:")
        print("  1. 使用 --cookie 带认证态测试")
        print("  2. 使用 --range 指定ID枚举范围")
        print("  3. 使用 --cookie-b 水平越权双账号测试")
    print("=" * 60)


if __name__ == "__main__":
    main()
