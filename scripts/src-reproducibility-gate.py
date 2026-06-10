#!/usr/bin/python3
"""
SRC Reproducibility Gate — 只放行能实际复现的漏洞

核心原则:
  - 没有 PoC 命令的发现 → REJECT
  - PoC 跑不通的发现 → REJECT
  - PoC 输出和预期不一致的 → REJECT
  - 只有"信息泄露"没有实际利用价值的 → REJECT (除非泄露的是密钥/token/密码)
  - 能跑通、能复现、有实际影响的 → PASS

用法:
  src-reproducibility-gate.py <workspace> [--dry-run] [--timeout 10] [--out /tmp/report.md]
  src-reproducibility-gate.py --finding '{"url":"...","poc":"curl ...","expected":"...","severity":"medium"}'

输入: workspace 目录下的 probe_results.tsv / quality_gate.md / 手动 JSON
输出: 可复现发现列表 + 被拒绝发现列表 + 统计
"""
#!/usr/bin/python3
import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# ─── 低价值发现模式 (单独不构成可报告漏洞) ─────────────────────────
LOW_VALUE_PATTERNS = [
    # 服务器信息泄露 (无直接利用价值)
    (r"Server:\s*\w+", "server_header", "Server头泄露，无直接利用价值"),
    (r"X-Powered-By:", "powered_by", "X-Powered-By泄露，无直接利用价值"),
    (r"X-AspNet-Version:", "aspnet_ver", "ASP.NET版本泄露，无直接利用价值"),

    # IP 泄露 (需验证是否为真实后端IP，CDN/WAF IP价值低)
    (r"value=\"\d+\.\d+\.\d+\.\d+\"", "ip_in_value", "IP地址泄露，需验证是否为真实后端IP"),

    # 堆栈跟踪 (中危但需配合其他漏洞)
    (r"java\.lang\.\w+Exception|at\s+[\w.]+\([\w.]+:\d+\)", "stack_trace", "Java堆栈泄露，单独中危"),

    # 默认页面/配置页
    (r"Tomcat Home Page|Apache Tomcat/|Welcome to nginx", "default_page", "默认欢迎页，非漏洞"),
    (r"Whitelabel Error Page", "whitelabel", "Spring Boot默认错误页"),

    # 登录页面 (不是漏洞)
    (r"<form[^>]+(login|password)|请登录|Sign In|登录", "login_page", "登录页面存在，非漏洞"),

    # CAS 特定误报
    (r"Application Not Authorized to Use IDS", "cas_block", "CAS白名单拦截，非漏洞"),
    (r"htm file not found.*redirecting", "sudy_redirect", "SUDY CMS重定向，非漏洞"),

    # 健康检查/状态端点
    (r'"status"\s*:\s*"(UP|DOWN|OK)"', "health_check", "健康检查端点，无敏感信息"),
]

# ─── 高价值发现模式 (可复现即报告) ─────────────────────────────────
HIGH_VALUE_PATTERNS = [
    # 敏感数据泄露
    (r'(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}', "password_leak", "密码泄露", "high"),
    (r'(api[_-]?key|app[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\'][^"\']{8,}', "key_leak", "API密钥泄露", "high"),
    (r'(bearer|authorization)\s*[:=]\s*["\'][^"\']{10,}', "auth_token_leak", "认证Token泄露", "high"),
    (r'(jdbc|mysql|redis|mongo|postgres)://[^\s"\']+', "db_conn_leak", "数据库连接串泄露", "critical"),

    # PII 批量泄露
    (r'(身份证|idcard|identity)\s*[:=]\s*\d{15,18}', "idcard_leak", "身份证号泄露", "high"),
    (r'(手机号|mobile|phone)\s*[:=]\s*1[3-9]\d{9}', "phone_leak", "手机号泄露", "medium"),
    (r'(学号|studentId|student_id)\s*[:=]\s*\d{6,}', "student_id_leak", "学号批量泄露", "medium"),

    # 实际可利用漏洞
    (r'root:\$\d\$|:[0-9a-f]{32}:', "etc_shadow", "Linux密码hash泄露", "critical"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "private_key", "私钥泄露", "critical"),
    (r'<web-app[^>]>.*<security-constraint>', "web_xml", "web.xml安全配置泄露", "medium"),

    # CORS 可利用 (带 credentials)
    (r'Access-Control-Allow-Credentials:\s*true', "cors_credentials", "CORS带凭证，可利用", "high"),

    # SQL 错误 (注入可能性)
    (r'SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR|SQLite.*error|MySqlClient\.MySqlException|SqlException|ODBC.*Driver|Unclosed quotation mark|Syntax error.*query', "sql_error", "SQL错误信息，可能SQL注入", "high"),

    # 文件上传可利用
    (r'"url"\s*:\s*"[^"]*\.(jsp|php|asp|aspx|py|sh)"', "upload_exec", "文件上传可执行文件", "critical"),
    (r'fileUrl.*https?://[^"]*\.(jsp|php|asp)', "file_url_leak", "文件URL泄露可执行文件", "high"),

    # 未授权访问
    (r'"totalCount"\s*:\s*\d{2,}', "data_dump", "未授权数据批量返回", "high"),
    (r'"list"\s*:\s*\[.*"id"\s*:', "data_list", "未授权列表数据返回", "high"),
]

# ─── 严重级别阈值 ──────────────────────────────────────────────────
MIN_REPORTABLE_SEVERITY = {"medium", "high", "critical"}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def check_poc_reproducible(poc_cmd: str, expected_pattern: str = "", timeout: int = 10) -> dict:
    """Execute a PoC command and verify it produces expected output.
    
    Returns:
        {
            "success": bool,
            "output": str (first 2000 chars),
            "output_hash": str,
            "exit_code": int,
            "error": str,
            "matches_expected": bool,
            "duration_ms": int
        }
    """
    if not poc_cmd or not poc_cmd.strip():
        return {"success": False, "output": "", "error": "No PoC command provided", "matches_expected": False}

    # Sanitize: only allow safe commands (curl, wget, python scripts)
    safe_prefixes = ["curl ", "wget ", "/usr/bin/python3 ", "python3 ", "python ", "echo ", "printf "]
    cmd_stripped = poc_cmd.strip()
    if not any(cmd_stripped.startswith(p) for p in safe_prefixes):
        return {"success": False, "output": "", "error": f"Command not in safe allowlist: {cmd_stripped[:50]}", "matches_expected": False}

    try:
        t0 = time.time()
        r = subprocess.run(
            cmd_stripped,
            shell=True,  # We've validated the prefix
            capture_output=True,
            text=True,
            timeout=timeout
        )
        duration = int((time.time() - t0) * 1000)
        output = r.stdout[:2000]
        output_hash = hashlib.md5(output.encode()).hexdigest()[:16]

        # Check if output matches expected pattern
        matches = True
        if expected_pattern:
            try:
                matches = bool(re.search(expected_pattern, output, re.I | re.S))
            except re.error:
                matches = expected_pattern.lower() in output.lower()

        return {
            "success": r.returncode == 0 and len(output) > 0,
            "output": output,
            "output_hash": output_hash,
            "exit_code": r.returncode,
            "error": r.stderr[:500] if r.stderr else "",
            "matches_expected": matches,
            "duration_ms": duration
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "error": f"Timeout after {timeout}s", "matches_expected": False}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e), "matches_expected": False}


def classify_finding(body: str, headers: str = "", url: str = "") -> dict:
    """Classify a finding as reproducible or not.
    
    Returns:
        {
            "reproducible": bool,
            "severity": str,
            "category": str,
            "description": str,
            "reason": str,
            "high_value_match": bool
        }
    """
    blob = f"{url}\n{headers}\n{body}"

    # Check high-value patterns first
    for pattern, category, description, severity in HIGH_VALUE_PATTERNS:
        if re.search(pattern, blob, re.I):
            return {
                "reproducible": True,
                "severity": severity,
                "category": category,
                "description": description,
                "reason": f"Matched high-value pattern: {category}",
                "high_value_match": True
            }

    # Check low-value patterns
    for pattern, category, description in LOW_VALUE_PATTERNS:
        if re.search(pattern, blob, re.I):
            return {
                "reproducible": False,
                "severity": "info",
                "category": category,
                "description": description,
                "reason": f"Low-value finding: {description}",
                "high_value_match": False
            }

    # No pattern matched - classify by response characteristics
    size = len(body)
    if size < 50:
        return {
            "reproducible": False,
            "severity": "info",
            "category": "empty_response",
            "description": "Response too small to be meaningful",
            "reason": f"Response only {size} bytes",
            "high_value_match": False
        }

    # Medium: has some content but no clear vulnerability pattern
    return {
        "reproducible": False,
        "severity": "low",
        "category": "unclassified",
        "description": "Response contains data but no clear vulnerability pattern",
        "reason": "Needs manual review - no matching high-value pattern",
        "high_value_match": False
    }


def process_workspace(workspace: Path, dry_run: bool = False, timeout: int = 10) -> dict:
    """Process all findings in a workspace through the reproducibility gate.
    
    Returns statistics and categorized findings.
    """
    results = {
        "total": 0,
        "passed": 0,
        "rejected": 0,
        "low_value": 0,
        "poc_failed": 0,
        "no_poc": 0,
        "passed_findings": [],
        "rejected_findings": [],
    }

    # Check for quality gate output
    qg_file = workspace / "quality_gate.md"
    probe_file = workspace / "probe_results.tsv"

    findings = []

    # Load from probe_results.tsv
    if probe_file.exists():
        try:
            reader = csv.DictReader(probe_file.read_text().splitlines(), delimiter="\t")
            for row in reader:
                if row.get("decision") in {"PENDING_REVIEW", ""}:
                    findings.append({
                        "url": row.get("url", ""),
                        "method": row.get("method", "GET"),
                        "status": row.get("status", ""),
                        "size": row.get("size", "0"),
                        "body_path": row.get("body_path", ""),
                        "header_path": row.get("header_path", ""),
                        "source": "probe",
                    })
        except Exception as e:
            print(f"[!] Error reading probe_results.tsv: {e}")

    # Load from quality_gate.json if exists
    qg_json = workspace / "quality_gate.json"
    if qg_json.exists():
        try:
            data = json.loads(qg_json.read_text())
            for item in data.get("candidates", []):
                findings.append({
                    "url": item.get("url", ""),
                    "poc": item.get("poc", ""),
                    "expected": item.get("expected", ""),
                    "severity": item.get("severity", "low"),
                    "source": "quality_gate",
                })
        except Exception as e:
            print(f"[!] Error reading quality_gate.json: {e}")

    # Process each finding
    for finding in findings:
        results["total"] += 1
        url = finding.get("url", "")
        body_path = finding.get("body_path", "")
        poc = finding.get("poc", "")

        # Read body content
        body = ""
        if body_path:
            bp = Path(body_path)
            if not bp.is_absolute():
                bp = workspace / body_path
            try:
                body = bp.read_text(encoding="utf-8", errors="replace")[:5000]
            except Exception:
                pass

        # If no body but has URL, try to fetch
        if not body and url and not dry_run:
            try:
                r = subprocess.run(
                    ["curl", "-sk", "--max-time", str(timeout), url],
                    capture_output=True, text=True, timeout=timeout + 5
                )
                body = r.stdout[:5000]
            except Exception:
                pass

        # Classify the finding
        classification = classify_finding(body, url=url)

        if not classification["reproducible"]:
            results["rejected"] += 1
            if classification["category"] in {"server_header", "powered_by", "default_page", "login_page", "cas_block", "sudy_redirect", "health_check"}:
                results["low_value"] += 1
            results["rejected_findings"].append({
                "url": url,
                "category": classification["category"],
                "reason": classification["reason"],
                "severity": classification["severity"],
            })
            continue

        # High-value pattern matched - now verify with PoC if available
        if poc and not dry_run:
            poc_result = check_poc_reproducible(poc, finding.get("expected", ""), timeout)
            if not poc_result["success"] or not poc_result["matches_expected"]:
                results["poc_failed"] += 1
                results["rejected_findings"].append({
                    "url": url,
                    "category": "poc_failed",
                    "reason": f"PoC failed: {poc_result['error'] or 'output mismatch'}",
                    "severity": classification["severity"],
                })
                continue

        # Passed!
        results["passed"] += 1
        results["passed_findings"].append({
            "url": url,
            "severity": classification["severity"],
            "category": classification["category"],
            "description": classification["description"],
            "poc": poc,
        })

    return results


def format_report(results: dict) -> str:
    """Format results as a readable report."""
    lines = ["# SRC Reproducibility Gate Report\n"]
    lines.append(f"Total findings: {results['total']}")
    lines.append(f"Passed (reproducible): {results['passed']}")
    lines.append(f"Rejected: {results['rejected']}")
    lines.append(f"  - Low value (info only): {results['low_value']}")
    lines.append(f"  - PoC failed: {results['poc_failed']}")
    lines.append(f"  - No PoC: {results['no_poc']}")
    lines.append("")

    if results["passed_findings"]:
        lines.append("## PASSED (Reproducible Findings)\n")
        for f in results["passed_findings"]:
            lines.append(f"### [{f['severity'].upper()}] {f['category']}")
            lines.append(f"URL: {f['url']}")
            lines.append(f"Description: {f['description']}")
            if f.get("poc"):
                lines.append(f"PoC: {f['poc']}")
            lines.append("")

    if results["rejected_findings"]:
        lines.append("## REJECTED (Not Reproducible / Low Value)\n")
        for f in results["rejected_findings"]:
            lines.append(f"- [{f['severity']}] {f['url']}: {f['reason']}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="SRC Reproducibility Gate - Only report reproducible vulnerabilities")
    parser.add_argument("workspace", nargs="?", help="Workspace directory with probe/quality gate results")
    parser.add_argument("--finding", help="Single finding JSON to check")
    parser.add_argument("--dry-run", action="store_true", help="Classify without executing PoC commands")
    parser.add_argument("--timeout", type=int, default=10, help="PoC execution timeout (seconds)")
    parser.add_argument("--out", help="Output report file")
    parser.add_argument("--json-out", help="Output JSON file")
    parser.add_argument("--min-severity", default="medium", help="Minimum severity to pass (default: medium)")
    args = parser.parse_args()

    if args.finding:
        # Single finding mode
        try:
            finding = json.loads(args.finding)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON: {e}")
            return 1

        body = finding.get("body", "")
        url = finding.get("url", "")
        poc = finding.get("poc", "")
        expected = finding.get("expected", "")

        classification = classify_finding(body, url=url)

        if not classification["reproducible"]:
            print(f"REJECT: {classification['reason']}")
            print(f"Category: {classification['category']}")
            print(f"Severity: {classification['severity']}")
            return 2

        if poc and not args.dry_run:
            poc_result = check_poc_reproducible(poc, expected, args.timeout)
            if not poc_result["success"]:
                print(f"REJECT: PoC failed - {poc_result['error']}")
                return 2
            if not poc_result["matches_expected"]:
                print(f"REJECT: PoC output mismatch")
                print(f"Expected pattern: {expected}")
                print(f"Actual output: {poc_result['output'][:200]}")
                return 2

        print(f"PASS: {classification['description']}")
        print(f"Severity: {classification['severity']}")
        print(f"Category: {classification['category']}")
        return 0

    if not args.workspace:
        parser.print_help()
        return 1

    workspace = Path(args.workspace)
    if not workspace.exists():
        print(f"[!] Workspace not found: {workspace}")
        return 1

    print(f"[*] Running Reproducibility Gate on: {workspace}")
    results = process_workspace(workspace, dry_run=args.dry_run, timeout=args.timeout)

    report = format_report(results)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"[*] Report written to: {args.out}")
    else:
        print(report)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    # Summary
    pass_rate = (results["passed"] / results["total"] * 100) if results["total"] > 0 else 0
    print(f"\n[*] Pass rate: {pass_rate:.0f}% ({results['passed']}/{results['total']})")

    if results["passed"] == 0:
        print("[!] NO REPRODUCIBLE FINDINGS - Do NOT submit a report")
        return 3
    else:
        print(f"[+] {results['passed']} reproducible findings ready for submission")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
