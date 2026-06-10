#!/usr/bin/env python3
"""
Exploit-DB Fingerprint Pipeline
================================
从 nmap/nuclei/whatweb/httpx 输出自动提取指纹，匹配 exploit-db exploit，
生成攻击命令。与现有 pentest-control-plane 和 src-vuln-hunting 联动。

用法:
  # 从 nmap XML 自动匹配
  edb-pipeline.py --nmap /tmp/scan.xml --target 192.168.1.1

  # 从手动指纹匹配
  edb-pipeline.py --product nginx --version 1.20.1 --port 80 --target 10.0.0.1

  # 从 nuclei JSON 结果匹配
  edb-pipeline.py --nuclei /tmp/nuclei_output.jsonl --target 10.0.0.1

  # 批量 CSV 输入
  edb-pipeline.py --csv /tmp/fingerprints.csv --output /tmp/exploit_report.txt

  # 与 src-fast-assess 联动
  edb-pipeline.py --fast-assess example.com
"""

import csv
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# 引入引擎
sys.path.insert(0, str(Path(__file__).parent))
from exploitdb_engine import ExploitDBEngine


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """解析 nmap XML 提取指纹"""
    import xml.etree.ElementTree as ET
    tree = ET.parse(xml_path)
    root = tree.getroot()
    fingerprints = []

    for host in root.findall(".//host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr", "")

        for port_el in host.findall(".//port"):
            portid = port_el.get("portid", "0")
            state = port_el.find("state")
            if state is not None and state.get("state") != "open":
                continue

            svc = port_el.find("service")
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            service = svc.get("name", "") if svc is not None else ""

            fingerprints.append({
                "host": ip,
                "port": int(portid),
                "product": product,
                "version": version,
                "service": service,
                "cves": [],
            })
    return fingerprints


def parse_nuclei_jsonl(jsonl_path: str) -> list[dict]:
    """解析 nuclei JSONL 输出提取 CVE"""
    fingerprints = []
    seen = set()

    with open(jsonl_path, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
            except Exception:
                continue

            template_id = entry.get("template-id", "")
            matched_at = entry.get("matched-at", "")
            info = entry.get("info", {})
            name = info.get("name", "")
            cve_tags = [t for t in info.get("tags", []) if t.startswith("cve-")]

            # 提取 CVE
            cves = []
            for tag in cve_tags:
                cve = "CVE-" + tag.upper().replace("CVE-", "")
                if cve not in seen:
                    cves.append(cve)
                    seen.add(cve)

            if cves:
                fingerprints.append({
                    "product": name,
                    "version": "",
                    "port": 0,
                    "service": "http",
                    "cves": cves,
                    "template_id": template_id,
                    "matched_at": matched_at,
                })
    return fingerprints


def parse_csv_input(csv_path: str) -> list[dict]:
    """解析 CSV 输入: host,product,port,service"""
    fingerprints = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fingerprints.append({
                "host": row.get("host", ""),
                "port": int(row.get("port", 0)),
                "product": row.get("product", ""),
                "version": row.get("version", ""),
                "service": row.get("service", ""),
                "cves": [c.strip() for c in row.get("cves", "").split(",") if c.strip()],
            })
    return fingerprints


def run_fast_assess(domain: str) -> list[dict]:
    """调用 src-fast-assess.py 并从结果提取指纹"""
    script = Path("/root/.hermes/scripts/src-fast-assess.py")
    if not script.exists():
        print(f"[!] src-fast-assess.py not found: {script}")
        return []

    print(f"[*] Running fast assessment on {domain}...")
    try:
        result = subprocess.run(
            ["/usr/bin/python3", str(script), domain],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout
    except Exception as ex:
        print(f"[!] Fast assess failed: {ex}")
        return []

    fingerprints = []
    # 从输出中提取技术栈指纹
    for line in output.split("\n"):
        # 匹配 server headers, tech stack 等
        tech_match = re.search(r'(?:Server|X-Powered-By|Tech):\s*(.+)', line, re.IGNORECASE)
        if tech_match:
            tech = tech_match.group(1).strip()
            fingerprints.append({
                "product": tech,
                "version": "",
                "port": 443,
                "service": "http",
                "cves": [],
                "host": domain,
            })

    # 也尝试从 httpx 输出解析
    httpx_out = Path(f"/tmp/{domain}_recon/httpx_output.json")
    if httpx_out.exists():
        with open(httpx_out) as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    tech_list = data.get("tech", [])
                    for tech in tech_list:
                        fingerprints.append({
                            "product": tech,
                            "version": "",
                            "port": data.get("port", 443),
                            "service": "http",
                            "cves": [],
                            "host": data.get("host", domain),
                        })
                except Exception:
                    pass

    return fingerprints


def generate_report(chain_results: dict, target: str = "") -> str:
    """生成可读报告"""
    lines = []
    lines.append("=" * 70)
    lines.append("  Exploit-DB Match Report")
    lines.append(f"  Target: {target or 'N/A'}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    total_exploits = 0
    critical_count = 0
    high_count = 0

    for key, data in chain_results.items():
        fp = data["fingerprint"]
        exploits = data["exploits"]
        if not exploits:
            continue

        total_exploits += len(exploits)
        critical_count += sum(1 for e in exploits if e.get("severity") == "critical")
        high_count += sum(1 for e in exploits if e.get("severity") == "high")

        lines.append("")
        lines.append(f"--- {fp.get('product', '?')} {fp.get('version', '')} "
                     f":{fp.get('port', '?')} [{fp.get('service', '?')}] ---")
        lines.append(f"  Matched: {data['total']} exploits ({len(exploits)} shown)")

        for exp in exploits:
            sev = exp['severity'].upper()
            lines.append(f"  [{sev:>8}] EDB-{exp['id']}: {exp['title']}")
            if exp.get("cve"):
                lines.append(f"           CVE: {', '.join(exp['cve'])}")
            lines.append(f"           URL: {exp['url']}")
            lines.append(f"           Path: {exp['local_path']}")

    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  Summary: {total_exploits} exploits matched")
    lines.append(f"  Critical: {critical_count}  High: {high_count}")
    lines.append("=" * 70)

    return "\n".join(lines)


def generate_attack_script(chain_results: dict, target: str, output_path: str) -> str:
    """生成攻击验证脚本"""
    lines = ["#!/bin/bash", "# Auto-generated exploit verification script",
             f"# Target: {target}", f"# Generated: {datetime.now().isoformat()}", ""]

    lines.append(f'TARGET="{target}"')
    lines.append('WORKDIR="/tmp/exploit_verify_$(date +%s)"')
    lines.append('mkdir -p "$WORKDIR"')
    lines.append('cd "$WORKDIR"')
    lines.append("")

    for key, data in chain_results.items():
        fp = data["fingerprint"]
        exploits = data["exploits"]
        if not exploits:
            continue

        lines.append(f"# === {fp.get('product', '')} {fp.get('version', '')} ===")
        for exp in exploits[:3]:  # 每个指纹最多3个exploit
            sev = exp['severity']
            lines.append(f"# [{sev.upper()}] EDB-{exp['id']}: {exp['title']}")
            path = exp['local_path']

            if path.endswith(".py"):
                lines.append(f'# python3 "{path}" "$TARGET" 2>&1 | tee "$WORKDIR/edb_{exp["id"]}.txt"')
            elif path.endswith(".rb"):
                lines.append(f'# msfconsole -q -x "use {exp.get("file", "")}; set RHOSTS $TARGET; run; exit"')
            elif path.endswith(".sh"):
                lines.append(f'# bash "{path}" "$TARGET" 2>&1 | tee "$WORKDIR/edb_{exp["id"]}.txt"')
            elif path.endswith(".txt"):
                lines.append(f'# Manual: cat "{path}" | head -50')
            else:
                lines.append(f'# File: "{path}"')

            # nuclei 补充
            if exp.get("cve"):
                for cve in exp["cve"][:1]:
                    year = cve.split("-")[1]
                    lines.append(f'nuclei -u "$TARGET" -t /root/nuclei-templates/http/cves/{year}/{cve}.yaml 2>&1 | tee "$WORKDIR/nuclei_{cve}.txt" || true')
            lines.append("")

    lines.append('echo "[*] Results in $WORKDIR"')
    lines.append('ls -la "$WORKDIR/"')

    content = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(content)
    os.chmod(output_path, 0o755)
    return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Exploit-DB Fingerprint Pipeline")
    parser.add_argument("--nmap", help="nmap XML file")
    parser.add_argument("--nuclei", help="nuclei JSONL output")
    parser.add_argument("--csv", help="CSV fingerprint file")
    parser.add_argument("--fast-assess", help="Run fast-assess on domain")
    parser.add_argument("--product", help="Manual product name")
    parser.add_argument("--version", default="", help="Manual version")
    parser.add_argument("--port", type=int, default=0, help="Manual port")
    parser.add_argument("--target", "-t", default="", help="Target for attack script")
    parser.add_argument("--output", "-o", help="Output report path")
    parser.add_argument("--script", help="Generate attack script to path")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--limit", "-n", type=int, default=10, help="Max exploits per fingerprint")
    args = parser.parse_args()

    engine = ExploitDBEngine()
    fingerprints = []

    # 收集指纹
    if args.nmap:
        fingerprints.extend(parse_nmap_xml(args.nmap))
    if args.nuclei:
        fingerprints.extend(parse_nuclei_jsonl(args.nuclei))
    if args.csv:
        fingerprints.extend(parse_csv_input(args.csv))
    if args.fast_assess:
        fingerprints.extend(run_fast_assess(args.fast_assess))
    if args.product:
        fingerprints.append({
            "product": args.product,
            "version": args.version,
            "port": args.port,
            "service": "",
            "cves": [],
        })

    if not fingerprints:
        parser.print_help()
        print("\n[!] No fingerprints provided. Use --nmap, --nuclei, --csv, --product, or --fast-assess")
        sys.exit(1)

    # 去重
    seen = set()
    unique_fps = []
    for fp in fingerprints:
        key = f"{fp.get('product','')}:{fp.get('version','')}:{fp.get('port',0)}"
        if key not in seen and fp.get("product"):
            seen.add(key)
            unique_fps.append(fp)

    print(f"[*] {len(unique_fps)} unique fingerprints to match against exploit-db...")

    # 匹配
    chain_results = engine.fingerprint_to_exploits(unique_fps)

    # 输出
    if args.json:
        # 简化 JSON 输出
        output = {}
        for key, data in chain_results.items():
            output[key] = {
                "fingerprint": data["fingerprint"],
                "exploits": data["exploits"],
                "total": data["total"],
            }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        report = generate_report(chain_results, args.target)
        print(report)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            print(f"\n[*] Report saved to: {args.output}")

    # 生成攻击脚本
    if args.script and args.target:
        script_path = generate_attack_script(chain_results, args.target, args.script)
        print(f"[*] Attack script saved to: {script_path}")

    # 返回非零如果没有匹配
    total = sum(d["total"] for d in chain_results.values())
    if total == 0:
        print("\n[!] No exploits matched. Try broader search terms.")
        sys.exit(1)


if __name__ == "__main__":
    main()
