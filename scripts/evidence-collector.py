#!/usr/bin/env python3
"""
Evidence Collector v3.0 — 统一证据采集与关联

从图谱中读取漏洞，自动采集/格式化证据：
  - 响应头/体截取
  - curl 复现命令生成
  - Burp 风格请求/响应
  - 截图位置标注
  - 证据关联到图谱节点

用法:
  evidence-collector.py <graph.db> [--vuln-id N] [--auto-curl] [--format butian|markdown]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from importlib import import_module


def _get_graph(db_path):
    spec = import_module("vuln-graph-engine")
    return spec.PentestGraph(db_path)


class EvidenceCollector:
    """Unified evidence collection and formatting."""

    def __init__(self, graph_db: str):
        self.graph = _get_graph(graph_db)
        self.collected = []

    def collect_all(self, auto_curl: bool = True) -> list[dict]:
        """Collect evidence for all unverified vulns."""
        vulns = self.graph.get_vulns(verified=0)  # Unverified
        print(f"[*] Evidence Collector: {len(vulns)} unverified vulns")

        for v in vulns:
            vid = v["id"]
            existing = self.graph.get_evidence(vid)

            # Auto-generate curl if missing
            if auto_curl and not any(e["type"] == "curl" for e in existing):
                curl_cmd = self._generate_curl(v)
                if curl_cmd:
                    self.graph.add_evidence(vid, "curl", curl_cmd, "Auto-generated reproduction command")
                    self.collected.append({"vuln_id": vid, "type": "curl", "added": True})

            # Auto-replay request if we have a curl command
            curl_ev = [e for e in self.graph.get_evidence(vid) if e["type"] == "curl"]
            if curl_ev and auto_curl:
                replay = self._replay_curl(curl_ev[0]["content"])
                if replay:
                    self.graph.add_evidence(vid, "response", replay["stdout"][:3000], "Auto-replayed response")
                    self.graph.add_evidence(vid, "request", replay["request"], "Replayed request")
                    self.collected.append({"vuln_id": vid, "type": "replay", "added": True})

            # Mark screenshots
            self.graph.add_evidence(vid, "screenshot", f"【截图位置{vid}】", "Browser screenshot placeholder")

        self.graph.close()
        return self.collected

    def format_report(self, format: str = "butian") -> str:
        """Format all verified vulns into a report."""
        vulns = self.graph.get_vulns()  # All vulns
        if not vulns:
            return "No vulnerabilities found."

        if format == "butian":
            return self._format_butian(vulns)
        elif format == "markdown":
            return self._format_markdown(vulns)
        else:
            return self._format_markdown(vulns)

    def _generate_curl(self, vuln: dict) -> Optional[str]:
        """Generate curl reproduction command from vuln data."""
        poc = vuln.get("poc", "")
        if poc and "curl" in poc:
            return poc

        # Build from endpoint
        ep_id = vuln.get("endpoint_id")
        if ep_id:
            ep = self.graph.conn.execute("SELECT * FROM endpoints WHERE id=?", (ep_id,)).fetchone()
            if ep:
                url = ep["url"]
                method = ep.get("method", "GET")
                if method == "GET":
                    return f'curl -sk "{url}"'
                else:
                    return f'curl -sk -X {method} "{url}"'

        # Build from host
        host_id = vuln.get("host_id")
        if host_id:
            host = self.graph.conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
            if host:
                domain = host.get("domain") or host.get("ip", "")
                return f'curl -sk "https://{domain}/"'

        return None

    def _replay_curl(self, curl_cmd: str) -> Optional[dict]:
        """Replay a curl command and capture output."""
        # Add -D- to capture headers
        if "-D" not in curl_cmd and "-i" not in curl_cmd:
            curl_cmd = curl_cmd.replace("curl ", "curl -D- ", 1)

        try:
            proc = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True, timeout=15)
            # Split headers and body
            output = proc.stdout
            request_line = curl_cmd  # The curl command IS the request
            return {"stdout": output[:5000], "request": request_line, "exit_code": proc.returncode}
        except Exception:
            return None

    def _format_butian(self, vulns: list) -> str:
        """Format as 补天 (Butian) report."""
        sections = []
        for i, v in enumerate(vulns, 1):
            vid = v["id"]
            evidence = self.graph.get_evidence(vid)
            curl_ev = [e for e in evidence if e["type"] == "curl"]
            resp_ev = [e for e in evidence if e["type"] == "response"]
            screenshot_ev = [e for e in evidence if e["type"] == "screenshot"]

            domain = v.get("domain", "unknown")
            severity = v.get("severity", "medium")

            section = f"""=== 漏洞报告 #{i} ===

标题: {v.get('title', 'N/A')}
域名: {domain}
类型: {v.get('vuln_type', 'N/A')}
等级: {severity}
行业: [待填写]
地址: [精确到区]
URL: {domain}

详情:
{v.get('description', v.get('title', ''))}

复现:
{''.join(e['content'] for e in curl_ev) if curl_ev else '[待补充]'}

响应:
{resp_ev[0]['content'][:1000] if resp_ev else '[待补充]'}

{screenshot_ev[0]['content'] if screenshot_ev else ''}

影响: {v.get('impact', '可获取敏感信息/未授权访问')}

修复建议:
{v.get('remediation', '1. 限制访问权限 2. 修复配置缺陷 3. 升级到最新版本')}"""
            sections.append(section)

        return "\n\n".join(sections)

    def _format_markdown(self, vulns: list) -> str:
        """Format as Markdown report."""
        lines = ["# 渗透测试报告", "", f"生成时间: {datetime.now(timezone.utc).isoformat()}", f"漏洞总数: {len(vulns)}", ""]

        # Severity summary
        severity_count = {}
        for v in vulns:
            s = v.get("severity", "info")
            severity_count[s] = severity_count.get(s, 0) + 1

        lines.append("## 漏洞统计")
        for s in ["critical", "high", "medium", "low", "info"]:
            if s in severity_count:
                lines.append(f"- {s}: {severity_count[s]}")
        lines.append("")

        lines.append("## 漏洞详情")
        for i, v in enumerate(vulns, 1):
            vid = v["id"]
            evidence = self.graph.get_evidence(vid)
            curl_ev = [e for e in evidence if e["type"] == "curl"]

            lines.append(f"### {i}. {v.get('title', 'N/A')}")
            lines.append(f"- **严重性**: {v.get('severity', 'N/A')}")
            lines.append(f"- **CVE**: {v.get('cve', 'N/A')}")
            lines.append(f"- **类型**: {v.get('vuln_type', 'N/A')}")
            lines.append(f"- **域名**: {v.get('domain', 'N/A')}")
            lines.append(f"- **PoC验证**: {'✅' if v.get('poc_verified') == 1 else '❌ 未验证'}")
            lines.append("")
            if curl_ev:
                lines.append("```bash")
                lines.append(curl_ev[0]["content"])
                lines.append("```")
                lines.append("")

        return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Evidence Collector v3.0")
    p.add_argument("graph_db", help="Path to graph.db")
    p.add_argument("--vuln-id", type=int, help="Specific vuln ID")
    p.add_argument("--auto-curl", action="store_true", default=True)
    p.add_argument("--format", choices=["butian", "markdown", "json"], default="butian")
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    collector = EvidenceCollector(args.graph_db)
    collected = collector.collect_all(auto_curl=args.auto_curl)
    print(f"\n[*] Collected {len(collected)} evidence items")

    report = collector.format_report(args.format)

    if args.output:
        Path(args.output).write_text(report)
        print(f"[*] Report saved to {args.output}")
    else:
        print("\n" + report)


if __name__ == "__main__":
    main()
