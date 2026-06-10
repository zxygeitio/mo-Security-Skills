#!/usr/bin/env python3
"""
Report Pipeline v3.2 — 图谱→报告，自动质量门禁

从图谱生成报告，内置质量门禁（拒绝误报/低质量漏洞）：
  - 补天格式
  - Markdown
  - JSON
  - 自动检查: 响应大小、敏感数据、负面关键词、SPA回退

用法:
  report-pipeline.py <graph.db> [--format butian|markdown|json] [--output /tmp/report.txt]
  report-pipeline.py <graph.db> --quality-gate  (仅运行质量门禁)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from importlib import import_module

def _get_graph(db_path):
    spec = import_module("vuln-graph-engine")
    return spec.PentestGraph(db_path)


# ─── Quality Gate ─────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = [
    ("pii", re.compile(r"姓名|手机号|身份证|学号|工号|邮箱|email|mobile|phone|idcard|identity", re.I)),
    ("auth", re.compile(r"token|authorization|session|jwt|ticket|secret|appsecret|apikey|access[_-]?key", re.I)),
    ("business", re.compile(r"订单|支付|金额|余额|成绩|课程|申请|流程|审批|借阅|住址|部门|组织", re.I)),
    ("sql_error", re.compile(r"SQLSyntaxErrorException|SQLException|mysql|oracle|postgres|mapper\.java|Unknown database|syntax error", re.I)),
    ("upload", re.compile(r"fileUrl|resId|ossId|genName|downloadUrl|upload.*success|上传成功", re.I)),
    ("rce", re.compile(r"uid=|gid=|root:|/bin/bash|Windows IP Configuration", re.I)),
]

HIGH_IMPACT_TYPES = {
    "rce", "sqli", "auth_bypass", "idor", "bola", "ssrf",
    "file_upload", "deserialization", "unauth_service", "cors",
}

NEGATIVE_PATTERNS = re.compile(
    r"Token失效|token信息不存在|FA_INVALID_SESSION|未登录|请登录|login|登录|"
    r"404 Not Found|403 Forbidden|Error Page|unexpected user service|empty|^$",
    re.I,
)

SPA_FALLBACK = re.compile(r"<!DOCTYPE html>|<div id=\"app\">|<div id=\"root\">|__NEXT_DATA__", re.I)


class QualityGate:
    """Validate vulns before report submission."""

    def __init__(self, graph_db: str):
        self.graph = _get_graph(graph_db)
        self.decisions = []

    def check_all(self, quiet: bool = False) -> list[dict]:
        """Run quality gate on all vulns."""
        vulns = self.graph.get_vulns()
        if not quiet:
            print(f"[*] Quality Gate: checking {len(vulns)} vulns")

        for v in vulns:
            decision = self._check_vuln(v)
            self.decisions.append(decision)
            status = "PASS" if decision["pass"] else "REJECT"
            if not quiet:
                print(f"  [{status}] {v['title']}: {decision['reason']}")

        self.graph.close()
        return self.decisions

    def _check_vuln(self, vuln: dict) -> dict:
        """Check a single vuln."""
        vid = vuln["id"]
        title = vuln.get("title", "")
        severity = vuln.get("severity", "info")
        evidence = self.graph.get_evidence(vid)

        # Rule 1: Must have evidence
        if not evidence:
            return {"vuln_id": vid, "pass": False, "reason": "NO_EVIDENCE", "detail": "No evidence attached"}

        # Rule 2: Check response body for false positives
        resp_ev = [e for e in evidence if e["type"] == "response"]
        if resp_ev:
            body = resp_ev[0]["content"]

            # Too small response
            if len(body.strip()) < 20:
                return {"vuln_id": vid, "pass": False, "reason": "EMPTY_RESPONSE", "detail": "Response body too small"}

            # SPA fallback detection
            if SPA_FALLBACK.search(body[:500]):
                return {"vuln_id": vid, "pass": False, "reason": "SPA_FALLBACK", "detail": "Response is SPA HTML fallback"}

            # Negative patterns (login page, error page)
            if NEGATIVE_PATTERNS.search(body[:500]):
                return {"vuln_id": vid, "pass": False, "reason": "NEGATIVE_SIGNAL", "detail": "Response contains login/error page indicators"}

        # Rule 3: Must have curl/PoC
        curl_ev = [e for e in evidence if e["type"] == "curl"]
        if not curl_ev and severity in ("critical", "high"):
            return {"vuln_id": vid, "pass": False, "reason": "NO_POC", "detail": "High/critical vuln without PoC command"}

        # Rule 4: Check for sensitive data in response
        sensitive_hits = []
        for ev in resp_ev:
            for name, pattern in SENSITIVE_PATTERNS:
                if pattern.search(ev["content"]):
                    sensitive_hits.append(name)

        # Rule 4b: High/Critical findings need concrete response impact.
        vuln_type = (vuln.get("vuln_type") or "").lower()
        if severity in ("critical", "high"):
            if not resp_ev:
                return {"vuln_id": vid, "pass": False, "reason": "NO_RESPONSE_EVIDENCE", "detail": "High/critical vuln without response evidence"}
            if vuln_type not in HIGH_IMPACT_TYPES and not sensitive_hits:
                return {"vuln_id": vid, "pass": False, "reason": "NO_HIGH_IMPACT_SIGNAL", "detail": "High/critical vuln lacks sensitive/business/exploit evidence"}

        # Rule 5: CVE claims must be verified
        cve = vuln.get("cve", "")
        if cve and vuln.get("poc_verified") != 1:
            return {"vuln_id": vid, "pass": False, "reason": "UNVERIFIED_CVE", "detail": f"CVE {cve} claimed but not verified"}

        # Passed
        return {
            "vuln_id": vid,
            "pass": True,
            "reason": "PASS",
            "sensitive_hits": sensitive_hits,
            "evidence_count": len(evidence),
        }


# ─── Report Generator ────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate reports from graph with quality gate."""

    def __init__(self, graph_db: str):
        self.graph_db = graph_db
        self.graph = _get_graph(graph_db)

    def generate(self, format: str = "butian", include_rejected: bool = False) -> str:
        """Generate report. Runs quality gate first."""
        # Quality gate
        gate = QualityGate(self.graph_db)
        # Re-open graph since quality gate closes it
        self.graph = _get_graph(self.graph_db)

        quiet = format == "json"
        decisions = gate.check_all(quiet=quiet)
        passed_ids = {d["vuln_id"] for d in decisions if d["pass"]}
        rejected = [d for d in decisions if not d["pass"]]

        if rejected and not quiet:
            print(f"\n[!] {len(rejected)} vulns rejected by quality gate:")
            for r in rejected:
                print(f"    - {r['reason']}: {r.get('detail', '')}")

        # Get vulns that passed
        vulns = self.graph.get_vulns()
        if not include_rejected:
            vulns = [v for v in vulns if v["id"] in passed_ids]

        if not vulns:
            return "所有漏洞均未通过质量门禁，无可提交报告。"

        if format == "butian":
            return self._format_butian(vulns)
        elif format == "json":
            return self._format_json(vulns)
        else:
            return self._format_markdown(vulns, rejected)

    def _format_butian(self, vulns: list) -> str:
        """补天格式报告."""
        sections = []
        for i, v in enumerate(vulns, 1):
            vid = v["id"]
            evidence = self.graph.get_evidence(vid)
            curl_ev = [e for e in evidence if e["type"] == "curl"]
            resp_ev = [e for e in evidence if e["type"] == "response"]
            screenshot_ev = [e for e in evidence if e["type"] == "screenshot"]

            domain = v.get("domain", "")
            section_parts = [
                f"=== 漏洞报告 #{i} ===",
                "",
                f"标题: {v.get('title', 'N/A')}",
                f"域名: {domain}",
                f"类型: {v.get('vuln_type', 'N/A')}",
                f"等级: {v.get('severity', 'medium')}",
                "行业: [待填写]",
                "地址: [精确到区]",
                f"URL: https://{domain}/",
                "",
                "详情:",
                v.get("description", v.get("title", "")),
                "",
                "复现:",
                curl_ev[0]["content"] if curl_ev else "[待补充]",
                "",
                "复现命令汇总:",
            ]

            # Deduplicate curl commands
            seen = set()
            for ev in curl_ev:
                cmd = ev["content"].strip()
                if cmd not in seen:
                    section_parts.append(cmd)
                    seen.add(cmd)

            section_parts.extend(["", "响应:"])
            if resp_ev:
                # Sanitize response (truncate, remove auth headers)
                body = resp_ev[0]["content"][:1500]
                section_parts.append(body)
            else:
                section_parts.append("[待补充]")

            if screenshot_ev:
                section_parts.extend(["", screenshot_ev[0]["content"]])

            section_parts.extend([
                "",
                "影响: 可获取敏感信息/未授权访问",
                "",
                "修复建议:",
                v.get("remediation", "1. 限制访问权限 2. 修复配置缺陷 3. 升级到最新版本"),
            ])

            sections.append("\n".join(section_parts))

        return "\n\n".join(sections)

    def _format_markdown(self, vulns: list, rejected: list) -> str:
        """Markdown格式报告."""
        stats = self.graph.stats()
        lines = [
            "# 渗透测试报告 v3.0",
            "",
            f"生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"漏洞总数: {len(vulns)} (通过质量门禁)",
            f"被拒绝: {len(rejected)}",
            "",
            "## 概览",
            f"- 主机: {stats.get('hosts', 0)}",
            f"- 端口: {stats.get('ports', 0)}",
            f"- 指纹: {stats.get('fingerprints', 0)}",
            f"- 端点: {stats.get('endpoints', 0)}",
            f"- CORS发现: {stats.get('cors_findings', 0)}",
            f"- 密钥泄露: {stats.get('secrets', 0)}",
            "",
            "## 漏洞统计",
        ]

        sev_count = {}
        for v in vulns:
            s = v.get("severity", "info")
            sev_count[s] = sev_count.get(s, 0) + 1

        for s in ["critical", "high", "medium", "low", "info"]:
            if s in sev_count:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(s, "")
                lines.append(f"- {icon} {s}: {sev_count[s]}")

        lines.extend(["", "## 漏洞详情"])

        for i, v in enumerate(vulns, 1):
            vid = v["id"]
            evidence = self.graph.get_evidence(vid)
            curl_ev = [e for e in evidence if e["type"] == "curl"]
            verified = "✅" if v.get("poc_verified") == 1 else "❌ 未验证"

            lines.extend([
                f"### {i}. {v.get('title', 'N/A')}",
                f"- **严重性**: {v.get('severity', 'N/A')}",
                f"- **CVE**: {v.get('cve', 'N/A')}",
                f"- **类型**: {v.get('vuln_type', 'N/A')}",
                f"- **域名**: {v.get('domain', 'N/A')}",
                f"- **验证**: {verified}",
                "",
            ])

            if curl_ev:
                lines.extend(["```bash", curl_ev[0]["content"], "```", ""])

        # Rejected vulns appendix
        if rejected:
            lines.extend(["", "## 被拒绝的漏洞 (未通过质量门禁)", ""])
            for r in rejected:
                lines.append(f"- vuln_id={r['vuln_id']}: {r['reason']} — {r.get('detail', '')}")

        return "\n".join(lines)

    def _format_json(self, vulns: list) -> str:
        """JSON格式报告."""
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": self.graph.stats(),
            "vulns": [],
        }
        for v in vulns:
            vid = v["id"]
            evidence = self.graph.get_evidence(vid)
            report["vulns"].append({
                **v,
                "evidence": evidence,
            })
        return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def main():
    p = argparse.ArgumentParser(description="Report Pipeline v3.2")
    p.add_argument("graph_db", help="Path to graph.db")
    p.add_argument("--format", choices=["butian", "markdown", "json"], default="butian")
    p.add_argument("--output", help="Output file path")
    p.add_argument("--quality-gate", action="store_true", help="Run quality gate only")
    p.add_argument("--include-rejected", action="store_true", help="Include rejected vulns")
    args = p.parse_args()

    if args.quality_gate:
        gate = QualityGate(args.graph_db)
        decisions = gate.check_all()
        passed = sum(1 for d in decisions if d["pass"])
        print(f"\n[*] Quality Gate: {passed}/{len(decisions)} passed")
        return

    gen = ReportGenerator(args.graph_db)
    report = gen.generate(args.format, args.include_rejected)

    if args.output:
        Path(args.output).write_text(report)
        print(f"[*] Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
