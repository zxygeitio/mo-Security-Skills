#!/usr/bin/python3
"""SRC Autonomy Audit Gate.

A read-only governance gate for Hermes SRC/pentest workspaces.
It checks whether an autonomous security-testing run has the minimum artifacts
needed for safe scope enforcement, falsifiable hypothesis testing, auditable
execution, evidence integrity, and reproducible reporting.

Inspired by public architecture patterns from:
- OWASP APTS: scope enforcement, safety controls, auditability, reporting.
- POPPER: hypothesis validation by falsification attempts.
- Shannon Lite: final reports should contain only verified PoC-backed findings.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
REPRO_PASS_KEYS = {"passed", "passed_findings", "reproducible", "PASS"}
REPORTABLE_DECISIONS = {"HAS_REPORTABLE_CANDIDATES", "REPORTABLE_CANDIDATE"}
SCOPE_HOST_RE = re.compile(r"^https?://([^/:?#]+)", re.I)


@dataclass
class CheckResult:
    check_id: str
    status: str
    score: int
    reason: str
    evidence: list[str]
    recommendation: str = ""


def read_text(path: Path, limit: int = 250_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def read_json(path: Path) -> Any:
    try:
        return json.loads(read_text(path, limit=2_000_000))
    except Exception:
        return None


def sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def iter_rows(path: Path) -> list[dict[str, str]]:
    text = read_text(path, limit=2_000_000)
    if not text.strip():
        return []
    try:
        dialect = "excel-tab" if "\t" in text.splitlines()[0] else "excel"
        return [dict(r) for r in csv.DictReader(text.splitlines(), dialect=dialect)]
    except Exception:
        return []


def workspace_files(workspace: Path) -> dict[str, Path]:
    names = [
        "scope.md",
        "state.json",
        "probe_results.tsv",
        "quality_gate.md",
        "quality_gate.json",
        "src-think.json",
        "src-think.md",
        "threat_model.json",
        "reproducibility_gate.json",
        "repro-report.json",
        "repro-report.md",
        "autonomy_audit.json",
        "tool_calls.jsonl",
        "hypotheses.jsonl",
        "audit_trail.jsonl",
        "final_gate.md",
    ]
    return {name: workspace / name for name in names if (workspace / name).exists()}


def collect_evidence_manifest(workspace: Path) -> dict[str, Any]:
    """Build a deterministic evidence manifest with paths, sizes, and hashes."""
    evidence_dirs = ["headers", "bodies", "raw", "screenshots", "candidate_reports", "final_reports", "logs"]
    evidence_files: list[Path] = []
    for folder in evidence_dirs:
        root = workspace / folder
        if root.exists():
            evidence_files.extend(path for path in root.rglob("*") if path.is_file())
    for name in [
        "scope.md",
        "state.json",
        "probe_results.tsv",
        "quality_gate.md",
        "quality_gate.json",
        "src-think.json",
        "src-think.md",
        "reproducibility_gate.json",
        "repro-report.json",
        "repro-report.md",
        "tool_calls.jsonl",
        "hypotheses.jsonl",
        "audit_trail.jsonl",
        "negative.md",
        "final_gate.md",
    ]:
        path = workspace / name
        if path.exists() and path.is_file():
            evidence_files.append(path)

    entries = []
    for path in sorted(set(evidence_files), key=lambda item: str(item.relative_to(workspace))):
        relative_path = str(path.relative_to(workspace))
        stat = path.stat()
        entries.append({
            "path": relative_path,
            "size": stat.st_size,
            "sha256": sha256_file(path),
        })

    manifest_payload = "\n".join(f"{item['sha256']}  {item['path']}  {item['size']}" for item in entries)
    return {
        "workspace": str(workspace),
        "file_count": len(entries),
        "total_size": sum(item["size"] for item in entries),
        "manifest_sha256": hashlib.sha256(manifest_payload.encode()).hexdigest(),
        "files": entries,
    }


def verify_evidence_manifest(workspace: Path, manifest_path: Path) -> dict[str, Any]:
    """Verify a previously generated evidence manifest against current files."""
    workspace = workspace.expanduser().resolve()
    manifest = read_json(manifest_path.expanduser())
    if not isinstance(manifest, dict):
        return {"ok": False, "reason": "manifest is not valid JSON", "missing": [], "changed": [], "extra": []}

    expected_files = {str(item.get("path", "")): item for item in manifest.get("files", []) if isinstance(item, dict)}
    current = collect_evidence_manifest(workspace)
    current_files = {str(item.get("path", "")): item for item in current.get("files", []) if isinstance(item, dict)}

    missing = sorted(path for path in expected_files if path not in current_files)
    extra = sorted(path for path in current_files if path not in expected_files)
    changed = []
    for path, expected in sorted(expected_files.items()):
        actual = current_files.get(path)
        if not actual:
            continue
        if actual.get("sha256") != expected.get("sha256") or actual.get("size") != expected.get("size"):
            changed.append({
                "path": path,
                "expected_size": expected.get("size"),
                "actual_size": actual.get("size"),
                "expected_sha256": expected.get("sha256"),
                "actual_sha256": actual.get("sha256"),
            })

    expected_manifest_sha = manifest.get("manifest_sha256")
    ok = not missing and not changed and current.get("manifest_sha256") == expected_manifest_sha
    return {
        "ok": ok,
        "workspace": str(workspace),
        "manifest": str(manifest_path),
        "expected_file_count": manifest.get("file_count", len(expected_files)),
        "actual_file_count": current.get("file_count", len(current_files)),
        "expected_manifest_sha256": expected_manifest_sha,
        "actual_manifest_sha256": current.get("manifest_sha256"),
        "missing": missing,
        "changed": changed,
        "extra": extra,
    }


def infer_scope_hosts(scope_text: str, state: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    target = str(state.get("target") or "").strip().lower()
    if target:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    for match in re.finditer(r"([a-z0-9][a-z0-9.-]+\.[a-z]{2,})", scope_text, re.I):
        hosts.add(match.group(1).lower())
    return hosts


def probe_hosts(workspace: Path) -> set[str]:
    hosts: set[str] = set()
    for name in ["probe_results.tsv", "assets.tsv", "endpoints.tsv"]:
        for row in iter_rows(workspace / name):
            for value in [row.get("url", ""), row.get("endpoint", ""), row.get("host", "")]:
                value = (value or "").strip()
                if not value:
                    continue
                if "://" not in value and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", value, re.I):
                    hosts.add(value.lower())
                    continue
                parsed = urlparse(value)
                if parsed.hostname:
                    hosts.add(parsed.hostname.lower())
    return hosts


def host_in_scope(host: str, scopes: set[str]) -> bool:
    if not scopes:
        return False
    host = host.lower().strip(".")
    for scope in scopes:
        scope = scope.lower().strip(".")
        if host == scope or host.endswith("." + scope):
            return True
    return False


def check_scope(workspace: Path, files: dict[str, Path]) -> CheckResult:
    state = read_json(files.get("state.json", workspace / "missing")) or {}
    scope_text = read_text(files.get("scope.md", workspace / "missing"))
    scopes = infer_scope_hosts(scope_text, state if isinstance(state, dict) else {})
    seen_hosts = probe_hosts(workspace)
    out = sorted(h for h in seen_hosts if not host_in_scope(h, scopes))
    evidence = [f"scope={','.join(sorted(scopes)) or 'missing'}", f"seen_hosts={len(seen_hosts)}"]
    if out:
        return CheckResult("APTS-SE", "FAIL", 0, f"Out-of-scope hosts found: {', '.join(out[:10])}", evidence, "Run probes with --scope-domain or split workspaces per target.")
    if not scopes:
        return CheckResult("APTS-SE", "WARN", 8, "Scope target is not explicit", evidence, "Write scope.md or initialize workspace with --scope.")
    return CheckResult("APTS-SE", "PASS", 20, "Scope is explicit and observed hosts stay inside scope", evidence)


def check_auditability(workspace: Path, files: dict[str, Path]) -> CheckResult:
    trails = [p for p in [workspace / "tool_calls.jsonl", workspace / "audit_trail.jsonl", workspace / "logs"] if p.exists()]
    evidence_files = []
    for folder in ["headers", "bodies", "raw", "screenshots", "candidate_reports", "final_reports"]:
        p = workspace / folder
        if p.exists():
            evidence_files.extend([x for x in p.rglob("*") if x.is_file()][:200])
    evidence = [f"audit_artifacts={len(trails)}", f"evidence_files={len(evidence_files)}"]
    if not trails:
        return CheckResult("APTS-AR", "WARN", 8, "No explicit audit trail/tool-call log found", evidence, "Log tool calls or append major actions to audit_trail.jsonl.")
    if not evidence_files:
        return CheckResult("APTS-AR", "WARN", 12, "Audit trail exists but no response/screenshot evidence files found", evidence, "Persist headers/bodies/screenshots for every candidate.")
    sample_hashes = [f"{p.name}:{sha256_file(p)[:12]}" for p in evidence_files[:10]]
    return CheckResult("APTS-AR", "PASS", 20, "Audit trail and evidence files are present", evidence + sample_hashes)


def check_hypothesis(workspace: Path, files: dict[str, Path]) -> CheckResult:
    sources = [p for p in [workspace / "src-think.json", workspace / "threat_model.json", workspace / "hypotheses.jsonl"] if p.exists()]
    text = "\n".join(read_text(p, limit=500_000) for p in sources)
    has_hypothesis = bool(re.search(r"hypothes|假设|category|attack", text, re.I))
    has_controls = bool(re.search(r"control|对照|invalid|random|nonexistent|wrong", text, re.I))
    has_missing = bool(re.search(r"missing|缺失|need_more|NO_REPORT|READY_TO_VALIDATE", text, re.I))
    score = 0
    score += 7 if has_hypothesis else 0
    score += 7 if has_controls else 0
    score += 6 if has_missing else 0
    evidence = [f"sources={[p.name for p in sources]}", f"hypothesis={has_hypothesis}", f"controls={has_controls}", f"falsification_gaps={has_missing}"]
    if score >= 18:
        return CheckResult("POPPER-HV", "PASS", 20, "Hypotheses include controls and falsification gaps", evidence)
    if score:
        return CheckResult("POPPER-HV", "WARN", score, "Hypothesis layer is incomplete", evidence, "Run src-think.py and keep A/B negative controls before validation.")
    return CheckResult("POPPER-HV", "FAIL", 0, "No hypothesis/validation planning artifact found", evidence, "Run src-think.py or write hypotheses.jsonl before exploitation/reporting.")


def quality_verdict(workspace: Path) -> str:
    qj = read_json(workspace / "quality_gate.json")
    if isinstance(qj, dict):
        for key in ["verdict", "final_verdict", "decision"]:
            if qj.get(key):
                return str(qj[key])
    text = read_text(workspace / "quality_gate.md")
    match = re.search(r"Verdict:\s*([A-Z_]+)", text)
    return match.group(1) if match else ""


def repro_pass_count(workspace: Path) -> int:
    for name in ["reproducibility_gate.json", "repro-report.json"]:
        data = read_json(workspace / name)
        if isinstance(data, dict):
            if isinstance(data.get("passed"), int):
                return int(data["passed"])
            if isinstance(data.get("passed_findings"), list):
                return len(data["passed_findings"])
            if data.get("reproducible") is True:
                return 1
    text = read_text(workspace / "repro-report.md")
    match = re.search(r"Passed \(reproducible\):\s*(\d+)", text)
    if match:
        return int(match.group(1))
    return 0


def check_reporting(workspace: Path, files: dict[str, Path]) -> CheckResult:
    verdict = quality_verdict(workspace)
    passed = repro_pass_count(workspace)
    final_reports = list((workspace / "final_reports").glob("*")) if (workspace / "final_reports").exists() else []
    evidence = [f"quality_verdict={verdict or 'missing'}", f"repro_passed={passed}", f"final_reports={len(final_reports)}"]
    if passed > 0:
        return CheckResult("SHANNON-PBE", "PASS", 20, "At least one finding passed reproducibility proof gate", evidence)
    if verdict in REPORTABLE_DECISIONS:
        return CheckResult("SHANNON-PBE", "WARN", 12, "Quality gate has reportable candidates but reproducibility proof is missing", evidence, "Run src-reproducibility-gate.py before writing/submitting report.")
    return CheckResult("SHANNON-PBE", "FAIL", 0, "No PoC-backed reproducible finding is present", evidence, "Do not submit; collect executable PoC evidence first.")


def check_safety(workspace: Path, files: dict[str, Path]) -> CheckResult:
    state = read_json(files.get("state.json", workspace / "missing")) or {}
    blocked = state.get("blocked_candidates", []) if isinstance(state, dict) else []
    negatives = read_text(workspace / "negative.md")
    loop_markers = read_text(workspace / "audit_trail.jsonl") + read_text(workspace / "tool_calls.jsonl")
    has_negative = bool(negatives.strip()) and "Negative evidence" not in negatives.strip()[-80:]
    has_blocked = bool(blocked)
    has_budget = bool(re.search(r"budget|loop|stop|critic|blocked|negative|reject", loop_markers, re.I))
    score = 0
    score += 7 if has_negative else 0
    score += 7 if has_blocked else 0
    score += 6 if has_budget else 0
    evidence = [f"negative_log={has_negative}", f"blocked_candidates={len(blocked) if isinstance(blocked, list) else 0}", f"budget_or_loop_markers={has_budget}"]
    if score >= 14:
        return CheckResult("APTS-SC", "PASS", 20, "Negative evidence or safety/budget controls are recorded", evidence)
    if score:
        return CheckResult("APTS-SC", "WARN", score, "Safety trail is partial", evidence, "Record rejected hypotheses and loop/budget decisions in the workspace.")
    return CheckResult("APTS-SC", "WARN", 6, "No negative-evidence or loop/budget trail found", evidence, "Append false positives and stop decisions to negative.md/audit_trail.jsonl.")


def evaluate(workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    files = workspace_files(workspace)
    manifest = collect_evidence_manifest(workspace)
    checks = [
        check_scope(workspace, files),
        check_auditability(workspace, files),
        check_hypothesis(workspace, files),
        check_reporting(workspace, files),
        check_safety(workspace, files),
    ]
    score = sum(c.score for c in checks)
    hard_fails = [c for c in checks if c.status == "FAIL"]
    if hard_fails:
        verdict = "BLOCK_REPORT"
    elif score >= 80:
        verdict = "READY_FOR_HUMAN_REVIEW"
    elif score >= 55:
        verdict = "NEEDS_MORE_EVIDENCE"
    else:
        verdict = "DO_NOT_SUBMIT"
    return {
        "workspace": str(workspace),
        "verdict": verdict,
        "score": score,
        "max_score": 100,
        "evidence_manifest": {
            "file_count": manifest["file_count"],
            "total_size": manifest["total_size"],
            "manifest_sha256": manifest["manifest_sha256"],
        },
        "checks": [asdict(c) for c in checks],
        "inspiration_mapping": {
            "OWASP_APTS": ["scope enforcement", "auditability", "safety controls", "reporting"],
            "POPPER": ["hypothesis", "controls", "falsification gaps"],
            "Shannon_Lite": ["proof-by-exploitation", "verified findings only"],
        },
    }


def format_markdown(result: dict[str, Any]) -> str:
    lines = ["# SRC Autonomy Audit Gate\n"]
    lines.append(f"Workspace: {result['workspace']}\n")
    lines.append(f"Verdict: {result['verdict']}\n")
    lines.append(f"Score: {result['score']}/{result['max_score']}\n")
    manifest = result.get("evidence_manifest", {})
    if manifest:
        lines.append(f"Evidence files: {manifest.get('file_count', 0)}\n")
        lines.append(f"Evidence manifest SHA256: {manifest.get('manifest_sha256', '')}\n")
    lines.append("\n## Checks\n")
    for check in result["checks"]:
        lines.append(f"- {check['check_id']} {check['status']} score={check['score']}: {check['reason']}\n")
        if check.get("recommendation"):
            lines.append(f"  Recommendation: {check['recommendation']}\n")
        if check.get("evidence"):
            lines.append(f"  Evidence: {'; '.join(check['evidence'][:8])}\n")
    lines.append("\n## External patterns absorbed\n")
    lines.append("- OWASP APTS: scope, safety, auditability, reporting governance.\n")
    lines.append("- POPPER: hypotheses must include controls and falsification gaps.\n")
    lines.append("- Shannon Lite: final report requires verified PoC-backed findings.\n")
    return "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit SRC workspace autonomy/evidence readiness")
    parser.add_argument("workspace", help="SRC workspace directory")
    parser.add_argument("--out", default="", help="Write markdown report path")
    parser.add_argument("--json-out", default="", help="Write JSON report path")
    parser.add_argument("--manifest-out", default="", help="Write evidence manifest JSON path")
    parser.add_argument("--verify-manifest", default="", help="Verify an existing evidence manifest JSON and exit")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    if not workspace.exists():
        print(f"Workspace not found: {workspace}")
        return 1

    if args.verify_manifest:
        verification = verify_evidence_manifest(workspace, Path(args.verify_manifest))
        print(json.dumps(verification, ensure_ascii=False, indent=2))
        return 0 if verification.get("ok") else 3

    result = evaluate(workspace)
    md = format_markdown(result)

    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    else:
        print(md)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.manifest_out:
        manifest = collect_evidence_manifest(Path(result["workspace"]))
        Path(args.manifest_out).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Verdict: {result['verdict']} score={result['score']}/100")
    return 0 if result["verdict"] in {"READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_EVIDENCE"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
