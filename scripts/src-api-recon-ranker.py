#!/usr/bin/env python3
"""Rank API/JS candidates for recon-driven SRC testing.

Inputs can be a Hermes workspace containing endpoints.tsv/js_api_findings.json or
explicit TSV/JSON/text files. Output is a ranked TSV plus a short markdown plan.
The ranker does not perform network access; it turns noisy API extraction into a
small, business-prioritized queue for low-impact verification.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs

CATEGORY_RULES = [
    ("auth_boundary", 100, r"login|logout|auth|oauth|sso|cas|token|session|jwt|refresh|password|passwd|pwd|reset|captcha|verify|sms|email|code"),
    ("idor_pii", 95, r"user|member|account|profile|person|student|teacher|employee|staff|patient|contact|phone|mobile|idcard|identity|realname|address"),
    ("object_access", 92, r"detail|info|get|query|view|download|export|list|page|search|record|history|order|invoice|bill|pay|refund|balance|score|grade|course|application|approval"),
    ("upload_file", 90, r"upload|file|attachment|import|avatar|image|oss|sign|signature|policy|callback|download|preview|deleteFile"),
    ("tenant_org", 88, r"tenant|org|organization|company|corp|school|dept|department|appId|clientId|group|role|permission|admin|manage|system"),
    ("admin_config", 82, r"admin|manage|config|setting|system|swagger|api-docs|openapi|actuator|druid|prometheus|metrics|debug|env"),
    ("business_flow", 80, r"register|signup|check|confirm|submit|create|add|update|save|delete|enable|disable|status|workflow|process"),
    ("secret_indicator", 78, r"secret|apikey|api_key|appkey|app_key|accesskey|access_key|authorization|bearer|credential|private"),
]

PARAM_RULES = [
    ("object_id", 14, r"(^|[_-])(id|uid|userId|memberId|studentId|orderId|fileId|resId|appId|tenantId|orgId|deptId|companyId|roleId|groupId)($|[_-])"),
    ("paging", 4, r"page|size|limit|offset|rows|current"),
    ("state_change", 10, r"status|role|type|permission|enabled|isAdmin|admin|owner|amount|price|quota|rate"),
]

METHOD_SCORE = {"GET": 0, "POST": 6, "PUT": 8, "PATCH": 8, "DELETE": 8}
LOW_VALUE_RE = re.compile(r"\.((png|jpg|jpeg|gif|svg|css|woff2?|ttf|ico|map|mp4|mp3|pdf|docx?|xlsx?))($|\?)", re.I)
FALLBACK_NOISE_RE = re.compile(r"/static/|/assets/|/node_modules/|webpack|runtime|chunk-|\.js($|\?)", re.I)


def norm(s: str) -> str:
    return (s or "").strip().strip('"\'` ,;')[:1000]


def infer_method(endpoint: str, row: dict[str, str]) -> str:
    raw = (row.get("method_guess") or row.get("method") or "").upper().strip()
    if raw in METHOD_SCORE:
        return raw
    low = endpoint.lower()
    if re.search(r"save|add|create|update|delete|upload|submit|login|auth|verify|send", low):
        return "POST"
    return "GET"


def params_from_endpoint(endpoint: str) -> set[str]:
    params: set[str] = set()
    parsed = urlparse(endpoint if re.match(r"https?://", endpoint) else "https://x.local" + (endpoint if endpoint.startswith("/") else "/" + endpoint))
    for k in parse_qs(parsed.query).keys():
        params.add(k)
    for m in re.finditer(r"[?&]([A-Za-z0-9_.-]+)=|[:{]([A-Za-z0-9_.-]*(?:id|Id|ID|token|Token|type|status)[A-Za-z0-9_.-]*)[}]?", endpoint):
        params.add(m.group(1) or m.group(2))
    for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Token|Type|Status|Code|Key))\b", endpoint):
        params.add(m.group(1))
    return params


def classify(endpoint: str, row: dict[str, str]) -> tuple[str, int, list[str]]:
    blob = " ".join([endpoint, row.get("risk_type", ""), row.get("auth_hint", ""), row.get("keyword", "")])
    reasons: list[str] = []
    best_cat, best_score = "api_candidate", 30
    for cat, score, pat in CATEGORY_RULES:
        if re.search(pat, blob, re.I):
            if score > best_score:
                best_cat, best_score = cat, score
            reasons.append(cat)
    method = infer_method(endpoint, row)
    best_score += METHOD_SCORE.get(method, 0)
    if method != "GET":
        reasons.append(f"method={method}")
    params = params_from_endpoint(endpoint)
    for pname in sorted(params):
        for label, score, pat in PARAM_RULES:
            if re.search(pat, pname, re.I):
                best_score += score
                reasons.append(f"param:{pname}:{label}")
    if re.search(r"/{[A-Za-z0-9_]+}|/:\w+|/\d+($|[/?#])", endpoint):
        best_score += 10
        reasons.append("path_object_identifier")
    if row.get("priority", "").lower() == "high":
        best_score += 8
        reasons.append("extractor_high_priority")
    if row.get("risk_type") == "secret_exposure" or endpoint.startswith("secret:"):
        best_score += 20
        reasons.append("secret_requires_impact_check")
    if LOW_VALUE_RE.search(endpoint) or FALLBACK_NOISE_RE.search(endpoint):
        best_score -= 35
        reasons.append("static_noise_penalty")
    if len(endpoint) > 220:
        best_score -= 8
        reasons.append("long_endpoint_penalty")
    return best_cat, max(0, min(150, best_score)), list(dict.fromkeys(reasons))


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", errors="replace", newline="") as f:
        return [dict(r) for r in csv.DictReader(f, delimiter="\t")]


def load_candidates(inputs: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for p in inputs:
        if p.is_dir():
            for child in [p / "endpoints.tsv", p / "js_api_findings.json"]:
                if child.exists():
                    rows.extend(load_candidates([child]))
            continue
        if not p.exists():
            continue
        if p.suffix.lower() == ".tsv":
            for r in read_tsv(p):
                ep = norm(r.get("endpoint") or r.get("url") or r.get("path") or "")
                if ep:
                    r["endpoint"] = ep
                    r.setdefault("source", str(p))
                    rows.append(r)
        elif p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                for key in ["endpoints", "urls", "scripts", "secrets"]:
                    for item in data.get(key, []) or []:
                        if not isinstance(item, dict):
                            continue
                        ep = norm(item.get("endpoint") or item.get("url") or (f"secret:{item.get('name','unknown')}:{item.get('value_sha256_12','')}" if key == "secrets" else ""))
                        if ep:
                            rows.append({"source": item.get("source", str(p)), "endpoint": ep, "risk_type": item.get("risk_type", "secret_exposure" if key == "secrets" else ""), "keyword": item.get("name", "")})
        else:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                ep = norm(line)
                if ep and not ep.startswith("#"):
                    rows.append({"source": str(p), "endpoint": ep})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Rank extracted API candidates for SRC verification")
    ap.add_argument("inputs", nargs="+", help="Workspace directories or endpoints.tsv/js_api_findings.json/text files")
    ap.add_argument("--out", default="", help="Ranked TSV output; default <workspace>/api_recon_ranked.tsv when first input is workspace")
    ap.add_argument("--plan", default="", help="Markdown plan output; default next to ranked TSV")
    ap.add_argument("--top", type=int, default=80)
    args = ap.parse_args()

    input_paths = [Path(x).expanduser().resolve() for x in args.inputs]
    candidates = load_candidates(input_paths)
    ranked = []
    seen = set()
    for r in candidates:
        ep = norm(r.get("endpoint", ""))
        if not ep or ep in seen:
            continue
        seen.add(ep)
        method = infer_method(ep, r)
        cat, score, reasons = classify(ep, r)
        params = ",".join(sorted(params_from_endpoint(ep)))
        next_step = {
            "auth_boundary": "check no-token/invalid-token behavior; map login/reset/register chain",
            "idor_pii": "run src-idor-check.py with safe IDs and auth/no-auth controls",
            "object_access": "test object id tampering, invalid id, and access-control contrast",
            "upload_file": "verify unauth upload/token/signature with harmless file and public access control",
            "tenant_org": "test tenant/org/role parameter tampering under low privilege",
            "admin_config": "verify exposure is real JSON/config, not login/WAF/SPA fallback",
            "business_flow": "model multi-step workflow and check missing auth between steps",
            "secret_indicator": "prove key/token impact with minimum safe API call before reporting",
            "api_candidate": "probe small batch; require sensitive data or state-changing proof",
        }.get(cat, "manual review")
        ranked.append({
            "score": score,
            "category": cat,
            "method": method,
            "endpoint": ep,
            "params": params,
            "source": r.get("source", ""),
            "risk_type": r.get("risk_type", ""),
            "reasons": ";".join(reasons),
            "next_step": next_step,
        })
    ranked.sort(key=lambda x: (-int(x["score"]), x["endpoint"]))
    ranked = ranked[: args.top]

    default_base = input_paths[0] if input_paths and input_paths[0].is_dir() else (input_paths[0].parent if input_paths else Path.cwd())
    out = Path(args.out).expanduser().resolve() if args.out else default_base / "api_recon_ranked.tsv"
    plan = Path(args.plan).expanduser().resolve() if args.plan else out.with_suffix(".md")
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["score", "category", "method", "endpoint", "params", "source", "risk_type", "reasons", "next_step"]
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, delimiter="\t", fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(ranked)

    lines = ["# API Recon Ranked Plan\n\n", f"Candidates ranked: {len(ranked)}\n\n", "## Top candidates\n"]
    for r in ranked[:30]:
        lines.append(f"- score={r['score']} {r['category']} {r['method']} {r['endpoint']}\n  - why: {r['reasons'] or '-'}\n  - next: {r['next_step']}\n")
    lines.append("\n## Usage notes\n- This is a prioritization queue, not a vulnerability result.\n- Report only after controls prove unauthorized access, IDOR, authentication bypass, usable key impact, or state-changing capability.\n")
    plan.write_text("".join(lines), encoding="utf-8")
    print(json.dumps({"success": True, "ranked": len(ranked), "out": str(out), "plan": str(plan)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
