#!/usr/bin/env python3
"""Low-impact BOLA/IDOR checker for Hermes SRC workflows.

The checker requests a URL template with safe object identifiers and compares
status, hash, JSON keys, owner-like fields, and control IDs. It does not decide
reportability; it writes evidence that Hermes must review before any report.

Examples:
  src-idor-check.py 'https://target/api/detail?id={id}' --ids 1,2,999999
  src-idor-check.py 'https://target/api/order/{id}' --ids 1001,1002 --header 'Authorization: Bearer ...'
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

SENSITIVE_KEYS_RE = re.compile(r"name|realname|mobile|phone|email|idcard|identity|student|teacher|user|member|owner|tenant|org|dept|order|amount|address", re.I)
NEGATIVE_RE = re.compile(r"未登录|请登录|login|forbidden|unauthorized|not found|不存在|无权限|token|session|error", re.I)


@dataclass
class Resp:
    label: str
    identifier: str
    url: str
    status: str
    size: int
    content_type: str
    sha256: str
    title: str
    json_keys: str
    owner_fields: str
    sensitive_keys: str
    body_path: str
    header_path: str
    decision_hint: str = ""


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:80] or "item"


def parse_headers(values: list[str]) -> list[str]:
    return [v for v in values if ":" in v]


def curl_fetch(url: str, outdir: Path, label: str, timeout: int, method: str, headers: list[str], data: str = "") -> tuple[str, int, str, Path, Path]:
    key = hashlib.sha1(f"{method}\t{url}\t{label}".encode()).hexdigest()
    hp = outdir / "headers" / f"{safe_name(label)}-{key}.hdr"
    bp = outdir / "bodies" / f"{safe_name(label)}-{key}.body"
    hp.parent.mkdir(parents=True, exist_ok=True)
    bp.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["curl", "-skL", "--connect-timeout", "4", "--max-time", str(timeout), "-X", method]
    for h in headers:
        cmd.extend(["-H", h])
    if data:
        cmd.extend(["--data", data])
    cmd.extend(["-D", str(hp), "-o", str(bp), "-w", "%{http_code}\t%{size_download}\t%{content_type}", "-A", "Mozilla/5.0", url])
    env = os.environ.copy(); env["LC_ALL"] = "C"; env["LANG"] = "C"
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout + 5, env=env)
        parts = (cp.stdout.strip().split("\t") + ["", "", ""])[:3]
    except Exception:
        parts = ["000", "0", ""]
    try:
        size = int(parts[1])
    except Exception:
        size = 0
    return parts[0], size, parts[2], hp, bp


def read_text(path: Path, limit: int = 200000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def flatten_json_keys(obj: Any, prefix: str = "", out: set[str] | None = None) -> set[str]:
    if out is None:
        out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = f"{prefix}.{k}" if prefix else str(k)
            out.add(name)
            flatten_json_keys(v, name, out)
    elif isinstance(obj, list):
        for item in obj[:3]:
            flatten_json_keys(item, prefix + "[]", out)
    return out


def pick_owner_fields(obj: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    def walk(x: Any, prefix: str = "") -> None:
        if len(result) >= 20:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                name = f"{prefix}.{k}" if prefix else str(k)
                if re.search(r"owner|userId|uid|memberId|studentId|tenantId|orgId|deptId|companyId|creator|createBy|phone|mobile|email|name", str(k), re.I):
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        result[name] = str(v)[:80]
                walk(v, name)
        elif isinstance(x, list):
            for item in x[:2]:
                walk(item, prefix + "[]")
    walk(obj)
    return result


def analyze_body(bp: Path) -> tuple[str, str, str, str]:
    data = bp.read_bytes() if bp.exists() else b""
    sha = hashlib.sha256(data).hexdigest() if data else ""
    text = read_text(bp)
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    keys: set[str] = set()
    owners: dict[str, str] = {}
    try:
        obj = json.loads(text)
        keys = flatten_json_keys(obj)
        owners = pick_owner_fields(obj)
    except Exception:
        pass
    sensitive = sorted([k for k in keys if SENSITIVE_KEYS_RE.search(k)])[:40]
    return sha, title, ",".join(sorted(list(keys))[:80]), json.dumps(owners, ensure_ascii=False)[:800] + ("" if not owners else ""), ",".join(sensitive)


def make_resp(label: str, identifier: str, url: str, outdir: Path, timeout: int, method: str, headers: list[str], data: str) -> Resp:
    status, size, ctype, hp, bp = curl_fetch(url, outdir, label, timeout, method, headers, data)
    sha, title, keys, owners, sensitive = analyze_body(bp)
    hint = ""
    blob = " ".join([status, title, read_text(bp, 2000)])
    if status.startswith("2") and size > 0 and not NEGATIVE_RE.search(blob):
        hint = "OBJECT_LIKE_RESPONSE"
    elif status in {"401", "403", "404", "000"} or NEGATIVE_RE.search(blob):
        hint = "NEGATIVE_CONTROL_OR_AUTH_REQUIRED"
    else:
        hint = "LOW_SIGNAL"
    return Resp(label, identifier, url, status, size, ctype, sha, title, keys, owners, sensitive, str(bp), str(hp), hint)


def verdict(resps: list[Resp]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    object_like = [r for r in resps if r.decision_hint == "OBJECT_LIKE_RESPONSE"]
    unique_hashes = {r.sha256 for r in object_like if r.sha256}
    unique_owner = {r.owner_fields for r in object_like if r.owner_fields and r.owner_fields != "{}"}
    has_sensitive = any(r.sensitive_keys for r in object_like)
    invalid_negative = any(r.label.startswith("control") and r.decision_hint == "NEGATIVE_CONTROL_OR_AUTH_REQUIRED" for r in resps)
    if len(object_like) >= 2 and len(unique_hashes) >= 2:
        reasons.append("multiple identifiers returned different non-error bodies")
    if len(unique_owner) >= 2:
        reasons.append("owner-like fields differ across identifiers")
    if has_sensitive:
        reasons.append("sensitive-looking JSON keys present")
    if invalid_negative:
        reasons.append("invalid/random control looks negative")
    if len(object_like) >= 2 and len(unique_hashes) >= 2 and (has_sensitive or len(unique_owner) >= 2) and invalid_negative:
        return "NEED_MORE_EVIDENCE_IDOR_CANDIDATE", reasons
    if object_like:
        return "MANUAL_REVIEW_LOW_CONFIDENCE", reasons or ["some object-like responses found but controls/ownership proof incomplete"]
    return "DO_NOT_SUBMIT", reasons or ["no object-like successful responses"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Low-impact BOLA/IDOR checker")
    ap.add_argument("template", help="URL template containing {id}, or a plain URL with ?id= style already included")
    ap.add_argument("--ids", required=True, help="Comma/newline separated object identifiers to test")
    ap.add_argument("--control-ids", default="999999999,00000000,hermes-nonexistent", help="Comma separated invalid/random IDs")
    ap.add_argument("--outdir", default="", help="Evidence directory; default /tmp/src-idor-check/<host>")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--header", action="append", default=[], help="Additional request header, can repeat")
    ap.add_argument("--data", default="", help="Optional request body for POST/PUT/PATCH; {id} is substituted")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()

    ids = [x.strip() for part in args.ids.split("\n") for x in part.split(",") if x.strip()]
    control_ids = [x.strip() for x in args.control_ids.split(",") if x.strip()]
    parsed = re.sub(r"\{id\}", ids[0] if ids else "0", args.template)
    host = re.sub(r"[^A-Za-z0-9_.-]+", "_", re.sub(r"^https?://", "", parsed).split("/")[0] or "target")
    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else Path("/tmp/src-idor-check") / host
    outdir.mkdir(parents=True, exist_ok=True)
    headers = parse_headers(args.header)
    method = args.method.upper()

    resps: list[Resp] = []
    for ident in ids:
        url = args.template.replace("{id}", ident)
        data = args.data.replace("{id}", ident) if args.data else ""
        resps.append(make_resp("candidate", ident, url, outdir, args.timeout, method, headers, data))
    for ident in control_ids:
        url = args.template.replace("{id}", ident)
        data = args.data.replace("{id}", ident) if args.data else ""
        resps.append(make_resp("control_invalid", ident, url, outdir, args.timeout, method, headers, data))

    v, reasons = verdict(resps)
    tsv = outdir / "idor_results.tsv"
    fields = list(asdict(resps[0]).keys()) if resps else []
    if fields:
        with tsv.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, delimiter="\t", fieldnames=fields, lineterminator="\n")
            w.writeheader(); w.writerows(asdict(r) for r in resps)
    md = outdir / "idor_gate.md"
    lines = ["# IDOR/BOLA Gate\n\n", f"Verdict: {v}\n", "Reasons:\n"]
    for r in reasons:
        lines.append(f"- {r}\n")
    lines.append("\n## Results\n")
    for r in resps:
        lines.append(f"- {r.label} id={r.identifier} status={r.status} size={r.size} hint={r.decision_hint} sensitive={r.sensitive_keys} body={r.body_path}\n")
    lines.append("\n## Report boundary\n- This gate only identifies an IDOR/BOLA candidate. Submit only after proving authorization boundary with no-token/low-privilege/high-privilege controls and business impact.\n")
    md.write_text("".join(lines), encoding="utf-8")
    print(json.dumps({"verdict": v, "outdir": str(outdir), "tsv": str(tsv), "gate": str(md), "rows": len(resps)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
