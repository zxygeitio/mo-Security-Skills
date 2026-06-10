#!/usr/bin/env python
"""Append structured records to an authorized SRC chain workspace."""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, time, uuid
from pathlib import Path

KINDS = {
    "asset": "assets.jsonl",
    "hypothesis": "hypotheses.jsonl",
    "evidence": "evidence.jsonl",
    "validation": "validations.jsonl",
    "finding": "findings.jsonl",
    "cleanup": "cleanup.jsonl",
    "tool_call": "tool_calls.jsonl",
}

SENSITIVE_KEYS = {"cookie", "authorization", "token", "password", "secret", "apikey", "api_key"}

def redact(v):
    if isinstance(v, dict):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE_KEYS else redact(val)) for k, val in v.items()}
    if isinstance(v, list):
        return [redact(x) for x in v]
    if isinstance(v, str) and len(v) > 120 and any(x in v.lower() for x in ["cookie", "token", "authorization"]):
        return v[:20] + "...[REDACTED]..." + v[-10:]
    return v

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

def parse_json_or_text(s: str):
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {"text": s}

def main():
    ap = argparse.ArgumentParser(description="Log a Chain Workspace record")
    ap.add_argument("workspace")
    ap.add_argument("kind", choices=sorted(KINDS))
    ap.add_argument("--title", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--severity", default="")
    ap.add_argument("--status", default="open")
    ap.add_argument("--tags", default="", help="comma-separated")
    ap.add_argument("--data", default="", help="JSON object or plain text")
    ap.add_argument("--from-file", default="", help="attach file metadata and sha256; content is not copied")
    ap.add_argument("--parent", default="")
    args = ap.parse_args()
    ws = Path(args.workspace).expanduser().resolve()
    if not (ws / "scope.json").exists():
        raise SystemExit(f"workspace missing scope.json: {ws}")
    rec = {
        "id": str(uuid.uuid4()),
        "ts": int(time.time()),
        "kind": args.kind,
        "title": args.title,
        "url": args.url,
        "severity": args.severity,
        "status": args.status,
        "tags": [x.strip() for x in args.tags.split(',') if x.strip()],
        "parent": args.parent,
        "data": redact(parse_json_or_text(args.data)),
    }
    if args.from_file:
        p = Path(args.from_file).expanduser().resolve()
        b = p.read_bytes()
        rec["file"] = {"path": str(p), "size": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    out = ws / KINDS[args.kind]
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    print(json.dumps({"ok": True, "file": str(out), "id": rec["id"], "kind": args.kind}, ensure_ascii=False))

if __name__ == "__main__":
    main()
