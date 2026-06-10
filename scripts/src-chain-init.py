#!/usr/bin/env python
"""Initialize a legal/authorized SRC chain workspace.
Creates JSONL evidence stores for scope, assets, hypotheses, evidence, validations, findings,
cleanup and tool_calls. This is a control/evidence framework, not an exploit tool.
"""
from __future__ import annotations
import argparse, json, os, time, uuid
from pathlib import Path

FILES = [
    "scope.json", "assets.jsonl", "hypotheses.jsonl", "evidence.jsonl",
    "validations.jsonl", "findings.jsonl", "cleanup.jsonl", "tool_calls.jsonl",
    "notes.md"
]

POLICY = {
    "mode": "authorized-only",
    "allowed": ["SRC", "CTF", "lab", "internal-test", "red-team-with-written-scope"],
    "forbidden": ["unauthorized access", "persistence", "lateral movement", "real data exfiltration", "destructive actions"],
    "proof_rule": "minimal safe proof; mask secrets/PII; prefer counts and synthetic objects",
}

def write_json(path: Path, obj: dict, overwrite: bool=False):
    if path.exists() and not overwrite:
        return
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Initialize authorized SRC Chain Workspace")
    ap.add_argument("target", help="target domain/project label, e.g. example.com")
    ap.add_argument("--root", default="/tmp/src-chain-workspaces", help="workspace root")
    ap.add_argument("--scope", default="", help="authorized scope description")
    ap.add_argument("--program", default="", help="SRC/program name")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in args.target)[:120]
    ws = Path(args.root).expanduser().resolve() / safe
    ws.mkdir(parents=True, exist_ok=True)
    for f in FILES:
        p = ws / f
        if f.endswith(".jsonl"):
            if not p.exists() or args.force:
                p.write_text("", encoding="utf-8")
        elif f == "notes.md":
            if not p.exists() or args.force:
                p.write_text(f"# SRC Chain Workspace: {args.target}\n\n", encoding="utf-8")
    scope = {
        "workspace_id": str(uuid.uuid4()),
        "created_at": int(time.time()),
        "target": args.target,
        "program": args.program,
        "scope": args.scope,
        "policy": POLICY,
        "status": "initialized",
    }
    write_json(ws / "scope.json", scope, overwrite=args.force or not (ws/"scope.json").exists())
    print(json.dumps({"ok": True, "workspace": str(ws), "target": args.target}, ensure_ascii=False))

if __name__ == "__main__":
    main()
