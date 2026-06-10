#!/usr/bin/env python3
"""Initialize an authorized SRC/red-team target workspace.

This script does not attack a target. It creates the local state files that let
Hermes automatically gather assets/evidence and avoid repeatedly asking for
routine permissions.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-._") or "target"


def run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 999, str(e)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Primary domain/IP/case target")
    ap.add_argument("--scope", default="authorized SRC/red-team low-impact research", help="Scope summary")
    ap.add_argument("--program", default="", help="Program/rules URL if known")
    ap.add_argument("--mode", choices=["src", "redteam", "lab"], default="src")
    ap.add_argument("--root", default="/tmp/vuln_reports", help="Report/profile root")
    args = ap.parse_args()

    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    slug = slugify(args.target)
    root = Path(args.root) / slug
    root.mkdir(parents=True, exist_ok=True)

    profile = root / "target_profile.md"
    if not profile.exists():
        profile.write_text(f"""# Target Profile: {args.target}

Created: {now}
Mode: {args.mode}
Scope: {args.scope}
Program/rules: {args.program or 'unknown / user-stated authorization required'}

## Authorization and boundaries

- User grants Hermes autonomy for routine recon, asset discovery, JS/API extraction, fingerprinting, evidence capture, and verified low-impact vulnerability proof within this target scope.
- User will provide accounts manually when account-state testing is required.
- Do not perform destructive actions, high-volume brute force, password spraying, DoS, malware, extortion, or mass data extraction unless a formal exercise rule explicitly allows the specific action.

## Account matrix

- anonymous: available
- user A: pending user-provided account/cookie/token
- user B: pending user-provided account/cookie/token
- special role: pending

## Valuable business objects

- orderId / fileId / userId / orgId / applicationId / ticketId: pending discovery or user-provided self-owned IDs

## Automated discovery sources

- passive DNS / CT logs / historical URLs
- JS bundle/API extraction
- HTTP fingerprinting
- Burp/HexStrike/MCP when useful
- local evidence workspace under /tmp/src-workspaces

## Dedupe / prior reports

- pending check against /tmp/vuln_reports and session history

## Negative evidence

- none yet
""", encoding="utf-8")

    commands = {}
    for c in ["subfinder", "httpx", "nuclei", "naabu", "dnsx", "katana", "gau", "waybackurls", "jq", "nmap", "sqlmap", "ffuf", "feroxbuster", "amass"]:
        code, out = run(["bash", "-lc", f"command -v {c} || true"])
        commands[c] = out or "MISSING"

    state = {
        "target": args.target,
        "slug": slug,
        "mode": args.mode,
        "scope": args.scope,
        "program": args.program,
        "created_at": now,
        "profile": str(profile),
        "tool_paths": commands,
        "next_steps": [
            "Run src-workspace-init.py for an evidence workspace",
            "Collect passive assets/historical URLs/JS/API routes automatically",
            "Ask user only for account credentials or scope-changing decisions",
            "Verify P0/P1 candidates with controls before reporting",
        ],
    }
    state_path = root / "research_state.json"
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "target_root": str(root), "profile": str(profile), "state": str(state_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
