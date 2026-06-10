#!/usr/bin/env python3
"""Hermes SRC workspace initializer.

Creates a deterministic, resumable workspace for SRC/pentest tasks.
No network access; safe to run anytime.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    return value.strip("-._") or "target"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Hermes SRC workspace")
    parser.add_argument("target", help="Target domain/name, e.g. bzuu.edu.cn")
    parser.add_argument("--root", default="/tmp/src-workspaces", help="Workspace root")
    parser.add_argument("--scope", default="", help="Optional scope note")
    parser.add_argument("--force", action="store_true", help="Reuse existing same-day workspace")
    args = parser.parse_args()

    os.environ.setdefault("LC_ALL", "C")
    os.environ.setdefault("LANG", "C")

    slug = slugify(args.target)
    date = time.strftime("%Y%m%d")
    base = Path(args.root).expanduser().resolve() / slug
    workspace = base / date
    if workspace.exists() and not args.force:
        i = 2
        while (base / f"{date}-{i}").exists():
            i += 1
        workspace = base / f"{date}-{i}"

    for sub in ["raw", "headers", "bodies", "screenshots", "candidate_reports", "final_reports", "logs", "scripts"]:
        (workspace / sub).mkdir(parents=True, exist_ok=True)

    files = {
        "scope.md": f"# Scope\n\nTarget: {args.target}\nScope note: {args.scope or 'public low-impact verification only'}\nCreated: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n",
        "assets.tsv": "host\tip\tprotocol\tstatus\tsize\tcontent_type\ttitle\tserver\twaf\thash\tdecision\tbody_path\theader_path\n",
        "endpoints.tsv": "source\tendpoint\tmethod_guess\tauth_hint\tkeyword\trisk_type\tpriority\tdecision\n",
        "probe_results.tsv": "method\turl\tstatus\tsize\tcontent_type\thash\ttitle\tsensitive_hit\tcontrol_result\tdecision\tbody_path\theader_path\n",
        "interesting.tsv": "type\turl\tevidence\tseverity_hint\tnext_step\n",
        "hypotheses.jsonl": "",
        "tool_calls.jsonl": "",
        "audit_trail.jsonl": "",
        "negative.md": f"# Negative evidence for {args.target}\n\n",
        "final_gate.md": f"# Final quality gate for {args.target}\n\nStatus: IN_PROGRESS\n\n",
    }
    for name, content in files.items():
        p = workspace / name
        if not p.exists():
            p.write_text(content, encoding="utf-8")

    state = {
        "target": args.target,
        "slug": slug,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "workspace": str(workspace),
        "current_phase": "initialized",
        "completed_phases": [],
        "submitted_root_causes": [],
        "blocked_candidates": [],
        "next_high_value_paths": [],
    }
    state_path = workspace / "state.json"
    if state_path.exists():
        old = json.loads(state_path.read_text(encoding="utf-8"))
        old.update({"workspace": str(workspace), "current_phase": old.get("current_phase", "initialized")})
        state = old
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    target_profile_dir = Path("/tmp/vuln_reports") / slug
    target_profile_dir.mkdir(parents=True, exist_ok=True)
    profile = target_profile_dir / "target_profile.md"
    if not profile.exists():
        profile.write_text(
            f"# Target profile: {args.target}\n\n"
            "## Submitted root causes\n\n- none recorded here yet\n\n"
            "## Negative evidence index\n\n- none recorded here yet\n\n"
            "## High-value remaining directions\n\n- unauthorized sensitive data/API access\n- auth bypass/account takeover\n- SQLi/RCE with safe proof\n- upload with executable or credible business impact\n\n"
            "## Do-not-report boundaries\n\n- WAF/403 only\n- SPA fallback\n- empty 200 responses\n- login redirects\n- public metadata/config without exploit impact\n",
            encoding="utf-8",
        )

    print(json.dumps({"success": True, "workspace": str(workspace), "target_profile": str(profile)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
