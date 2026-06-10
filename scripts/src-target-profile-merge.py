#!/usr/bin/env python3
"""Merge SRC workspace evidence summaries into /tmp/vuln_reports/<target>/target_profile.md."""
from __future__ import annotations

import argparse
import csv
import json
import re
import time
from pathlib import Path


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r'^https?://', '', value)
    value = re.sub(r'[^a-z0-9._-]+', '-', value)
    return value.strip('-._') or 'target'


def ensure_section(text: str, title: str) -> str:
    if f'## {title}' not in text:
        text = text.rstrip() + f'\n\n## {title}\n\n- none recorded here yet\n'
    return text


def replace_section(text: str, title: str, body: str) -> str:
    pat = re.compile(rf'(^## {re.escape(title)}\n)(.*?)(?=^## |\Z)', re.S | re.M)
    if pat.search(text):
        return pat.sub(rf'## {title}\n\n{body.rstrip()}\n\n', text)
    return text.rstrip() + f'\n\n## {title}\n\n{body.rstrip()}\n'


def rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def bulletize(items: list[str], empty='- none recorded here yet') -> str:
    clean = []
    seen = set()
    for item in items:
        item = re.sub(r'\s+', ' ', item).strip()
        if item and item not in seen:
            seen.add(item); clean.append(item)
    return '\n'.join(f'- {x}' for x in clean) if clean else empty


def main() -> int:
    ap = argparse.ArgumentParser(description='Update target_profile.md from a workspace')
    ap.add_argument('workspace')
    ap.add_argument('--target', default='', help='Target name/domain; default state.json target or workspace parent')
    ap.add_argument('--profile', default='', help='Explicit target_profile.md path')
    args = ap.parse_args()

    ws = Path(args.workspace).resolve()
    state = {}
    if (ws / 'state.json').exists():
        state = json.loads((ws / 'state.json').read_text(encoding='utf-8'))
    target = args.target or state.get('target') or ws.parent.name
    profile = Path(args.profile) if args.profile else Path('/tmp/vuln_reports') / slugify(target) / 'target_profile.md'
    profile.parent.mkdir(parents=True, exist_ok=True)
    if profile.exists():
        text = profile.read_text(encoding='utf-8', errors='replace')
    else:
        text = f'# Target profile: {target}\n'
    for sec in ['Submitted root causes', 'Negative evidence index', 'High-value remaining directions', 'Do-not-report boundaries', 'Recent workspace summary', 'Candidate API inventory']:
        text = ensure_section(text, sec)

    probes = rows(ws / 'probe_results.tsv')
    endpoints = rows(ws / 'endpoints.tsv')
    interesting = rows(ws / 'interesting.tsv')
    final_gate = (ws / 'final_gate.md').read_text(encoding='utf-8', errors='replace') if (ws / 'final_gate.md').exists() else ''
    negative = (ws / 'negative.md').read_text(encoding='utf-8', errors='replace') if (ws / 'negative.md').exists() else ''

    review_probe = [r for r in probes if (r.get('decision') or '').upper() in {'PENDING_REVIEW', 'NEED_REVIEW'} or r.get('sensitive_hit')]
    high_eps = [r for r in endpoints if (r.get('priority') or '').lower() == 'high']
    med_eps = [r for r in endpoints if (r.get('priority') or '').lower() == 'medium']

    summary_items = [
        f'updated {time.strftime("%Y-%m-%d %H:%M:%S %z")} from workspace {ws}',
        f'probe rows={len(probes)}, review-like rows={len(review_probe)}, endpoint rows={len(endpoints)}, high-priority endpoints={len(high_eps)}',
    ]
    m = re.search(r'Verdict:\s*([^\n]+)', final_gate)
    if m:
        summary_items.append(f'latest quality-gate verdict={m.group(1).strip()}')
    if interesting:
        summary_items.extend(f"interesting {r.get('type','')} {r.get('url','')} evidence={r.get('evidence','')[:120]}" for r in interesting[:20])
    text = replace_section(text, 'Recent workspace summary', bulletize(summary_items))

    api_items = []
    for r in high_eps[:60] + med_eps[:40]:
        api_items.append(f"[{r.get('priority','')}/{r.get('risk_type','')}] {r.get('method_guess','')} {r.get('endpoint','')} source={Path(r.get('source','')).name}")
    text = replace_section(text, 'Candidate API inventory', bulletize(api_items))

    neg_items = []
    for line in negative.splitlines():
        if line.strip().startswith('-') and 'none recorded' not in line:
            neg_items.append(line.strip()[1:].strip())
    for r in probes[:100]:
        if (r.get('decision') or '').upper() == 'NEGATIVE_OR_LOW_SIGNAL':
            neg_items.append(f"{r.get('status')} {r.get('url')} {r.get('title','')[:80]}")
    text = replace_section(text, 'Negative evidence index', bulletize(neg_items[:120]))

    profile.write_text(text.rstrip() + '\n', encoding='utf-8')
    print(json.dumps({'success': True, 'profile': str(profile), 'probes': len(probes), 'endpoints': len(endpoints), 'high_priority_endpoints': len(high_eps)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
