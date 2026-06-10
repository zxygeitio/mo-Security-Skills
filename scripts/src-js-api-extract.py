#!/usr/bin/env python3
"""Extract JS URLs, API endpoints, secrets hints from saved HTTP bodies or URL lists.

Safe offline helper for Hermes SRC workspaces. It does not perform network access.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

JS_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", re.I)
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
API_RE = re.compile(r"(?<![A-Za-z0-9_])((?:/[A-Za-z0-9._~:@!$&'()*+,;=%-]+){1,}(?:\?[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?)")
SECRET_RE = re.compile(r"(?i)(appsecret|app_secret|apikey|api_key|accesskey|access_key|secretkey|secret_key|token|authorization|bearer|jwt|password|passwd|pwd)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})")
METHOD_HINT_RE = re.compile(r"(?i)\b(GET|POST|PUT|DELETE|PATCH)\b")
NOISE_EXT = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ttf', '.ico', '.map')


def norm_endpoint(s: str) -> str:
    s = s.strip().strip('"\'` )]}>,;')
    s = s.replace('\\/', '/')
    return s[:500]


def risk_for(endpoint: str, secret_hit: bool = False) -> str:
    low = endpoint.lower()
    if secret_hit:
        return 'secret_exposure'
    if any(k in low for k in ['upload', 'file', 'import', 'attachment']):
        return 'upload_or_file'
    if any(k in low for k in ['user', 'student', 'teacher', 'member', 'account', 'profile', 'person', 'employee']):
        return 'idor_or_pii'
    if any(k in low for k in ['order', 'pay', 'bill', 'balance', 'invoice']):
        return 'business_data'
    if any(k in low for k in ['admin', 'manage', 'config', 'actuator', 'swagger', 'druid']):
        return 'admin_or_config'
    return 'api_candidate'


def priority_for(risk: str, endpoint: str) -> str:
    if risk in {'secret_exposure', 'idor_or_pii', 'business_data'}:
        return 'high'
    if risk in {'upload_or_file', 'admin_or_config'}:
        return 'medium'
    if len(endpoint) > 180:
        return 'low'
    return 'medium'


def base_from_url(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return ''
    return f'{p.scheme}://{p.netloc}/'


def read_probe_rows(workspace: Path) -> list[dict[str, str]]:
    p = workspace / 'probe_results.tsv'
    if not p.exists():
        return []
    with p.open(encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def source_items(workspace: Path, extra_paths: list[str]) -> list[tuple[str, str, str]]:
    items: list[tuple[str, str, str]] = []  # source, base_url, text
    rows = read_probe_rows(workspace)
    for row in rows:
        body_path = row.get('body_path') or ''
        if body_path and Path(body_path).exists():
            try:
                text = Path(body_path).read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            items.append((body_path, base_from_url(row.get('url', '')), text))
    for raw in extra_paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            for child in sorted(p.rglob('*')):
                if child.is_file() and child.stat().st_size <= 5_000_000:
                    try:
                        items.append((str(child), '', child.read_text(encoding='utf-8', errors='ignore')))
                    except Exception:
                        pass
        elif p.exists() and p.is_file():
            try:
                items.append((str(p), '', p.read_text(encoding='utf-8', errors='ignore')))
            except Exception:
                pass
    return items


def main() -> int:
    ap = argparse.ArgumentParser(description='Extract JS/API candidates into workspace endpoints.tsv and js_api_findings.json')
    ap.add_argument('workspace')
    ap.add_argument('paths', nargs='*', help='Optional additional files/directories to parse')
    ap.add_argument('--out', default='', help='JSON output path; default workspace/js_api_findings.json')
    args = ap.parse_args()

    ws = Path(args.workspace).resolve()
    endpoints_tsv = ws / 'endpoints.tsv'
    if not endpoints_tsv.exists():
        endpoints_tsv.write_text('source\tendpoint\tmethod_guess\tauth_hint\tkeyword\trisk_type\tpriority\tdecision\n', encoding='utf-8')

    findings = {'scripts': [], 'urls': [], 'endpoints': [], 'secrets': []}
    seen = set()
    endpoint_rows = []

    for source, base, text in source_items(ws, args.paths):
        for m in JS_SRC_RE.finditer(text):
            js = urljoin(base, m.group(1)) if base else m.group(1)
            k = ('script', js)
            if k not in seen:
                seen.add(k); findings['scripts'].append({'source': source, 'url': js})
        for m in URL_RE.finditer(text):
            u = norm_endpoint(m.group(0))
            if u.lower().endswith(NOISE_EXT):
                continue
            k = ('url', u)
            if k not in seen:
                seen.add(k); findings['urls'].append({'source': source, 'url': u})
        for m in API_RE.finditer(text):
            ep = norm_endpoint(m.group(1))
            if len(ep) < 4 or ep.lower().endswith(NOISE_EXT) or ep.startswith('//'):
                continue
            if re.fullmatch(r'/[0-9./-]+', ep):
                continue
            k = ('endpoint', ep)
            if k in seen:
                continue
            seen.add(k)
            method = 'POST' if re.search(r'(?i)(save|add|update|delete|upload|submit|login|auth)', ep) else 'GET'
            auth_hint = 'auth_or_token' if re.search(r'(?i)(token|auth|session|login|sso|oauth)', ep) else ''
            risk = risk_for(ep)
            priority = priority_for(risk, ep)
            rec = {'source': source, 'endpoint': ep, 'method_guess': method, 'auth_hint': auth_hint, 'keyword': '', 'risk_type': risk, 'priority': priority, 'decision': 'PENDING_REVIEW'}
            findings['endpoints'].append(rec)
            endpoint_rows.append(rec)
        for m in SECRET_RE.finditer(text):
            name, value = m.group(1), m.group(2)
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            rec = {'source': source, 'name': name, 'value_sha256_12': digest, 'sample_prefix': value[:4], 'risk_type': 'secret_exposure'}
            findings['secrets'].append(rec)
            ep = f'secret:{name}:{digest}'
            if ('secret-endpoint', ep) not in seen:
                seen.add(('secret-endpoint', ep))
                endpoint_rows.append({'source': source, 'endpoint': ep, 'method_guess': '', 'auth_hint': name, 'keyword': name, 'risk_type': 'secret_exposure', 'priority': 'high', 'decision': 'VERIFY_IMPACT_BEFORE_REPORT'})

    with endpoints_tsv.open('a', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, delimiter='\t', fieldnames=['source','endpoint','method_guess','auth_hint','keyword','risk_type','priority','decision'], lineterminator='\n')
        for r in endpoint_rows:
            w.writerow(r)

    out = Path(args.out) if args.out else ws / 'js_api_findings.json'
    out.write_text(json.dumps(findings, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'success': True, 'out': str(out), 'scripts': len(findings['scripts']), 'urls': len(findings['urls']), 'endpoints': len(findings['endpoints']), 'secrets': len(findings['secrets']), 'endpoints_tsv': str(endpoints_tsv)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
