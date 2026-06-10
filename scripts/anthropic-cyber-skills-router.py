#!/usr/bin/env python3
"""Query the Anthropic Cybersecurity Skills corpus for Hermes fusion.

The external repo is large (754 skills). This router keeps it as an indexed
knowledge corpus and returns a small, task-specific set of source skills with
framework metadata so Hermes can fuse relevant procedures without loading or
installing the entire library.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

DEFAULT_AUDIT = Path('/tmp/anthropic-cybersecurity-skills-audit/audit.json')
DEFAULT_REPO = Path('/tmp/Anthropic-Cybersecurity-Skills')
DEFAULT_OUT = Path('/root/.hermes/data/external-skill-corpora/anthropic-cybersecurity')

HERMES_DOMAIN_BRIDGES = {
    'src-pentest': {
        'keywords': ['src', 'pentest', '漏洞', '渗透', 'web', 'api', 'idor', 'bola', 'sqli', 'ssrf', 'jwt', 'oauth', 'saml', 'cloud', 'cve', 'kev'],
        'hermes_skills': ['global-control', 'src-vuln-hunting', 'pentest-unified-engine', 'web-pentest-fast', 'vuln-intel'],
        'external_domains': ['web-api-appsec', 'cloud-security', 'identity-ad', 'supply-chain'],
    },
    'blue-team-dfir': {
        'keywords': ['dfir', 'forensics', 'incident', '日志', '取证', 'memory', 'volatility', 'siem', 'splunk', 'elastic', 'ioc', 'yara', 'sigma'],
        'hermes_skills': ['global-control', 'pentest-unified-engine', 'native-mcp'],
        'external_domains': ['dfir-forensics', 'threat-detection', 'malware-reverse', 'network-security'],
    },
    'cloud-identity': {
        'keywords': ['aws', 'azure', 'gcp', 'kubernetes', 'docker', 'entra', 'iam', 'active directory', 'kerberos', 'oauth', 'saml', 'zero trust'],
        'hermes_skills': ['global-control', 'native-mcp', 'pentest-unified-engine'],
        'external_domains': ['cloud-security', 'identity-ad', 'network-security'],
    },
    'ai-security': {
        'keywords': ['llm', 'prompt injection', 'jailbreak', 'rag', 'ai security', 'model poisoning', 'guardrail', 'atlas', 'ai rmf'],
        'hermes_skills': ['global-control', 'hermes-agent', 'hermes-agent-self-evolution'],
        'external_domains': ['ai-security', 'governance-risk', 'web-api-appsec'],
    },
    'risk-compliance': {
        'keywords': ['nist', 'mitre', 'attack', 'd3fend', 'csf', 'risk', 'compliance', 'governance', 'kev', 'epss', 'cve prioritization'],
        'hermes_skills': ['global-control', 'vuln-intel', 'hermes-agent-self-evolution'],
        'external_domains': ['governance-risk', 'threat-detection', 'supply-chain'],
    },
}


def load_audit(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())
    return data['skills']


def tokens(text: str) -> set[str]:
    return set(re.findall(r'[a-z][a-z0-9_+-]{2,}|[\u4e00-\u9fff]{2,}', text.lower()))


def select_bridge(query: str) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    q = query.lower()
    scored = []
    for name, bridge in HERMES_DOMAIN_BRIDGES.items():
        score = sum(4 for kw in bridge['keywords'] if kw in q)
        scored.append({'bridge': name, 'score': score, 'hermes_skills': bridge['hermes_skills'], 'external_domains': bridge['external_domains']})
    scored.sort(key=lambda r: r['score'], reverse=True)
    best = scored[0] if scored and scored[0]['score'] > 0 else {'bridge': 'risk-compliance', **HERMES_DOMAIN_BRIDGES['risk-compliance'], 'score': 0}
    return best['bridge'], HERMES_DOMAIN_BRIDGES[best['bridge']], scored


def rank(records: list[dict[str, Any]], query: str, limit: int) -> list[dict[str, Any]]:
    q_tokens = tokens(query)
    bridge_name, bridge, bridge_scores = select_bridge(query)
    rows = []
    for rec in records:
        hay = ' '.join([rec['name'], rec['dir'], rec.get('description', ''), ' '.join(rec.get('keywords', []))]).lower()
        rec_tokens = tokens(hay)
        overlap = q_tokens & rec_tokens
        score = len(overlap) * 8
        score += sum(12 for d in rec.get('domains', []) if d in bridge['external_domains'])
        score += len(rec.get('frameworks', {})) * 2
        if any(term in rec['name'] for term in ['detecting', 'analyzing', 'performing', 'implementing', 'auditing', 'hunting', 'testing', 'exploiting']):
            score += 3
        offensive_terms = ['idor', 'bola', 'api', 'oauth', 'jwt', 'saml', 'cve', 'kev', 'vulnerability', 'penetration', 'testing', 'exploiting', 'fuzzing']
        if bridge_name == 'src-pentest':
            score += sum(10 for term in offensive_terms if term in rec['name'] or term in hay)
            if any(term in rec['name'] for term in ['implementing', 'posture', 'controls', 'dlp']):
                score -= 8
        if score <= 0:
            continue
        rows.append({
            'name': rec['name'],
            'score': score,
            'domains': rec.get('domains', []),
            'description': rec.get('description', ''),
            'source_path': rec['path'],
            'repo_relative': rec['path'].replace(str(DEFAULT_REPO) + '/', '') if rec['path'].startswith(str(DEFAULT_REPO)) else rec.get('dir', ''),
            'frameworks': sorted(rec.get('frameworks', {}).keys()),
            'matched_terms': sorted(overlap)[:20],
        })
    rows.sort(key=lambda r: r['score'], reverse=True)
    return rows[:limit]


def write_markdown(out: Path, query_result: dict[str, Any]) -> None:
    lines = ['# Anthropic Cybersecurity Skills Fusion Query', '']
    lines.append(f"- query: {query_result['query']}")
    lines.append(f"- bridge: {query_result['bridge']}")
    lines.append(f"- hermes load first: {', '.join(query_result['hermes_load_first'])}")
    lines.append('')
    lines.append('## External Skills')
    for item in query_result['external_skills']:
        lines.append(f"- {item['name']} score={item['score']} domains={','.join(item['domains'])} frameworks={','.join(item['frameworks'])}")
        lines.append(f"  path: {item['source_path']}")
        if item['description']:
            lines.append(f"  desc: {item['description'][:180]}")
    lines.append('')
    lines.append('## Fusion Rules')
    lines.append('- Use external skills as procedure references, not final conclusions.')
    lines.append('- Preserve Hermes evidence gates: exploitability, A/B controls, response artifacts, and report readiness still decide submission.')
    lines.append('- Prefer copying stable distilled patterns into Hermes references instead of importing all 754 skills into active skill context.')
    out.write_text('\n'.join(lines) + '\n')


def main() -> int:
    parser = argparse.ArgumentParser(description='Query external Anthropic Cybersecurity Skills for Hermes fusion')
    parser.add_argument('--audit', default=str(DEFAULT_AUDIT))
    parser.add_argument('--out-dir', default=str(DEFAULT_OUT))
    parser.add_argument('--query', required=True)
    parser.add_argument('--limit', type=int, default=12)
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records = load_audit(Path(args.audit))
    bridge_name, bridge, bridge_scores = select_bridge(args.query)
    result = {
        'query': args.query,
        'bridge': bridge_name,
        'bridge_scores': bridge_scores,
        'hermes_load_first': bridge['hermes_skills'],
        'external_domains': bridge['external_domains'],
        'external_skills': rank(records, args.query, args.limit),
        'source_repo': str(DEFAULT_REPO),
        'audit_file': str(Path(args.audit)),
    }
    (out_dir / 'last-query.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    write_markdown(out_dir / 'last-query.md', result)
    print(json.dumps({
        'bridge': result['bridge'],
        'hermes_load_first': result['hermes_load_first'],
        'external_count': len(result['external_skills']),
        'top_external': [s['name'] for s in result['external_skills'][:8]],
        'out': str(out_dir),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
