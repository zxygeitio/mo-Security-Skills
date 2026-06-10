#!/usr/bin/env python3
"""Build a Hermes skill neural graph and route index.

This is not an ML model. It is a deterministic control-plane graph that
connects skills by explicit references, related_skills frontmatter, shared
keywords, local artifacts, and task-domain signals so Hermes can load and
compose skills as a fused system instead of isolated documents.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

BASE = Path('/root/.hermes/skills')
DEFAULT_OUT = Path('/root/.hermes/data/skill-network')

DOMAIN_RULES: dict[str, dict[str, Any]] = {
    'global-control': {
        'must': ['global-control'],
        'keywords': ['控制', '全局', 'system', 'audit', 'mcp', 'cron', 'gateway', 'provider', 'skill', 'hermes'],
        'hubs': ['global-control', 'hermes-agent', 'native-mcp', 'hermes-agent-self-evolution', 'workspace-dispatch'],
    },
    'src-pentest': {
        'must': ['global-control', 'src-vuln-hunting', 'pentest-unified-engine'],
        'keywords': ['src', '渗透', '漏洞', 'pentest', 'burp', 'hexstrike', 'cve', 'poc', 'idor', 'sqli', 'rce'],
        'hubs': ['src-vuln-hunting', 'pentest-unified-engine', 'pentest-control-plane', 'web-pentest-fast', 'burp-suite-setup', 'hexstrike-usage', 'vuln-intel'],
    },
    'hermes-system': {
        'must': ['global-control', 'hermes-agent'],
        'keywords': ['hermes', 'agent', 'config', 'provider', 'gateway', 'mcp', 'cron', 'tools', 'skills', 'memory'],
        'hubs': ['hermes-agent', 'global-control', 'native-mcp', 'hermes-agent-self-evolution', 'hermes-web-ui'],
    },
    'mcp-tools': {
        'must': ['global-control', 'native-mcp'],
        'keywords': ['mcp', 'server', 'tool', 'stdio', 'http', 'burp', 'hexstrike', 'api'],
        'hubs': ['native-mcp', 'burp-suite-setup', 'hexstrike-usage', 'hexstrike-api-fallback'],
    },
    'long-task': {
        'must': ['global-control'],
        'keywords': ['long', '任务', 'cron', 'persistence', 'workspace', 'dispatch', 'agent', 'parallel', 'retry'],
        'hubs': ['workspace-dispatch', 'task-persistence', 'agent-retry-parallel', 'agent-execution-monitor', 'agent-task-planner'],
    },
    'mlops-training': {
        'must': [],
        'keywords': ['fine-tuning', 'lora', 'qlora', 'trl', 'dpo', 'grpo', 'axolotl', 'unsloth', 'training'],
        'hubs': ['axolotl', 'fine-tuning-with-trl', 'unsloth'],
    },
}


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith('---'):
        return {}, text
    parts = text.split('---', 2)
    if len(parts) < 3:
        return {}, text
    raw, body = parts[1], parts[2]
    data: dict[str, str] = {}
    current_key = None
    for line in raw.splitlines():
        if ':' in line and not line.startswith((' ', '\t')):
            key, value = line.split(':', 1)
            current_key = key.strip()
            data[current_key] = value.strip().strip('"')
        elif current_key and line.startswith((' ', '\t')):
            data[current_key] = data.get(current_key, '') + ' ' + line.strip()
    return data, body


def token_list(value: str) -> list[str]:
    return re.findall(r'[A-Za-z0-9][A-Za-z0-9_-]+|[\u4e00-\u9fff]{2,}', value or '')


def extract_skills(base: Path) -> list[dict[str, Any]]:
    skills = []
    for path in sorted(base.rglob('SKILL.md')):
        text = path.read_text(errors='replace')
        frontmatter, body = parse_frontmatter(text)
        rel = path.relative_to(base)
        name = frontmatter.get('name') or path.parent.name
        description = frontmatter.get('description', '')
        category = frontmatter.get('category') or str(rel.parent)
        backticks = re.findall(r'`([^`]+)`', body)
        local_refs = []
        missing_refs = []
        for token in backticks:
            if token.startswith(('references/', 'scripts/', 'templates/', 'assets/')) and '*' not in token:
                local_refs.append(token)
                target = path.parent / token
                if not target.exists():
                    missing_refs.append(token)
        related = token_list(frontmatter.get('related_skills', ''))
        tags = token_list(frontmatter.get('tags', ''))
        explicit = [t for t in backticks if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{2,64}', t)]
        words = set(re.findall(r'[A-Za-z][A-Za-z0-9_-]{2,}|[\u4e00-\u9fff]{2,}', (name + ' ' + description + ' ' + body[:8000]).lower()))
        skills.append({
            'name': name,
            'category': category,
            'path': str(path),
            'rel': str(rel),
            'description': description[:800],
            'tags': sorted(set(tags)),
            'related_skills': sorted(set(related)),
            'explicit_skill_refs': sorted(set(explicit)),
            'local_refs': sorted(set(local_refs)),
            'missing_local_refs': sorted(set(missing_refs)),
            'scripts': sorted(str(p.relative_to(path.parent)) for p in path.parent.glob('scripts/*') if p.is_file()),
            'references': sorted(str(p.relative_to(path.parent)) for p in path.parent.glob('references/*') if p.is_file()),
            'keywords': sorted(words),
            'size_bytes': path.stat().st_size,
        })
    return skills


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / len(a | b)


def build_graph(skills: list[dict[str, Any]]) -> dict[str, Any]:
    by_name = {s['name']: s for s in skills}
    names = set(by_name)
    text_cache = {s['name']: Path(s['path']).read_text(errors='replace').lower() for s in skills}
    edges: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def add_edge(src: str, dst: str, weight: float, reason: str) -> None:
        if src == dst or dst not in names or src not in names:
            return
        existing = edges[src].setdefault(dst, {'weight': 0.0, 'reasons': []})
        existing['weight'] += weight
        if reason not in existing['reasons']:
            existing['reasons'].append(reason)

    for skill in skills:
        src = skill['name']
        for dst in skill['related_skills']:
            add_edge(src, dst, 5.0, 'frontmatter.related_skills')
        for dst in skill['explicit_skill_refs']:
            add_edge(src, dst, 4.0, 'inline.skill_ref')
        text = text_cache[src]
        for dst in names:
            if dst != src and dst.lower() in text:
                add_edge(src, dst, 3.0, 'body.name_mention')

    keyword_sets = {s['name']: set(s['keywords']) for s in skills}
    for idx, left in enumerate(skills):
        for right in skills[idx + 1:]:
            score = jaccard(keyword_sets[left['name']], keyword_sets[right['name']])
            if score >= 0.055:
                weight = round(min(3.0, score * 18), 3)
                add_edge(left['name'], right['name'], weight, 'semantic.keyword_overlap')
                add_edge(right['name'], left['name'], weight, 'semantic.keyword_overlap')

    for skill in skills:
        for domain, rule in DOMAIN_RULES.items():
            domain_node = f'domain:{domain}'
            names.add(domain_node)
            haystack = ' '.join([skill['name'], skill['category'], skill['description'], ' '.join(skill['keywords'])]).lower()
            score = sum(1 for kw in rule['keywords'] if kw.lower() in haystack)
            if skill['name'] in rule.get('hubs', []):
                score += 6
            if skill['name'] in rule.get('must', []):
                score += 8
            if score:
                edges[domain_node].setdefault(skill['name'], {'weight': 0.0, 'reasons': []})
                edges[domain_node][skill['name']]['weight'] += float(score)
                edges[domain_node][skill['name']]['reasons'].append('domain.route_signal')
                add_edge(skill['name'], domain_node, max(1.0, score / 3), 'domain.backlink')

    nodes = []
    for skill in skills:
        degree_out = len(edges.get(skill['name'], {}))
        degree_in = sum(1 for src in edges for dst in edges[src] if dst == skill['name'])
        nodes.append({
            'id': skill['name'],
            'type': 'skill',
            'category': skill['category'],
            'path': skill['path'],
            'description': skill['description'],
            'degree_out': degree_out,
            'degree_in': degree_in,
            'hub_score': round(degree_in * 1.4 + degree_out + math.log1p(skill['size_bytes']) / 3, 3),
        })
    for domain in DOMAIN_RULES:
        node = f'domain:{domain}'
        nodes.append({'id': node, 'type': 'domain', 'degree_out': len(edges.get(node, {})), 'degree_in': 0, 'hub_score': 100.0})

    edge_rows = []
    for src, dsts in sorted(edges.items()):
        for dst, info in sorted(dsts.items()):
            edge_rows.append({'source': src, 'target': dst, 'weight': round(info['weight'], 3), 'reasons': sorted(info['reasons'])})
    return {'nodes': nodes, 'edges': edge_rows}


def best_routes(graph: dict[str, Any], limit: int = 10) -> dict[str, Any]:
    edges_by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in graph['edges']:
        edges_by_src[edge['source']].append(edge)
    routes = {}
    for domain in DOMAIN_RULES:
        src = f'domain:{domain}'
        ranked = sorted(edges_by_src.get(src, []), key=lambda e: e['weight'], reverse=True)
        selected = []
        seen = set()
        for must in DOMAIN_RULES[domain].get('must', []):
            if must not in seen:
                selected.append({'skill': must, 'weight': 999.0, 'reason': 'mandatory_hub'})
                seen.add(must)
        for edge in ranked:
            if edge['target'] not in seen and not edge['target'].startswith('domain:'):
                selected.append({'skill': edge['target'], 'weight': edge['weight'], 'reason': ','.join(edge['reasons'])})
                seen.add(edge['target'])
            if len(selected) >= limit:
                break
        routes[domain] = selected
    return routes


def query_routes(scan: dict[str, Any], routes: dict[str, Any], query: str, limit: int = 12) -> dict[str, Any]:
    text = query.lower()
    domain_scores = []
    for domain, rule in DOMAIN_RULES.items():
        score = sum(3 for kw in rule['keywords'] if kw.lower() in text)
        score += sum(6 for skill in rule.get('must', []) if skill.lower() in text)
        domain_scores.append((score, domain))
    domain_scores.sort(reverse=True)
    selected_domain = domain_scores[0][1] if domain_scores and domain_scores[0][0] > 0 else 'global-control'

    ranked: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(routes.get(selected_domain, [])):
        ranked[item['skill']] = {'skill': item['skill'], 'score': 100 - idx * 3, 'reasons': [f'domain:{selected_domain}', item['reason']]}
    for skill in scan['skills']:
        haystack = ' '.join([skill['name'], skill['category'], skill['description'], ' '.join(skill['keywords'])]).lower()
        score = 0
        hits = []
        for token in set(re.findall(r'[A-Za-z][A-Za-z0-9_-]{2,}|[\u4e00-\u9fff]{2,}', text)):
            if token in haystack:
                score += 5
                hits.append(token)
        if score:
            row = ranked.setdefault(skill['name'], {'skill': skill['name'], 'score': 0, 'reasons': []})
            row['score'] += score
            row['reasons'].append('query:' + ','.join(sorted(hits)[:8]))
    selected = sorted(ranked.values(), key=lambda x: x['score'], reverse=True)[:limit]
    return {
        'query': query,
        'selected_domain': selected_domain,
        'domain_scores': [{'domain': d, 'score': s} for s, d in domain_scores],
        'skills': selected,
        'mandatory_first': DOMAIN_RULES[selected_domain].get('must', []),
        'load_order': [item['skill'] for item in selected],
        'notes': [
            'Load mandatory_first before domain skills.',
            'Validate external backing services before trusting MCP/Burp/HexStrike outputs.',
            'Patch domain and hub skills when a reusable connection is discovered.',
        ],
    }


def clusters(graph: dict[str, Any]) -> list[dict[str, Any]]:
    undirected: dict[str, set[str]] = defaultdict(set)
    skill_nodes = {n['id'] for n in graph['nodes'] if n.get('type') == 'skill'}
    for edge in graph['edges']:
        if edge['source'] in skill_nodes and edge['target'] in skill_nodes and edge['weight'] >= 2.0:
            undirected[edge['source']].add(edge['target'])
            undirected[edge['target']].add(edge['source'])
    seen = set()
    result = []
    for node in sorted(skill_nodes):
        if node in seen:
            continue
        queue = deque([node])
        seen.add(node)
        comp = []
        while queue:
            cur = queue.popleft()
            comp.append(cur)
            for nxt in undirected[cur]:
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        result.append({'size': len(comp), 'skills': sorted(comp)})
    return sorted(result, key=lambda x: x['size'], reverse=True)


def write_markdown(outdir: Path, scan: dict[str, Any], graph: dict[str, Any], routes: dict[str, Any], comps: list[dict[str, Any]]) -> None:
    node_by_id = {n['id']: n for n in graph['nodes']}
    top_hubs = sorted([n for n in graph['nodes'] if n.get('type') == 'skill'], key=lambda n: n['hub_score'], reverse=True)[:15]
    missing = [(s['name'], ref) for s in scan['skills'] for ref in s['missing_local_refs']]
    lines = []
    lines.append('# Hermes Skill Neural Network')
    lines.append('')
    lines.append('## Summary')
    lines.append(f"- skills: {scan['summary']['skill_count']}")
    lines.append(f"- graph nodes: {len(graph['nodes'])}")
    lines.append(f"- graph edges: {len(graph['edges'])}")
    lines.append(f"- connected components: {len(comps)}")
    lines.append(f"- missing local references: {len(missing)}")
    lines.append('')
    lines.append('## Control Hubs')
    for node in top_hubs:
        lines.append(f"- {node['id']} score={node['hub_score']} in={node['degree_in']} out={node['degree_out']}")
    lines.append('')
    lines.append('## Domain Routes')
    for domain, skills in routes.items():
        chain = ' -> '.join(item['skill'] for item in skills[:8])
        lines.append(f"- {domain}: {chain}")
    lines.append('')
    lines.append('## Largest Clusters')
    for comp in comps[:8]:
        lines.append(f"- size={comp['size']}: {', '.join(comp['skills'][:20])}")
    lines.append('')
    lines.append('## Missing Local References')
    if missing:
        for name, ref in missing:
            lines.append(f"- {name}: {ref}")
    else:
        lines.append('- none')
    lines.append('')
    lines.append('## Use')
    lines.append('- Before a task, query `route-index.json` for domain routes, then load the mandatory hubs and top adjacent skills.')
    lines.append('- During a task, if a selected skill points to MCP/Burp/HexStrike/Cron/provider scripts, validate backing service health before relying on it.')
    lines.append('- After a complex task, patch both the domain skill and its hub edge if a new reusable connection is discovered.')
    (outdir / 'skill-network-report.md').write_text('\n'.join(lines) + '\n')


def main() -> int:
    parser = argparse.ArgumentParser(description='Build Hermes skill neural graph and route index')
    parser.add_argument('--skills-dir', default=str(BASE))
    parser.add_argument('--out-dir', default=str(DEFAULT_OUT))
    parser.add_argument('--query', default='', help='Optional task/domain text to rank routes for')
    args = parser.parse_args()
    base = Path(args.skills_dir)
    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    skills = extract_skills(base)
    scan = {
        'summary': {
            'skill_count': len(skills),
            'categories': sorted(set(s['category'] for s in skills)),
            'missing_ref_count': sum(len(s['missing_local_refs']) for s in skills),
            'oversized_count': sum(1 for s in skills if s['size_bytes'] > 80000),
        },
        'skills': skills,
    }
    graph = build_graph(skills)
    routes = best_routes(graph)
    comps = clusters(graph)
    (outdir / 'skill-scan.json').write_text(json.dumps(scan, ensure_ascii=False, indent=2))
    (outdir / 'skill-graph.json').write_text(json.dumps(graph, ensure_ascii=False, indent=2))
    (outdir / 'route-index.json').write_text(json.dumps(routes, ensure_ascii=False, indent=2))
    (outdir / 'clusters.json').write_text(json.dumps(comps, ensure_ascii=False, indent=2))
    query_result = None
    if args.query:
        query_result = query_routes(scan, routes, args.query)
        (outdir / 'last-query-route.json').write_text(json.dumps(query_result, ensure_ascii=False, indent=2))
    write_markdown(outdir, scan, graph, routes, comps)
    summary = {
        'out_dir': str(outdir),
        'skills': len(skills),
        'nodes': len(graph['nodes']),
        'edges': len(graph['edges']),
        'routes': len(routes),
        'components': len(comps),
        'missing_refs': scan['summary']['missing_ref_count'],
    }
    if query_result:
        summary['query_domain'] = query_result['selected_domain']
        summary['query_load_order'] = query_result['load_order'][:8]
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
