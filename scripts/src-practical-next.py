#!/usr/bin/python3
"""Generate practical next-step attack commands from Hermes SRC artifacts.

Input can be src-fast-assess output directories, probe_results.tsv, or a plain
alive URL list. Output is a ranked markdown plan plus copyable shell commands.

v2.0 (2026-06-09, NJMU lessons):
  - Subdomain value tiering: P0(api/auth/actuator) > P1(ehall/oa) > P2(static) > P3(cdn/placeholder)
  - Low-value auto-skip: CDN/placeholder/news hosts automatically filtered
  - Education-specific patterns: 金智CAS, SUDY, 正方/强智, 统一身份认证
  - Quick-exit: hosts scoring < threshold skipped entirely
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

# v2.0: Enhanced host patterns with priority tiers
P0_HOST_RE = re.compile(r"(^|[.-])(api|openapi|gateway|actuator|swagger|upload|file|oss|graphql|grpc|websocket|ws)([.-]|$)", re.I)
P1_HOST_RE = re.compile(r"(^|[.-])(authserver|cas|sso|ids|oauth|passport|login|portal|ehall|oa|xoa|workflow|admin|manage|cms|pay|order|booking|user|member|vip|crm|erp|hr|finance)([.-]|$)", re.I)
P2_HOST_RE = re.compile(r"(^|[.-])(app|mobile|m|wap|touch|h5|mini|weixin|wechat|alipay)([.-]|$)", re.I)

EDU_HOST_RE = re.compile(r"(^|[.-])(authserver|cas|ehall|one|portal|jw|jwxt|yjs|oa|vpn|webvpn|mail|ecard|pay|zfw|jwxt|yjscx|ksxt|cet)([.-]|$)", re.I)

# v2.0: Expanded low-value patterns - auto-skip these
# NOTE: test/dev/staging/jenkins/gitlab/nexus are NOT skipped in SRC - they are high-value attack surfaces
LOW_VALUE_HOST_RE = re.compile(r"(^|[.-])(www|www2|www3|static|cdn|assets|img|image|images|news|notice|bulletin|announc|blog|forum|bbs|wiki|doc|docs|help|faq|support|status|monitor|old|backup|bak|archive)([.-]|$)", re.I)

# v2.0: High-value admin/dev surfaces (P1 in SRC, NOT skipped)
ADMIN_DEV_HOST_RE = re.compile(r"(^|[.-])(test|dev|staging|demo|sandbox|jenkins|gitlab|nexus|sonar|fortify|jira|confluence|grafana|prometheus|zabbix|nagios)([.-]|$)", re.I)

# v2.0: CDN/placeholder detection
CDN_PLACEHOLDER_RE = re.compile(r"(^|[.-])(cdn|cloudfront|akamai|cloudflare|fastly|edgecast|limelight|cdn[0-9]*|img[0-9]*|static[0-9]*|assets[0-9]*)([.-]|$)", re.I)

PATH_WEIGHTS = {
    "actuator": 55,
    "api": 45,
    "swagger": 40,
    "upload": 55,
    "auth": 45,
    "login": 35,
    "cas": 42,
    "oauth": 42,
    "admin": 35,
    "manage": 35,
    "open": 32,
    "graphql": 38,
    # v2.0: Education-specific paths
    "ehall": 40,
    "ids": 42,
    "sso": 42,
    "portal": 30,
    "workflow": 35,
    "pay": 40,
    "file": 35,
    "upload": 55,
    "config": 40,
    "env": 40,
    "debug": 45,
    "trace": 40,
    "info": 30,
    "health": 20,
    "metrics": 30,
    "log": 25,
    "monitor": 25,
    "jolokia": 50,
    "hessian": 45,
    "invoker": 50,
}

# v2.0: Known safe/low-value response patterns (used by quality gate, kept here for reference)
LOW_VALUE_RESPONSE_PATTERNS = [
    r"htm file not found",
    r"redirecting\.\.\.",
    r"Application Not Authorized",
    r"<title>404</title>",
    r"<title>503</title>",
    r"Service Unavailable",
    r"nginx.*404",
]

# v2.0: Quick-exit threshold - hosts below this score are skipped
QUICK_EXIT_THRESHOLD = 15


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if not re.match(r"https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        return ""
    return value.rstrip("/")


def collect_urls(path: Path) -> list[str]:
    urls: list[str] = []
    if path.is_dir():
        for name in ("alive.txt", "urls.txt", "targets.txt"):
            candidate = path / name
            if candidate.exists():
                urls.extend(collect_urls(candidate))
        probe = path / "probe_results.tsv"
        if probe.exists():
            urls.extend(collect_urls(probe))
        return sorted(dict.fromkeys(urls))

    text = path.read_text(encoding="utf-8", errors="replace")
    first = text.splitlines()[0] if text.splitlines() else ""
    if "\t" in first and "url" in first.lower():
        reader = csv.DictReader(text.splitlines(), delimiter="\t")
        for row in reader:
            url = normalize_url(row.get("url", ""))
            if url:
                urls.append(url)
    else:
        for line in text.splitlines():
            url = normalize_url(line.split()[0] if line.split() else "")
            if url:
                urls.append(url)
    return sorted(dict.fromkeys(urls))


def classify_host_tier(host: str) -> str:
    """v2.0: Classify host into priority tier P0/P1/P2/P3/SKIP"""
    h = host.lower()

    # Skip CDN/placeholder
    if CDN_PLACEHOLDER_RE.search(h):
        return "SKIP"

    # Skip known low-value (www/static/news)
    if LOW_VALUE_HOST_RE.search(h):
        return "SKIP"

    # P0: API/auth/upload/actuator
    if P0_HOST_RE.search(h):
        return "P0"

    # P1: Education core / admin systems / admin-dev surfaces
    if P1_HOST_RE.search(h) or EDU_HOST_RE.search(h) or ADMIN_DEV_HOST_RE.search(h):
        return "P1"

    # P2: Mobile/app variants
    if P2_HOST_RE.search(h):
        return "P2"

    return "P2"  # Default to P2 for unknown hosts


def url_score(url: str) -> tuple[int, list[str]]:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    score = 10
    reasons: list[str] = []

    # v2.0: Tier-based scoring
    tier = classify_host_tier(host)
    if tier == "P0":
        score += 40
        reasons.append(f"P0-host({tier})")
    elif tier == "P1":
        score += 25
        reasons.append(f"P1-host({tier})")
    elif tier == "P2":
        score += 10
        reasons.append(f"P2-host({tier})")
    elif tier == "SKIP":
        score -= 30
        reasons.append("SKIP-tier(host)")

    if EDU_HOST_RE.search(host):
        score += 15
        reasons.append("education core system")

    for key, weight in PATH_WEIGHTS.items():
        if key in host or key in path:
            score += weight
            reasons.append(key)
    if parsed.scheme == "https":
        score += 3

    return max(score, 0), reasons


def commands_for(url: str) -> list[str]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    host = parsed.netloc
    # Sanitize host for filenames: replace : and special chars
    safe_host = re.sub(r'[^a-zA-Z0-9.-]', '_', host)
    qbase = shlex.quote(base)
    commands = [
        f'curl -skL -D- {qbase}"/" -o /tmp/hermes-src-{safe_host}-index.body',
        f'curl -skL -D- {qbase}"/actuator" -o /tmp/hermes-src-{safe_host}-actuator.body',
        f'curl -skL -D- {qbase}"/swagger-ui.html" -o /tmp/hermes-src-{safe_host}-swagger.body',
        f'curl -skL -D- {qbase}"/v3/api-docs" -o /tmp/hermes-src-{safe_host}-v3-api-docs.body',
        f'curl -skL -D- {qbase}"/api" -H "Origin: https://evil.example" -o /tmp/hermes-src-{safe_host}-api-cors.body',
    ]
    if re.search(r"cas|auth|sso|ids|authserver", host, re.I):
        commands.extend([
            f'curl -skL -D- {qbase}"/login?service=https://evil.example/cb" -o /tmp/hermes-src-{safe_host}-cas-redirect.body',
            f'curl -skL -D- {qbase}"/authserver/login?service=https://evil.example/cb" -o /tmp/hermes-src-{safe_host}-authserver-redirect.body',
        ])
    if re.search(r"upload|file|oss", host, re.I):
        commands.append(f'curl -skL -D- {qbase}"/api/upload" -o /tmp/hermes-src-{safe_host}-upload.body')
    return commands


def main() -> int:
    parser = argparse.ArgumentParser(description="Rank practical SRC next steps from existing artifacts")
    parser.add_argument("input", help="src-fast-assess dir, probe_results.tsv, or URL list")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--out", default="")
    parser.add_argument("--json-out", default="")
    # v2.0: New flags
    parser.add_argument("--skip-threshold", type=int, default=QUICK_EXIT_THRESHOLD,
                        help=f"Skip hosts scoring below this threshold (default: {QUICK_EXIT_THRESHOLD})")
    parser.add_argument("--show-skipped", action="store_true",
                        help="Show skipped low-value hosts in output")
    parser.add_argument("--tiers", action="store_true",
                        help="Show tier distribution summary")
    args = parser.parse_args()

    urls = collect_urls(Path(args.input))
    ranked = []
    skipped = []
    tier_counts = {"P0": 0, "P1": 0, "P2": 0, "SKIP": 0}

    for url in urls:
        score, reasons = url_score(url)
        tier = classify_host_tier(urlparse(url).netloc)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

        # v2.0: Quick-exit filter
        if score < args.skip_threshold:
            skipped.append({"url": url, "score": score, "tier": tier, "reasons": reasons})
            continue

        ranked.append({"url": url, "score": score, "reasons": reasons, "commands": commands_for(url), "tier": tier})

    ranked.sort(key=lambda item: item["score"], reverse=True)
    ranked = ranked[:args.top]

    lines = ["# Hermes SRC Practical Next Steps\n", f"Input: {args.input}\n"]
    lines.append(f"Total URLs: {len(urls)}, Ranked: {len(ranked)}, Skipped: {len(skipped)}\n")

    # v2.0: Tier distribution
    if args.tiers:
        lines.append(f"\n## Tier Distribution\n")
        for tier in ["P0", "P1", "P2", "SKIP"]:
            lines.append(f"- {tier}: {tier_counts.get(tier, 0)} URLs\n")

    lines.append("\n")
    for i, item in enumerate(ranked, 1):
        lines.append(f"## {i}. [{item['tier']}] score={item['score']} {item['url']}\n")
        lines.append(f"Reasons: {', '.join(item['reasons']) or 'baseline'}\n")
        for command in item["commands"][:7]:
            lines.append(f"{command}\n")
        lines.append("\n")

    # v2.0: Show skipped if requested
    if args.show_skipped and skipped:
        lines.append(f"\n## Skipped Low-Value Hosts ({len(skipped)})\n")
        for item in skipped[:20]:
            lines.append(f"- [{item['tier']}] score={item['score']} {item['url']} ({', '.join(item['reasons'])})\n")

    output = "".join(lines)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(ranked, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
