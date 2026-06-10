#!/usr/bin/env python3
"""
Association Analyzer v3.1 — 服务间信任关系分析

漏洞不在单个服务里，而在服务之间的"信任缝隙"中：
  1. SSO/OAuth信任链 — token在A签发，B是否无条件接受？
  2. CORS信任关系 — 哪些origin被信任？信任是否过宽？
  3. API网关 vs 后端 — 网关过滤了什么？后端是否假设网关已过滤？
  4. 缓存投毒 — 不同服务对同一cache key的理解是否一致？
  5. DNS/Host头信任 — 后端是否信任Host头生成URL？
  6. 共享Session — 不同子域/服务是否共享session？
  7. 回调URL信任 — redirect_uri/callback是否校验？

核心问题：系统由多个组件组成，每个组件都假设其他组件是可信的。
攻击者就活在这些假设的缝隙里。

用法:
  association-analyzer.py <graph.db> [--think] [--output /tmp/assoc.json]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from importlib import import_module

def _get_graph(db_path):
    spec = import_module("vuln-graph-engine")
    return spec.PentestGraph(db_path)


@dataclass
class TrustLink:
    """A trust relationship between two components."""
    source: str              # What trusts
    target: str              # What is trusted
    trust_type: str          # sso, cors, shared_session, callback, gateway_pass, cache, host_header
    evidence: list[str]      # What led us to this conclusion
    gap_description: str     # Where the vulnerability could hide
    test_method: str         # How to verify if trust is abused
    test_commands: list[str]
    severity: str            # critical/high/medium
    confidence: str          # high/medium/low


class AssociationAnalyzer:
    """Map trust relationships between services and find the gaps."""

    def __init__(self, graph_db: str):
        self.graph = _get_graph(graph_db)
        self.links: list[TrustLink] = []

    def analyze(self) -> list[TrustLink]:
        """Analyze all inter-service trust relationships."""
        self._analyze_sso_trust()
        self._analyze_cors_trust()
        self._analyze_shared_infrastructure()
        self._analyze_callback_redirect()
        self._analyze_host_header_trust()
        self._analyze_cross_service_data()

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2}
        self.links.sort(key=lambda l: sev_order.get(l.severity, 3))

        self.graph.close()
        return self.links

    # ── SSO/OAuth Trust Chains ─────────────────────────────────────────────

    def _analyze_sso_trust(self):
        """Analyze SSO/OAuth trust relationships."""
        endpoints = self.graph.get_endpoints()
        fingerprints = self.graph.get_fingerprints(host_id=None) if False else []

        # Get all fingerprints
        all_fp = [dict(r) for r in self.graph.conn.execute("SELECT * FROM fingerprints").fetchall()]

        # Find SSO/CAS/OAuth related services
        sso_fps = [fp for fp in all_fp if any(k in fp.get("tech", "").lower() for k in ("cas", "oauth", "saml", "sso", "shiro"))]

        # Find auth-related endpoints
        auth_eps = [
            ep for ep in endpoints
            if re.search(r"/auth|/login|/token|/oauth|/cas|/sso|/passport", ep.get("url", ""), re.I)
        ]

        # Find service endpoints that accept tokens
        service_eps = [
            ep for ep in endpoints
            if ep.get("auth_required") == 1
            or re.search(r"token|ticket|authorization|bearer", (ep.get("body_snippet", "") or "").lower())
        ]

        if auth_eps and service_eps:
            # Multiple services accepting the same SSO token = trust chain
            auth_domains = set()
            service_domains = set()
            for ep in auth_eps:
                url = ep.get("url", "")
                domain = re.search(r"://([^/]+)", url)
                if domain:
                    auth_domains.add(domain.group(1))
            for ep in service_eps:
                url = ep.get("url", "")
                domain = re.search(r"://([^/]+)", url)
                if domain:
                    service_domains.add(domain.group(1))

            cross_domain = service_domains - auth_domains
            if cross_domain:
                self.links.append(TrustLink(
                    source=", ".join(auth_domains),
                    target=", ".join(cross_domain),
                    trust_type="sso",
                    evidence=[f"Auth domains: {auth_domains}", f"Service domains: {service_domains}"],
                    gap_description=(
                        f"Services on {cross_domain} accept tokens from auth servers on {auth_domains}. "
                        f"If the auth server is compromised or a token can be forged, "
                        f"all trusting services are vulnerable. "
                        f"Also check: does the service validate token audience/issuer?"
                    ),
                    test_method="Use token from one service on another service",
                    test_commands=[
                        f'# Get token from auth service, then use on cross-domain service',
                        f'curl -sk -H "Authorization: Bearer TOKEN" "https://{list(cross_domain)[0]}/api/userinfo"',
                    ],
                    severity="high",
                    confidence="medium",
                ))

        # Check for CAS ticket reuse across services
        cas_eps = [ep for ep in endpoints if "ticket=" in (ep.get("url", "") or "").lower() or "cas" in (ep.get("url", "") or "").lower()]
        if len(cas_eps) > 1:
            domains = set()
            for ep in cas_eps:
                domain = re.search(r"://([^/]+)", ep.get("url", ""))
                if domain:
                    domains.add(domain.group(1))
            if len(domains) > 1:
                self.links.append(TrustLink(
                    source="CAS server",
                    target=", ".join(domains),
                    trust_type="sso",
                    evidence=[f"CAS endpoints on {len(domains)} domains"],
                    gap_description=(
                        f"CAS ticket accepted on {len(domains)} domains. "
                        f"Check: is the ticket validated against the service parameter? "
                        f"Can a ticket issued for service A be used on service B?"
                    ),
                    test_method="Use CAS ticket issued for domain A on domain B",
                    test_commands=[
                        f'# CAS ticket replay across services',
                        f'# 1. Get ticket for service A',
                        f'# 2. Use same ticket on service B',
                    ],
                    severity="critical",
                    confidence="medium",
                ))

    # ── CORS Trust ─────────────────────────────────────────────────────────

    def _analyze_cors_trust(self):
        """Analyze CORS trust relationships."""
        cors = [dict(r) for r in self.graph.conn.execute("SELECT * FROM cors_findings").fetchall()]

        for c in cors:
            acao = c.get("acao", "")
            url = c.get("url", "")
            acac = c.get("acac", "")

            if not acao:
                continue

            # Wildcard with credentials
            if acao == "*" and acac and "true" in acac.lower():
                self.links.append(TrustLink(
                    source="any origin",
                    target=url,
                    trust_type="cors",
                    evidence=[f"ACAO=* ACAC=true"],
                    gap_description=(
                        "Wildcard ACAO with credentials. Any website can read authenticated "
                        "responses from this endpoint. Attacker can steal user data via JS."
                    ),
                    test_method="Cross-origin authenticated request from attacker page",
                    test_commands=[
                        f'curl -sk -H "Origin: https://evil.com" -H "Cookie: session=VALID" "{url}" -D-',
                    ],
                    severity="critical",
                    confidence="high",
                ))

            # Reflected origin
            elif acao not in ("*", "null") and "evil" not in acao:
                # Check if origin is truly validated or just reflected
                self.links.append(TrustLink(
                    source="reflected origin",
                    target=url,
                    trust_type="cors",
                    evidence=[f"ACAO={acao}"],
                    gap_description=(
                        f"Origin '{acao}' is reflected in ACAO. "
                        f"If the server doesn't validate origin against a whitelist "
                        f"and simply reflects it, any origin can be used."
                    ),
                    test_method="Send arbitrary origin and check if reflected",
                    test_commands=[
                        f'curl -sk -H "Origin: https://attacker.com" "{url}" -D- | grep -i access-control',
                        f'curl -sk -H "Origin: null" "{url}" -D- | grep -i access-control',
                    ],
                    severity="high",
                    confidence="medium",
                ))

    # ── Shared Infrastructure ──────────────────────────────────────────────

    def _analyze_shared_infrastructure(self):
        """Analyze shared backend trust."""
        hosts = self.graph.get_hosts()

        # Group by IP
        ip_groups = defaultdict(list)
        for h in hosts:
            ip = h.get("ip", "")
            if ip:
                ip_groups[ip].append(h)

        for ip, group in ip_groups.items():
            if len(group) < 2:
                continue

            domains = [h.get("domain", "") for h in group]
            wafs = set(h.get("waf", "") for h in group if h.get("waf"))

            self.links.append(TrustLink(
                source=", ".join(domains[:5]),
                target=f"shared backend {ip}",
                trust_type="shared_infrastructure",
                evidence=[f"IP: {ip}", f"Domains: {domains[:5]}"],
                gap_description=(
                    f"Multiple domains ({', '.join(domains[:3])}) share backend {ip}. "
                    f"If one domain has weaker auth, it may provide access to others' data. "
                    f"Also: host header manipulation may route requests to wrong vhost."
                ),
                test_method="Access domain A's endpoints with domain B's Host header",
                test_commands=[
                    f'curl -sk -H "Host: {domains[0]}" "https://{ip}/" -k',
                ],
                severity="medium",
                confidence="medium",
            ))

    # ── Callback/Redirect Trust ────────────────────────────────────────────

    def _analyze_callback_redirect(self):
        """Analyze callback/redirect URL trust."""
        endpoints = self.graph.get_endpoints()

        callback_eps = [
            ep for ep in endpoints
            if re.search(r"callback|redirect|return|next|continue|returnUrl|redirect_uri",
                        ep.get("url", ""), re.I)
        ]

        for ep in callback_eps:
            url = ep.get("url", "")
            self.links.append(TrustLink(
                source="user input",
                target=url,
                trust_type="callback",
                evidence=[f"Callback/redirect endpoint: {url}"],
                gap_description=(
                    f"Endpoint {url} handles redirects/callbacks. "
                    f"If the redirect target is user-controlled and not validated, "
                    f"attacker can redirect users to malicious sites (open redirect) "
                    f"or steal OAuth tokens via manipulated redirect_uri."
                ),
                test_method="Inject arbitrary redirect URL",
                test_commands=[
                    f'curl -sk "{url}?redirect=https://evil.com" -D- -L --max-redirs 0',
                    f'curl -sk "{url}?returnUrl=https://evil.com" -D- -L --max-redirs 0',
                    f'curl -sk "{url}?next=javascript:alert(1)" -D-',
                ],
                severity="high",
                confidence="medium",
            ))

    # ── Host Header Trust ──────────────────────────────────────────────────

    def _analyze_host_header_trust(self):
        """Detect if backend trusts Host header for URL generation."""
        endpoints = self.graph.get_endpoints()

        # Endpoints that might generate URLs from Host header
        url_gen_patterns = [
            r"reset.*password", r"forgot.*password", r"verify.*email",
            r"activate", r"confirm", r"invite", r"share",
        ]

        for ep in endpoints:
            url = ep.get("url", "")
            for pattern in url_gen_patterns:
                if re.search(pattern, url, re.I):
                    self.links.append(TrustLink(
                        source="Host header",
                        target=url,
                        trust_type="host_header",
                        evidence=[f"URL-generating endpoint: {url}"],
                        gap_description=(
                            f"Endpoint {url} likely generates URLs (password reset, email verification). "
                            f"If it uses the Host header to construct the URL, "
                            f"an attacker can poison the link by injecting a malicious Host header."
                        ),
                        test_method="Send request with poisoned Host header",
                        test_commands=[
                            f'curl -sk -H "Host: evil.com" "{url}" -X POST -d "email=test@test.com" -D-',
                        ],
                        severity="high",
                        confidence="medium",
                    ))
                    break

    # ── Cross-Service Data Consistency ─────────────────────────────────────

    def _analyze_cross_service_data(self):
        """Detect data that's handled differently across services."""
        endpoints = self.graph.get_endpoints()

        # Find same resource accessible via different paths
        path_variants = defaultdict(list)
        for ep in endpoints:
            url = ep.get("url", "")
            # Normalize: remove version prefixes, trailing slashes
            normalized = re.sub(r"/v\d+/", "/", url).rstrip("/")
            normalized = re.sub(r"^https?://[^/]+", "", normalized)
            path_variants[normalized].append(ep)

        for norm_path, eps in path_variants.items():
            if len(eps) < 2:
                continue

            urls = [ep.get("url", "") for ep in eps]
            domains = set()
            for u in urls:
                d = re.search(r"://([^/]+)", u)
                if d:
                    domains.add(d.group(1))

            if len(domains) > 1:
                self.links.append(TrustLink(
                    source=", ".join(domains),
                    target=norm_path,
                    trust_type="cross_service",
                    evidence=[f"Same path on {len(domains)} domains: {urls[:5]}"],
                    gap_description=(
                        f"Resource '{norm_path}' exists on {len(domains)} different services. "
                        f"Different services may have different auth checks, "
                        f"data filters, or access controls. "
                        f"Find the weakest link."
                    ),
                    test_method="Compare responses from different services for same resource",
                    test_commands=[
                        f'curl -sk "{u}" -D- -m 10' for u in urls[:3]
                    ],
                    severity="medium",
                    confidence="medium",
                ))


def main():
    p = argparse.ArgumentParser(description="Association Analyzer v3.1")
    p.add_argument("graph_db", help="Path to graph.db")
    p.add_argument("--think", action="store_true", help="Analysis only, no execution")
    p.add_argument("--output", help="Output JSON file")
    args = p.parse_args()

    analyzer = AssociationAnalyzer(args.graph_db)
    links = analyzer.analyze()

    print(f"=== Association Analysis: {len(links)} Trust Links ===\n")

    for i, link in enumerate(links, 1):
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(link.severity, "⚪")
        print(f"{i}. {sev_icon} [{link.confidence.upper()}] {link.trust_type}: {link.source} → {link.target}")
        print(f"   Gap: {link.gap_description[:150]}")
        if link.test_commands:
            print(f"   Test: {link.test_commands[0][:120]}")
        print()

    if args.output:
        result = [asdict(l) for l in links]
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
