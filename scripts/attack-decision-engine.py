#!/usr/bin/env python3
"""
Attack Decision Engine v3.2 — 基于图谱的智能攻击路由

从图谱读取指纹/端点/漏洞状态，自动选择最佳攻击路径：
  - WAF自适应策略
  - Loop Guard集成（防止重复无效操作）
  - 优先级排序：RCE > SQLi > AuthBypass > IDOR > SSRF > InfoLeak
  - 支持 dry-run 模式

用法:
  attack-decision-engine.py <graph.db> [--mode full|fast|stealth] [--dry-run]
  attack-decision-engine.py <graph.db> --phase sqli [--target-host <host_id>]
  attack-decision-engine.py --waf-fingerprint <domain>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from importlib import import_module


def _get_graph(db_path):
    spec = import_module("vuln-graph-engine")
    return spec.PentestGraph(db_path)


# ─── WAF Fingerprint Database ─────────────────────────────────────────────────

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookies": ["__cflb", "__cfuid"],
        "block_codes": [403, 503],
        "block_body": ["attention required", "cloudflare ray id"],
        "delay_ms": 500, "batch_size": 5, "encoding": "unicode",
        "rotate_ua": True, "note": "Rotate UA + delay 500ms",
    },
    "aliyun_waf": {
        "headers": ["x-powered-by: yundun", "server: yundun"],
        "cookies": ["aliyungf_tc", "acw_tc", "acw_sc"],
        "block_codes": [405, 501],
        "block_body": ["request rejected", "aliyun"],
        "delay_ms": 300, "batch_size": 10, "encoding": "double_encoding",
        "rotate_ua": True, "note": "Double URL encoding",
    },
    "tencent_waf": {
        "headers": ["x-powered-by: tencent-waf"],
        "cookies": ["waf_cookie", "tencent_waf"],
        "block_codes": [218, 403],
        "block_body": ["tencent", "waf"],
        "delay_ms": 2000, "batch_size": 3, "encoding": "normal",
        "rotate_ua": True, "note": "~25 req then IP block, wait 30min",
    },
    "openrasp": {
        "headers": ["x-powered-by: openrasp"],
        "block_codes": [403, 500],
        "block_body": ["openrasp", "rasp"],
        "delay_ms": 200, "batch_size": 10, "encoding": "case_variation",
        "rotate_ua": True,
    },
    "safeline": {
        "headers": ["server: safeline"],
        "cookies": ["safeline_gc"],
        "block_codes": [403, 502],
        "block_body": ["safeline", "长亭雷池"],
        "delay_ms": 500, "batch_size": 5, "encoding": "http_smuggling",
        "rotate_ua": True,
    },
    "tengine": {
        "headers": ["server: tengine"],
        "block_codes": [405],
        "block_body": [],
        "delay_ms": 200, "batch_size": 10, "encoding": "normal",
        "rotate_ua": False, "note": "Non-whitelist paths return 405",
    },
}


# ─── Attack Phase Definitions ─────────────────────────────────────────────────

ATTACK_PHASES = {
    "cors": {
        "name": "CORS Misconfiguration",
        "priority": 60,
        "severity": "high",
        "conditions": lambda g, h: True,  # Always test
    },
    "info_leak": {
        "name": "Information Disclosure",
        "priority": 50,
        "severity": "medium",
        "conditions": lambda g, h: True,
    },
    "actuator": {
        "name": "Spring Boot Actuator",
        "priority": 85,
        "severity": "critical",
        "conditions": lambda g, h: any("spring" in f["tech"].lower() for f in g.get_fingerprints(h["id"])),
    },
    "nacos": {
        "name": "Nacos Unauthorized",
        "priority": 80,
        "severity": "critical",
        "conditions": lambda g, h: any("nacos" in f["tech"].lower() for f in g.get_fingerprints(h["id"])),
    },
    "shiro": {
        "name": "Shiro Deserialization",
        "priority": 90,
        "severity": "critical",
        "conditions": lambda g, h: any("shiro" in f["tech"].lower() for f in g.get_fingerprints(h["id"])),
    },
    "swagger": {
        "name": "Swagger/API Doc Exposure",
        "priority": 55,
        "severity": "medium",
        "conditions": lambda g, h: any(t in f["tech"].lower() for f in g.get_fingerprints(h["id"]) for t in ("swagger", "graphql")),
    },
    "sqli": {
        "name": "SQL Injection",
        "priority": 95,
        "severity": "critical",
        "conditions": lambda g, h: any(
            e.get("params") or "?" in (e.get("url") or "")
            for e in g.get_endpoints(h["id"])
        ),
    },
    "idor": {
        "name": "IDOR/BOLA",
        "priority": 75,
        "severity": "high",
        "conditions": lambda g, h: any(
            re.search(r"(id|uid|userId|memberId|orderId|fileId)", (e.get("url") or ""), re.I)
            for e in g.get_endpoints(h["id"])
        ),
    },
    "unauth_service": {
        "name": "Unauthenticated Service",
        "priority": 95,
        "severity": "critical",
        "conditions": lambda g, h: any(
            p["port"] in (6379, 27017, 9200, 5984, 2379, 8500) and p["state"] == "open"
            for p in g.get_ports(h["id"])
        ),
    },
    "git_leak": {
        "name": ".git Directory Exposure",
        "priority": 70,
        "severity": "high",
        "conditions": lambda g, h: True,
    },
}


class AttackDecisionEngine:
    """Intelligent attack routing based on graph state."""

    def __init__(self, graph_db: str, mode: str = "full", dry_run: bool = False):
        self.graph = _get_graph(graph_db)
        self.mode = mode
        self.dry_run = dry_run
        self.executed = []  # Track what we've run
        self.loop_guard = {}  # tool -> count

    def run(self, phase: str = None, target_host: int = None) -> dict:
        """Execute attack decisions."""
        results = {"attacks": [], "vulns_found": 0, "errors": []}

        # Get priority targets
        hosts = self.graph.priority_targets(top=20)
        if target_host:
            hosts = [h for h in hosts if h["id"] == target_host]

        if not hosts:
            print("[!] No targets in graph. Run recon first.")
            return results

        print(f"[*] Attack Engine v3.2: {len(hosts)} targets, mode={self.mode}")

        for host in hosts:
            hid = host["id"]
            domain = host.get("domain", "")
            waf = host.get("waf", "")

            # WAF-aware strategy
            waf_strategy = WAF_SIGNATURES.get(waf, {})

            # Determine which phases apply
            phases_to_run = {}
            if phase:
                if phase in ATTACK_PHASES:
                    phases_to_run[phase] = ATTACK_PHASES[phase]
            else:
                for pname, pdef in ATTACK_PHASES.items():
                    try:
                        if pdef["conditions"](self.graph, host):
                            phases_to_run[pname] = pdef
                    except Exception:
                        pass

            # Sort by priority
            sorted_phases = sorted(phases_to_run.items(), key=lambda x: x[1]["priority"], reverse=True)

            for pname, pdef in sorted_phases:
                # Loop guard
                guard_key = f"{pname}:{hid}"
                if self.loop_guard.get(guard_key, 0) >= 3:
                    continue

                attack_fn = getattr(self, f"_attack_{pname}", None)
                if not attack_fn:
                    continue

                print(f"\n  [*] {pdef['name']} on {domain} (priority={pdef['priority']})")
                if waf:
                    print(f"      WAF: {waf} | delay={waf_strategy.get('delay_ms','?')}ms | batch={waf_strategy.get('batch_size','?')}")

                try:
                    attack_result = attack_fn(host, waf_strategy)
                    if attack_result:
                        results["attacks"].append(attack_result)
                        if attack_result.get("vuln_id"):
                            results["vulns_found"] += 1
                except Exception as e:
                    results["errors"].append({"phase": pname, "host": domain, "error": str(e)})

                self.loop_guard[guard_key] = self.loop_guard.get(guard_key, 0) + 1

                # Rate limiting per WAF strategy
                delay = waf_strategy.get("delay_ms", 100) / 1000.0
                time.sleep(delay)

        self.graph.close()
        return results

    # ── CORS Attack ────────────────────────────────────────────────────────

    def _attack_cors(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Test CORS misconfiguration."""
        domain = host.get("domain", "")
        hid = host["id"]

        # Get endpoints or probe root
        endpoints = self.graph.get_endpoints(hid)
        urls = [e["url"] for e in endpoints[:5]]
        if not urls:
            scheme = "https"
            urls = [f"{scheme}://{domain}/"]

        for url in urls:
            cmd = f'curl -sk -H "Origin: https://evil.com" -D- "{url}" -m 10'
            if self.dry_run:
                print(f"    [DRY] {cmd}")
                continue

            result = self._exec(cmd, 15)
            output = result["stdout"]

            acao = self._extract_header(output, "access-control-allow-origin")
            acac = self._extract_header(output, "access-control-allow-credentials")

            if acao:
                severity = "high" if (acao in ("*", "https://evil.com", "null") and acac and "true" in acac.lower()) else "medium"
                cors_id = self.graph.add_cors(hid, url, acao, acac, "https://evil.com", severity)
                vuln_id = self.graph.add_vuln(
                    title=f"CORS Misconfiguration: ACAO={acao}",
                    severity=severity, host_id=hid,
                    vuln_type="cors", source="attack-engine",
                    poc=cmd,
                )
                self.graph.add_evidence(vuln_id, "response", output[:2000], f"CORS response from {url}")
                self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
                print(f"    [!] CORS: ACAO={acao} ACAC={acac} severity={severity}")
                return {"phase": "cors", "domain": domain, "url": url, "acao": acao, "severity": severity, "vuln_id": vuln_id}

        return None

    # ── Actuator Attack ────────────────────────────────────────────────────

    def _attack_actuator(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Probe Spring Boot Actuator endpoints."""
        domain = host.get("domain", "")
        hid = host["id"]

        for path in ["/actuator/env", "/actuator/health", "/actuator/info",
                      "/env", "/actuator/configprops", "/actuator/mappings"]:
            url = f"https://{domain}{path}"
            cmd = f'curl -sk "{url}" -m 10'
            if self.dry_run:
                print(f"    [DRY] {cmd}")
                continue

            result = self._exec(cmd, 15)
            body = result["stdout"]

            if result["exit_code"] == 0 and len(body) > 100:
                # Check for real data (not WAF/login page)
                if any(k in body for k in ("activeProfiles", "propertySources", "status", "beans", "mappings")):
                    vuln_id = self.graph.add_vuln(
                        title=f"Spring Boot Actuator Exposed: {path}",
                        severity="critical" if "env" in path else "high",
                        host_id=hid, vuln_type="info_leak",
                        poc=cmd, source="attack-engine",
                    )
                    self.graph.add_evidence(vuln_id, "response", body[:3000], f"Actuator {path}")
                    self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
                    self.graph.add_endpoint(hid, url, "GET", result["exit_code"], source="actuator-probe")
                    print(f"    [!] Actuator exposed: {path}")
                    return {"phase": "actuator", "domain": domain, "path": path, "vuln_id": vuln_id}

        return None

    # ── Nacos Attack ───────────────────────────────────────────────────────

    def _attack_nacos(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Check Nacos unauthorized access."""
        domain = host.get("domain", "")
        hid = host["id"]

        for base in ["/nacos", ""]:
            url = f"https://{domain}{base}/v1/auth/users?pageSize=100&pageNo=1"
            cmd = f'curl -sk "{url}" -m 10'
            if self.dry_run:
                print(f"    [DRY] {cmd}")
                continue

            result = self._exec(cmd, 15)
            body = result["stdout"]

            if result["exit_code"] == 0 and "pageItems" in body:
                try:
                    data = json.loads(body)
                    users = data.get("pageItems", [])
                    if users:
                        vuln_id = self.graph.add_vuln(
                            title="Nacos Unauthorized User Enumeration",
                            severity="critical", host_id=hid,
                            vuln_type="auth_bypass", poc=cmd,
                            source="attack-engine",
                            description=f"Exposed {len(users)} user accounts",
                        )
                        self.graph.add_evidence(vuln_id, "response", body[:3000], "Nacos user list")
                        self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
                        print(f"    [!] Nacos unauth: {len(users)} users")
                        return {"phase": "nacos", "domain": domain, "users": len(users), "vuln_id": vuln_id}
                except json.JSONDecodeError:
                    pass

        return None

    # ── Shiro Attack ───────────────────────────────────────────────────────

    def _attack_shiro(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Check Shiro rememberMe deserialization."""
        domain = host.get("domain", "")
        hid = host["id"]

        url = f"https://{domain}/"
        cmd = f'curl -sk -I "{url}" -H "Cookie: rememberMe=test" -m 10'
        if self.dry_run:
            print(f"    [DRY] {cmd}")
            return None

        result = self._exec(cmd, 15)
        headers = result["stdout"].lower()

        if "rememberme=deleteme" in headers:
            vuln_id = self.graph.add_vuln(
                title="Apache Shiro rememberMe Detected",
                severity="high", host_id=hid,
                vuln_type="deserialization", poc=cmd,
                source="attack-engine",
                description="Shiro rememberMe cookie accepted — potential deserialization attack",
            )
            self.graph.add_evidence(vuln_id, "response", result["stdout"][:1000], "Shiro deleteMe header")
            self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
            print(f"    [!] Shiro rememberMe detected")
            return {"phase": "shiro", "domain": domain, "vuln_id": vuln_id}

        return None

    # ── Swagger Attack ─────────────────────────────────────────────────────

    def _attack_swagger(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Check for exposed Swagger/API docs."""
        domain = host.get("domain", "")
        hid = host["id"]

        for path in ["/swagger-ui.html", "/api/swagger-ui.html", "/swagger-ui/",
                      "/v2/api-docs", "/v3/api-docs", "/api-docs",
                      "/graphql", "/graphiql"]:
            url = f"https://{domain}{path}"
            cmd = f'curl -sk -o /dev/null -w "%{{http_code}}" "{url}" -m 8'
            if self.dry_run:
                print(f"    [DRY] {cmd}")
                continue

            result = self._exec(cmd, 12)
            code = result["stdout"].strip().strip('"')

            if code in ("200",):
                vuln_id = self.graph.add_vuln(
                    title=f"API Documentation Exposed: {path}",
                    severity="medium", host_id=hid,
                    vuln_type="info_leak", poc=f'curl -sk "{url}"',
                    source="attack-engine",
                )
                self.graph.add_endpoint(hid, url, "GET", int(code), source="swagger-probe")
                self.graph.add_evidence(vuln_id, "curl", f'curl -sk "{url}"', "Reproduction command")
                print(f"    [!] Swagger/API doc: {path}")
                return {"phase": "swagger", "domain": domain, "path": path, "vuln_id": vuln_id}

        return None

    # ── Unauth Service Attack ──────────────────────────────────────────────

    def _attack_unauth_service(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Check unauthenticated services (Redis, MongoDB, ES, etc.)."""
        hid = host["id"]
        ip = host.get("ip", "")
        domain = host.get("domain", "")
        target = ip or domain

        port_checks = {
            6379: ("redis", "redis-cli -h {t} -p 6379 INFO server 2>&1 | head -5"),
            27017: ("mongodb", "curl -sk 'http://{t}:27017/' -m 5"),
            9200: ("elasticsearch", "curl -sk 'http://{t}:9200/_cat/indices' -m 5"),
            5984: ("couchdb", "curl -sk 'http://{t}:5984/_all_dbs' -m 5"),
            2379: ("etcd", "curl -sk 'http://{t}:2379/v2/keys/?recursive=true' -m 5"),
            8500: ("consul", "curl -sk 'http://{t}:8500/v1/agent/members' -m 5"),
        }

        ports = self.graph.get_ports(hid)
        for p in ports:
            port_num = p["port"]
            if port_num in port_checks and p["state"] == "open":
                service, cmd_template = port_checks[port_num]
                cmd = cmd_template.format(t=target)

                if self.dry_run:
                    print(f"    [DRY] {cmd}")
                    continue

                result = self._exec(cmd, 10)
                body = result["stdout"]

                # Check for real data (not errors)
                if body and len(body) > 20 and not any(k in body.lower() for k in ("connection refused", "error", "denied", "timeout")):
                    vuln_id = self.graph.add_vuln(
                        title=f"Unauthenticated {service.upper()} on port {port_num}",
                        severity="critical", host_id=hid,
                        vuln_type="auth_bypass", poc=cmd,
                        source="attack-engine",
                    )
                    self.graph.add_evidence(vuln_id, "response", body[:2000], f"{service} response")
                    self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
                    print(f"    [!] Unauth {service} on {target}:{port_num}")
                    return {"phase": "unauth_service", "service": service, "port": port_num, "vuln_id": vuln_id}

        return None

    # ── Git Leak Attack ────────────────────────────────────────────────────

    def _attack_git_leak(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Check for .git directory exposure."""
        domain = host.get("domain", "")
        hid = host["id"]

        url = f"https://{domain}/.git/HEAD"
        cmd = f'curl -sk "{url}" -m 8'
        if self.dry_run:
            print(f"    [DRY] {cmd}")
            return None

        result = self._exec(cmd, 12)
        body = result["stdout"]

        if "ref:" in body and result["exit_code"] == 0:
            vuln_id = self.graph.add_vuln(
                title=".git Directory Exposed",
                severity="high", host_id=hid,
                vuln_type="info_leak", poc=cmd,
                source="attack-engine",
            )
            self.graph.add_evidence(vuln_id, "response", body[:500], ".git/HEAD content")
            self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
            print(f"    [!] .git exposed")
            return {"phase": "git_leak", "domain": domain, "vuln_id": vuln_id}

        return None

    # ── SQLi Attack (stub — delegates to sqlmap) ───────────────────────────

    def _attack_sqli(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """SQL injection testing (parameterized endpoints)."""
        domain = host.get("domain", "")
        hid = host["id"]

        # Find parameterized endpoints
        endpoints = self.graph.get_endpoints(hid)
        sqli_candidates = []
        for ep in endpoints:
            url = ep.get("url", "")
            params = ep.get("params", "")
            if "?" in url or params:
                sqli_candidates.append(ep)

        if not sqli_candidates:
            return None

        # Test first 3 candidates with error-based detection
        for ep in sqli_candidates[:3]:
            url = ep["url"]
            # Add a test parameter
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}id=1'"
            cmd = f'curl -sk "{test_url}" -m 10'
            if self.dry_run:
                print(f"    [DRY] {cmd}")
                continue

            result = self._exec(cmd, 15)
            body = result["stdout"].lower()

            sql_errors = [
                "sql syntax", "mysql_fetch", "sqlite3.operational",
                "postgresql", "ora-", "microsoft ole db",
                "unclosed quotation", "syntax error",
            ]
            if any(err in body for err in sql_errors):
                vuln_id = self.graph.add_vuln(
                    title=f"SQL Injection: {url}",
                    severity="critical", host_id=hid,
                    endpoint_id=ep["id"], vuln_type="sqli",
                    poc=cmd, source="attack-engine",
                )
                self.graph.add_evidence(vuln_id, "response", result["stdout"][:2000], "SQL error response")
                self.graph.add_evidence(vuln_id, "curl", cmd, "Reproduction command")
                print(f"    [!] SQLi: {url}")
                return {"phase": "sqli", "url": url, "vuln_id": vuln_id}

        return None

    # ── IDOR Attack (stub) ─────────────────────────────────────────────────

    def _attack_idor(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """IDOR testing — needs auth context, stub for now."""
        # IDOR requires authenticated requests — this is a placeholder
        # Real IDOR testing happens in the Hermes agent loop with real tokens
        return None

    # ── Info Leak Attack ───────────────────────────────────────────────────

    def _attack_info_leak(self, host: dict, waf_strategy: dict) -> Optional[dict]:
        """Check common information disclosure paths."""
        domain = host.get("domain", "")
        hid = host["id"]

        leak_paths = [
            ("/.env", "critical"),
            ("/robots.txt", "info"),
            ("/sitemap.xml", "info"),
            ("/.DS_Store", "medium"),
            ("/WEB-INF/web.xml", "high"),
            ("/backup.zip", "high"),
            ("/dump.sql", "critical"),
            ("/phpinfo.php", "medium"),
            ("/server-status", "medium"),
            ("/server-info", "medium"),
        ]

        found = []
        for path, severity in leak_paths:
            url = f"https://{domain}{path}"
            cmd = f'curl -sk -o /dev/null -w "%{{http_code}}:%{{size_download}}" "{url}" -m 8'
            if self.dry_run:
                continue

            result = self._exec(cmd, 12)
            parts = result["stdout"].strip().strip('"').split(":")
            code = parts[0] if parts else ""
            size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

            if code == "200" and size > 50:
                vuln_id = self.graph.add_vuln(
                    title=f"Information Disclosure: {path}",
                    severity=severity, host_id=hid,
                    vuln_type="info_leak", poc=f'curl -sk "{url}"',
                    source="attack-engine",
                )
                found.append({"path": path, "severity": severity, "vuln_id": vuln_id})
                print(f"    [!] Leak: {path} ({severity})")

        return {"phase": "info_leak", "domain": domain, "found": found} if found else None

    # ── Helpers ────────────────────────────────────────────────────────────

    def _exec(self, cmd: str, timeout: int) -> dict:
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return {"stdout": proc.stdout[:50000], "stderr": proc.stderr[:5000], "exit_code": proc.returncode}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "TIMEOUT", "exit_code": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def _extract_header(self, raw_headers: str, header_name: str) -> str:
        """Extract header value from raw HTTP headers."""
        for line in raw_headers.splitlines():
            if line.lower().startswith(header_name.lower() + ":"):
                return line.split(":", 1)[1].strip()
        return ""


def cmd_waf_fingerprint(args):
    """Standalone WAF fingerprinting."""
    import urllib.request
    domain = args.domain
    print(f"[*] WAF fingerprinting: {domain}")

    headers_to_check = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Origin": "https://evil.com",
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}/"
        try:
            req = urllib.request.Request(url, headers=headers_to_check)
            resp = urllib.request.urlopen(req, timeout=10)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(2000).decode("utf-8", errors="replace")

            print(f"\n  URL: {url}")
            print(f"  Status: {resp.status}")
            print(f"  Server: {resp_headers.get('server', 'N/A')}")

            # Check WAF signatures
            detected = []
            for waf_name, sig in WAF_SIGNATURES.items():
                for h_check in sig.get("headers", []):
                    if ":" in h_check:
                        hname, hval = h_check.split(":", 1)
                        if hval.strip() in resp_headers.get(hname.strip().lower(), "").lower():
                            detected.append(waf_name)
                            break
                    elif h_check.lower() in str(resp_headers).lower():
                        detected.append(waf_name)
                        break

                for cookie in sig.get("cookies", []):
                    cookie_header = resp_headers.get("set-cookie", "").lower()
                    if cookie.lower() in cookie_header:
                        if waf_name not in detected:
                            detected.append(waf_name)

            if detected:
                print(f"  WAF Detected: {', '.join(detected)}")
                for w in detected:
                    strategy = WAF_SIGNATURES[w]
                    print(f"    {w}: delay={strategy['delay_ms']}ms batch={strategy['batch_size']} encoding={strategy['encoding']}")
            else:
                print("  WAF: None detected")

            break  # HTTPS worked, no need for HTTP
        except Exception as e:
            print(f"  {scheme}://{domain}: {e}")


def main():
    p = argparse.ArgumentParser(description="Attack Decision Engine v3.2")
    p.add_argument("graph_db", nargs="?", help="Path to graph.db")
    p.add_argument("--mode", choices=["full", "fast", "stealth"], default="full")
    p.add_argument("--phase", help="Run specific attack phase only")
    p.add_argument("--target-host", type=int, help="Target specific host ID")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--waf-fingerprint", metavar="DOMAIN", help="Fingerprint WAF for a domain")

    args = p.parse_args()

    if args.waf_fingerprint:
        args.domain = args.waf_fingerprint
        cmd_waf_fingerprint(args)
        return

    if not args.graph_db:
        p.print_help()
        return

    engine = AttackDecisionEngine(args.graph_db, args.mode, args.dry_run)
    results = engine.run(phase=args.phase, target_host=args.target_host)
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
