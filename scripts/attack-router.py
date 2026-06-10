#!/usr/bin/env python3
"""
Intelligent Attack Router v1.0 — 智能攻击路由引擎
根据目标指纹、WAF状态、历史成功率自动选择最佳攻击路径

用法:
  attack-router.py scan <target> [--outdir /tmp/attack_router] [--mode fast|full|stealth]
  attack-router.py fingerprint <target>
  attack-router.py route <graph_dir>
  attack-router.py execute <graph_dir> [--phase <phase_name>] [--dry-run]
  attack-router.py waf-adapt <target>
  attack-router.py history <fingerprint>
"""

import json
import os
import sys
import subprocess
import sqlite3
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import argparse
import re

# Try to import hermes tools for integrated execution
try:
    sys.path.insert(0, os.path.expanduser("~/.hermes/hermes-agent"))
    HAS_HERMES = True
except:
    HAS_HERMES = False


# === WAF Fingerprint Database ===
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookies": ["__cflb", "__cfuid", "cf_clearance"],
        "blocks": [403, 503],
        "bypass": ["unicode", "chunked", "http_smuggling", "case_variation"]
    },
    "aliyun_waf": {
        "headers": ["x-aliwaf-*", "eagleid"],
        "cookies": ["aliyungf_tc", "acw_tc"],
        "blocks": [405, 200],
        "response_patterns": ["Request Rejected"],
        "bypass": ["double_encoding", "unicode", "xff"]
    },
    "tencent_waf": {
        "headers": ["x-nws-*", "x-cache-lookup"],
        "blocks": [218, 403],
        "bypass": ["slow_loris", "ip_rotation"]
    },
    "openrasp": {
        "headers": ["x-request-id"],
        "blocks": [403],
        "response_patterns": ["openrasp", "blocked by"],
        "bypass": ["case_variation", "unicode", "double_encoding"]
    },
    "safeline": {
        "headers": ["x-safeline-*"],
        "blocks": [403, 502],
        "response_patterns": ["safeline", "长亭雷池"],
        "bypass": ["http_smuggling", "chunked"]
    },
    "sangfor_waf": {
        "headers": ["server: sangfor"],
        "blocks": [403, 302],
        "bypass": ["case_variation", "unicode"]
    },
    "akamai": {
        "headers": ["x-akamai-*", "server: akamaighost"],
        "blocks": [247, 403],
        "response_patterns": ["Access Denied"],
        "bypass": ["js_challenge", "ip_rotation"]
    },
    "f5_bigip": {
        "headers": ["server: bigip", "server: big-ip"],
        "cookies": ["bigipserverserver", "f5_"],
        "bypass": ["unicode", "case_variation"]
    },
    "tengine": {
        "headers": ["server: tengine"],
        "blocks": [405],
        "bypass": ["case_variation", "unicode"]
    },
    "nginx_waf": {
        "headers": ["server: nginx"],
        "blocks": [403, 406],
        "bypass": ["unicode", "path_traversal", "null_byte"]
    }
}

# === Attack Module Registry ===
ATTACK_MODULES = {
    "recon": {
        "priority": 10,
        "tools": ["subfinder", "amass", "httpx", "nmap", "whatweb"],
        "phases": ["subdomain_enum", "port_scan", "tech_fingerprint", "waf_detect"],
        "description": "Passive and active reconnaissance"
    },
    "finger": {
        "priority": 20,
        "tools": ["whatweb", "nuclei", "curl", "wappalyzer"],
        "phases": ["cms_detect", "framework_detect", "waf_fingerprint", "api_discovery"],
        "description": "Precise fingerprinting and attack surface mapping"
    },
    "low_hanging": {
        "priority": 30,
        "tools": ["curl", "nuclei", "ffuf"],
        "phases": ["info_leak", "cors_check", "security_headers", "default_pages", "sensitive_paths"],
        "description": "Low-hanging fruit collection"
    },
    "sqli": {
        "priority": 50,
        "tools": ["sqlmap", "curl"],
        "phases": ["detect", "exploit", "dump"],
        "description": "SQL injection detection and exploitation"
    },
    "rce": {
        "priority": 55,
        "tools": ["nuclei", "curl", "commix", "tplmap"],
        "phases": ["detect", "verify", "exploit"],
        "description": "Remote code execution"
    },
    "auth_bypass": {
        "priority": 60,
        "tools": ["curl", "hydra"],
        "phases": ["enum_users", "weak_password", "session_fixation", "token_leak"],
        "description": "Authentication bypass"
    },
    "idor": {
        "priority": 65,
        "tools": ["curl", "burp"],
        "phases": ["detect", "verify", "impact"],
        "description": "Insecure direct object reference"
    },
    "upload": {
        "priority": 70,
        "tools": ["curl"],
        "phases": ["detect", "bypass", "verify"],
        "description": "File upload exploitation"
    },
    "ssrf": {
        "priority": 75,
        "tools": ["curl", "burp"],
        "phases": ["detect", "internal_scan", "cloud_metadata"],
        "description": "Server-side request forgery"
    },
    "ssti": {
        "priority": 72,
        "tools": ["tplmap", "curl"],
        "phases": ["detect", "exploit"],
        "description": "Server-side template injection"
    },
    "xxe": {
        "priority": 68,
        "tools": ["curl"],
        "phases": ["detect", "file_read", "ssrf"],
        "description": "XML external entity"
    },
    "cors": {
        "priority": 40,
        "tools": ["curl"],
        "phases": ["detect", "exploit"],
        "description": "CORS misconfiguration"
    },
    "business_logic": {
        "priority": 80,
        "tools": ["curl", "python"],
        "phases": ["race_condition", "workflow_bypass", "price_manipulation", "mass_assignment"],
        "description": "Business logic vulnerabilities"
    },
    "api_security": {
        "priority": 55,
        "tools": ["curl", "jwt_tool"],
        "phases": ["enum_endpoints", "auth_test", "bola", "rate_limit"],
        "description": "API security testing"
    },
    "zero_day": {
        "priority": 90,
        "tools": ["nuclei", "searchsploit", "exploitdb_engine"],
        "phases": ["cve_lookup", "poc_verify", "exploit"],
        "description": "0-day vulnerability scanning"
    }
}

# === WAF Adaptive Strategy ===
class WAFAdapter:
    """Adaptive WAF bypass strategy selector."""

    def __init__(self):
        self.detected_waf = None
        self.bypass_strategies = []
        self.request_budget = 50  # Max requests before WAF trigger
        self.cooldown_seconds = 300

    def detect_waf(self, target: str, port: int = 443) -> dict:
        """Detect WAF by sending probe requests."""
        result = {"waf": "none", "confidence": 0, "details": {}}
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"

        try:
            # Normal request
            cmd = ['curl', '-sk', '-D-', '-o', '/dev/null',
                   '-w', '%{http_code}', f'{base_url}/', '--max-time', '10']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            normal_code = proc.stdout.strip()[-3:] if len(proc.stdout) >= 3 else "000"

            # SQL injection probe
            cmd2 = ['curl', '-sk', '-D-', '-o', '/dev/null',
                    '-w', '%{http_code}', f"{base_url}/?id=1'+OR+'1'='1", '--max-time', '10']
            proc2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
            sqli_code = proc2.stdout.strip()[-3:] if len(proc2.stdout) >= 3 else "000"
            headers = proc.stdout + proc2.stdout

            # XSS probe
            cmd3 = ['curl', '-sk', '-D-', '-o', '/dev/null',
                    '-w', '%{http_code}', f"{base_url}/?<script>alert(1)</script>", '--max-time', '10']
            proc3 = subprocess.run(cmd3, capture_output=True, text=True, timeout=15)
            xss_code = proc3.stdout.strip()[-3:] if len(proc3.stdout) >= 3 else "000"

            headers_lower = headers.lower()

            for waf_name, sig in WAF_SIGNATURES.items():
                score = 0
                # Check headers
                for h_sig in sig.get("headers", []):
                    if "*" in h_sig:
                        prefix = h_sig.replace("*", "")
                        if prefix.lower() in headers_lower:
                            score += 30
                    elif h_sig.lower() in headers_lower:
                        score += 30

                # Check block codes
                if int(sqli_code) in sig.get("blocks", []):
                    score += 20
                if int(xss_code) in sig.get("blocks", []):
                    score += 20

                # Check response patterns
                for pattern in sig.get("response_patterns", []):
                    if pattern.lower() in headers_lower:
                        score += 25

                if score > result["confidence"]:
                    result = {
                        "waf": waf_name,
                        "confidence": min(score, 100),
                        "details": {
                            "normal_code": normal_code,
                            "sqli_code": sqli_code,
                            "xss_code": xss_code,
                            "bypass_strategies": sig.get("bypass", [])
                        }
                    }

        except Exception as e:
            result["error"] = str(e)

        self.detected_waf = result["waf"] if result["confidence"] > 40 else "none"
        self.bypass_strategies = result.get("details", {}).get("bypass_strategies", [])
        return result

    def get_request_strategy(self, waf: str = None) -> dict:
        """Get request strategy for given WAF."""
        waf = waf or self.detected_waf or "none"
        strategies = {
            "none": {
                "delay_ms": 0, "batch_size": 20, "rotate_ua": False,
                "encoding": "normal", "max_concurrent": 10
            },
            "cloudflare": {
                "delay_ms": 500, "batch_size": 5, "rotate_ua": True,
                "encoding": "unicode", "max_concurrent": 2
            },
            "aliyun_waf": {
                "delay_ms": 300, "batch_size": 10, "rotate_ua": True,
                "encoding": "double_encoding", "max_concurrent": 3
            },
            "tencent_waf": {
                "delay_ms": 2000, "batch_size": 3, "rotate_ua": True,
                "encoding": "normal", "max_concurrent": 1,
                "note": "IP will be blocked at ~25 requests, wait 30min for unblock"
            },
            "openrasp": {
                "delay_ms": 200, "batch_size": 10, "rotate_ua": True,
                "encoding": "case_variation", "max_concurrent": 5
            },
            "safeline": {
                "delay_ms": 500, "batch_size": 5, "rotate_ua": True,
                "encoding": "http_smuggling", "max_concurrent": 2
            }
        }
        return strategies.get(waf, strategies["none"])

    def adapt_headers(self, headers: dict = None, waf: str = None) -> dict:
        """Adapt headers for WAF bypass."""
        headers = headers or {}
        waf = waf or self.detected_waf or "none"

        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]
        import random
        headers.setdefault("User-Agent", random.choice(ua_list))

        if waf in ("cloudflare", "akamai"):
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9"
            headers["Accept-Language"] = "en-US,en;q=0.9"
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Connection"] = "keep-alive"

        return headers


# === Attack Router ===
class AttackRouter:
    """Intelligent attack routing based on target fingerprint and history."""

    def __init__(self, outdir: str):
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.waf_adapter = WAFAdapter()
        self.tool_memory_db = os.path.expanduser("~/.hermes/data/tool_success.db")

    def _now(self):
        return datetime.now(timezone.utc).isoformat() + "Z"

    def quick_fingerprint(self, target: str) -> dict:
        """Quick fingerprint scan to determine attack routing."""
        result = {
            "target": target,
            "timestamp": self._now(),
            "hosts": [],
            "tech_stack": [],
            "waf": None,
            "recommended_attacks": [],
            "skip_reasons": []
        }

        # 1. DNS resolution
        try:
            proc = subprocess.run(['dig', '+short', target], capture_output=True, text=True, timeout=10)
            ips = [l.strip() for l in proc.stdout.strip().split('\n') if l.strip() and not l.startswith(';')]
            result["hosts"] = [ip for ip in ips if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip)]
        except:
            pass

        # 2. HTTP probe
        for scheme in ['https', 'http']:
            url = f"{scheme}://{target}/"
            try:
                cmd = ['curl', '-sk', '-D-', '-m', '10', '-o', '/dev/null',
                       '-w', 'status=%{http_code}|size=%{size_download}|time=%{time_total}', url]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                output = proc.stdout + proc.stderr
                headers = output.split('\r\n\r\n')[0] if '\r\n\r\n' in output else output

                # Extract tech stack
                for pattern, tech in [
                    (r'server:\s*(.+)', 'server'),
                    (r'x-powered-by:\s*(.+)', 'framework'),
                    (r'x-generator:\s*(.+)', 'cms'),
                ]:
                    m = re.search(pattern, headers, re.IGNORECASE)
                    if m:
                        result["tech_stack"].append({"type": tech, "value": m.group(1).strip()})

                # WAF detection
                waf_result = self.waf_adapter.detect_waf(target, 443 if scheme == 'https' else 80)
                result["waf"] = waf_result

                break
            except:
                continue

        # 3. Tech stack analysis → recommended attacks
        tech_str = " ".join([t["value"].lower() for t in result["tech_stack"]])

        # CMS-specific routing
        if any(x in tech_str for x in ['spring', 'springboot']):
            result["recommended_attacks"].append("actuator_scan")
        if any(x in tech_str for x in ['tomcat']):
            result["recommended_attacks"].append("tomcat_manager")
        if any(x in tech_str for x in ['nginx']):
            result["recommended_attacks"].append("nginx_misconfig")
        if any(x in tech_str for x in ['php']):
            result["recommended_attacks"].append("php_info_leak")
        if any(x in tech_str for x in ['iis']):
            result["recommended_attacks"].append("iis_shortname")

        # Default attacks for all HTTP targets
        result["recommended_attacks"].extend([
            "info_leak_scan", "cors_check", "sensitive_paths",
            "graphql_discovery", "jwt_detection", "oauth_detection"
        ])

        # WAF-adapted routing
        waf_name = result["waf"].get("waf", "none") if isinstance(result["waf"], dict) else "none"
        if waf_name != "none":
            strategy = self.waf_adapter.get_request_strategy(waf_name)
            result["waf_strategy"] = strategy
            # Reduce aggressive scans if WAF detected
            if waf_name in ("tencent_waf", "cloudflare", "akamai"):
                result["skip_reasons"].append(f"WAF detected ({waf_name}): reduce scan intensity")
                result["recommended_attacks"] = [
                    a for a in result["recommended_attacks"]
                    if a not in ("sqli_scan", "xss_scan")
                ]

        # Save result
        out_file = self.outdir / "fingerprint.json"
        with open(out_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)

        return result

    def route_attacks(self, graph_dir: str) -> list:
        """Route attacks based on target graph analysis."""
        graph_db = Path(graph_dir) / "target_graph.db"
        if not graph_db.exists():
            print(f"[!] Graph not found: {graph_db}")
            return []

        conn = sqlite3.connect(graph_db)
        c = conn.cursor()

        # Get all hosts with their fingerprints
        c.execute("""
            SELECT h.host, h.waf, p.port, p.service, p.product, p.version
            FROM hosts h
            LEFT JOIN ports p ON h.host = p.host
            WHERE p.state = 'open'
            ORDER BY h.host, p.port
        """)
        rows = c.fetchall()

        routes = []
        for host, waf, port, service, product, version in rows:
            route = {
                "host": host, "port": port, "service": service,
                "product": product, "version": version, "waf": waf,
                "attacks": []
            }

            # High-value services
            if service in ('redis', 'memcached', 'mongodb', 'elasticsearch'):
                route["attacks"].append({
                    "type": "auth_bypass", "tool": "curl/nmap",
                    "cmd": f'nmap -sV -p {port} {host}',
                    "reason": f"{service} unauthorized access check"
                })

            # Web services
            if service in ('http', 'https'):
                # Always check info leaks
                route["attacks"].append({
                    "type": "info_leak", "tool": "curl",
                    "cmd": f'for p in /robots.txt /.env /.git/config /swagger-ui.html /actuator/env; do curl -sk "{host}:{port}$p" -o /dev/null -w "$p: %{{http_code}}\\n"; done',
                    "reason": "Common sensitive path probe"
                })

                # CMS-specific
                if product:
                    product_lower = product.lower()
                    if 'spring' in product_lower:
                        route["attacks"].append({
                            "type": "info_leak", "tool": "curl",
                            "cmd": f'for ep in env beans configprops heapdump mappings health info; do curl -sk "{host}:{port}/actuator/$ep" -o /dev/null -w "/actuator/$ep: %{{http_code}}\\n"; done',
                            "reason": "Spring Boot Actuator endpoints"
                        })
                    if 'tomcat' in product_lower:
                        route["attacks"].append({
                            "type": "auth_bypass", "tool": "hydra",
                            "cmd": f'hydra -L /usr/share/wordlists/tomcat.txt -P /usr/share/wordlists/tomcat.txt {host} http-get /manager/html -s {port}',
                            "reason": "Tomcat Manager weak credentials"
                        })

                # CORS check
                route["attacks"].append({
                    "type": "cors", "tool": "curl",
                    "cmd": f'curl -sk -H "Origin: https://evil.com" "{host}:{port}/" -D- -o /dev/null',
                    "reason": "CORS misconfiguration check"
                })

            routes.append(route)

        conn.close()

        # Sort by attack value
        for route in routes:
            route["attacks"].sort(key=lambda a: SURFACE_WEIGHT.get(a["type"], 0), reverse=True)

        # Save routes
        out_file = self.outdir / "attack_routes.json"
        with open(out_file, 'w') as f:
            json.dump(routes, f, indent=2, default=str)

        return routes

    def execute_phase(self, graph_dir: str, phase: str = None, dry_run: bool = True):
        """Execute attack phase with intelligent routing."""
        routes = self.route_attacks(graph_dir)
        if not routes:
            print("[!] No routes to execute")
            return

        phase_filter = phase
        executed = 0
        skipped = 0

        for route in routes:
            host = route["host"]
            port = route["port"]

            for attack in route["attacks"]:
                if phase_filter and attack["type"] != phase_filter:
                    continue

                cmd = attack["cmd"]
                reason = attack["reason"]

                if dry_run:
                    print(f"  [DRY-RUN] {host}:{port} | {attack['type']} | {reason}")
                    print(f"    Cmd: {cmd[:120]}")
                    executed += 1
                else:
                    print(f"  [EXEC] {host}:{port} | {attack['type']} | {reason}")
                    try:
                        proc = subprocess.run(cmd, shell=True, capture_output=True,
                                             text=True, timeout=60)
                        output = proc.stdout[:500]
                        print(f"    Result: {output[:200]}")

                        # Save output
                        out_file = self.outdir / f"exec_{host}_{port}_{attack['type']}.txt"
                        with open(out_file, 'w') as f:
                            f.write(f"Command: {cmd}\n")
                            f.write(f"Reason: {reason}\n")
                            f.write(f"Output:\n{proc.stdout}\n")
                            f.write(f"Error:\n{proc.stderr}\n")
                        executed += 1
                    except subprocess.TimeoutExpired:
                        print(f"    [!] Timeout after 60s")
                        skipped += 1
                    except Exception as e:
                        print(f"    [!] Error: {e}")
                        skipped += 1

                    # WAF-aware delay
                    waf = route.get("waf")
                    if waf and waf != "none":
                        strategy = self.waf_adapter.get_request_strategy(waf)
                        delay = strategy.get("delay_ms", 0) / 1000
                        if delay > 0:
                            time.sleep(delay)

        print(f"\n[+] Executed: {executed}, Skipped: {skipped}")

    def waf_adapt(self, target: str):
        """Run WAF detection and show adaptive strategy."""
        result = self.waf_adapter.detect_waf(target)
        print(f"\n{'='*50}")
        print(f"  WAF DETECTION: {target}")
        print(f"{'='*50}")
        print(f"  WAF: {result['waf']}")
        print(f"  Confidence: {result['confidence']}%")

        if result.get("details"):
            d = result["details"]
            print(f"  Normal: HTTP {d.get('normal_code', '?')}")
            print(f"  SQLi:   HTTP {d.get('sqli_code', '?')}")
            print(f"  XSS:    HTTP {d.get('xss_code', '?')}")
            if d.get("bypass_strategies"):
                print(f"  Bypass strategies: {', '.join(d['bypass_strategies'])}")

        waf_name = result["waf"] if result["confidence"] > 40 else "none"
        strategy = self.waf_adapter.get_request_strategy(waf_name)
        print(f"\n  Request Strategy:")
        print(f"    Delay: {strategy['delay_ms']}ms")
        print(f"    Batch size: {strategy['batch_size']}")
        print(f"    Rotate UA: {strategy['rotate_ua']}")
        print(f"    Encoding: {strategy['encoding']}")
        print(f"    Max concurrent: {strategy['max_concurrent']}")
        if strategy.get("note"):
            print(f"    Note: {strategy['note']}")
        print(f"{'='*50}")

        # Save
        out_file = self.outdir / "waf_detection.json"
        with open(out_file, 'w') as f:
            json.dump({"target": target, "result": result, "strategy": strategy}, f, indent=2)
        print(f"\n[+] Saved to {out_file}")


SURFACE_WEIGHT = {
    "auth_bypass": 100, "rce": 95, "sqli": 90, "ssrf": 85,
    "idor": 80, "upload": 75, "ssti": 75, "xxe": 70,
    "cors": 60, "info_leak": 50, "xss": 40, "csrf": 30,
    "misconfig": 25, "version_leak": 10, "default_page": 5
}


def main():
    parser = argparse.ArgumentParser(description="Intelligent Attack Router v1.0")
    sub = parser.add_subparsers(dest="command")

    # fingerprint
    p_fp = sub.add_parser("fingerprint")
    p_fp.add_argument("target")
    p_fp.add_argument("--outdir", default="/tmp/attack_router")

    # route
    p_route = sub.add_parser("route")
    p_route.add_argument("graph_dir")
    p_route.add_argument("--outdir", default="/tmp/attack_router")

    # execute
    p_exec = sub.add_parser("execute")
    p_exec.add_argument("graph_dir")
    p_exec.add_argument("--phase")
    p_exec.add_argument("--dry-run", action="store_true", default=True)
    p_exec.add_argument("--outdir", default="/tmp/attack_router")

    # waf-adapt
    p_waf = sub.add_parser("waf-adapt")
    p_waf.add_argument("target")
    p_waf.add_argument("--outdir", default="/tmp/attack_router")

    # scan (full pipeline)
    p_scan = sub.add_parser("scan")
    p_scan.add_argument("target")
    p_scan.add_argument("--outdir", default="/tmp/attack_router")
    p_scan.add_argument("--mode", choices=["fast", "full", "stealth"], default="fast")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    router = AttackRouter(args.outdir)

    if args.command == "fingerprint":
        result = router.quick_fingerprint(args.target)
        print(f"\n{'='*50}")
        print(f"  QUICK FINGERPRINT: {args.target}")
        print(f"{'='*50}")
        print(f"  Hosts: {result['hosts']}")
        print(f"  Tech Stack:")
        for t in result['tech_stack']:
            print(f"    {t['type']}: {t['value']}")
        waf = result.get('waf', {})
        if isinstance(waf, dict) and waf.get('waf') != 'none':
            print(f"  WAF: {waf['waf']} (confidence: {waf['confidence']}%)")
        else:
            print(f"  WAF: None detected")
        print(f"  Recommended Attacks: {', '.join(result['recommended_attacks'])}")
        if result.get('skip_reasons'):
            for r in result['skip_reasons']:
                print(f"  [!] {r}")
        print(f"{'='*50}")

    elif args.command == "route":
        routes = router.route_attacks(args.graph_dir)
        print(f"\n[+] Generated {len(routes)} attack routes")
        for i, r in enumerate(routes[:10], 1):
            print(f"  [{i}] {r['host']}:{r['port']} ({r['service']}) — {len(r['attacks'])} attacks")
            for a in r['attacks'][:3]:
                print(f"      {a['type']}: {a['reason']}")

    elif args.command == "execute":
        router.execute_phase(args.graph_dir, args.phase, dry_run=True)

    elif args.command == "waf-adapt":
        router.waf_adapt(args.target)

    elif args.command == "scan":
        print(f"[*] Phase 1: Fingerprinting {args.target}...")
        result = router.quick_fingerprint(args.target)
        print(f"[+] WAF: {result.get('waf', {}).get('waf', 'none')}")

        # For full mode, also run nmap/httpx
        if args.mode in ("full", "stealth"):
            print(f"\n[*] Phase 2: Port scanning...")
            nmap_out = Path(args.outdir) / "nmap_quick.xml"
            nmap_cmd = f"nmap -sV -T4 --top-ports 1000 -oX {nmap_out} {args.target}"
            print(f"    Cmd: {nmap_cmd}")
            print(f"    (Run manually or via HexStrike MCP)")

        print(f"\n[+] Scan plan saved to {args.outdir}/")


if __name__ == "__main__":
    main()
