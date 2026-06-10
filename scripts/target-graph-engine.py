#!/usr/bin/env python3
"""
Target Graph Engine v1.0 — 统一目标图谱引擎
构建目标资产→指纹→漏洞→攻击路径的完整知识图谱
支持增量更新、跨工具关联、智能优先级排序

用法:
  target-graph-engine.py init <domain> [--outdir /tmp/target_graph]
  target-graph-engine.py add-host <graph_dir> --host <ip> --ports "22,80,443"
  target-graph-engine.py add-fingerprint <graph_dir> --host <ip> --port 80 --service http --product nginx --version 1.21
  target-graph-engine.py add-vuln <graph_dir> --host <ip> --port 80 --vuln "CVE-2021-1234" --severity high
  target-graph-engine.py from-nmap <graph_dir> --nmap-xml /tmp/scan.xml
  target-graph-engine.py from-nuclei <graph_dir> --nuclei-json /tmp/nuclei.json
  target-graph-engine.py from-httpx <graph_dir> --httpx-json /tmp/httpx.json
  target-graph-engine.py priority [--top N] [--severity critical,high]
  target-graph-engine.py attack-plan [--mode fast|full|stealth]
  target-graph-engine.py export [--format json|md|csv]
  target-graph-engine.py stats
  target-graph-engine.py correlate
"""

import json
import os
import sys
import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import argparse
import re

# === Severity scoring ===
SEVERITY_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}

# === Attack surface priority weights ===
SURFACE_WEIGHT = {
    "auth_bypass": 100, "rce": 95, "sqli": 90, "ssrf": 85,
    "idor": 80, "upload": 75, "ssti": 75, "xxe": 70,
    "cors": 60, "info_leak": 50, "xss": 40, "csrf": 30,
    "misconfig": 25, "version_leak": 10, "default_page": 5,
    # 2025-2026 new attack types
    "graphql": 70, "jwt": 80, "oauth": 75, "nextjs": 85,
    "race_condition": 75, "mass_assignment": 70, "tomcat_put_deser": 95,
    "subdomain_takeover": 65, "container_escape": 90
}

# === Service risk ranking ===
SERVICE_RISK = {
    "mysql": 85, "redis": 90, "mongodb": 85, "elasticsearch": 80,
    "memcached": 75, "postgresql": 80, "ftp": 60, "smb": 70,
    "rdp": 65, "ssh": 40, "http": 30, "https": 30,
    "docker": 75, "kubernetes": 90, "jenkins": 80, "gitlab": 70,
    "tomcat": 60, "weblogic": 80, "jboss": 70, "spring": 50,
    "nginx": 30, "apache": 30, "iis": 35, "actuator": 85,
    "swagger": 55, "graphql": 65, "consul": 80, "etcd": 85,
    "zookeeper": 70, "kafka": 65, "rabbitmq": 60
}

# === CVE exploit availability boost ===
EXPLOIT_BOOST = {
    "metasploit": 30, "poc_public": 25, "exploitdb": 20,
    "nuclei_template": 15, "manual_only": 5, "unknown": 0
}


class TargetGraph:
    """Unified target asset graph with SQLite backend."""

    def __init__(self, graph_dir: str):
        self.graph_dir = Path(graph_dir)
        self.graph_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.graph_dir / "target_graph.db"
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS target (
                domain TEXT PRIMARY KEY,
                created_at TEXT,
                updated_at TEXT,
                metadata TEXT
            );
            CREATE TABLE IF NOT EXISTS hosts (
                host TEXT PRIMARY KEY,
                ip TEXT,
                domain TEXT,
                os TEXT,
                first_seen TEXT,
                last_seen TEXT,
                alive INTEGER DEFAULT 1,
                waf TEXT,
                metadata TEXT
            );
            CREATE TABLE IF NOT EXISTS ports (
                host TEXT,
                port INTEGER,
                protocol TEXT DEFAULT 'tcp',
                state TEXT DEFAULT 'open',
                service TEXT,
                product TEXT,
                version TEXT,
                extra TEXT,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (host, port)
            );
            CREATE TABLE IF NOT EXISTS fingerprints (
                host TEXT,
                port INTEGER,
                fp_type TEXT,
                fp_value TEXT,
                confidence REAL DEFAULT 0.8,
                source TEXT,
                timestamp TEXT,
                PRIMARY KEY (host, port, fp_type, fp_value)
            );
            CREATE TABLE IF NOT EXISTS vulns (
                vuln_id TEXT,
                host TEXT,
                port INTEGER,
                service TEXT,
                severity TEXT,
                cvss REAL,
                cve TEXT,
                title TEXT,
                description TEXT,
                exploit_available TEXT DEFAULT 'unknown',
                exploit_boost INTEGER DEFAULT 0,
                detection_method TEXT,
                detection_result TEXT,
                poc TEXT,
                verified INTEGER DEFAULT 0,
                submitted INTEGER DEFAULT 0,
                timestamp TEXT,
                PRIMARY KEY (vuln_id, host, port)
            );
            CREATE TABLE IF NOT EXISTS attack_paths (
                path_id TEXT PRIMARY KEY,
                host TEXT,
                port INTEGER,
                attack_type TEXT,
                description TEXT,
                tools TEXT,
                commands TEXT,
                priority_score REAL,
                status TEXT DEFAULT 'candidate',
                result TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                vuln_id TEXT,
                host TEXT,
                port INTEGER,
                evidence_type TEXT,
                content TEXT,
                file_path TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS cors_findings (
                host TEXT,
                port INTEGER,
                origin_reflected INTEGER,
                acao TEXT,
                acac TEXT,
                severity TEXT,
                poc TEXT,
                timestamp TEXT,
                PRIMARY KEY (host, port)
            );
            CREATE TABLE IF NOT EXISTS api_endpoints (
                host TEXT,
                port INTEGER,
                path TEXT,
                method TEXT,
                params TEXT,
                auth_required INTEGER,
                response_code INTEGER,
                content_type TEXT,
                source TEXT,
                timestamp TEXT,
                PRIMARY KEY (host, port, path, method)
            );
            CREATE TABLE IF NOT EXISTS js_secrets (
                host TEXT,
                port INTEGER,
                js_path TEXT,
                secret_type TEXT,
                secret_value TEXT,
                context TEXT,
                timestamp TEXT,
                PRIMARY KEY (host, port, js_path, secret_type, secret_value)
            );
        """)
        conn.commit()
        conn.close()

    def _now(self):
        return datetime.now(timezone.utc).isoformat() + "Z"

    def init_target(self, domain: str, metadata: dict = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO target VALUES (?,?,?,?)",
                  (domain, self._now(), self._now(), json.dumps(metadata or {})))
        conn.commit()
        conn.close()
        print(f"[+] Target graph initialized for {domain}")
        print(f"    DB: {self.db_path}")

    def add_host(self, host: str, ip: str = None, domain: str = None,
                 os_info: str = None, waf: str = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO hosts
                     (host, ip, domain, os, first_seen, last_seen, alive, waf, metadata)
                     VALUES (?,?,?,?,?,?,?,?,?)""",
                  (host, ip or host, domain, os_info, self._now(), self._now(), 1, waf, "{}"))
        conn.commit()
        conn.close()

    def add_port(self, host: str, port: int, protocol: str = "tcp",
                 state: str = "open", service: str = None, product: str = None,
                 version: str = None, extra: str = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # Ensure host exists
        c.execute("SELECT host FROM hosts WHERE host=?", (host,))
        if not c.fetchone():
            self.add_host(host)
        c.execute("""INSERT OR REPLACE INTO ports
                     (host, port, protocol, state, service, product, version, extra, first_seen, last_seen)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (host, port, protocol, state, service, product, version, extra, self._now(), self._now()))
        conn.commit()
        conn.close()

    def add_fingerprint(self, host: str, port: int, fp_type: str,
                        fp_value: str, confidence: float = 0.8, source: str = "manual"):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO fingerprints
                     (host, port, fp_type, fp_value, confidence, source, timestamp)
                     VALUES (?,?,?,?,?,?,?)""",
                  (host, port, fp_type, fp_value, confidence, source, self._now()))
        conn.commit()
        conn.close()

    def add_vuln(self, vuln_id: str, host: str, port: int, service: str = None,
                 severity: str = "medium", cvss: float = None, cve: str = None,
                 title: str = None, description: str = None,
                 exploit_available: str = "unknown", detection_method: str = None,
                 detection_result: str = None, poc: str = None):
        boost = EXPLOIT_BOOST.get(exploit_available, 0)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO vulns
                     (vuln_id, host, port, service, severity, cvss, cve, title,
                      description, exploit_available, exploit_boost, detection_method,
                      detection_result, poc, verified, submitted, timestamp)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (vuln_id, host, port, service, severity, cvss, cve, title,
                   description, exploit_available, boost, detection_method,
                   detection_result, poc, 0, 0, self._now()))
        conn.commit()
        conn.close()

    def add_cors(self, host: str, port: int, origin_reflected: bool,
                 acao: str, acac: str, severity: str = "medium", poc: str = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO cors_findings
                     (host, port, origin_reflected, acao, acac, severity, poc, timestamp)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  (host, port, 1 if origin_reflected else 0, acao, acac, severity, poc, self._now()))
        conn.commit()
        conn.close()

    def add_api_endpoint(self, host: str, port: int, path: str, method: str = "GET",
                         params: str = None, auth_required: bool = None,
                         response_code: int = None, content_type: str = None,
                         source: str = "manual"):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO api_endpoints
                     (host, port, path, method, params, auth_required, response_code,
                      content_type, source, timestamp)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (host, port, path, method, params,
                   1 if auth_required else (0 if auth_required is not None else None),
                   response_code, content_type, source, self._now()))
        conn.commit()
        conn.close()

    def add_js_secret(self, host: str, port: int, js_path: str,
                      secret_type: str, secret_value: str, context: str = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO js_secrets
                     (host, port, js_path, secret_type, secret_value, context, timestamp)
                     VALUES (?,?,?,?,?,?,?)""",
                  (host, port, js_path, secret_type, secret_value, context, self._now()))
        conn.commit()
        conn.close()

    def add_attack_path(self, host: str, port: int, attack_type: str,
                        description: str, tools: list, commands: list,
                        priority_score: float = None, status: str = "candidate"):
        path_id = hashlib.md5(f"{host}:{port}:{attack_type}:{description}".encode()).hexdigest()[:12]
        if priority_score is None:
            priority_score = SURFACE_WEIGHT.get(attack_type, 30)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO attack_paths
                     (path_id, host, port, attack_type, description, tools, commands,
                      priority_score, status, result, timestamp)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                  (path_id, host, port, attack_type, description,
                   json.dumps(tools), json.dumps(commands),
                   priority_score, status, None, self._now()))
        conn.commit()
        conn.close()
        return path_id

    def add_evidence(self, vuln_id: str, host: str, port: int,
                     evidence_type: str, content: str, file_path: str = None):
        eid = hashlib.md5(f"{vuln_id}:{evidence_type}:{self._now()}".encode()).hexdigest()[:12]
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT INTO evidence
                     (evidence_id, vuln_id, host, port, evidence_type, content, file_path, timestamp)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  (eid, vuln_id, host, port, evidence_type, content, file_path, self._now()))
        conn.commit()
        conn.close()
        return eid

    # === Import methods ===
    def import_nmap_xml(self, xml_path: str):
        """Import nmap XML scan results."""
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            print("[!] xml.etree.ElementTree not available")
            return

        tree = ET.parse(xml_path)
        root = tree.getroot()
        count = 0

        for host_elem in root.findall('.//host'):
            addr = host_elem.find('address')
            if addr is None:
                continue
            ip = addr.get('addr', '')

            # OS detection
            os_elem = host_elem.find('.//osmatch')
            os_info = os_elem.get('name', '') if os_elem is not None else None

            self.add_host(ip, ip=ip, os_info=os_info)

            for port_elem in host_elem.findall('.//port'):
                port_id = int(port_elem.get('portid', 0))
                protocol = port_elem.get('protocol', 'tcp')
                state_elem = port_elem.find('state')
                state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

                service_elem = port_elem.find('service')
                service = product = version = extra = None
                if service_elem is not None:
                    service = service_elem.get('name')
                    product = service_elem.get('product')
                    version = service_elem.get('version')
                    extra_info = []
                    for attr in ['extrainfo', 'ostype', 'method']:
                        v = service_elem.get(attr)
                        if v:
                            extra_info.append(f"{attr}={v}")
                    extra = "; ".join(extra_info) if extra_info else None

                if state == 'open':
                    self.add_port(ip, port_id, protocol, state, service, product, version, extra)
                    count += 1

                    # Auto-add fingerprints
                    if product:
                        self.add_fingerprint(ip, port_id, "product", product, source="nmap")
                    if version:
                        self.add_fingerprint(ip, port_id, "version", version, source="nmap")
                    if service:
                        self.add_fingerprint(ip, port_id, "service", service, source="nmap")

                    # Auto-generate attack paths for high-risk services
                    self._auto_generate_attack_paths(ip, port_id, service, product, version)

        print(f"[+] Imported {count} open ports from nmap XML")
        self._correlate()

    def import_nuclei_json(self, json_path: str):
        """Import nuclei scan results (JSONL format)."""
        count = 0
        with open(json_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue

                host = finding.get('host', '')
                matched_at = finding.get('matched-at', '')
                # Extract port from matched-at
                port = 443 if 'https' in matched_at else 80
                if ':' in matched_at:
                    try:
                        port = int(matched_at.split(':')[-1].split('/')[0])
                    except ValueError:
                        pass

                info = finding.get('info', {})
                severity = info.get('severity', 'info')
                name = info.get('name', '')
                desc = info.get('description', '')[:200]
                cve_id = None
                for tag in info.get('classification', {}).get('cve-id', []) if isinstance(info.get('classification'), dict) else []:
                    cve_id = tag
                    break
                cvss = info.get('classification', {}).get('cvss-score') if isinstance(info.get('classification'), dict) else None

                vuln_id = f"nuclei-{finding.get('template-id', hashlib.md5(name.encode()).hexdigest()[:8])}"
                poc = finding.get('curl-command', '')

                self.add_vuln(vuln_id, host, port, service="http",
                              severity=severity, cvss=cvss, cve=cve_id,
                              title=name, description=desc,
                              exploit_available="nuclei_template" if poc else "unknown",
                              detection_method="nuclei",
                              detection_result=finding.get('matcher-name', ''),
                              poc=poc)
                count += 1

        print(f"[+] Imported {count} findings from nuclei scan")
        self._correlate()

    def import_httpx_json(self, json_path: str):
        """Import httpx probe results (JSONL format)."""
        count = 0
        with open(json_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    probe = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = probe.get('url', '')
                host = probe.get('host', probe.get('input', ''))
                port = probe.get('port', 443 if 'https' in url else 80)
                status_code = probe.get('status-code', 0)
                tech = probe.get('tech', [])
                webserver = probe.get('webserver', '')
                title = probe.get('title', '')
                cdn = probe.get('cdn-name', '')
                waf = probe.get('waf', '')

                if status_code > 0:
                    self.add_host(host, waf=waf if waf else None)
                    if webserver:
                        self.add_fingerprint(host, port, "webserver", webserver, source="httpx")
                    for t in (tech if isinstance(tech, list) else []):
                        self.add_fingerprint(host, port, "technology", t, source="httpx")
                    count += 1

        print(f"[+] Imported {count} hosts from httpx probe")

    # === Analysis methods ===
    def _auto_generate_attack_paths(self, host: str, port: int,
                                     service: str, product: str, version: str):
        """Auto-generate attack paths based on fingerprint."""
        paths = []

        # High-risk services
        if service in ('redis', 'memcached', 'mongodb', 'elasticsearch'):
            paths.append({
                'type': 'auth_bypass',
                'desc': f'{service} unauthorized access check',
                'tools': ['nmap', 'redis-cli', 'curl'],
                'cmds': [f'nmap -sV -p {port} {host}',
                         f'redis-cli -h {host} -p {port} INFO']
            })

        if service in ('mysql', 'postgresql', 'mssql', 'ftp', 'ssh'):
            paths.append({
                'type': 'auth_bypass',
                'desc': f'{service} weak password check',
                'tools': ['hydra', 'medusa'],
                'cmds': [f'hydra -L /usr/share/wordlists/users.txt -P /usr/share/wordlists/passwords.txt {host} {service} -s {port}']
            })

        if service in ('http', 'https') or (product and any(x in (product or '').lower() for x in ['tomcat', 'weblogic', 'jboss', 'spring'])):
            paths.append({
                'type': 'rce',
                'desc': f'{product or "Web"} RCE vulnerability scan',
                'tools': ['nuclei', 'curl'],
                'cmds': [f'nuclei -u {host}:{port} -severity critical,high -timeout 10']
            })

        # Tomcat specific
        if product and 'tomcat' in product.lower():
            paths.append({
                'type': 'auth_bypass',
                'desc': 'Tomcat Manager weak credentials',
                'tools': ['hydra'],
                'cmds': [f'hydra -L /usr/share/wordlists/tomcat.txt -P /usr/share/wordlists/tomcat.txt {host} http-get /manager/html -s {port}']
            })
            paths.append({
                'type': 'rce',
                'desc': 'Tomcat AJP Ghostcat (CVE-2020-1938)',
                'tools': ['nmap'],
                'cmds': [f'nmap -sV -p {port} --script ajp-auth {host}']
            })

        # Spring Boot / Actuator
        if product and any(x in (product or '').lower() for x in ['spring', 'actuator']):
            paths.append({
                'type': 'info_leak',
                'desc': 'Spring Boot Actuator endpoints',
                'tools': ['curl'],
                'cmds': [f'for ep in env beans configprops heapdump mappings health info; do curl -sk "{host}:{port}/actuator/$ep" -o /dev/null -w "/actuator/$ep: %{{http_code}}\\n"; done']
            })

        # Weblogic
        if product and 'weblogic' in product.lower():
            paths.append({
                'type': 'rce',
                'desc': 'WebLogic IIOP/T3 deserialization',
                'tools': ['nuclei'],
                'cmds': [f'nuclei -u {host}:{port} -t /root/nuclei-templates/http/cves/2020/ -id CVE-2020-14882']
            })

        # Nginx
        if product and 'nginx' in product.lower():
            paths.append({
                'type': 'info_leak',
                'desc': 'Nginx configuration probe',
                'tools': ['curl'],
                'cmds': [f'for p in /nginx_status /nginx.conf /../etc/passwd; do curl -sk "{host}:{port}$p" -o /dev/null -w "$p: %{{http_code}}\\n"; done']
            })

        # Generic HTTP
        if service in ('http', 'https'):
            paths.append({
                'type': 'sqli',
                'desc': 'SQL injection scan',
                'tools': ['sqlmap'],
                'cmds': [f'sqlmap -u "http://{host}:{port}/" --batch --level=2 --risk=2 --timeout=10 --crawl=2']
            })
            paths.append({
                'type': 'info_leak',
                'desc': 'Common sensitive paths',
                'tools': ['curl', 'ffuf'],
                'cmds': [f'curl -sk "{host}:{port}/.env" -o /dev/null -w ".env: %{{http_code}}\\n"',
                         f'curl -sk "{host}:{port}/robots.txt" -w "\\n"',
                         f'curl -sk "{host}:{port}/.git/config" -o /dev/null -w ".git: %{{http_code}}"']
            })
            # 2025-2026: GraphQL/JWT/OAuth/Next.js检测
            paths.append({
                'type': 'graphql',
                'desc': 'GraphQL endpoint discovery and introspection',
                'tools': ['curl'],
                'cmds': [f'for p in /graphql /api/graphql /v1/graphql /query /gql; do code=$(curl -sk "{host}:{port}$p" -o /dev/null -w "%{{http_code}}"); [ "$code" != "000" ] && [ "$code" != "404" ] && echo "$p: $code"; done',
                         f'curl -sk -X POST "{host}:{port}/graphql" -H "Content-Type: application/json" -d \'{{"query":"{{ __schema {{ types {{ name }} }} }}"}}\' | head -c 500']
            })
            paths.append({
                'type': 'jwt',
                'desc': 'JWT token detection and algorithm bypass test',
                'tools': ['curl'],
                'cmds': [f'curl -sk "{host}:{port}/" -D- | grep -i "authorization\\|x-jwt\\|bearer"',
                         f'curl -sk "{host}:{port}/" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0." -o /dev/null -w "JWT none: %{{http_code}}"']
            })
            paths.append({
                'type': 'oauth',
                'desc': 'OAuth2/OIDC endpoint discovery',
                'tools': ['curl'],
                'cmds': [f'curl -sk "{host}:{port}/.well-known/openid-configuration" -o /dev/null -w "OIDC: %{{http_code}}"',
                         f'curl -sk "{host}:{port}/.well-known/oauth-authorization-server" -o /dev/null -w "OAuth: %{{http_code}}"']
            })
            paths.append({
                'type': 'nextjs',
                'desc': 'Next.js middleware auth bypass (CVE-2025-29927)',
                'tools': ['curl'],
                'cmds': [f'curl -sk "{host}:{port}/" -D- | grep -i "x-powered-by.*next"',
                         f'curl -sk "{host}:{port}/admin" -H "x-middleware-subrequest: middleware" -o /dev/null -w "middleware bypass: %{{http_code}}"']
            })
            paths.append({
                'type': 'race_condition',
                'desc': 'Race condition detection on non-idempotent endpoints',
                'tools': ['curl'],
                'cmds': [f'curl -sk "{host}:{port}/" -D- | grep -i "transfer\\|withdraw\\|coupon\\|redeem\\|order"']
            })

        for p in paths:
            self.add_attack_path(host, port, p['type'], p['desc'],
                               p['tools'], p['cmds'])

    def _correlate(self):
        """Cross-correlate data: fingerprint → CVE lookup, vuln dedup, priority update."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Boost attack path scores based on confirmed vulns
        c.execute("SELECT host, port, severity, exploit_boost FROM vulns WHERE verified=0")
        for row in c.fetchall():
            host, port, severity, exploit_boost = row
            base_score = SEVERITY_SCORE.get(severity, 25)
            # Update matching attack paths
            c.execute("""UPDATE attack_paths SET priority_score = MAX(priority_score, ?)
                        WHERE host=? AND port=?""",
                      (base_score + (exploit_boost or 0), host, port))

        # Mark hosts with WAF
        c.execute("SELECT DISTINCT host FROM ports WHERE service IN ('http','https')")
        http_hosts = [r[0] for r in c.fetchall()]
        for h in http_hosts:
            c.execute("SELECT waf FROM hosts WHERE host=?", (h,))
            waf_row = c.fetchone()
            if waf_row and waf_row[0]:
                # Downgrade non-critical attack paths for WAF-protected hosts
                c.execute("""UPDATE attack_paths SET priority_score = priority_score * 0.7
                            WHERE host=? AND attack_type IN ('sqli', 'xss', 'rce')""",
                          (h,))

        conn.commit()
        conn.close()

    def correlate(self):
        """Public method to trigger correlation."""
        self._correlate()
        print("[+] Cross-correlation complete")

    # === Query methods ===
    def get_priority_targets(self, top_n: int = 20, min_severity: str = None):
        """Get top priority attack targets sorted by score."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        if min_severity:
            min_score = SEVERITY_SCORE.get(min_severity, 0)
            c.execute("""SELECT path_id, host, port, attack_type, description,
                         priority_score, status, tools, commands
                         FROM attack_paths
                         WHERE priority_score >= ? AND status = 'candidate'
                         ORDER BY priority_score DESC LIMIT ?""",
                      (min_score, top_n))
        else:
            c.execute("""SELECT path_id, host, port, attack_type, description,
                         priority_score, status, tools, commands
                         FROM attack_paths
                         WHERE status = 'candidate'
                         ORDER BY priority_score DESC LIMIT ?""", (top_n,))

        results = c.fetchall()
        conn.close()
        return results

    def get_stats(self):
        """Get graph statistics."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        stats = {}
        for table in ['hosts', 'ports', 'fingerprints', 'vulns', 'attack_paths', 'cors_findings', 'api_endpoints', 'js_secrets', 'evidence']:
            c.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = c.fetchone()[0]

        # Vuln breakdown by severity
        c.execute("SELECT severity, COUNT(*) FROM vulns GROUP BY severity")
        stats['vulns_by_severity'] = dict(c.fetchall())

        # Attack path breakdown by type
        c.execute("SELECT attack_type, COUNT(*) FROM attack_paths GROUP BY attack_type")
        stats['paths_by_type'] = dict(c.fetchall())

        # Top 5 priority
        c.execute("""SELECT host, port, attack_type, description, priority_score
                     FROM attack_paths WHERE status='candidate'
                     ORDER BY priority_score DESC LIMIT 5""")
        stats['top5'] = c.fetchall()

        # Verified vulns
        c.execute("SELECT COUNT(*) FROM vulns WHERE verified=1")
        stats['verified_vulns'] = c.fetchone()[0]

        conn.close()
        return stats

    def generate_attack_plan(self, mode: str = "full"):
        """Generate an intelligent attack plan based on current graph state."""
        plans = {
            "fast": ["info_leak", "auth_bypass", "cors", "misconfig"],
            "full": ["info_leak", "auth_bypass", "rce", "sqli", "ssrf",
                     "idor", "upload", "ssti", "xxe", "cors", "xss"],
            "stealth": ["info_leak", "cors", "misconfig", "version_leak"]
        }
        attack_types = plans.get(mode, plans["full"])

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        plan = []
        for atype in attack_types:
            c.execute("""SELECT path_id, host, port, description, tools, commands, priority_score
                        FROM attack_paths
                        WHERE attack_type=? AND status='candidate'
                        ORDER BY priority_score DESC""", (atype,))
            rows = c.fetchall()
            if rows:
                plan.append({
                    'phase': atype,
                    'targets': len(rows),
                    'top_score': rows[0][6] if rows else 0,
                    'paths': [{'id': r[0], 'host': r[1], 'port': r[2],
                               'desc': r[3], 'tools': json.loads(r[4]),
                               'cmds': json.loads(r[5]), 'score': r[6]} for r in rows[:5]]
                })

        conn.close()
        return plan

    def export_graph(self, fmt: str = "json"):
        """Export graph in various formats."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        if fmt == "json":
            data = {"timestamp": self._now(), "stats": self.get_stats()}
            tables = ['hosts', 'ports', 'fingerprints', 'vulns', 'attack_paths',
                      'cors_findings', 'api_endpoints', 'js_secrets']
            for table in tables:
                c.execute(f"SELECT * FROM {table}")
                cols = [d[0] for d in c.description]
                data[table] = [dict(zip(cols, row)) for row in c.fetchall()]

            out_path = self.graph_dir / "graph_export.json"
            with open(out_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"[+] Exported to {out_path}")
            return str(out_path)

        elif fmt == "md":
            stats = self.get_stats()
            lines = [
                f"# Target Graph Report",
                f"Generated: {self._now()}",
                "",
                "## Summary",
                f"- Hosts: {stats.get('hosts', 0)}",
                f"- Open Ports: {stats.get('ports', 0)}",
                f"- Vulnerabilities: {stats.get('vulns', 0)}",
                f"- Verified: {stats.get('verified_vulns', 0)}",
                f"- Attack Paths: {stats.get('attack_paths', 0)}",
                "",
                "## Vulns by Severity",
            ]
            for sev, count in stats.get('vulns_by_severity', {}).items():
                lines.append(f"- {sev}: {count}")

            lines.append("")
            lines.append("## Top Priority Targets")
            for item in stats.get('top5', []):
                lines.append(f"- [{item[4]:.0f}] {item[0]}:{item[1]} - {item[2]}: {item[3]}")

            out_path = self.graph_dir / "graph_report.md"
            with open(out_path, 'w') as f:
                f.write("\n".join(lines))
            print(f"[+] Exported to {out_path}")
            return str(out_path)

        elif fmt == "csv":
            import csv
            c.execute("""SELECT host, port, attack_type, description, priority_score, status
                        FROM attack_paths ORDER BY priority_score DESC""")
            out_path = self.graph_dir / "attack_paths.csv"
            with open(out_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['host', 'port', 'attack_type', 'description', 'score', 'status'])
                writer.writerows(c.fetchall())
            print(f"[+] Exported to {out_path}")
            return str(out_path)

        conn.close()

    def print_priority(self, top_n: int = 15):
        """Print priority targets in a readable format."""
        targets = self.get_priority_targets(top_n)
        print(f"\n{'='*70}")
        print(f"  TOP {top_n} PRIORITY ATTACK TARGETS")
        print(f"{'='*70}")
        for i, t in enumerate(targets, 1):
            pid, host, port, atype, desc, score, status, tools_json, cmds_json = t
            tools = json.loads(tools_json)
            cmds = json.loads(cmds_json)
            print(f"\n  [{i}] Score: {score:.0f} | {host}:{port}")
            print(f"      Type: {atype}")
            print(f"      Desc: {desc}")
            print(f"      Tools: {', '.join(tools)}")
            if cmds:
                print(f"      Cmd:  {cmds[0][:100]}")
        print(f"\n{'='*70}")

    def print_stats(self):
        """Print statistics."""
        stats = self.get_stats()
        print(f"\n{'='*50}")
        print(f"  TARGET GRAPH STATISTICS")
        print(f"{'='*50}")
        print(f"  Hosts:           {stats.get('hosts', 0)}")
        print(f"  Open Ports:      {stats.get('ports', 0)}")
        print(f"  Fingerprints:    {stats.get('fingerprints', 0)}")
        print(f"  Vulnerabilities: {stats.get('vulns', 0)} (verified: {stats.get('verified_vulns', 0)})")
        print(f"  Attack Paths:    {stats.get('attack_paths', 0)}")
        print(f"  CORS Findings:   {stats.get('cors_findings', 0)}")
        print(f"  API Endpoints:   {stats.get('api_endpoints', 0)}")
        print(f"  JS Secrets:      {stats.get('js_secrets', 0)}")
        print(f"  Evidence:        {stats.get('evidence', 0)}")

        if stats.get('vulns_by_severity'):
            print(f"\n  Vulns by Severity:")
            for sev, count in sorted(stats['vulns_by_severity'].items(),
                                      key=lambda x: SEVERITY_SCORE.get(x[0], 0), reverse=True):
                print(f"    {sev:10s}: {count}")

        if stats.get('paths_by_type'):
            print(f"\n  Attack Paths by Type:")
            for atype, count in sorted(stats['paths_by_type'].items(),
                                        key=lambda x: SURFACE_WEIGHT.get(x[0], 0), reverse=True):
                print(f"    {atype:15s}: {count}")

        if stats.get('top5'):
            print(f"\n  Top 5 Priority:")
            for item in stats['top5']:
                print(f"    [{item[4]:.0f}] {item[0]}:{item[1]} - {item[2]}: {item[3]}")

        print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description="Target Graph Engine v1.0")
    sub = parser.add_subparsers(dest="command")

    # init
    p_init = sub.add_parser("init")
    p_init.add_argument("domain")
    p_init.add_argument("--outdir", default="/tmp/target_graph")

    # add-host
    p_host = sub.add_parser("add-host")
    p_host.add_argument("graph_dir")
    p_host.add_argument("--host", required=True)
    p_host.add_argument("--ip")
    p_host.add_argument("--domain")
    p_host.add_argument("--os")
    p_host.add_argument("--waf")

    # add-fingerprint
    p_fp = sub.add_parser("add-fingerprint")
    p_fp.add_argument("graph_dir")
    p_fp.add_argument("--host", required=True)
    p_fp.add_argument("--port", type=int, required=True)
    p_fp.add_argument("--service")
    p_fp.add_argument("--product")
    p_fp.add_argument("--version")
    p_fp.add_argument("--source", default="manual")

    # add-vuln
    p_vuln = sub.add_parser("add-vuln")
    p_vuln.add_argument("graph_dir")
    p_vuln.add_argument("--host", required=True)
    p_vuln.add_argument("--port", type=int, required=True)
    p_vuln.add_argument("--vuln", required=True)
    p_vuln.add_argument("--severity", default="medium")
    p_vuln.add_argument("--cvss", type=float)
    p_vuln.add_argument("--cve")
    p_vuln.add_argument("--title")
    p_vuln.add_argument("--poc")
    p_vuln.add_argument("--exploit", default="unknown")

    # from-nmap
    p_nmap = sub.add_parser("from-nmap")
    p_nmap.add_argument("graph_dir")
    p_nmap.add_argument("--nmap-xml", required=True)

    # from-nuclei
    p_nuclei = sub.add_parser("from-nuclei")
    p_nuclei.add_argument("graph_dir")
    p_nuclei.add_argument("--nuclei-json", required=True)

    # from-httpx
    p_httpx = sub.add_parser("from-httpx")
    p_httpx.add_argument("graph_dir")
    p_httpx.add_argument("--httpx-json", required=True)

    # priority
    p_pri = sub.add_parser("priority")
    p_pri.add_argument("graph_dir")
    p_pri.add_argument("--top", type=int, default=15)
    p_pri.add_argument("--severity")

    # attack-plan
    p_plan = sub.add_parser("attack-plan")
    p_plan.add_argument("graph_dir")
    p_plan.add_argument("--mode", choices=["fast", "full", "stealth"], default="full")

    # export
    p_export = sub.add_parser("export")
    p_export.add_argument("graph_dir")
    p_export.add_argument("--format", choices=["json", "md", "csv"], default="json")

    # stats
    p_stats = sub.add_parser("stats")
    p_stats.add_argument("graph_dir")

    # correlate
    p_corr = sub.add_parser("correlate")
    p_corr.add_argument("graph_dir")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "init":
        graph = TargetGraph(args.outdir)
        graph.init_target(args.domain)
        print(f"[+] Graph initialized at: {args.outdir}")
        return

    graph = TargetGraph(args.graph_dir)

    if args.command == "add-host":
        graph.add_host(args.host, args.ip, args.domain, args.os, args.waf)
        print(f"[+] Added host: {args.host}")
    elif args.command == "add-fingerprint":
        if args.service:
            graph.add_fingerprint(args.host, args.port, "service", args.service, source=args.source)
        if args.product:
            graph.add_fingerprint(args.host, args.port, "product", args.product, source=args.source)
        if args.version:
            graph.add_fingerprint(args.host, args.port, "version", args.version, source=args.source)
        # Always add/update port and generate attack paths
        graph.add_port(args.host, args.port, service=args.service, product=args.product, version=args.version)
        graph._auto_generate_attack_paths(args.host, args.port, args.service, args.product, args.version)
        print(f"[+] Added fingerprint for {args.host}:{args.port}")
    elif args.command == "add-vuln":
        graph.add_vuln(args.vuln, args.host, args.port,
                       severity=args.severity, cvss=args.cvss, cve=args.cve,
                       title=args.title, poc=args.poc, exploit_available=args.exploit)
        print(f"[+] Added vuln: {args.vuln} on {args.host}:{args.port}")
    elif args.command == "from-nmap":
        graph.import_nmap_xml(args.nmap_xml)
    elif args.command == "from-nuclei":
        graph.import_nuclei_json(args.nuclei_json)
    elif args.command == "from-httpx":
        graph.import_httpx_json(args.httpx_json)
    elif args.command == "priority":
        graph.print_priority(args.top)
    elif args.command == "attack-plan":
        plan = graph.generate_attack_plan(args.mode)
        print(f"\n{'='*60}")
        print(f"  ATTACK PLAN: {args.mode.upper()}")
        print(f"{'='*60}")
        for i, phase in enumerate(plan, 1):
            print(f"\n  Phase {i}: {phase['phase']}")
            print(f"    Targets: {phase['targets']}")
            print(f"    Top Score: {phase['top_score']:.0f}")
            for p in phase['paths'][:3]:
                print(f"      - {p['host']}:{p['port']} ({p['desc'][:60]})")
        print(f"\n{'='*60}")
    elif args.command == "export":
        graph.export_graph(args.format)
    elif args.command == "stats":
        graph.print_stats()
    elif args.command == "correlate":
        graph.correlate()


if __name__ == "__main__":
    main()
