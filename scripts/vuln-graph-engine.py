#!/usr/bin/env python3
"""
Pentest Graph Engine v3.0 — 统一知识图谱

所有渗透模块共享的 SQLite 知识图谱。取代 v1 的 target-graph-engine.py，
设计目标：
  - 单文件嵌入式，零外部依赖
  - 所有模块读写同一张图，自动关联
  - 支持并发读（WAL 模式）
  - 内置优先级评分和攻击路径生成

用法:
  vuln-graph-engine.py init <domain> [--outdir /tmp/pentest]
  vuln-graph-engine.py add-host <graph.db> --domain X [--ip Y] [--waf Z]
  vuln-graph-engine.py add-port <graph.db> --host-id N --port P --service S [--product R] [--version V]
  vuln-graph-engine.py add-fingerprint <graph.db> --host-id N --tech T [--version V]
  vuln-graph-engine.py add-endpoint <graph.db> --host-id N --url U [--method M] [--status S]
  vuln-graph-engine.py add-vuln <graph.db> --title T --severity S [--cve C] [--host-id N] [--endpoint U]
  vuln-graph-engine.py add-evidence <graph.db> --vuln-id N --type T --content C
  vuln-graph-engine.py add-secret <graph.db> --host-id N --type T --value V
  vuln-graph-engine.py priority <graph.db> [--top N] [--min-score S]
  vuln-graph-engine.py attack-plan <graph.db> [--mode full|fast|stealth]
  vuln-graph-engine.py stats <graph.db>
  vuln-graph-engine.py export <graph.db> [--format json|csv]
  vuln-graph-engine.py query <graph.db> --sql "SELECT ..."
  vuln-graph-engine.py import-nmap <graph.db> --xml <path>
  vuln-graph-engine.py import-httpx <graph.db> --json <path>
  vuln-graph-engine.py import-nuclei <graph.db> --json <path>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ─── Schema ───────────────────────────────────────────────────────────────────

SCHEMA_VERSION = 3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT NOT NULL,
    url       TEXT,
    scope     TEXT,           -- in-scope / out-of-scope
    note      TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER REFERENCES targets(id),
    domain     TEXT,
    ip         TEXT,
    cdn        TEXT,           -- cloudflare / akamai / aliyun_cdn / ...
    waf        TEXT,           -- cloudflare / aliyun_waf / tencent_waf / openrasp / safeline / ...
    os         TEXT,
    http_server TEXT,          -- nginx / apache / tengine / ...
    title      TEXT,
    status     TEXT DEFAULT 'alive',  -- alive / dead / timeout / blocked
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(target_id, domain, ip)
);

CREATE TABLE IF NOT EXISTS ports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER REFERENCES hosts(id),
    port      INTEGER NOT NULL,
    protocol  TEXT DEFAULT 'tcp',
    state     TEXT DEFAULT 'open',
    service   TEXT,            -- http / ssh / mysql / redis / ...
    product   TEXT,            -- openssh / apache / nginx / ...
    version   TEXT,
    banner    TEXT,
    script_output TEXT,        -- nmap script results
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    port_id     INTEGER REFERENCES ports(id),
    category    TEXT NOT NULL,  -- cms / framework / language / server / waf / cdn / component
    tech        TEXT NOT NULL,  -- spring-boot / shiro / nacos / liferay / ...
    version     TEXT,
    confidence  REAL DEFAULT 0.8,
    source      TEXT,           -- whatweb / nuclei / manual / http-header / ...
    detail      TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    url         TEXT NOT NULL,
    method      TEXT DEFAULT 'GET',
    status      INTEGER,       -- HTTP status code
    content_type TEXT,
    content_length INTEGER,
    title       TEXT,
    body_snippet TEXT,         -- first 500 chars
    source      TEXT,           -- crawl / js-extract / brute / swagger / ...
    auth_required INTEGER DEFAULT -1,  -- -1=unknown, 0=no, 1=yes
    sensitive   INTEGER DEFAULT 0,     -- 0=no, 1=yes (contains PII/business data)
    params      TEXT,           -- JSON: [{"name":"id","in":"query","type":"int"}, ...]
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(host_id, url, method)
);

CREATE TABLE IF NOT EXISTS vulns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    endpoint_id INTEGER REFERENCES endpoints(id),
    title       TEXT NOT NULL,
    vuln_type   TEXT,           -- sqli / xss / rce / idor / ssrf / cors / info_leak / auth_bypass / ...
    severity    TEXT NOT NULL,  -- critical / high / medium / low / info
    cve         TEXT,
    cvss        REAL,
    description TEXT,
    poc         TEXT,           -- PoC command or payload
    poc_verified INTEGER DEFAULT 0,  -- 0=unverified, 1=verified, 2=fail
    remediation TEXT,
    source      TEXT,           -- nuclei / sqlmap / manual / exploit-db / ...
    status      TEXT DEFAULT 'open',  -- open / confirmed / submitted / fixed / wontfix
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id     INTEGER REFERENCES vulns(id),
    type        TEXT NOT NULL,  -- request / response / screenshot / curl / burp / file
    content     TEXT NOT NULL,
    label       TEXT,           -- human-readable label
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    endpoint_id INTEGER REFERENCES endpoints(id),
    type        TEXT NOT NULL,  -- api_key / app_secret / token / password / jwt / cert / private_key
    value       TEXT NOT NULL,
    context     TEXT,           -- where it was found
    verified    INTEGER DEFAULT 0,  -- 0=untested, 1=valid, 2=invalid
    impact      TEXT,           -- what can be done with it
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    vuln_id     INTEGER REFERENCES vulns(id),
    path_type   TEXT NOT NULL,  -- rce / sqli_dump / auth_bypass / idor_chain / ssrf_internal / ...
    description TEXT,
    priority    REAL DEFAULT 0,  -- higher = more promising
    status      TEXT DEFAULT 'planned',  -- planned / executing / success / failed / blocked
    tool        TEXT,           -- sqlmap / nuclei / curl / custom
    command     TEXT,
    result      TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cors_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    url         TEXT NOT NULL,
    origin      TEXT,           -- reflected origin
    acao        TEXT,           -- Access-Control-Allow-Origin
    acac        TEXT,           -- Access-Control-Allow-Credentials
    severity    TEXT,           -- high / medium / low
    verified    INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS js_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id),
    source_url  TEXT,           -- JS file URL
    finding_type TEXT,          -- api_endpoint / secret / config / route
    value       TEXT NOT NULL,
    context     TEXT,           -- surrounding code
    created_at  TEXT DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_hosts_target ON hosts(target_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_fp_host ON fingerprints(host_id);
CREATE INDEX IF NOT EXISTS idx_ep_host ON endpoints(host_id);
CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulns(host_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulns(status);
CREATE INDEX IF NOT EXISTS idx_evidence_vuln ON evidence(vuln_id);
CREATE INDEX IF NOT EXISTS idx_secrets_host ON secrets(host_id);
CREATE INDEX IF NOT EXISTS idx_attack_vuln ON attack_paths(vuln_id);
CREATE INDEX IF NOT EXISTS idx_cors_host ON cors_findings(host_id);
CREATE INDEX IF NOT EXISTS idx_js_host ON js_findings(host_id);
"""


# ─── Database helpers ─────────────────────────────────────────────────────────

class PentestGraph:
    """Unified pentest knowledge graph."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self):
        self.conn.executescript(SCHEMA_SQL)
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            ("created_at", datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ── Targets ────────────────────────────────────────────────────────────

    def add_target(self, domain: str, url: str = None, scope: str = "in-scope",
                   note: str = None) -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO targets(domain, url, scope, note) VALUES(?,?,?,?)",
            (domain, url, scope, note),
        )
        self.conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        row = self.conn.execute(
            "SELECT id FROM targets WHERE domain=?", (domain,)
        ).fetchone()
        return row["id"]

    # ── Hosts ──────────────────────────────────────────────────────────────

    def add_host(self, domain: str = None, ip: str = None, cdn: str = None,
                 waf: str = None, os: str = None, http_server: str = None,
                 title: str = None, target_id: int = None) -> int:
        # Auto-link target
        if target_id is None and domain:
            tld = _extract_tld(domain)
            row = self.conn.execute(
                "SELECT id FROM targets WHERE domain=?", (tld,)
            ).fetchone()
            if row:
                target_id = row["id"]
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO hosts(target_id, domain, ip, cdn, waf, os, http_server, title)
               VALUES(?,?,?,?,?,?,?,?)""",
            (target_id, domain, ip, cdn, waf, os, http_server, title),
        )
        self.conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        # Find existing
        conds, params = [], []
        if target_id:
            conds.append("target_id=?"); params.append(target_id)
        if domain:
            conds.append("domain=?"); params.append(domain)
        if ip:
            conds.append("ip=?"); params.append(ip)
        if not conds:
            return 0
        row = self.conn.execute(
            f"SELECT id FROM hosts WHERE {' AND '.join(conds)}", params
        ).fetchone()
        return row["id"] if row else 0

    def update_host(self, host_id: int, **kwargs):
        allowed = {"domain", "ip", "cdn", "waf", "os", "http_server", "title", "status"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return
        sets = ", ".join(f"{k}=?" for k in updates)
        self.conn.execute(
            f"UPDATE hosts SET {sets} WHERE id=?",
            (*updates.values(), host_id),
        )
        self.conn.commit()

    # ── Ports ──────────────────────────────────────────────────────────────

    def add_port(self, host_id: int, port: int, protocol: str = "tcp",
                 state: str = "open", service: str = None, product: str = None,
                 version: str = None, banner: str = None,
                 script_output: str = None) -> int:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO ports(host_id, port, protocol, state, service, product, version, banner, script_output)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (host_id, port, protocol, state, service, product, version, banner, script_output),
        )
        self.conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        row = self.conn.execute(
            "SELECT id FROM ports WHERE host_id=? AND port=? AND protocol=?",
            (host_id, port, protocol),
        ).fetchone()
        return row["id"] if row else 0

    # ── Fingerprints ───────────────────────────────────────────────────────

    def add_fingerprint(self, host_id: int, category: str, tech: str,
                        version: str = None, confidence: float = 0.8,
                        source: str = None, detail: str = None,
                        port_id: int = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO fingerprints(host_id, port_id, category, tech, version, confidence, source, detail)
               VALUES(?,?,?,?,?,?,?,?)""",
            (host_id, port_id, category, tech, version, confidence, source, detail),
        )
        self.conn.commit()
        return cur.lastrowid

    # ── Endpoints ──────────────────────────────────────────────────────────

    def add_endpoint(self, host_id: int, url: str, method: str = "GET",
                     status: int = None, content_type: str = None,
                     content_length: int = None, title: str = None,
                     body_snippet: str = None, source: str = None,
                     auth_required: int = -1, sensitive: int = 0,
                     params: str = None) -> int:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO endpoints(host_id, url, method, status, content_type,
               content_length, title, body_snippet, source, auth_required, sensitive, params)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (host_id, url, method.upper(), status, content_type, content_length,
             title, body_snippet, source, auth_required, sensitive, params),
        )
        self.conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        row = self.conn.execute(
            "SELECT id FROM endpoints WHERE host_id=? AND url=? AND method=?",
            (host_id, url, method.upper()),
        ).fetchone()
        return row["id"] if row else 0

    # ── Vulnerabilities ────────────────────────────────────────────────────

    def add_vuln(self, title: str, severity: str, host_id: int = None,
                 endpoint_id: int = None, vuln_type: str = None,
                 cve: str = None, cvss: float = None, description: str = None,
                 poc: str = None, remediation: str = None,
                 source: str = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO vulns(host_id, endpoint_id, title, vuln_type, severity,
               cve, cvss, description, poc, remediation, source)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (host_id, endpoint_id, title, vuln_type, severity,
             cve, cvss, description, poc, remediation, source),
        )
        self.conn.commit()
        return cur.lastrowid

    def verify_vuln(self, vuln_id: int, verified: int, poc: str = None):
        """Update verification status: 0=unverified, 1=verified, 2=fail"""
        updates = {"poc_verified": verified, "updated_at": datetime.now(timezone.utc).isoformat()}
        if poc:
            updates["poc"] = poc
        sets = ", ".join(f"{k}=?" for k in updates)
        self.conn.execute(f"UPDATE vulns SET {sets} WHERE id=?", (*updates.values(), vuln_id))
        self.conn.commit()

    # ── Evidence ───────────────────────────────────────────────────────────

    def add_evidence(self, vuln_id: int, type: str, content: str,
                     label: str = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO evidence(vuln_id, type, content, label) VALUES(?,?,?,?)",
            (vuln_id, type, content, label),
        )
        self.conn.commit()
        return cur.lastrowid

    # ── Secrets ────────────────────────────────────────────────────────────

    def add_secret(self, type: str, value: str, host_id: int = None,
                   endpoint_id: int = None, context: str = None,
                   impact: str = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO secrets(host_id, endpoint_id, type, value, context, impact)
               VALUES(?,?,?,?,?,?)""",
            (host_id, endpoint_id, type, value, context, impact),
        )
        self.conn.commit()
        return cur.lastrowid

    # ── CORS ───────────────────────────────────────────────────────────────

    def add_cors(self, host_id: int, url: str, acao: str, acac: str = None,
                 origin: str = None, severity: str = "medium") -> int:
        cur = self.conn.execute(
            """INSERT INTO cors_findings(host_id, url, origin, acao, acac, severity)
               VALUES(?,?,?,?,?,?)""",
            (host_id, url, origin, acao, acac, severity),
        )
        self.conn.commit()
        return cur.lastrowid

    # ── JS Findings ────────────────────────────────────────────────────────

    def add_js_finding(self, host_id: int, finding_type: str, value: str,
                       source_url: str = None, context: str = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO js_findings(host_id, source_url, finding_type, value, context)
               VALUES(?,?,?,?,?)""",
            (host_id, source_url, finding_type, value, context),
        )
        self.conn.commit()
        return cur.lastrowid

    # ── Attack Paths ───────────────────────────────────────────────────────

    def add_attack_path(self, host_id: int, path_type: str, description: str,
                        priority: float = 0, vuln_id: int = None,
                        tool: str = None, command: str = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO attack_paths(host_id, vuln_id, path_type, description, priority, tool, command)
               VALUES(?,?,?,?,?,?,?)""",
            (host_id, vuln_id, path_type, description, priority, tool, command),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_attack_path(self, path_id: int, status: str = None,
                           result: str = None, priority: float = None):
        updates = {"updated_at": datetime.now(timezone.utc).isoformat()}
        if status:
            updates["status"] = status
        if result is not None:
            updates["result"] = result
        if priority is not None:
            updates["priority"] = priority
        sets = ", ".join(f"{k}=?" for k in updates)
        self.conn.execute(f"UPDATE attack_paths SET {sets} WHERE id=?", (*updates.values(), path_id))
        self.conn.commit()

    # ── Queries ────────────────────────────────────────────────────────────

    def get_hosts(self, target_id: int = None) -> list[dict]:
        sql = "SELECT * FROM hosts"
        params = []
        if target_id:
            sql += " WHERE target_id=?"
            params.append(target_id)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def get_ports(self, host_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM ports WHERE host_id=? ORDER BY port", (host_id,)
        ).fetchall()]

    def get_fingerprints(self, host_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM fingerprints WHERE host_id=?", (host_id,)
        ).fetchall()]

    def get_endpoints(self, host_id: int = None, sensitive_only: bool = False) -> list[dict]:
        sql = "SELECT e.*, h.domain FROM endpoints e LEFT JOIN hosts h ON e.host_id=h.id WHERE 1=1"
        params = []
        if host_id:
            sql += " AND e.host_id=?"
            params.append(host_id)
        if sensitive_only:
            sql += " AND e.sensitive=1"
        sql += " ORDER BY e.sensitive DESC, e.status"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def get_vulns(self, severity: str = None, status: str = None,
                  verified: int = None) -> list[dict]:
        sql = "SELECT v.*, h.domain FROM vulns v LEFT JOIN hosts h ON v.host_id=h.id WHERE 1=1"
        params = []
        if severity:
            sql += " AND v.severity=?"
            params.append(severity)
        if status:
            sql += " AND v.status=?"
            params.append(status)
        if verified is not None:
            sql += " AND v.poc_verified=?"
            params.append(verified)
        sql += " ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def get_evidence(self, vuln_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM evidence WHERE vuln_id=?", (vuln_id,)
        ).fetchall()]

    def get_secrets(self, verified: int = None) -> list[dict]:
        sql = "SELECT s.*, h.domain FROM secrets s LEFT JOIN hosts h ON s.host_id=h.id WHERE 1=1"
        params = []
        if verified is not None:
            sql += " AND s.verified=?"
            params.append(verified)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def priority_targets(self, top: int = 20, min_score: float = 0) -> list[dict]:
        """Rank hosts by attack priority (high-value services, many ports, known vulns)."""
        sql = """
        SELECT h.*,
            (SELECT COUNT(*) FROM ports p WHERE p.host_id=h.id) as port_count,
            (SELECT COUNT(*) FROM vulns v WHERE v.host_id=h.id AND v.status='open') as vuln_count,
            (SELECT COUNT(*) FROM endpoints e WHERE e.host_id=h.id AND e.sensitive=1) as sensitive_ep_count,
            (SELECT COUNT(*) FROM secrets s WHERE s.host_id=h.id) as secret_count,
            (SELECT COUNT(*) FROM fingerprints f WHERE f.host_id=h.id) as fp_count
        FROM hosts h
        """
        rows = [dict(r) for r in self.conn.execute(sql).fetchall()]
        for r in rows:
            score = 0
            # High-value domain keywords
            domain = (r.get("domain") or "").lower()
            for kw, pts in [
                ("api", 20), ("auth", 25), ("admin", 15), ("oa", 15),
                ("upload", 20), ("pay", 25), ("swagger", 15), ("actuator", 25),
                ("graphql", 20), ("cas", 20), ("sso", 20), ("oauth", 20),
                ("portal", 10), ("manage", 10), ("gateway", 15),
            ]:
                if kw in domain:
                    score += pts
            score += r.get("port_count", 0) * 3
            score += r.get("vuln_count", 0) * 15
            score += r.get("sensitive_ep_count", 0) * 10
            score += r.get("secret_count", 0) * 20
            score += r.get("fp_count", 0) * 5
            # WAF penalty
            if r.get("waf"):
                score -= 10
            r["priority_score"] = max(0, score)

        rows = sorted(rows, key=lambda x: x["priority_score"], reverse=True)
        if min_score > 0:
            rows = [r for r in rows if r["priority_score"] >= min_score]
        return rows[:top]

    def generate_attack_plan(self, mode: str = "full") -> list[dict]:
        """Generate prioritized attack paths from graph state."""
        plan = []
        hosts = self.priority_targets(top=50)

        for h in hosts:
            hid = h["id"]
            fps = {f["tech"].lower(): f for f in self.get_fingerprints(hid)}
            ports = self.get_ports(hid)
            port_map = {p["port"]: p for p in ports}

            # Spring Boot Actuator
            if any("spring" in t for t in fps):
                plan.append({
                    "host_id": hid, "domain": h.get("domain"),
                    "action": "probe_actuator", "priority": 85,
                    "command": f'curl -sk "https://{h.get("domain","")}/actuator/env" | head -c 2000',
                    "description": "Spring Boot Actuator endpoint probe",
                })

            # Shiro deserialization
            if any("shiro" in t for t in fps):
                plan.append({
                    "host_id": hid, "domain": h.get("domain"),
                    "action": "shiro_deserial", "priority": 90,
                    "description": "Shiro rememberMe deserialization check",
                })

            # Nacos unauth
            if any("nacos" in t for t in fps):
                plan.append({
                    "host_id": hid, "domain": h.get("domain"),
                    "action": "nacos_unauth", "priority": 80,
                    "command": f'curl -sk "https://{h.get("domain","")}/nacos/v1/auth/users?pageSize=100&pageNo=1"',
                    "description": "Nacos unauthorized access check",
                })

            # Swagger/GraphQL
            if any(t in fps for t in ("swagger", "graphql")):
                plan.append({
                    "host_id": hid, "domain": h.get("domain"),
                    "action": "api_doc_leak", "priority": 70,
                    "description": "API documentation exposure",
                })

            # Redis/MongoDB/ES exposed
            for port in [6379, 27017, 9200, 5984]:
                if port in port_map and port_map[port]["state"] == "open":
                    plan.append({
                        "host_id": hid, "domain": h.get("domain"),
                        "action": f"unauth_service_{port}", "priority": 95,
                        "description": f"Unauthenticated {port_map[port].get('service','service')} on port {port}",
                    })

            # CORS testing for HTTP services
            for p in ports:
                if p["service"] in ("http", "https") or p["port"] in (80, 443, 8080, 8443):
                    scheme = "https" if p["port"] in (443, 8443) else "http"
                    ep_count = self.conn.execute(
                        "SELECT COUNT(*) FROM endpoints WHERE host_id=?", (hid,)
                    ).fetchone()[0]
                    if ep_count == 0:
                        # No endpoints discovered yet — probe root
                        plan.append({
                            "host_id": hid, "domain": h.get("domain"),
                            "action": "cors_test", "priority": 50,
                            "command": f'curl -sk -H "Origin: https://evil.com" "{scheme}://{h.get("domain","")}/" -D-',
                            "description": "CORS configuration check",
                        })

            # SQLi on parameterized endpoints
            eps = self.get_endpoints(host_id=hid)
            for ep in eps:
                if ep.get("params") and "?" in ep.get("url", ""):
                    plan.append({
                        "host_id": hid, "endpoint_id": ep["id"],
                        "domain": h.get("domain"), "url": ep["url"],
                        "action": "sqli_test", "priority": 65,
                        "description": f"SQLi test on {ep['url']}",
                    })

            if mode == "fast":
                plan = plan[:20]
                break

        plan.sort(key=lambda x: x["priority"], reverse=True)
        return plan

    # ── Importers ──────────────────────────────────────────────────────────

    def import_nmap_xml(self, xml_path: str) -> dict:
        """Import nmap XML output into graph."""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        stats = {"hosts": 0, "ports": 0, "fingerprints": 0}

        for host_el in root.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            ip = addr_el.get("addr") if addr_el is not None else None
            status_el = host_el.find("status")
            state = status_el.get("state") if status_el is not None else "unknown"
            if state != "up":
                continue

            # Hostname
            hostname = None
            for hn in host_el.findall(".//hostname"):
                hostname = hn.get("name")
                break

            # OS detection
            os_name = None
            for osmatch in host_el.findall(".//osmatch"):
                os_name = osmatch.get("name")
                break

            host_id = self.add_host(domain=hostname, ip=ip, os=os_name)
            stats["hosts"] += 1

            for port_el in host_el.findall(".//port"):
                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                port_state = state_el.get("state") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None

                # Script output
                scripts = []
                for script_el in port_el.findall("script"):
                    scripts.append(f"{script_el.get('id')}: {script_el.get('output','')[:500]}")
                script_text = "\n".join(scripts) if scripts else None

                port_id = self.add_port(
                    host_id, port_num, protocol, port_state,
                    service, product, version, script_output=script_text,
                )
                stats["ports"] += 1

                # Auto-fingerprint from service/product
                if product:
                    fp_category = _classify_service(service, product)
                    self.add_fingerprint(
                        host_id, fp_category, product, version,
                        source="nmap", port_id=port_id,
                    )
                    stats["fingerprints"] += 1

        self.conn.commit()
        return stats

    def import_httpx_json(self, json_path: str) -> dict:
        """Import httpx JSON output."""
        stats = {"hosts": 0, "endpoints": 0}
        with open(json_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = data.get("url", "")
                host = data.get("host", data.get("input", ""))
                ip = data.get("a", [None])[0] if isinstance(data.get("a"), list) else data.get("a")
                status = data.get("status_code")
                title = data.get("title", "")
                server = data.get("webserver", "")
                tech = data.get("tech", [])  # list of technologies
                cdn = "yes" if data.get("cdn") else None
                content_type = data.get("content_type", "")
                content_length = data.get("content_length", 0)
                waf = data.get("waf", "")

                host_id = self.add_host(
                    domain=host, ip=ip, cdn=cdn, waf=waf,
                    http_server=server, title=title,
                )
                stats["hosts"] += 1

                self.add_endpoint(
                    host_id, url, "GET", status, content_type,
                    content_length, title, source="httpx",
                )
                stats["endpoints"] += 1

                # Auto-fingerprint from tech stack
                for t in (tech if isinstance(tech, list) else [tech]):
                    if t:
                        cat = _classify_tech(t)
                        self.add_fingerprint(host_id, cat, t, source="httpx")

        self.conn.commit()
        return stats

    def import_nuclei_json(self, json_path: str) -> dict:
        """Import nuclei JSON output."""
        stats = {"vulns": 0}
        with open(json_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = data.get("info", {})
                matched_at = data.get("matched-at", data.get("matched", ""))
                host = data.get("host", "")
                template_id = data.get("template-id", "")
                name = info.get("name", template_id)
                severity = info.get("severity", "info")
                description = info.get("description", "")
                cve_id = info.get("classification", {}).get("cve-id", "")
                cvss = info.get("classification", {}).get("cvss-score")
                remediation = info.get("remediation", "")

                # Find host_id
                host_row = self.conn.execute(
                    "SELECT id FROM hosts WHERE domain=? OR ip=?",
                    (host, host),
                ).fetchone()
                host_id = host_row["id"] if host_row else None

                # Find endpoint_id
                ep_row = None
                if matched_at:
                    ep_row = self.conn.execute(
                        "SELECT id FROM endpoints WHERE url=?", (matched_at,)
                    ).fetchone()
                ep_id = ep_row["id"] if ep_row else None

                self.add_vuln(
                    title=name, severity=severity, host_id=host_id,
                    endpoint_id=ep_id, cve=cve_id, cvss=cvss,
                    description=description, remediation=remediation,
                    source="nuclei",
                )
                stats["vulns"] += 1

        self.conn.commit()
        return stats

    # ── Stats ──────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return graph statistics."""
        result = {}
        for table in ["targets", "hosts", "ports", "fingerprints", "endpoints",
                       "vulns", "evidence", "secrets", "attack_paths",
                       "cors_findings", "js_findings"]:
            count = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            result[table] = count

        # Vuln breakdown by severity
        for row in self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM vulns GROUP BY severity"
        ).fetchall():
            result[f"vuln_{row['severity']}"] = row["cnt"]

        # Verified vulns
        result["vulns_verified"] = self.conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE poc_verified=1"
        ).fetchone()[0]

        # Hosts with WAF
        result["hosts_with_waf"] = self.conn.execute(
            "SELECT COUNT(*) FROM hosts WHERE waf IS NOT NULL AND waf != ''"
        ).fetchone()[0]

        return result

    def export_json(self) -> dict:
        """Export entire graph as JSON."""
        tables = {}
        for table in ["targets", "hosts", "ports", "fingerprints", "endpoints",
                       "vulns", "evidence", "secrets", "attack_paths",
                       "cors_findings", "js_findings"]:
            rows = self.conn.execute(f"SELECT * FROM {table}").fetchall()
            tables[table] = [dict(r) for r in rows]
        return {"meta": {"schema_version": SCHEMA_VERSION, "exported_at": datetime.now(timezone.utc).isoformat()}, "data": tables}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extract_tld(domain: str) -> str:
    """Extract registrable domain: sub.example.co.uk -> example.co.uk"""
    parts = domain.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _classify_service(service: str, product: str) -> str:
    """Classify nmap service/product into fingerprint category."""
    product_lower = (product or "").lower()
    if any(k in product_lower for k in ("apache", "nginx", "iis", "tengine", "tomcat")):
        return "server"
    if any(k in product_lower for k in ("spring", "struts", "laravel", "django", "flask", "express")):
        return "framework"
    if any(k in product_lower for k in ("wordpress", "drupal", "joomla", "liferay", "nacos")):
        return "cms"
    if any(k in product_lower for k in ("mysql", "postgres", "redis", "mongo", "elasticsearch", "oracle")):
        return "database"
    if service in ("http", "https"):
        return "server"
    return "component"


def _classify_tech(tech: str) -> str:
    """Classify httpx tech stack into fingerprint category."""
    t = tech.lower()
    if any(k in t for k in ("spring", "struts", "laravel", "django", "flask", "express", "next.js", "nuxt", "vue", "react", "angular")):
        return "framework"
    if any(k in t for k in ("wordpress", "drupal", "joomla", "liferay", "nacos")):
        return "cms"
    if any(k in t for k in ("nginx", "apache", "iis", "tengine", "tomcat", "jetty", "undertow")):
        return "server"
    if any(k in t for k in ("java", "python", "node", "php", "ruby", "go", "asp.net")):
        return "language"
    if any(k in t for k in ("shiro", "jwt", "oauth", "cas", "saml")):
        return "auth"
    return "component"


# ─── CLI ──────────────────────────────────────────────────────────────────────

def cmd_init(args):
    outdir = Path(args.outdir) / args.domain.replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    db_path = str(outdir / "graph.db")
    g = PentestGraph(db_path)
    tid = g.add_target(args.domain)
    g.close()
    print(json.dumps({"db": db_path, "target_id": tid, "domain": args.domain}))


def cmd_add_host(args):
    g = PentestGraph(args.db)
    hid = g.add_host(
        domain=args.domain, ip=args.ip, cdn=args.cdn, waf=args.waf,
        os=args.os, http_server=args.http_server, title=args.title,
    )
    g.close()
    print(json.dumps({"host_id": hid}))


def cmd_add_port(args):
    g = PentestGraph(args.db)
    pid = g.add_port(
        args.host_id, args.port, args.protocol, args.state,
        args.service, args.product, args.version,
    )
    g.close()
    print(json.dumps({"port_id": pid}))


def cmd_add_fingerprint(args):
    g = PentestGraph(args.db)
    fid = g.add_fingerprint(
        args.host_id, args.category, args.tech,
        args.version, args.confidence, args.source,
    )
    g.close()
    print(json.dumps({"fingerprint_id": fid}))


def cmd_add_endpoint(args):
    g = PentestGraph(args.db)
    eid = g.add_endpoint(
        args.host_id, args.url, args.method, args.status,
        args.content_type, source=args.source,
    )
    g.close()
    print(json.dumps({"endpoint_id": eid}))


def cmd_add_vuln(args):
    g = PentestGraph(args.db)
    vid = g.add_vuln(
        title=args.title, severity=args.severity, host_id=args.host_id,
        endpoint_id=args.endpoint_id, vuln_type=args.vuln_type,
        cve=args.cve, poc=args.poc, source=args.source,
    )
    g.close()
    print(json.dumps({"vuln_id": vid}))


def cmd_add_evidence(args):
    g = PentestGraph(args.db)
    eid = g.add_evidence(args.vuln_id, args.type, args.content, args.label)
    g.close()
    print(json.dumps({"evidence_id": eid}))


def cmd_add_secret(args):
    g = PentestGraph(args.db)
    sid = g.add_secret(
        args.type, args.value, args.host_id,
        context=args.context, impact=args.impact,
    )
    g.close()
    print(json.dumps({"secret_id": sid}))


def cmd_priority(args):
    g = PentestGraph(args.db)
    targets = g.priority_targets(top=args.top, min_score=args.min_score)
    g.close()
    for t in targets:
        print(json.dumps(t, ensure_ascii=False))


def cmd_attack_plan(args):
    g = PentestGraph(args.db)
    plan = g.generate_attack_plan(mode=args.mode)
    g.close()
    for step in plan:
        print(json.dumps(step, ensure_ascii=False))


def cmd_stats(args):
    g = PentestGraph(args.db)
    s = g.stats()
    g.close()
    print(json.dumps(s, indent=2))


def cmd_export(args):
    g = PentestGraph(args.db)
    data = g.export_json()
    g.close()
    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Exported to {args.output}")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_import_nmap(args):
    g = PentestGraph(args.db)
    s = g.import_nmap_xml(args.xml)
    g.close()
    print(json.dumps(s))


def cmd_import_httpx(args):
    g = PentestGraph(args.db)
    s = g.import_httpx_json(args.json_file)
    g.close()
    print(json.dumps(s))


def cmd_import_nuclei(args):
    g = PentestGraph(args.db)
    s = g.import_nuclei_json(args.json_file)
    g.close()
    print(json.dumps(s))


def cmd_query(args):
    g = PentestGraph(args.db)
    try:
        rows = g.conn.execute(args.sql).fetchall()
        for r in rows:
            print(json.dumps(dict(r), ensure_ascii=False, default=str))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    g.close()


def cmd_add_cors(args):
    g = PentestGraph(args.db)
    cid = g.add_cors(args.host_id, args.url, args.acao, args.acac, args.origin, args.severity)
    g.close()
    print(json.dumps({"cors_id": cid}))


def cmd_add_js_finding(args):
    g = PentestGraph(args.db)
    jid = g.add_js_finding(args.host_id, args.finding_type, args.value, args.source_url, args.context)
    g.close()
    print(json.dumps({"js_finding_id": jid}))


def main():
    p = argparse.ArgumentParser(description="Pentest Graph Engine v3.0")
    sub = p.add_subparsers(dest="cmd")

    # init
    sp = sub.add_parser("init")
    sp.add_argument("domain")
    sp.add_argument("--outdir", default="/tmp/pentest")

    # add-host
    sp = sub.add_parser("add-host")
    sp.add_argument("db")
    sp.add_argument("--domain")
    sp.add_argument("--ip")
    sp.add_argument("--cdn")
    sp.add_argument("--waf")
    sp.add_argument("--os")
    sp.add_argument("--http-server")
    sp.add_argument("--title")

    # add-port
    sp = sub.add_parser("add-port")
    sp.add_argument("db")
    sp.add_argument("--host-id", type=int, required=True)
    sp.add_argument("--port", type=int, required=True)
    sp.add_argument("--protocol", default="tcp")
    sp.add_argument("--state", default="open")
    sp.add_argument("--service")
    sp.add_argument("--product")
    sp.add_argument("--version")

    # add-fingerprint
    sp = sub.add_parser("add-fingerprint")
    sp.add_argument("db")
    sp.add_argument("--host-id", type=int, required=True)
    sp.add_argument("--category", default="component")
    sp.add_argument("--tech", required=True)
    sp.add_argument("--version")
    sp.add_argument("--confidence", type=float, default=0.8)
    sp.add_argument("--source")

    # add-endpoint
    sp = sub.add_parser("add-endpoint")
    sp.add_argument("db")
    sp.add_argument("--host-id", type=int, required=True)
    sp.add_argument("--url", required=True)
    sp.add_argument("--method", default="GET")
    sp.add_argument("--status", type=int)
    sp.add_argument("--content-type")
    sp.add_argument("--source")

    # add-vuln
    sp = sub.add_parser("add-vuln")
    sp.add_argument("db")
    sp.add_argument("--title", required=True)
    sp.add_argument("--severity", required=True)
    sp.add_argument("--host-id", type=int)
    sp.add_argument("--endpoint-id", type=int)
    sp.add_argument("--vuln-type")
    sp.add_argument("--cve")
    sp.add_argument("--poc")
    sp.add_argument("--source")

    # add-evidence
    sp = sub.add_parser("add-evidence")
    sp.add_argument("db")
    sp.add_argument("--vuln-id", type=int, required=True)
    sp.add_argument("--type", required=True)
    sp.add_argument("--content", required=True)
    sp.add_argument("--label")

    # add-secret
    sp = sub.add_parser("add-secret")
    sp.add_argument("db")
    sp.add_argument("--type", required=True)
    sp.add_argument("--value", required=True)
    sp.add_argument("--host-id", type=int)
    sp.add_argument("--context")
    sp.add_argument("--impact")

    # priority
    sp = sub.add_parser("priority")
    sp.add_argument("db")
    sp.add_argument("--top", type=int, default=20)
    sp.add_argument("--min-score", type=float, default=0)

    # attack-plan
    sp = sub.add_parser("attack-plan")
    sp.add_argument("db")
    sp.add_argument("--mode", choices=["full", "fast", "stealth"], default="full")

    # stats
    sp = sub.add_parser("stats")
    sp.add_argument("db")

    # export
    sp = sub.add_parser("export")
    sp.add_argument("db")
    sp.add_argument("--format", default="json")
    sp.add_argument("--output")

    # import-nmap
    sp = sub.add_parser("import-nmap")
    sp.add_argument("db")
    sp.add_argument("--xml", required=True)

    # import-httpx
    sp = sub.add_parser("import-httpx")
    sp.add_argument("db")
    sp.add_argument("--json-file", required=True, dest="json_file")

    # import-nuclei
    sp = sub.add_parser("import-nuclei")
    sp.add_argument("db")
    sp.add_argument("--json-file", required=True, dest="json_file")

    # query
    sp = sub.add_parser("query")
    sp.add_argument("db")
    sp.add_argument("--sql", required=True)

    # add-cors
    sp = sub.add_parser("add-cors")
    sp.add_argument("db")
    sp.add_argument("--host-id", type=int, required=True)
    sp.add_argument("--url", required=True)
    sp.add_argument("--acao", required=True)
    sp.add_argument("--acac")
    sp.add_argument("--origin")
    sp.add_argument("--severity", default="medium")

    # add-js-finding
    sp = sub.add_parser("add-js-finding")
    sp.add_argument("db")
    sp.add_argument("--host-id", type=int, required=True)
    sp.add_argument("--finding-type", required=True)
    sp.add_argument("--value", required=True)
    sp.add_argument("--source-url")
    sp.add_argument("--context")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return

    cmds = {
        "init": cmd_init, "add-host": cmd_add_host, "add-port": cmd_add_port,
        "add-fingerprint": cmd_add_fingerprint, "add-endpoint": cmd_add_endpoint,
        "add-vuln": cmd_add_vuln, "add-evidence": cmd_add_evidence,
        "add-secret": cmd_add_secret, "add-cors": cmd_add_cors,
        "add-js-finding": cmd_add_js_finding,
        "priority": cmd_priority, "attack-plan": cmd_attack_plan,
        "stats": cmd_stats, "export": cmd_export,
        "import-nmap": cmd_import_nmap, "import-httpx": cmd_import_httpx,
        "import-nuclei": cmd_import_nuclei, "query": cmd_query,
    }
    fn = cmds.get(args.cmd)
    if fn:
        fn(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
