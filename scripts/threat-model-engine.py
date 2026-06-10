#!/usr/bin/env python3
"""
Threat Model Engine v3.1 — 系统级威胁建模

不做枚举，做理解。从图谱中推断：
  1. 业务对象 (Business Objects) — 系统管理什么实体？
  2. 信任边界 (Trust Boundaries) — 谁信任谁？边界在哪？
  3. 数据流 (Data Flows) — 敏感数据怎么流动？
  4. 角色层次 (Role Hierarchy) — 有哪些权限级别？
  5. 攻击面 (Attack Surface) — 边界交叉点在哪？

这些信息无法通过扫描获得，必须从URL结构、参数命名、响应内容、
JS代码、API文档中推断。

用法:
  threat-model-engine.py <graph.db> [--output /tmp/model.json]
  threat-model-engine.py <graph.db> --objects     (仅业务对象)
  threat-model-engine.py <graph.db> --boundaries  (仅信任边界)
  threat-model-engine.py <graph.db> --flows       (仅数据流)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from importlib import import_module

def _get_graph(db_path):
    spec = import_module("vuln-graph-engine")
    return spec.PentestGraph(db_path)


# ─── Business Object Patterns ─────────────────────────────────────────────────

# 从URL路径和参数名推断业务对象
OBJECT_SIGNALS = {
    "user": {
        "url_patterns": [r"/user[s]?/", r"/member[s]?/", r"/account[s]?/", r"/profile",
                         r"/student[s]?/", r"/teacher[s]?/", r"/employee[s]?/", r"/staff[s]?"],
        "param_patterns": [r"userId", r"uid", r"memberId", r"studentId", r"teacherId",
                           r"employeeId", r"accountId", r"username"],
        "sensitive_fields": ["phone", "mobile", "email", "idcard", "身份证", "姓名",
                             "address", "住址", "salary", "工资"],
        "importance": 10,
    },
    "order": {
        "url_patterns": [r"/order[s]?/", r"/booking[s]?/", r"/trade[s]?/",
                         r"/transaction[s]?/", r"/payment[s]?/"],
        "param_patterns": [r"orderId", r"tradeNo", r"transactionId", r"bookingId", r"payId"],
        "sensitive_fields": ["amount", "金额", "price", "价格", "total", "payTime", "status"],
        "importance": 9,
    },
    "file": {
        "url_patterns": [r"/file[s]?/", r"/upload[s]?/", r"/download[s]?/",
                         r"/attachment[s]?/", r"/document[s]?/", r"/resource[s]?/"],
        "param_patterns": [r"fileId", r"resId", r"ossId", r"fileUrl", r"genName", r"attachId"],
        "sensitive_fields": ["fileUrl", "downloadUrl", "resId", "genName", "path"],
        "importance": 8,
    },
    "auth": {
        "url_patterns": [r"/auth[s]?/", r"/login", r"/logout", r"/token",
                         r"/oauth/", r"/sso/", r"/cas/", r"/passport/"],
        "param_patterns": [r"token", r"ticket", r"code", r"session", r"jwt",
                           r"accessToken", r"refreshToken", r"grant_type"],
        "sensitive_fields": ["token", "ticket", "secret", "password", "credential"],
        "importance": 10,
    },
    "config": {
        "url_patterns": [r"/config[s]?/", r"/setting[s]?/", r"/admin[s]?/",
                         r"/manage[r]?/", r"/system/", r"/env"],
        "param_patterns": [r"configId", r"settingKey", r"env"],
        "sensitive_fields": ["database", "redis", "password", "secret", "key", "dsn"],
        "importance": 9,
    },
    "message": {
        "url_patterns": [r"/message[s]?/", r"/notification[s]?/", r"/mail[s]?/",
                         r"/sms/", r"/email/", r"/chat[s]?/"],
        "param_patterns": [r"msgId", r"notifId", r"mailId"],
        "sensitive_fields": ["content", "body", "subject", "recipient", "phone"],
        "importance": 6,
    },
    "course": {
        "url_patterns": [r"/course[s]?/", r"/class[es]?/", r"/lesson[s]?/",
                         r"/grade[s]?/", r"/score[s]?/", r"/exam[s]?/"],
        "param_patterns": [r"courseId", r"classId", r"lessonId", r"gradeId", r"examId"],
        "sensitive_fields": ["score", "成绩", "grade", "rank", "排名", "gpa"],
        "importance": 7,
    },
    "org": {
        "url_patterns": [r"/org[s]?/", r"/tenant[s]?/", r"/department[s]?/",
                         r"/dept[s]?/", r"/company/", r"/enterprise/"],
        "param_patterns": [r"orgId", r"tenantId", r"deptId", r"companyId", r"enterpriseId"],
        "sensitive_fields": ["orgName", "tenant", "department", "部门"],
        "importance": 8,
    },
    "api_key": {
        "url_patterns": [r"/api[_-]?key", r"/app[_-]?key", r"/secret",
                         r"/credential[s]?/", r"/token[s]?/"],
        "param_patterns": [r"appKey", r"appSecret", r"apiKey", r"clientSecret", r"accessKey"],
        "sensitive_fields": ["appKey", "appSecret", "apiKey", "clientSecret", "AK", "SK"],
        "importance": 10,
    },
}

# Trust boundary signals
BOUNDARY_SIGNALS = {
    "auth_required": {
        "detect": lambda ep: ep.get("auth_required") == 1,
        "severity": "info",
        "note": "Endpoint requires authentication",
    },
    "no_auth": {
        "detect": lambda ep: ep.get("auth_required") == 0,
        "severity": "high",
        "note": "Endpoint accessible without authentication — potential unauthorized access",
    },
    "auth_unknown": {
        "detect": lambda ep: ep.get("auth_required") == -1,
        "severity": "info",
        "note": "Authentication status unknown — needs manual check",
    },
    "sensitive_no_auth": {
        "detect": lambda ep: ep.get("auth_required") == 0 and ep.get("sensitive") == 1,
        "severity": "critical",
        "note": "Sensitive data accessible without authentication",
    },
    "admin_panel": {
        "detect": lambda ep: bool(re.search(r"/admin|/manage|/system|/backend", ep.get("url", ""), re.I)),
        "severity": "high",
        "note": "Admin/management interface detected",
    },
}

# Role inference from URL patterns
ROLE_PATTERNS = {
    "superadmin": [r"/superadmin", r"/root", r"/system/manage"],
    "admin": [r"/admin", r"/manage[r]?/", r"/backend", r"/console"],
    "operator": [r"/operator", r"/staff", r"/editor"],
    "user": [r"/user", r"/member", r"/my", r"/profile", r"/personal"],
    "anonymous": [r"/public", r"/open", r"/guest", r"/anonymous"],
}


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class BusinessObject:
    name: str
    type: str                   # user, order, file, auth, config, ...
    endpoints: list[str]        # Related endpoint URLs
    params: list[str]           # Related parameters
    sensitive_fields: list[str] # Sensitive fields found
    importance: int             # 1-10
    operations: dict[str, list[str]] = field(default_factory=dict)  # CRUD operations

@dataclass
class TrustBoundary:
    name: str
    type: str                   # auth_required, no_auth, cors, sso, service_mesh
    source: str                 # What trusts
    target: str                 # What is trusted
    severity: str
    note: str
    evidence: list[str] = field(default_factory=list)

@dataclass
class DataFlow:
    source: str                 # Where data enters
    destination: str            # Where data goes
    data_type: str              # What kind of data
    sensitivity: str            # high/medium/low
    path: list[str] = field(default_factory=list)  # Intermediate hops

@dataclass
class RoleLevel:
    name: str                   # superadmin, admin, user, anonymous
    endpoints: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)  # What led us to infer this role

@dataclass
class ThreatModel:
    target: str
    business_objects: list[dict] = field(default_factory=list)
    trust_boundaries: list[dict] = field(default_factory=list)
    data_flows: list[dict] = field(default_factory=list)
    role_hierarchy: list[dict] = field(default_factory=list)
    attack_surface: list[dict] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)


# ─── Engine ───────────────────────────────────────────────────────────────────

class ThreatModelEngine:
    """Model the target as a system, not a list of URLs."""

    def __init__(self, graph_db: str):
        self.graph = _get_graph(graph_db)
        self.model = ThreatModel(target="")
        self.reasoning = []

    def build_model(self) -> ThreatModel:
        """Build complete threat model from graph data."""
        targets = self.graph.conn.execute("SELECT * FROM targets").fetchall()
        if targets:
            self.model.target = targets[0]["domain"]

        self._infer_business_objects()
        self._infer_trust_boundaries()
        self._infer_data_flows()
        self._infer_role_hierarchy()
        self._compute_attack_surface()

        self.model.reasoning = self.reasoning
        self.graph.close()
        return self.model

    # ── Business Objects ───────────────────────────────────────────────────

    def _infer_business_objects(self):
        """Infer business objects from URL patterns and parameters."""
        endpoints = self.graph.get_endpoints()
        secrets = self.graph.get_secrets()
        js_findings = [dict(r) for r in self.graph.conn.execute("SELECT * FROM js_findings").fetchall()]

        # Group endpoints by object type
        object_hits = defaultdict(lambda: {"endpoints": [], "params": set(), "sensitive": set(), "ops": defaultdict(list)})

        for ep in endpoints:
            url = ep.get("url", "")
            url_lower = url.lower()

            for obj_type, signals in OBJECT_SIGNALS.items():
                score = 0

                # URL pattern match
                for pattern in signals["url_patterns"]:
                    if re.search(pattern, url_lower):
                        score += 3
                        break

                # Parameter match
                params_str = ep.get("params", "") or ""
                for pattern in signals["param_patterns"]:
                    if re.search(pattern, url_lower + " " + params_str, re.I):
                        score += 2
                        break

                # Sensitive field match
                body = ep.get("body_snippet", "") or ""
                for field in signals["sensitive_fields"]:
                    if field.lower() in body.lower() or field.lower() in url_lower:
                        object_hits[obj_type]["sensitive"].add(field)
                        score += 1

                if score >= 2:
                    object_hits[obj_type]["endpoints"].append(url)
                    object_hits[obj_type]["params"].update(
                        re.findall(r"[A-Za-z][A-Za-z0-9_]*[Ii]d|[A-Za-z][A-Za-z0-9_]*[Kk]ey", url + " " + params_str)
                    )

                    # Infer CRUD operation
                    method = (ep.get("method") or "GET").upper()
                    if method in ("POST", "PUT", "PATCH"):
                        object_hits[obj_type]["ops"]["write"].append(url)
                    elif method == "DELETE":
                        object_hits[obj_type]["ops"]["delete"].append(url)
                    else:
                        object_hits[obj_type]["ops"]["read"].append(url)

        # Also check JS findings for object references
        for js in js_findings:
            val = js.get("value", "")
            for obj_type, signals in OBJECT_SIGNALS.items():
                for pattern in signals["param_patterns"]:
                    if re.search(pattern, val, re.I):
                        object_hits[obj_type]["params"].add(val[:100])

        # Check secrets for API keys
        for s in secrets:
            if s.get("type") in ("api_key", "app_secret", "token"):
                object_hits["api_key"]["sensitive"].add(s["type"])

        # Build business objects
        for obj_type, data in object_hits.items():
            if not data["endpoints"] and not data["params"]:
                continue

            signals = OBJECT_SIGNALS[obj_type]
            bo = BusinessObject(
                name=obj_type,
                type=obj_type,
                endpoints=data["endpoints"][:20],
                params=list(data["params"])[:20],
                sensitive_fields=list(data["sensitive"]),
                importance=signals["importance"],
                operations={k: v[:10] for k, v in data["ops"].items()},
            )
            self.model.business_objects.append(asdict(bo))

            ep_count = len(data["endpoints"])
            self.reasoning.append(
                f"[OBJECT] {obj_type}: {ep_count} endpoints, "
                f"{len(data['params'])} params, "
                f"sensitive={list(data['sensitive'])[:5]}"
            )

    # ── Trust Boundaries ───────────────────────────────────────────────────

    def _infer_trust_boundaries(self):
        """Infer trust boundaries from auth patterns, CORS, WAF, service topology."""
        endpoints = self.graph.get_endpoints()
        hosts = self.graph.get_hosts()
        cors = [dict(r) for r in self.graph.conn.execute("SELECT * FROM cors_findings").fetchall()]
        secrets = self.graph.get_secrets()

        boundaries = []

        # 1. Auth boundaries from endpoints
        for ep in endpoints:
            for btype, bsignal in BOUNDARY_SIGNALS.items():
                if bsignal["detect"](ep):
                    tb = TrustBoundary(
                        name=f"{btype}:{ep.get('url', '')}",
                        type=btype,
                        source="client",
                        target=ep.get("url", ""),
                        severity=bsignal["severity"],
                        note=bsignal["note"],
                    )
                    boundaries.append(tb)

                    if btype == "sensitive_no_auth":
                        self.reasoning.append(
                            f"[CRITICAL BOUNDARY] Sensitive endpoint without auth: {ep.get('url', '')}"
                        )

        # 2. CORS trust relationships
        for c in cors:
            acao = c.get("acao", "")
            if acao in ("*", "null") or "evil" in acao.lower():
                tb = TrustBoundary(
                    name=f"cors_trust:{c.get('url', '')}",
                    type="cors",
                    source=f"origin:{acao}",
                    target=c.get("url", ""),
                    severity=c.get("severity", "medium"),
                    note=f"CORS allows origin={acao}, credentials={c.get('acac', 'N/A')}",
                    evidence=[f"ACAO={acao}, ACAC={c.get('acac', '')}"],
                )
                boundaries.append(tb)

        # 3. Service-to-service trust (from WAF/CDN/host topology)
        host_groups = defaultdict(list)
        for h in hosts:
            ip = h.get("ip", "")
            if ip:
                host_groups[ip].append(h)

        # Multiple domains behind same IP = shared trust boundary
        for ip, group in host_groups.items():
            if len(group) > 1:
                domains = [h.get("domain", "") for h in group]
                tb = TrustBoundary(
                    name=f"shared_backend:{ip}",
                    type="shared_infrastructure",
                    source=", ".join(domains[:5]),
                    target=ip,
                    severity="info",
                    note=f"Multiple domains share backend IP {ip}",
                )
                boundaries.append(tb)

        # 4. Secrets as trust tokens
        for s in secrets:
            if s.get("type") in ("api_key", "app_secret", "token"):
                tb = TrustBoundary(
                    name=f"leaked_credential:{s.get('type', '')}",
                    type="credential_leak",
                    source="frontend/config",
                    target=s.get("context", "unknown"),
                    severity="high",
                    note=f"Leaked {s['type']} — system trusts this credential for access",
                )
                boundaries.append(tb)
                self.reasoning.append(
                    f"[BOUNDARY] Leaked {s['type']} in {s.get('context', 'unknown')} — "
                    f"this credential is a trust token"
                )

        self.model.trust_boundaries = [asdict(b) for b in boundaries]

    # ── Data Flows ─────────────────────────────────────────────────────────

    def _infer_data_flows(self):
        """Infer how sensitive data flows through the system."""
        endpoints = self.graph.get_endpoints()
        js_findings = [dict(r) for r in self.graph.conn.execute("SELECT * FROM js_findings").fetchall()]

        flows = []

        # Pattern: endpoint returns sensitive data
        for ep in endpoints:
            url = ep.get("url", "")
            body = (ep.get("body_snippet", "") or "").lower()

            # Check if response contains sensitive patterns
            sensitive_types = []
            if re.search(r"phone|mobile|手机|电话", body):
                sensitive_types.append("phone")
            if re.search(r"email|邮箱", body):
                sensitive_types.append("email")
            if re.search(r"idcard|身份证|identity", body):
                sensitive_types.append("idcard")
            if re.search(r"token|jwt|session", body):
                sensitive_types.append("auth_token")
            if re.search(r"password|密码|passwd", body):
                sensitive_types.append("password")
            if re.search(r"余额|balance|amount|金额|价格|price", body):
                sensitive_types.append("financial")

            for st in sensitive_types:
                df = DataFlow(
                    source="api_response",
                    destination=url,
                    data_type=st,
                    sensitivity="high" if st in ("idcard", "password", "auth_token", "financial") else "medium",
                    path=[url],
                )
                flows.append(df)

        # Pattern: JS file → API endpoint → sensitive data
        for js in js_findings:
            if js.get("finding_type") == "api_endpoint":
                val = js.get("value", "")
                source_url = js.get("source_url", "")
                df = DataFlow(
                    source=f"js:{source_url}",
                    destination=val,
                    data_type="api_reference",
                    sensitivity="medium",
                    path=[source_url, val],
                )
                flows.append(df)

        self.model.data_flows = [asdict(f) for f in flows]

        if flows:
            self.reasoning.append(
                f"[DATA FLOW] {len(flows)} sensitive data flows identified"
            )

    # ── Role Hierarchy ─────────────────────────────────────────────────────

    def _infer_role_hierarchy(self):
        """Infer role hierarchy from URL patterns."""
        endpoints = self.graph.get_endpoints()

        roles = {}
        for role_name, patterns in ROLE_PATTERNS.items():
            role = RoleLevel(name=role_name)
            for ep in endpoints:
                url = ep.get("url", "")
                for pattern in patterns:
                    if re.search(pattern, url, re.I):
                        role.endpoints.append(url)
                        role.indicators.append(pattern)
                        break

            if role.endpoints:
                roles[role_name] = role

        self.model.role_hierarchy = [asdict(r) for r in roles.values()]

        if roles:
            self.reasoning.append(
                f"[ROLES] Inferred {len(roles)} role levels: {', '.join(roles.keys())}"
            )

    # ── Attack Surface ─────────────────────────────────────────────────────

    def _compute_attack_surface(self):
        """Compute attack surface as intersection of boundaries and objects."""
        surface = []

        # 1. High-value objects accessible at trust boundary crossings
        for obj in self.model.business_objects:
            if obj["importance"] >= 8:
                for ep_url in obj["endpoints"]:
                    # Check if this endpoint is at a trust boundary
                    matching_boundaries = [
                        b for b in self.model.trust_boundaries
                        if ep_url in b.get("target", "") or ep_url in b.get("source", "")
                    ]
                    for boundary in matching_boundaries:
                        if boundary["severity"] in ("high", "critical"):
                            surface.append({
                                "type": "boundary_object_intersection",
                                "object": obj["name"],
                                "endpoint": ep_url,
                                "boundary": boundary["type"],
                                "severity": boundary["severity"],
                                "reasoning": (
                                    f"High-value object '{obj['name']}' (importance={obj['importance']}) "
                                    f"is accessible at trust boundary '{boundary['type']}'"
                                ),
                            })

        # 2. Write operations on sensitive objects without clear auth
        for obj in self.model.business_objects:
            for write_ep in obj.get("operations", {}).get("write", []):
                surface.append({
                    "type": "write_operation",
                    "object": obj["name"],
                    "endpoint": write_ep,
                    "severity": "high",
                    "reasoning": (
                        f"Write operation on '{obj['name']}' — check if authorization "
                        f"is enforced for create/update"
                    ),
                })

        # 3. Parameter manipulation opportunities
        for obj in self.model.business_objects:
            if len(obj["params"]) >= 2:
                surface.append({
                    "type": "parameter_manipulation",
                    "object": obj["name"],
                    "params": obj["params"][:10],
                    "severity": "high",
                    "reasoning": (
                        f"Object '{obj['name']}' has {len(obj['params'])} identifiers — "
                        f"test cross-object access (IDOR/BOLA)"
                    ),
                })

        # 4. Auth → Sensitive data flow
        for flow in self.model.data_flows:
            if flow["sensitivity"] == "high":
                surface.append({
                    "type": "sensitive_data_exposure",
                    "data_type": flow["data_type"],
                    "endpoint": flow["destination"],
                    "severity": "high",
                    "reasoning": (
                        f"Sensitive data '{flow['data_type']}' flows to {flow['destination']} — "
                        f"verify access controls on this endpoint"
                    ),
                })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        surface.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))

        self.model.attack_surface = surface

        self.reasoning.append(
            f"[ATTACK SURFACE] {len(surface)} attack surface points identified"
        )


def main():
    p = argparse.ArgumentParser(description="Threat Model Engine v3.1")
    p.add_argument("graph_db", help="Path to graph.db")
    p.add_argument("--output", help="Output JSON file")
    p.add_argument("--objects", action="store_true", help="Show business objects only")
    p.add_argument("--boundaries", action="store_true", help="Show trust boundaries only")
    p.add_argument("--flows", action="store_true", help="Show data flows only")
    args = p.parse_args()

    engine = ThreatModelEngine(args.graph_db)
    model = engine.build_model()

    if args.objects:
        for obj in model.business_objects:
            print(json.dumps(obj, ensure_ascii=False, indent=2))
        return

    if args.boundaries:
        for b in model.trust_boundaries:
            print(json.dumps(b, ensure_ascii=False, indent=2))
        return

    if args.flows:
        for f in model.data_flows:
            print(json.dumps(f, ensure_ascii=False, indent=2))
        return

    # Full model
    result = asdict(model)

    if args.output:
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(f"Model saved to {args.output}")
    else:
        # Summary
        print(f"=== Threat Model: {model.target} ===")
        print(f"  Business Objects: {len(model.business_objects)}")
        print(f"  Trust Boundaries: {len(model.trust_boundaries)}")
        print(f"  Data Flows: {len(model.data_flows)}")
        print(f"  Role Levels: {len(model.role_hierarchy)}")
        print(f"  Attack Surface: {len(model.attack_surface)}")
        print()

        for r in model.reasoning:
            print(f"  {r}")

        print(f"\n=== Top Attack Surface ===")
        for point in model.attack_surface[:10]:
            sev = point.get("severity", "info")
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "⚪")
            print(f"  {icon} [{sev}] {point.get('reasoning', '')}")


if __name__ == "__main__":
    main()
