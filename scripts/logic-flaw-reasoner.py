#!/usr/bin/env python3
"""
Logic Flaw Reasoner v3.1 — 从设计缺陷中寻找漏洞

不穷举payload，而是推理系统设计中的逻辑漏洞：

1. 状态机绕过 — 多步流程能否跳步？能否回退？
2. 竞态条件 — 并发请求能否突破业务限制？
3. 参数篡改 — 前端限制能否绕过？负数/零/极大值？
4. TOCTOU — 检查和使用之间的时间窗口
5. 不一致性攻击 — 不同接口对同一数据的处理是否一致？
6. 信任反向 — 后端信任前端的什么假设？
7. 权限水平越权 — 同角色间能否互相访问？
8. 权限垂直越权 — 低权限能否访问高权限功能？

核心思路：每个业务系统都有"假设"，漏洞就藏在假设不成立的地方。

用法:
  logic-flaw-reasoner.py <graph.db> [--model <threat-model.json>] [--phase state_machine|race|inconsistency|privilege]
  logic-flaw-reasoner.py <graph.db> --think  (仅输出推理分析，不执行)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import subprocess
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


# ─── Logic Flaw Patterns ─────────────────────────────────────────────────────

@dataclass
class FlawHypothesis:
    """A hypothesis about a logic flaw in the system."""
    flaw_type: str              # state_machine, race, param_tamper, inconsistency, privilege, trust_reverse
    title: str
    confidence: str             # high / medium / low
    reasoning: str              # Why we think this flaw exists
    targets: list[str]          # Endpoints/objects involved
    test_method: str            # How to verify
    test_commands: list[str]    # Specific commands to run
    expected_if_vulnerable: str # What we expect to see if flaw exists
    expected_if_safe: str       # What we expect to see if system is safe
    severity: str               # critical / high / medium
    status: str = "untested"    # untested / testing / confirmed / disproved


class LogicFlawReasoner:
    """Reason about logic flaws in the target system."""

    def __init__(self, graph_db: str, model_path: str = None):
        self.graph = _get_graph(graph_db)
        self.hypotheses: list[FlawHypothesis] = []

        # Load threat model if available
        self.model = None
        if model_path and Path(model_path).exists():
            self.model = json.loads(Path(model_path).read_text())

    def think(self) -> list[FlawHypothesis]:
        """Generate hypotheses about logic flaws. No execution, pure reasoning."""
        self._reason_state_machines()
        self._reason_parameter_tampering()
        self._reason_inconsistency()
        self._reason_privilege_escalation()
        self._reason_trust_reversal()
        self._reason_race_conditions()

        # Sort by confidence
        conf_order = {"high": 0, "medium": 1, "low": 2}
        self.hypotheses.sort(key=lambda h: conf_order.get(h.confidence, 3))

        self.graph.close()
        return self.hypotheses

    def test(self, phase: str = None) -> list[FlawHypothesis]:
        """Generate and test hypotheses."""
        hypotheses = self.think()

        if phase:
            hypotheses = [h for h in hypotheses if h.flaw_type == phase]

        print(f"\n[*] Logic Flaw Reasoner: {len(hypotheses)} hypotheses")
        for h in hypotheses:
            print(f"\n  [{h.confidence.upper()}] {h.title}")
            print(f"    Type: {h.flaw_type}")
            print(f"    Reasoning: {h.reasoning[:120]}")
            if h.test_commands:
                print(f"    Test: {h.test_commands[0][:120]}")

        return hypotheses

    # ── State Machine Analysis ─────────────────────────────────────────────

    def _reason_state_machines(self):
        """Detect multi-step flows that might be bypassable."""
        endpoints = self.graph.get_endpoints()

        # Find sequential endpoint patterns (step1/step2, verify/confirm, etc.)
        step_patterns = [
            (r"(step|stage|phase)[-_]?(\d+)", "numbered_steps"),
            (r"(verify|confirm|validate|check)", "verification_step"),
            (r"(submit|approve|reject|review)", "approval_step"),
            (r"(send|receive|callback|notify)", "callback_step"),
            (r"(init|start|begin).*?(complete|finish|end|done)", "init_complete_flow"),
        ]

        # Group endpoints by potential flow
        flows = defaultdict(list)
        for ep in endpoints:
            url = ep.get("url", "")
            for pattern, flow_type in step_patterns:
                if re.search(pattern, url, re.I):
                    flows[flow_type].append(ep)

        # For each flow with multiple steps, hypothesize bypass
        for flow_type, eps in flows.items():
            if len(eps) < 2:
                continue

            urls = [ep.get("url", "") for ep in eps]

            # Can we skip to the last step directly?
            last_step = urls[-1]
            self.hypotheses.append(FlawHypothesis(
                flaw_type="state_machine",
                title=f"State machine bypass: {flow_type} flow",
                confidence="medium",
                reasoning=(
                    f"Found {len(eps)}-step flow ({flow_type}). "
                    f"Pattern: {' → '.join(u.split('/')[-1] for u in urls[:5])}. "
                    f"Hypothesis: system may not enforce that previous steps were completed "
                    f"before allowing access to later steps."
                ),
                targets=urls,
                test_method="Direct access to final step without completing prerequisites",
                test_commands=[
                    f'curl -sk "{last_step}" -D- -m 10',
                    f'curl -sk "{last_step}" -X POST -D- -m 10',
                ],
                expected_if_vulnerable="200 with real data or successful action",
                expected_if_safe="400/403/422 indicating missing prerequisites",
                severity="high",
            ))

            # Can we replay a completed step?
            if flow_type == "verification_step":
                self.hypotheses.append(FlawHypothesis(
                    flaw_type="state_machine",
                    title=f"Verification replay: {flow_type}",
                    confidence="low",
                    reasoning=(
                        f"Verification step found. If the system uses a one-time token/code, "
                        f"replaying the same verification might work if the token isn't invalidated."
                    ),
                    targets=urls,
                    test_method="Replay verification request",
                    test_commands=[f'curl -sk "{urls[-1]}" -X POST -d "same_token" -m 10'],
                    expected_if_vulnerable="Repeated verification succeeds",
                    expected_if_safe="Token already used / expired",
                    severity="medium",
                ))

    # ── Parameter Tampering ────────────────────────────────────────────────

    def _reason_parameter_tampering(self):
        """Detect parameters that might be manipulable."""
        endpoints = self.graph.get_endpoints()

        # Find endpoints with business parameters
        business_params = {
            "price": {"tests": ["0", "-1", "9999999"], "reason": "Price can be set to zero or negative"},
            "amount": {"tests": ["0", "-1", "9999999"], "reason": "Amount manipulation"},
            "quantity": {"tests": ["0", "-1", "9999999"], "reason": "Quantity manipulation"},
            "discount": {"tests": ["100", "9999", "-1"], "reason": "Discount override"},
            "role": {"tests": ["admin", "superadmin", "1"], "reason": "Role escalation via parameter"},
            "type": {"tests": ["admin", "vip", "premium"], "reason": "Type/level escalation"},
            "status": {"tests": ["approved", "verified", "active"], "reason": "Status bypass"},
            "isAdmin": {"tests": ["true", "1", "yes"], "reason": "Admin flag injection"},
            "permission": {"tests": ["all", "admin", "*"], "reason": "Permission escalation"},
            "score": {"tests": ["100", "9999", "-1"], "reason": "Score/grade manipulation"},
        }

        for ep in endpoints:
            url = ep.get("url", "")
            params_str = (ep.get("params", "") or "").lower()
            body = (ep.get("body_snippet", "") or "").lower()
            method = (ep.get("method") or "GET").upper()

            if method not in ("POST", "PUT", "PATCH"):
                continue

            combined = url + " " + params_str + " " + body

            for param, config in business_params.items():
                if param.lower() in combined:
                    sep = "&" if "?" in url else "?"
                    test_cmds = []
                    for val in config["tests"]:
                        test_cmds.append(
                            f'curl -sk "{url}" -X {method} -d "{param}={val}" -H "Content-Type: application/x-www-form-urlencoded" -m 10'
                        )

                    self.hypotheses.append(FlawHypothesis(
                        flaw_type="param_tamper",
                        title=f"Parameter manipulation: {param} on {url.split('/')[-1]}",
                        confidence="medium",
                        reasoning=(
                            f"Endpoint {url} accepts '{param}' parameter. "
                            f"Hypothesis: {config['reason']}. "
                            f"The system may trust client-provided values for '{param}' "
                            f"without server-side validation."
                        ),
                        targets=[url],
                        test_method=f"Submit manipulated {param} values",
                        test_commands=test_cmds,
                        expected_if_vulnerable=f"System accepts manipulated {param} value",
                        expected_if_safe=f"System rejects or normalizes {param}",
                        severity="high" if param in ("role", "isAdmin", "permission") else "medium",
                    ))

    # ── Inconsistency Attacks ──────────────────────────────────────────────

    def _reason_inconsistency(self):
        """Detect inconsistencies between endpoints that handle same data."""
        endpoints = self.graph.get_endpoints()

        # Group endpoints by apparent resource
        resource_groups = defaultdict(list)
        for ep in endpoints:
            url = ep.get("url", "")
            # Extract resource name from URL
            parts = [p for p in url.split("/") if p and not p.startswith("{") and not p.startswith("?")]
            if len(parts) >= 2:
                # Use last 2 path segments as resource key
                resource = "/".join(parts[-2:])
                resource_groups[resource].append(ep)

        # Find resources accessed via different methods or paths
        for resource, eps in resource_groups.items():
            methods = set(ep.get("method", "GET") for ep in eps)
            auth_states = set(ep.get("auth_required", -1) for ep in eps)

            # Different auth requirements for same resource = inconsistency
            if len(auth_states) > 1 and 0 in auth_states:
                no_auth_eps = [ep for ep in eps if ep.get("auth_required") == 0]
                auth_eps = [ep for ep in eps if ep.get("auth_required") == 1]

                self.hypotheses.append(FlawHypothesis(
                    flaw_type="inconsistency",
                    title=f"Auth inconsistency: {resource}",
                    confidence="high",
                    reasoning=(
                        f"Resource '{resource}' has endpoints with different auth requirements. "
                        f"Unauthenticated: {[ep.get('url','') for ep in no_auth_eps[:3]]}. "
                        f"Authenticated: {[ep.get('url','') for ep in auth_eps[:3]]}. "
                        f"The unauthenticated endpoint may expose the same data as the authenticated one."
                    ),
                    targets=[ep.get("url", "") for ep in eps],
                    test_method="Compare responses from auth vs no-auth endpoints",
                    test_commands=[
                        f'curl -sk "{no_auth_eps[0].get("url","")}" -D- -m 10',
                        f'curl -sk "{auth_eps[0].get("url","")}" -D- -m 10',
                    ],
                    expected_if_vulnerable="Same or similar data from both endpoints",
                    expected_if_safe="Unauthenticated endpoint returns error or empty",
                    severity="high",
                ))

            # Different methods on same resource (GET returns what POST protects)
            if "GET" in methods and "POST" in methods:
                get_eps = [ep for ep in eps if ep.get("method") == "GET"]
                post_eps = [ep for ep in eps if ep.get("method") == "POST"]

                if get_eps and post_eps:
                    self.hypotheses.append(FlawHypothesis(
                        flaw_type="inconsistency",
                        title=f"Method inconsistency: {resource}",
                        confidence="low",
                        reasoning=(
                            f"Resource '{resource}' is accessible via both GET and POST. "
                            f"If POST requires auth but GET doesn't, data may leak."
                        ),
                        targets=[get_eps[0].get("url", ""), post_eps[0].get("url", "")],
                        test_method="Compare GET vs POST responses",
                        test_commands=[f'curl -sk "{get_eps[0].get("url","")}" -m 10'],
                        expected_if_vulnerable="GET returns data that should require POST",
                        expected_if_safe="GET returns 405 or same auth requirement",
                        severity="medium",
                    ))

    # ── Privilege Escalation ───────────────────────────────────────────────

    def _reason_privilege_escalation(self):
        """Detect potential privilege escalation paths."""
        endpoints = self.graph.get_endpoints()
        secrets = self.graph.get_secrets()

        # 1. Admin endpoints without clear auth
        admin_eps = [
            ep for ep in endpoints
            if re.search(r"/admin|/manage|/system|/backend|/console", ep.get("url", ""), re.I)
            and ep.get("auth_required") != 1
        ]

        if admin_eps:
            self.hypotheses.append(FlawHypothesis(
                flaw_type="privilege",
                title=f"Admin interface potentially accessible: {len(admin_eps)} endpoints",
                confidence="medium",
                reasoning=(
                    f"Found {len(admin_eps)} admin/management endpoints without confirmed auth: "
                    f"{[ep.get('url','') for ep in admin_eps[:5]]}. "
                    f"These might be accessible without admin privileges."
                ),
                targets=[ep.get("url", "") for ep in admin_eps],
                test_method="Access admin endpoints without admin token",
                test_commands=[
                    f'curl -sk "{ep.get("url","")}" -D- -m 10' for ep in admin_eps[:3]
                ],
                expected_if_vulnerable="200 with admin data",
                expected_if_safe="302 to login / 403",
                severity="critical",
            ))

        # 2. API with predictable IDs (horizontal IDOR)
        id_params = set()
        for ep in endpoints:
            url = ep.get("url", "")
            for match in re.finditer(r"/(\d+)(?:/|$|\?)", url):
                id_params.add(match.group(1))

        if id_params:
            # Find the base URL pattern
            sample_ep = endpoints[0] if endpoints else None
            if sample_ep:
                sample_url = sample_ep.get("url", "")
                base = re.sub(r"/\d+", "/{id}", sample_url)
                self.hypotheses.append(FlawHypothesis(
                    flaw_type="privilege",
                    title="Predictable resource IDs (IDOR potential)",
                    confidence="medium",
                    reasoning=(
                        f"Found {len(id_params)} numeric IDs in URLs. "
                        f"Pattern: {base}. "
                        f"If the system doesn't verify resource ownership, "
                        f"users may access other users' resources by changing the ID."
                    ),
                    targets=[sample_url],
                    test_method="Access resource with different user's ID",
                    test_commands=[
                        f'curl -sk "{sample_url}" -m 10',
                        f'# Try with different ID value',
                    ],
                    expected_if_vulnerable="Returns another user's data",
                    expected_if_safe="Returns 403/404 or own data only",
                    severity="high",
                ))

        # 3. Leaked credentials → privilege escalation
        for s in secrets:
            if s.get("type") in ("api_key", "app_secret") and s.get("verified") != 2:
                self.hypotheses.append(FlawHypothesis(
                    flaw_type="privilege",
                    title=f"Leaked {s['type']} → potential privilege escalation",
                    confidence="high",
                    reasoning=(
                        f"Found {s['type']} in {s.get('context', 'unknown')}. "
                        f"If this credential grants API access, it may allow "
                        f"accessing admin functions or other users' data."
                    ),
                    targets=[s.get("context", "")],
                    test_method="Use leaked credential to access privileged endpoints",
                    test_commands=[
                        f'curl -sk -H "Authorization: Bearer {s.get("value","***")}" "TARGET_URL" -m 10',
                    ],
                    expected_if_vulnerable="Credential grants unexpected access",
                    expected_if_safe="Credential is invalid or has limited scope",
                    severity="critical",
                ))

    # ── Trust Reversal ─────────────────────────────────────────────────────

    def _reason_trust_reversal(self):
        """Detect where backend trusts frontend assumptions."""
        endpoints = self.graph.get_endpoints()
        js_findings = [dict(r) for r in self.graph.conn.execute("SELECT * FROM js_findings").fetchall()]

        # Pattern 1: Frontend validation only (check if API accepts bypassed values)
        # Look for endpoints where the response suggests server-side logic depends on client params
        for ep in endpoints:
            body = (ep.get("body_snippet", "") or "").lower()
            url = ep.get("url", "")

            # If response mentions validation but endpoint is accessible
            if any(k in body for k in ("验证码", "captcha", "verify", "validate")):
                self.hypotheses.append(FlawHypothesis(
                    flaw_type="trust_reverse",
                    title=f"Possible client-side validation: {url.split('/')[-1]}",
                    confidence="low",
                    reasoning=(
                        f"Endpoint {url} response mentions validation/captcha. "
                        f"Hypothesis: the validation might be client-side only, "
                        f"or the captcha check might be bypassable."
                    ),
                    targets=[url],
                    test_method="Submit request bypassing validation step",
                    test_commands=[
                        f'curl -sk "{url}" -X POST -d "skip_validation=true" -m 10',
                    ],
                    expected_if_vulnerable="Request succeeds without validation",
                    expected_if_safe="Server rejects missing/invalid validation",
                    severity="high",
                ))

        # Pattern 2: JS config exposes client-side feature flags
        for js in js_findings:
            val = js.get("value", "")
            if re.search(r"(isAdmin|isVip|role|permission|feature_flag|debug)\s*[:=]\s*(true|1|admin)", val, re.I):
                self.hypotheses.append(FlawHypothesis(
                    flaw_type="trust_reverse",
                    title=f"Client-side privilege flag: {val[:80]}",
                    confidence="high",
                    reasoning=(
                        f"JS code contains privilege/role flag: {val[:100]}. "
                        f"If the backend reads this from the client request, "
                        f"an attacker can set it to gain elevated access."
                    ),
                    targets=[js.get("source_url", "")],
                    test_method="Modify client-side flag in requests",
                    test_commands=[
                        f'# Set flag in request header/cookie/body',
                        f'curl -sk "TARGET_URL" -H "X-Is-Admin: true" -m 10',
                    ],
                    expected_if_vulnerable="Backend grants elevated access",
                    expected_if_safe="Backend ignores client-side flag",
                    severity="critical",
                ))

    # ── Race Conditions ────────────────────────────────────────────────────

    def _reason_race_conditions(self):
        """Detect operations susceptible to race conditions."""
        endpoints = self.graph.get_endpoints()

        # Race-prone operations: transfer, redeem, use, consume, vote, like
        race_keywords = [
            (r"transfer|转账|划转", "money_transfer"),
            (r"redeem|兑换|coupon", "coupon_redeem"),
            (r"vote|投票|like|点赞", "vote_like"),
            (r"withdraw|提现|取款", "withdrawal"),
            (r"claim|领取|collect", "claim_reward"),
            (r"apply|报名|register", "registration"),
            (r"book|预约|reserve", "booking"),
        ]

        for ep in endpoints:
            url = ep.get("url", "")
            method = (ep.get("method") or "GET").upper()

            if method not in ("POST", "PUT", "PATCH"):
                continue

            for pattern, race_type in race_keywords:
                if re.search(pattern, url, re.I):
                    self.hypotheses.append(FlawHypothesis(
                        flaw_type="race",
                        title=f"Race condition: {race_type} on {url.split('/')[-1]}",
                        confidence="medium",
                        reasoning=(
                            f"Endpoint {url} performs '{race_type}' operation. "
                            f"This type of operation is susceptible to TOCTOU "
                            f"(time-of-check-time-of-use) race conditions when "
                            f"multiple concurrent requests bypass business limits "
                            f"(e.g., double-spend, duplicate redemption)."
                        ),
                        targets=[url],
                        test_method="Send N concurrent requests and check if limit is enforced",
                        test_commands=[
                            f'# Race condition test: send 20 concurrent requests',
                            f'for i in $(seq 1 20); do curl -sk "{url}" -X POST -d "data" & done; wait',
                        ],
                        expected_if_vulnerable="Multiple requests succeed (double-spend, duplicate)",
                        expected_if_safe="Only one request succeeds, others rejected",
                        severity="critical" if race_type in ("money_transfer", "withdrawal") else "high",
                    ))
                    break  # One hypothesis per endpoint


def main():
    p = argparse.ArgumentParser(description="Logic Flaw Reasoner v3.1")
    p.add_argument("graph_db", help="Path to graph.db")
    p.add_argument("--model", help="Threat model JSON from threat-model-engine.py")
    p.add_argument("--phase", choices=["state_machine", "param_tamper", "inconsistency", "privilege", "trust_reverse", "race"])
    p.add_argument("--think", action="store_true", help="Reasoning only, no execution")
    p.add_argument("--output", help="Output JSON file")
    args = p.parse_args()

    reasoner = LogicFlawReasoner(args.graph_db, args.model)

    if args.think:
        hypotheses = reasoner.think()
    else:
        hypotheses = reasoner.test(phase=args.phase)

    if args.output:
        result = [asdict(h) for h in hypotheses]
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(f"\nSaved to {args.output}")
    else:
        print(f"\n=== {len(hypotheses)} Logic Flaw Hypotheses ===")
        for i, h in enumerate(hypotheses, 1):
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(h.severity, "⚪")
            print(f"\n{i}. {sev_icon} [{h.confidence.upper()}] {h.title}")
            print(f"   Type: {h.flaw_type}")
            print(f"   Reasoning: {h.reasoning[:200]}")
            print(f"   Test: {h.test_method}")
            if h.test_commands:
                print(f"   Command: {h.test_commands[0][:150]}")


if __name__ == "__main__":
    main()
