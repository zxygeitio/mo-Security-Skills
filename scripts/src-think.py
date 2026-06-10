#!/usr/bin/python3
"""SRC reasoning layer: evidence -> hypotheses -> validation queue.

This script intentionally sits between scanners and PoC/reporting. It consumes
Hermes SRC artifacts (probe_results.tsv, endpoints.tsv, js_api_findings.json,
Burp/MITM JSONL, alive/url lists) and produces a small human-pentester style
plan: business objects, attack hypotheses, missing evidence, A/B controls, and
copyable low-impact validation commands.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

HIGH_VALUE_HOST = re.compile(r"(^|[.-])(api|open|auth|sso|cas|ids|oauth|passport|login|portal|ehall|oa|workflow|admin|manage|gateway|pay|order|booking|user|member|vip|upload|file|oss|actuator|swagger)([.-]|$)", re.I)
LOW_VALUE_HOST = re.compile(r"(^|[.-])(www|static|cdn|assets|img|image|news|notice|m|wap)([.-]|$)", re.I)
STATIC_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|css|woff2?|ttf|ico|map|mp4|mp3|pdf|docx?|xlsx?)(?:$|[?#])", re.I)
# Split: FALLBACK_NEGATIVE = always bad (SPA/WAF/error pages)
# LOGIN_FORM = login page forms (negative only when no auth API signal)
FALLBACK_NEGATIVE = re.compile(r"spa_fallback|waf|generic_error|static|401|403|404|access denied|forbidden", re.I)
LOGIN_FORM = re.compile(r"请登录|未登录|登录超时|login required|sign in|用户名.*密码|<form[^>]+login", re.I)
# Full negative hint for backward compat (used where fine-grained control not needed)
NEGATIVE_HINT = re.compile(r"spa_fallback|waf|login|generic_error|static|401|403|404|未登录|请登录|access denied|forbidden", re.I)
SENSITIVE_HINT = re.compile(r"姓名|手机号|身份证|学号|工号|邮箱|email|mobile|phone|idcard|identity|订单|金额|余额|成绩|课程|审批|tenant|orgId|userId|studentId|memberId|orderId|fileId|resId|downloadUrl|fileUrl|token|ticket", re.I)
SECRET_HINT = re.compile(r"appsecret|api[_-]?key|app[_-]?key|access[_-]?token|client[_-]?secret|authorization|bearer|signature|sign|policy", re.I)
OBJECT_PARAM = re.compile(r"(^|[_-])(id|uid|userId|memberId|studentId|teacherId|orderId|fileId|resId|tenantId|orgId|deptId|roleId|appId|clientId|taskId|recordId)($|[_-])", re.I)
STATE_PARAM = re.compile(r"status|role|type|permission|enabled|isAdmin|owner|amount|price|quota|rate|tenant|org|dept", re.I)
METHOD_WRITE = {"POST", "PUT", "PATCH", "DELETE"}

CATEGORY_META = {
    "auth_boundary": {
        "title": "认证边界/未授权敏感接口",
        "gate": "无登录/无token或无效token必须仍能获得真实敏感数据或执行低影响业务动作。",
        "controls": ["no-cookie", "invalid-token", "random-path-same-origin"],
    },
    "idor_bola": {
        "title": "IDOR/BOLA 对象归属校验缺失",
        "gate": "必须证明跨用户/跨组织/非本人对象可读写；随机不存在ID不能返回同样内容。",
        "controls": ["owner-id", "other-low-impact-id", "nonexistent-id"],
    },
    "tenant_bfla": {
        "title": "租户/组织/角色权限边界缺失",
        "gate": "必须证明低权限身份可访问或修改高权限/跨租户对象。",
        "controls": ["low-privilege", "different-tenant", "invalid-role"],
    },
    "file_chain": {
        "title": "上传/下载/文件ID链路",
        "gate": "必须证明未授权上传、可访问URL、下载越权或浏览器处理影响；强制下载按真实影响降级。",
        "controls": ["no-token", "invalid-fileId", "other-fileId"],
    },
    "secret_to_data": {
        "title": "前端密钥/API Key 到数据访问链",
        "gate": "必须证明密钥仍有效且可换token或调用真实只读接口；仅发现密钥不提交。",
        "controls": ["wrong-key", "no-key", "origin-mismatch"],
    },
    "workflow_logic": {
        "title": "多步业务流程状态机缺陷",
        "gate": "必须证明跳步、重放、状态篡改、验证码/回调校验缺失等真实业务影响。",
        "controls": ["missing-previous-step", "wrong-code", "replay-once"],
    },
    "config_exposure": {
        "title": "管理/调试配置暴露",
        "gate": "必须是可读真实JSON/配置/接口文档，并能链到敏感接口或攻击面；登录页/WAF/SPA不提交。",
        "controls": ["random-path", "accept-json", "no-auth"],
    },
}

@dataclass
class Candidate:
    url: str
    method: str = "GET"
    status: str = ""
    size: int = 0
    source: str = ""
    body_path: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    fp_class: str = ""
    decision: str = ""
    params: set[str] = field(default_factory=set)

@dataclass
class Hypothesis:
    category: str
    target: str
    score: int
    confidence: str
    reasons: list[str]
    candidates: list[Candidate]
    missing: list[str]
    controls: list[str]
    commands: list[str]
    evidence_graph: list[dict[str, Any]] = field(default_factory=list)
    rigor: dict[str, Any] = field(default_factory=dict)
    submit_readiness: str = "NO_REPORT"
    next_decision: str = "validate_small_batch"


def normalize_url(value: str) -> str:
    value = (value or "").strip().strip('"\'`,;')
    if not value or value.startswith("#"):
        return ""
    if not re.match(r"https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def safe_int(value: Any) -> int:
    try:
        return int(str(value).strip() or 0)
    except Exception:
        return 0


def params_from_url(url: str) -> set[str]:
    parsed = urlparse(url)
    params = set(parse_qs(parsed.query).keys())
    for m in re.finditer(r"[/{:]([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Token|Type|Status|Code|Key|No|Num))[}]?", parsed.path):
        params.add(m.group(1))
    return params


def infer_method(url: str, row: dict[str, Any] | None = None) -> str:
    row = row or {}
    raw = str(row.get("method") or row.get("method_guess") or "").upper().strip()
    if raw in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return raw
    low = url.lower()
    if re.search(r"upload|save|add|create|update|delete|submit|verify|send|login|token|callback", low):
        return "POST"
    return "GET"


def read_body_preview(path: Path, body_path: str) -> str:
    if not body_path:
        return ""
    p = Path(body_path)
    if not p.is_absolute():
        p = path.parent / body_path
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:4000]
    except Exception:
        return ""


def candidate_from_row(row: dict[str, Any], source: str, base_path: Path) -> Candidate | None:
    url = normalize_url(str(row.get("url") or row.get("endpoint") or row.get("path") or ""))
    if not url:
        return None
    body_path = str(row.get("body_path") or "")
    cand = Candidate(
        url=url,
        method=infer_method(url, row),
        status=str(row.get("status") or row.get("status_code") or ""),
        size=safe_int(row.get("size") or row.get("content_length") or row.get("response_body_len") or 0),
        source=source,
        body_path=body_path,
        body_preview=str(row.get("response_body_preview") or row.get("sample") or "")[:4000],
        fp_class=str(row.get("fp_class") or row.get("decision") or row.get("verdict") or ""),
        decision=str(row.get("decision") or ""),
    )
    if not cand.body_preview:
        cand.body_preview = read_body_preview(base_path, body_path)
    cand.params = params_from_url(cand.url)
    return cand


def load_json_records(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".jsonl":
        for line in text.splitlines():
            if line.strip():
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    else:
        try:
            data = json.loads(text)
        except Exception:
            return
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
        elif isinstance(data, dict):
            for key in ["items", "results", "endpoints", "urls"]:
                val = data.get(key)
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            yield item
                        elif isinstance(item, str):
                            yield {"url": item}
            for item in data.get("secrets", []) or []:
                if isinstance(item, dict):
                    value = item.get("endpoint") or item.get("url") or item.get("source") or ""
                    yield {"url": value, "risk_type": "secret_exposure", "keyword": item.get("name", "secret")}


def collect_candidates(inputs: list[Path]) -> list[Candidate]:
    files: list[Path] = []
    for p in inputs:
        if p.is_dir():
            for name in ["probe_results.tsv", "endpoints.tsv", "api_recon_ranked.tsv", "js_api_findings.json", "traffic.jsonl", "alive.txt", "urls.txt", "targets.txt"]:
                if (p / name).exists():
                    files.append(p / name)
            for child in sorted(p.glob("*.jsonl")):
                if child.name not in {"tool_calls.jsonl"}:
                    files.append(child)
        elif p.exists():
            files.append(p)
    out: list[Candidate] = []
    seen = set()  # Dedup by (method, url) to preserve different methods on same endpoint
    for f in files:
        suffix = f.suffix.lower()
        if suffix == ".tsv":
            try:
                rows = csv.DictReader(f.read_text(encoding="utf-8", errors="replace").splitlines(), delimiter="\t")
                for row in rows:
                    cand = candidate_from_row(row, str(f), f)
                    key = (cand.method, cand.url) if cand else None
                    if cand and key not in seen:
                        seen.add(key); out.append(cand)
            except Exception:
                continue
        elif suffix in {".json", ".jsonl"}:
            for row in load_json_records(f):
                cand = candidate_from_row(row, str(f), f)
                key = (cand.method, cand.url) if cand else None
                if cand and key not in seen:
                    if str(row.get("risk_type") or "") == "secret_exposure":
                        cand.body_preview += " secret_exposure " + str(row.get("keyword") or "")
                    seen.add(key); out.append(cand)
        else:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                url = normalize_url(line.split()[0] if line.split() else "")
                method = infer_method(url)
                key = (method, url)
                if url and key not in seen:
                    seen.add(key); out.append(Candidate(url=url, method=method, source=str(f), params=params_from_url(url)))
    return out


def classify(c: Candidate) -> tuple[list[str], int, list[str]]:
    parsed = urlparse(c.url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    blob = " ".join([c.url, c.body_preview[:2000], c.fp_class, c.decision]).lower()
    cats: list[str] = []
    score = 10
    reasons: list[str] = []
    if HIGH_VALUE_HOST.search(host):
        score += 15; reasons.append("high-value host")
    if LOW_VALUE_HOST.search(host) or STATIC_EXT.search(c.url):
        score -= 25; reasons.append("static/news penalty")
    if FALLBACK_NEGATIVE.search(blob):
        score -= 30; reasons.append("fallback/WAF/error signal")
    elif LOGIN_FORM.search(blob) and not SENSITIVE_HINT.search(blob):
        # Only penalize login forms when no sensitive data present (auth APIs with data are valuable)
        score -= 15; reasons.append("login page form (no sensitive data)")
    if SENSITIVE_HINT.search(blob):
        score += 35; reasons.append("sensitive/business data signal")
    if SECRET_HINT.search(blob):
        cats.append("secret_to_data"); score += 28; reasons.append("secret/token signal")
    object_params = [p for p in c.params if OBJECT_PARAM.search(p)]
    state_params = [p for p in c.params if STATE_PARAM.search(p)]
    if object_params or re.search(r"/\d+(?:$|[/?#])|detail|info|view|download|export|profile|order|student|member|user", path):
        cats.append("idor_bola"); score += 24; reasons.append("object access surface")
    if state_params or re.search(r"tenant|org|role|permission|admin|manage|dept", blob):
        cats.append("tenant_bfla"); score += 22; reasons.append("tenant/role surface")
    if re.search(r"upload|file|attachment|oss|policy|signature|download|preview|resid|fileid", blob):
        cats.append("file_chain"); score += 24; reasons.append("file flow surface")
    if re.search(r"login|auth|oauth|sso|cas|token|session|password|reset|captcha|sms|verify|openid", blob):
        cats.append("auth_boundary"); score += 20; reasons.append("auth/session surface")
    if re.search(r"actuator|swagger|api-docs|openapi|druid|env|metrics|debug|config", blob):
        cats.append("config_exposure"); score += 18; reasons.append("debug/config surface")
    if c.method in METHOD_WRITE or re.search(r"submit|create|save|update|delete|callback|refund|pay|workflow|process|approve|register", blob):
        cats.append("workflow_logic"); score += 20; reasons.append("state-changing/workflow surface")
    if str(c.status).startswith("2"):
        score += 8; reasons.append("2xx reachable")
    if c.size > 200:
        score += 5; reasons.append("non-trivial response")
    if not cats and score >= 40:
        cats.append("auth_boundary")
    return list(dict.fromkeys(cats)), max(0, min(score, 150)), list(dict.fromkeys(reasons))


def mutate_url(url: str, mode: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    id_controls = {"nonexistent-id", "invalid-fileId", "other-fileId", "other-low-impact-id", "different-tenant", "invalid-role", "low-privilege"}
    if mode in id_controls:
        changed = False
        for k in list(qs):
            lk = k.lower()
            if mode == "invalid-role" and re.search(r"role|permission|admin", lk):
                qs[k] = ["guest"]
                changed = True
            elif mode in {"different-tenant", "low-privilege"} and re.search(r"tenant|org|dept|school|company", lk):
                qs[k] = ["999999999"]
                changed = True
            elif mode in {"invalid-fileId", "other-fileId"} and re.search(r"file|res|oss|download", lk):
                qs[k] = ["invalid-file-control"] if mode == "invalid-fileId" else ["other-file-control"]
                changed = True
            elif OBJECT_PARAM.search(k) or lk.endswith("id"):
                qs[k] = ["999999999"] if mode in {"nonexistent-id", "invalid-fileId"} else ["1002"]
                changed = True
        if not changed:
            new_path = re.sub(r"/\d+(?=$|/)", "/999999999", p.path)
            if new_path == p.path:
                new_path = p.path.rstrip("/") + "/999999999"
            return urlunparse((p.scheme, p.netloc, new_path, "", p.query, ""))
    elif mode == "wrong-key":
        for k in list(qs):
            if SECRET_HINT.search(k):
                qs[k] = ["wrong-test-key"]
    elif mode == "invalid-token":
        qs["access_token"] = ["invalid-test-token"]
    elif mode == "random-path-same-origin" or mode == "random-path":
        return f"{p.scheme}://{p.netloc}/__hermes_control_{quote(p.netloc)}_404__"
    elif mode in {"no-auth", "no-cookie", "no-token", "owner-id", "missing-previous-step", "wrong-code", "replay-once", "accept-json", "origin-mismatch", "no-key"}:
        return url
    query = urlencode({k: v[-1] if v else "" for k, v in qs.items()})
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", query, ""))


def command_for(c: Candidate, control: str = "") -> str:
    url = mutate_url(c.url, control) if control else c.url
    method = c.method  # Preserve original method (don't downgrade PUT/PATCH/DELETE)
    headers = ['-H "User-Agent: Hermes-SRC-Think/1.0"']
    if control == "wrong-key":
        headers.append('-H "X-API-Key: wrong-test-key"')
    if control in {"no-cookie", "no-auth", "no-token", "no-key"}:
        headers.append('-H "Cookie:" -H "Authorization:"')
    if control == "accept-json":
        headers.append('-H "Accept: application/json"')
    if control == "origin-mismatch":
        headers.append('-H "Origin: https://evil.example"')
    out_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", urlparse(url).netloc + urlparse(url).path)[:90] or "target"
    extra = ""
    # Add --data for write methods, but mark as state-changing
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        extra = " --data '{}'"
        if method != "POST":
            extra += f" # WARNING: {method} is state-changing, review before running"
    label = f" # control:{control}" if control else ""
    qurl = shlex.quote(url)
    return f'curl -skL -X {method} -D /tmp/src-think-{out_name}.headers -o /tmp/src-think-{out_name}.body {" ".join(headers)} {qurl}{extra}{label}'


def evidence_node(c: Candidate, category: str, score: int, reasons: list[str]) -> dict[str, Any]:
    parsed = urlparse(c.url)
    signals = []
    blob = " ".join([c.url, c.body_preview[:2000], c.fp_class, c.decision])
    if str(c.status).startswith("2"):
        signals.append("2xx")
    if c.size > 200:
        signals.append("non_trivial_size")
    if SENSITIVE_HINT.search(blob):
        signals.append("sensitive_fields")
    if NEGATIVE_HINT.search(blob):
        signals.append("negative_or_fallback")
    if c.params:
        signals.append("controllable_params")
    return {
        "url": c.url,
        "origin": f"{parsed.scheme}://{parsed.netloc}",
        "method": c.method,
        "status": c.status,
        "size": c.size,
        "params": sorted(c.params),
        "category": category,
        "score": score,
        "signals": signals,
        "reasons": reasons,
        "source": c.source,
    }


def assess_rigor(category: str, selected: list[Candidate], reasons: list[str], base_score: int) -> tuple[int, str, list[str], dict[str, Any], str, str]:
    blob = "\n".join(" ".join([c.url, c.body_preview[:3000], c.fp_class, c.decision]) for c in selected)
    has_2xx = any(str(c.status).startswith("2") for c in selected)
    has_body = any(c.size > 200 or len(c.body_preview) > 120 for c in selected)
    has_sensitive = bool(SENSITIVE_HINT.search(blob))
    has_negative = bool(NEGATIVE_HINT.search(blob))
    has_params = any(c.params for c in selected)
    has_write = any(c.method in METHOD_WRITE for c in selected)
    has_secret = bool(SECRET_HINT.search(blob))
    mutated_controls = sum(1 for c in selected for ctrl in CATEGORY_META[category]["controls"] if mutate_url(c.url, ctrl) != c.url)
    control_count = len(selected) * min(3, len(CATEGORY_META[category]["controls"]))

    missing: list[str] = []
    deductions: list[str] = []
    score = base_score
    if not has_2xx:
        missing.append("缺少2xx/业务成功响应，先确认不是登录页/WAF/SPA fallback")
        score -= 18; deductions.append("no_2xx:-18")
    if not has_body:
        missing.append("缺少足够响应体/内容长度，无法判断是否真实业务结果")
        score -= 12; deductions.append("thin_response:-12")
    if has_negative:
        missing.append("存在登录页/WAF/SPA/错误页负信号，必须用随机路径和内容差异排除误报")
        score -= 25; deductions.append("negative_signal:-25")
    if category in {"auth_boundary", "idor_bola", "tenant_bfla", "secret_to_data"} and not has_sensitive:
        missing.append("缺少敏感字段/业务对象回显，需要补响应体证据")
        score -= 16; deductions.append("no_sensitive_business_result:-16")
    if category in {"idor_bola", "tenant_bfla"} and not has_params:
        missing.append("缺少可控对象ID/租户/角色参数，需从JS或运行态接口补参数")
        score -= 14; deductions.append("no_controllable_object:-14")
    if category == "workflow_logic" and not has_write:
        missing.append("状态机假设缺少写动作/流程动作端点，只能作为低置信候选")
        score -= 10; deductions.append("no_state_change_method:-10")
    if category == "secret_to_data" and has_secret and not has_sensitive:
        missing.append("密钥线索尚未链到真实数据/API调用，严禁仅凭密钥位置提交")
        score -= 20; deductions.append("secret_without_impact:-20")
    if control_count and mutated_controls == 0 and category in {"idor_bola", "tenant_bfla", "file_chain"}:
        missing.append("当前A/B对照无法实际改变关键参数，需补可控ID样本")
        score -= 10; deductions.append("non_mutating_controls:-10")

    score = max(0, min(score, 150))
    if score >= 95 and not missing and has_sensitive:
        confidence = "high"
    elif score >= 65 and (has_2xx or has_params or has_secret):
        confidence = "medium"
    else:
        confidence = "low"

    readiness = "READY_TO_VALIDATE" if confidence == "high" else "NEED_MORE_EVIDENCE" if confidence == "medium" else "NO_REPORT"
    next_decision = "validate_small_batch" if readiness != "NO_REPORT" else "collect_runtime_or_skip"
    rigor = {
        "has_2xx": has_2xx,
        "has_body": has_body,
        "has_sensitive_business_result": has_sensitive,
        "has_negative_signal": has_negative,
        "has_controllable_params": has_params,
        "has_state_change_method": has_write,
        "has_secret_signal": has_secret,
        "mutated_controls": mutated_controls,
        "planned_controls": control_count,
        "deductions": deductions,
        "submit_gate": "PASS_TO_VALIDATE" if readiness == "READY_TO_VALIDATE" else "BLOCK_REPORT_UNTIL_VALIDATED",
    }
    return score, confidence, list(dict.fromkeys(missing)), rigor, readiness, next_decision


def build_hypotheses(candidates: list[Candidate], top: int, batch: int) -> list[Hypothesis]:
    grouped: dict[tuple[str, str], list[tuple[Candidate, int, list[str]]]] = {}
    classified: dict[tuple[str, str], tuple[int, list[str]]] = {}
    for c in candidates:
        cats, score, reasons = classify(c)
        if not cats or score < 25:
            continue
        origin = f"{urlparse(c.url).scheme}://{urlparse(c.url).netloc}"
        for cat in cats:
            grouped.setdefault((cat, origin), []).append((c, score, reasons))
            classified[(cat, c.url)] = (score, reasons)
    hyps: list[Hypothesis] = []
    for (cat, origin), items in grouped.items():
        items.sort(key=lambda x: x[1], reverse=True)
        selected = [x[0] for x in items[: min(5, len(items))]]
        avg_score = int(sum(x[1] for x in items[:5]) / max(1, min(5, len(items))))
        reasons = list(dict.fromkeys(r for _, _, rs in items[:5] for r in rs))[:10]
        meta = CATEGORY_META[cat]
        score, confidence, missing, rigor, readiness, next_decision = assess_rigor(cat, selected, reasons, avg_score)
        controls = meta["controls"]
        commands: list[str] = []
        for c in selected:
            commands.append(command_for(c))
            for ctrl in controls[:3]:
                commands.append(command_for(c, ctrl))
            if len(commands) >= batch:
                break
        graph=[]
        for c in selected:
            raw_score, raw_reasons = classified.get((cat, c.url), (score, reasons))
            graph.append(evidence_node(c, cat, raw_score, raw_reasons))
        hyps.append(Hypothesis(cat, origin, score, confidence, reasons, selected, missing, controls, commands[:batch], graph, rigor, readiness, next_decision))
    hyps.sort(key=lambda h: (h.submit_readiness == "READY_TO_VALIDATE", h.confidence == "high", h.score, len(h.candidates)), reverse=True)
    return hyps[:top]


def render_markdown(hyps: list[Hypothesis], total_candidates: int, args: argparse.Namespace) -> str:
    lines: list[str] = []
    ready = sum(1 for h in hyps if h.submit_readiness == "READY_TO_VALIDATE")
    need = sum(1 for h in hyps if h.submit_readiness == "NEED_MORE_EVIDENCE")
    blocked = sum(1 for h in hyps if h.submit_readiness == "NO_REPORT")
    lines.append("# Hermes SRC Think Plan\n")
    lines.append(f"Inputs: {', '.join(args.inputs)}\n")
    lines.append(f"Candidates analyzed: {total_candidates}\n")
    lines.append(f"Hypotheses: {len(hyps)}\n")
    lines.append(f"Readiness: READY_TO_VALIDATE={ready} NEED_MORE_EVIDENCE={need} NO_REPORT={blocked}\n")
    lines.append("Rule: 每个假设先跑小批量 A/B 对照；无攻击结果不进报告；中/低置信只补证，不写报告。\n\n")
    for idx, h in enumerate(hyps, 1):
        meta = CATEGORY_META[h.category]
        lines.append(f"## {idx}. score={h.score} confidence={h.confidence} readiness={h.submit_readiness} {meta['title']}\n")
        lines.append(f"Target: {h.target}\n")
        lines.append(f"Next decision: {h.next_decision}\n")
        lines.append(f"Reasoning: {', '.join(h.reasons) or 'baseline'}\n")
        lines.append(f"Submit gate: {meta['gate']}\n")
        lines.append("Rigor checks:\n")
        for key in ["has_2xx", "has_body", "has_sensitive_business_result", "has_negative_signal", "has_controllable_params", "has_state_change_method", "has_secret_signal"]:
            lines.append(f"- {key}: {h.rigor.get(key)}\n")
        lines.append(f"- controls: mutated={h.rigor.get('mutated_controls')} planned={h.rigor.get('planned_controls')}\n")
        if h.rigor.get("deductions"):
            lines.append(f"- deductions: {', '.join(h.rigor['deductions'])}\n")
        if h.missing:
            lines.append("Missing evidence:\n")
            for m in h.missing:
                lines.append(f"- {m}\n")
        lines.append("Evidence graph:\n")
        for node in h.evidence_graph[:5]:
            sig = ",".join(node.get("signals", [])) or "none"
            params = ",".join(node.get("params", [])) or "none"
            lines.append(f"- Evidence -> Hypothesis: {node['method']} {node['url']} status={node['status'] or '-'} signals={sig} params={params}\n")
        lines.append("Candidate endpoints:\n")
        for c in h.candidates[:5]:
            status = f" status={c.status}" if c.status else ""
            params = f" params={','.join(sorted(c.params))}" if c.params else ""
            lines.append(f"- {c.method} {c.url}{status}{params}\n")
        lines.append("Validation batch:\n")
        for cmd in h.commands:
            lines.append(cmd + "\n")
        lines.append("\n")
    if not hyps:
        lines.append("No valuable hypothesis generated. 建议换目标或补充登录态/API运行态流量，而不是继续机械扫静态面。\n")
    return "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Reason over SRC artifacts and generate hypothesis-driven validation queue")
    ap.add_argument("inputs", nargs="+", help="workspace dirs or artifact files")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--batch", type=int, default=20, help="max commands per hypothesis")
    ap.add_argument("--out", default="")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()

    paths = [Path(x).expanduser().resolve() for x in args.inputs]
    candidates = collect_candidates(paths)
    hyps = build_hypotheses(candidates, args.top, max(4, min(args.batch, 20)))
    md = render_markdown(hyps, len(candidates), args)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    else:
        print(md)
    if args.json_out:
        data = []
        for h in hyps:
            data.append({
                "category": h.category,
                "target": h.target,
                "score": h.score,
                "confidence": h.confidence,
                "reasons": h.reasons,
                "missing": h.missing,
                "controls": h.controls,
                "rigor": h.rigor,
                "submit_readiness": h.submit_readiness,
                "next_decision": h.next_decision,
                "evidence_graph": h.evidence_graph,
                "candidates": [{"method": c.method, "url": c.url, "status": c.status, "size": c.size, "params": sorted(c.params), "source": c.source} for c in h.candidates],
                "commands": h.commands,
            })
        Path(args.json_out).write_text(json.dumps({"candidates": len(candidates), "hypotheses": data}, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

