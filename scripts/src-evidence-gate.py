#!/usr/bin/env python3
"""Hermes SRC evidence gate.

Directory-level evidence reviewer for SRC candidates. It does not replace
Hermes' reasoning; it turns scattered request/response/probe artifacts into a
conservative PASS / NEED_MORE / REJECT decision and an auditor-rebuttal list.

Expected candidate directory examples:
  request.txt, response.headers, response.body, meta.tsv, curls.txt,
  controls/*.body, screenshots.txt, probe_results.tsv

Usage:
  /root/.hermes/scripts/src-evidence-gate.py /tmp/candidate --out gate.md
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Tuple

SECRET_VALUE = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"(?:access[_-]?token|authorization|appsecret|api[_-]?key|secret|password|passwd|pwd|cookie|session)\s*[:=]\s*[\"']?[^\s\"',;]{6,})"
)
SENSITIVE = re.compile(
    r"姓名|手机号|身份证|学号|工号|邮箱|email|mobile|phone|idcard|identity|订单|金额|余额|成绩|课程|流程|审批|住址|部门|组织|tenant|orgId|userId|studentId|fileUrl|resId|ossId|genName|downloadUrl|access[_-]?token|appSecret|api[_-]?key|authorization|session|jwt|ticket|secret|SQLSyntaxErrorException|SQLException|uid=|gid=",
    re.I,
)
NEGATIVE = re.compile(
    r"SPA fallback|Token失效|token信息不存在|FA_INVALID_SESSION|未登录|请登录|login required|Full authentication is required|401 Unauthorized|403 Forbidden|404 Not Found|WAF|Web应用防火墙|请求异常|Access Denied|forbidden|error page|页面不存在|not found",
    re.I,
)
CONTROL_WORDS = re.compile(r"control|对照|random|nonexistent|invalid|wrong[_-]?token|随机|不存在|无效", re.I)
CURL_WORDS = re.compile(r"curl\s+[-\w]", re.I)
REQUEST_WORDS = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+|^Host:\s+|HTTP/1\.[01]", re.I | re.M)
UPLOAD_PROOF = re.compile(r"fileUrl|resId|ossId|genName|downloadUrl|上传成功|/upload/|/file/", re.I)
CORS_PROOF = re.compile(r"access-control-allow-origin\s*:\s*https?://|access-control-allow-credentials\s*:\s*true", re.I)
AUTH_PROOF = re.compile(r"authorization|bearer|token|jwt|session|cookie|x-.*token|appsecret|api[_-]?key", re.I)

TEXT_SUFFIXES = {".txt", ".md", ".log", ".tsv", ".csv", ".json", ".body", ".hdr", ".headers", ".req", ".resp", ".html", ".js", ".sh"}

@dataclass
class Finding:
    name: str
    passed: bool
    evidence: List[str] = field(default_factory=list)
    missing: str = ""

@dataclass
class FileInfo:
    path: Path
    rel: str
    text: str
    size: int
    sha256: str


def redact(text: str) -> str:
    return SECRET_VALUE.sub(lambda m: m.group(0).split("=", 1)[0] + "=[REDACTED]" if "=" in m.group(0) else "[REDACTED]", text)


def iter_text_files(base: Path, max_bytes: int = 2_000_000) -> Iterable[FileInfo]:
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES and not re.search(r"(request|response|header|body|curl|meta|proof|control|screenshot|截图)", p.name, re.I):
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        if len(data) > max_bytes:
            data = data[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        yield FileInfo(p, str(p.relative_to(base)), redact(text), len(data), hashlib.sha256(data).hexdigest())


def load_probe_rows(files: List[FileInfo]) -> List[dict]:
    rows: List[dict] = []
    for fi in files:
        if not fi.rel.endswith(".tsv"):
            continue
        lines = fi.text.splitlines()
        if not lines or "\t" not in lines[0]:
            continue
        try:
            reader = csv.DictReader(lines, delimiter="\t")
            if reader.fieldnames and any(x in reader.fieldnames for x in ("url", "status", "body_path")):
                for r in reader:
                    r["_source"] = fi.rel
                    rows.append(dict(r))
        except Exception:
            pass
    return rows


def any_file(files: List[FileInfo], pattern: str) -> List[FileInfo]:
    rx = re.compile(pattern, re.I)
    return [f for f in files if rx.search(f.rel) or rx.search(f.text[:5000])]


def status_success_seen(files: List[FileInfo], rows: List[dict]) -> List[str]:
    ev: List[str] = []
    for r in rows:
        st = str(r.get("status", ""))
        if st.startswith("2") and int(str(r.get("size", "0") or "0").split()[0] if re.match(r"^\d+", str(r.get("size", "0"))) else 0) > 20:
            ev.append(f"{r.get('_source')} {st} {r.get('url','')[:160]}")
    for f in files:
        if re.search(r"HTTP/1\.[01]\s+20\d|\bstatus\b[^\n]{0,20}\b20\d\b|\"code\"\s*:\s*200|\"success\"\s*:\s*true", f.text, re.I):
            ev.append(f.rel)
    return ev[:20]


def build_findings(base: Path, files: List[FileInfo], rows: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    alltext = "\n".join(f.text[:100000] for f in files)

    req = [f.rel for f in files if REQUEST_WORDS.search(f.text) or re.search(r"request|\.req$", f.rel, re.I)]
    curls = [f.rel for f in files if CURL_WORDS.search(f.text) or re.search(r"curl|poc|repro", f.rel, re.I)]
    responses = [f.rel for f in files if re.search(r"response|body|\.resp$|\.hdr$|headers", f.rel, re.I)]
    meta = [f.rel for f in files if re.search(r"meta|probe_results|summary|verdict|decision", f.rel, re.I)]
    controls = [f.rel for f in files if CONTROL_WORDS.search(f.rel) or CONTROL_WORDS.search(f.text[:20000])]
    screenshots = [f.rel for f in files if re.search(r"screenshot|截图|image|png|jpg|jpeg", f.rel, re.I) or re.search(r"【截图位置\d+】|截图位置\d+", f.text)]
    success = status_success_seen(files, rows)
    sensitive = [f.rel for f in files if SENSITIVE.search(f.text)]
    negative = [f.rel for f in files if NEGATIVE.search(f.text)]
    upload = [f.rel for f in files if UPLOAD_PROOF.search(f.text)]
    cors = [f.rel for f in files if CORS_PROOF.search(f.text)]
    auth = [f.rel for f in files if AUTH_PROOF.search(f.text)]

    findings.append(Finding("完整请求/触发入口", bool(req or curls), (req + curls)[:10], "缺 request.txt、原始HTTP请求或单行curl"))
    findings.append(Finding("完整响应证据", bool(responses and success), (responses + success)[:10], "缺响应头/响应体，或未见2xx/成功业务结果"))
    findings.append(Finding("可复制PoC/curl", bool(curls), curls[:10], "缺可直接复制的一行curl或bash heredoc PoC"))
    findings.append(Finding("对照组/反证", bool(controls), controls[:10], "缺随机路径、无效ID、无效token、未登录/登录态等对照"))
    findings.append(Finding("敏感数据或攻击结果", bool(sensitive or upload or cors), (sensitive + upload + cors)[:12], "缺真实敏感字段、上传URL、密钥可用性、CORS可读等攻击结果"))
    findings.append(Finding("元数据/小批验证记录", bool(meta or rows), meta[:10] + ([f"probe rows={len(rows)}"] if rows else []), "缺meta.tsv/probe_results.tsv/候选归类"))
    findings.append(Finding("截图位置标注", bool(screenshots), screenshots[:10], "缺【截图位置N】标注或截图清单"))
    findings.append(Finding("负证据过滤", not (negative and not sensitive and not upload), negative[:12], "当前证据主要像登录页/WAF/SPA/401/403/404，需排除误报"))

    # Type-specific optional hints become pass if present; otherwise neutral info.
    if upload:
        findings.append(Finding("上传类专项证明", bool(re.search(r"https?://[^\s\"']+", alltext) and success), upload[:10], "上传类需证明fileUrl/resId/genName和公网访问/浏览器处理"))
    if cors:
        findings.append(Finding("CORS专项证明", bool(re.search(r"access-control-allow-credentials\s*:\s*true", alltext, re.I) and sensitive), cors[:10], "CORS需证明浏览器可读敏感接口，不能只看ACAO"))
    if auth:
        findings.append(Finding("密钥/Token专项证明", bool(sensitive and success), auth[:10], "密钥泄露需证明可换token或调用真实接口"))
    return findings


def verdict(findings: List[Finding]) -> Tuple[str, str]:
    by_name = {f.name: f for f in findings}
    required = [
        "完整请求/触发入口",
        "完整响应证据",
        "可复制PoC/curl",
        "对照组/反证",
        "敏感数据或攻击结果",
        "负证据过滤",
    ]
    passed = sum(1 for name in required if by_name.get(name) and by_name[name].passed)
    if by_name.get("负证据过滤") and not by_name["负证据过滤"].passed:
        return "REJECT", "证据主要命中登录页/WAF/SPA/401/403/404等负面模式，不能提交。"
    if passed == len(required):
        # screenshots/meta are quality requirements but not always hard blockers for early gate.
        return "PASS", "核心请求、响应、PoC、对照组和攻击结果均具备，可进入报告编写/人工截图阶段。"
    if by_name.get("敏感数据或攻击结果") and by_name["敏感数据或攻击结果"].passed and passed >= 4:
        return "NEED_MORE", "已有攻击结果信号，但缺少部分对照/PoC/截图/元数据，补齐后再提交。"
    return "REJECT", "缺少真实攻击结果或可复现证据，不建议提交。"


def rebuttal(findings: List[Finding]) -> List[str]:
    qs = [
        "这个接口/页面是否可能是公开设计？证据是否说明其本应鉴权？",
        "是否用随机不存在路径、无效ID、无效token或未登录状态做了对照？",
        "响应是否真实业务数据，而不是SPA fallback、登录页、WAF页、错误页或示例数据？",
        "敏感字段/上传URL/API Key可用性是否已经用最小低影响动作证明？",
        "如果是文件上传，文件是否公网可访问，浏览器如何处理，是否避免夸大为RCE/XSS？",
        "如果是CORS，是否有Credentials或敏感接口可读证明，而不只是ACAO反射？",
        "如果是密钥泄露，是否证明密钥仍有效且能调用真实接口，是否已脱敏？",
        "是否检查历史报告/同根因，避免重复提交？",
        "报告中的curl/脚本是否已经本机实测，可直接复制？",
        "是否准备了【截图位置N】：入口、请求、响应、攻击结果、对照组？",
    ]
    missing = [f"缺口：{f.name} — {f.missing}" for f in findings if not f.passed]
    return qs + missing


def render_md(base: Path, files: List[FileInfo], findings: List[Finding], v: str, reason: str) -> str:
    lines: List[str] = []
    lines.append("# SRC Evidence Gate\n\n")
    lines.append(f"Candidate: {base}\n")
    lines.append(f"Verdict: {v}\n")
    lines.append(f"Reason: {reason}\n")
    lines.append(f"Files analyzed: {len(files)}\n\n")
    lines.append("## Gate checklist\n")
    for f in findings:
        mark = "PASS" if f.passed else "MISS"
        lines.append(f"- [{mark}] {f.name}\n")
        if f.evidence:
            for e in f.evidence[:8]:
                lines.append(f"  - evidence: {e}\n")
        elif f.missing:
            lines.append(f"  - missing: {f.missing}\n")
    lines.append("\n## Auditor rebuttal list\n")
    for q in rebuttal(findings):
        lines.append(f"- {q}\n")
    lines.append("\n## Files\n")
    for f in files[:200]:
        lines.append(f"- {f.rel} size={f.size} sha256={f.sha256[:16]}\n")
    return "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Directory-level SRC evidence gate")
    ap.add_argument("candidate_dir")
    ap.add_argument("--out", default="", help="Write markdown gate report")
    ap.add_argument("--json", action="store_true", help="Print JSON instead of compact text")
    args = ap.parse_args()
    base = Path(args.candidate_dir).resolve()
    if not base.exists() or not base.is_dir():
        raise SystemExit(f"candidate_dir not found or not a directory: {base}")
    files = list(iter_text_files(base))
    rows = load_probe_rows(files)
    findings = build_findings(base, files, rows)
    v, reason = verdict(findings)
    md = render_md(base, files, findings, v, reason)
    out = args.out or str(base / "evidence_gate.md")
    Path(out).write_text(md, encoding="utf-8")
    result = {
        "verdict": v,
        "reason": reason,
        "candidate": str(base),
        "files": len(files),
        "probe_rows": len(rows),
        "out": out,
        "missing": [f.name for f in findings if not f.passed],
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
