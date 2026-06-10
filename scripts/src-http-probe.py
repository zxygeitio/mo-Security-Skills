#!/usr/bin/python3
"""Low-noise HTTP probe helper for Hermes SRC workspaces.

Input: newline-delimited URLs.
Output: appends normalized TSV rows and stores headers/bodies by SHA1(method+url).

By default the probe appends rows so long-running SRC workspaces can survive
interruptions and preserve history. Use --fresh for one-shot self-tests or
repeatable framework checks that should start with an empty probe_results.tsv.
Use --dedupe to avoid appending duplicate method+url rows already present in
the TSV; this is useful for idempotent reruns while still keeping prior rows.

False-positive controls: use --control to fetch a same-origin random path once
per origin. The probe then records control_hash, similarity, fp_class, and
reject_reason so SPA fallback/WAF/login/unified-error candidates can be filtered
before quality gate review.
"""
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import os
import random
import re
import string
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

# HEADER defined after classify_fp below (uses HEADER_FIELDS list)

WAF_RE = re.compile(r"Web应用防火墙|安全狗|云盾|阿里云盾|AliyunDun|GSRM Security|Request blocked|Access Denied|非法请求|请求异常|拦截|WAF|blocked by|forbidden by", re.I)
LOGIN_RE = re.compile(r"<form[^>]+(login|password|passwd)|/login|请登录|未登录|登录超时|login required|sign in|用户名|密码", re.I)
SPA_RE = re.compile(r"<div[^>]+id=[\"']?(app|root|__next)[\"']?|webpackJsonp|window\.__INITIAL_STATE__|static/js/|/assets/", re.I)
UNIFIED_ERROR_RE = re.compile(r"404 Not Found|403 Forbidden|Error Page|Whitelabel Error Page|系统异常|请求错误|页面不存在|Not Found|Bad Request", re.I)
SENSITIVE_RE = re.compile(r"Token失效|token信息不存在|FA_INVALID_SESSION|未登录|请登录|姓名|手机号|身份证|学号|工号|邮箱|appName|serviceName|SQLSyntaxErrorException|SQLException|fileUrl|resId|ossId|genName|secret|token|Authorization", re.I)


@dataclass
class ProbeResult:
    method: str
    url: str
    status: str
    size: int
    content_type: str
    digest: str
    title: str
    hits: str
    body_path: Path
    header_path: Path
    fp_class: str = ""
    reject_reason: str = ""
    control_hash: str = ""
    similarity: float = 0.0
    decision: str = "NEGATIVE_OR_LOW_SIGNAL"


def safe_int(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def read_text(path: Path, limit: int = 200000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def title_from_body(path: Path) -> str:
    text = read_text(path, 20000)
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def grep_hits(path: Path) -> str:
    text = read_text(path)
    hits = SENSITIVE_RE.findall(text)
    return ",".join(dict.fromkeys(hits))[:200]


def body_digest(path: Path) -> str:
    data = path.read_bytes() if path.exists() else b""
    return hashlib.sha256(data).hexdigest() if data else ""


def body_similarity(a: Path, b: Path) -> float:
    ta = re.sub(r"\s+", " ", read_text(a, 60000))
    tb = re.sub(r"\s+", " ", read_text(b, 60000))
    if not ta or not tb:
        return 0.0
    if len(ta) > 50000:
        ta = ta[:50000]
    if len(tb) > 50000:
        tb = tb[:50000]
    return round(difflib.SequenceMatcher(None, ta, tb).ratio(), 4)


def random_control_url(url: str) -> str:
    p = urlparse(url)
    token = "hermes-src-control-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    return urlunparse((p.scheme, p.netloc, "/" + token, "", "", ""))


def key_for(method: str, url: str) -> str:
    return hashlib.sha1(f"{method}\t{url}".encode("utf-8")).hexdigest()


def curl_fetch(method: str, url: str, header_path: Path, body_path: Path, timeout: int, origin: str = "") -> tuple[str, int, str]:
    header_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "curl", "-skL", "--connect-timeout", "4", "--max-time", str(timeout),
        "-X", method,
        "-D", str(header_path), "-o", str(body_path), "-w", "%{http_code}\t%{size_download}\t%{content_type}",
        "-A", "Mozilla/5.0", url,
    ]
    if origin:
        cmd[-1:-1] = ["-H", f"Origin: {origin}"]
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout + 5, env=env)
        parts = (cp.stdout.strip().split("\t") + ["", "", ""])[:3]
    except Exception:
        parts = ["000", "0", ""]
    return parts[0], safe_int(parts[1]), parts[2]


def probe(method: str, url: str, workspace: Path, timeout: int, origin: str = "") -> ProbeResult:
    key = key_for(method, url)
    hp = workspace / "headers" / f"{key}.hdr"
    bp = workspace / "bodies" / f"{key}.body"
    status, size, ctype = curl_fetch(method, url, hp, bp, timeout, origin=origin)
    return ProbeResult(
        method=method,
        url=url,
        status=status,
        size=size,
        content_type=ctype,
        digest=body_digest(bp),
        title=title_from_body(bp),
        hits=grep_hits(bp),
        body_path=bp,
        header_path=hp,
    )


def classify_fp(result: ProbeResult, control: ProbeResult | None) -> None:
    text = read_text(result.body_path)
    header_text = read_text(result.header_path, 50000)
    blob = header_text + "\n" + text[:50000]
    reasons: list[str] = []
    fp: list[str] = []
    if result.status in {"000"} or result.size == 0:
        fp.append("EMPTY_OR_UNREACHABLE"); reasons.append("status 000 or empty body")
    if WAF_RE.search(blob):
        fp.append("WAF_BLOCK"); reasons.append("WAF/block signature")
    if LOGIN_RE.search(blob) or result.status in {"401", "403"}:
        fp.append("LOGIN_OR_AUTH_REQUIRED"); reasons.append("login/auth required signature or 401/403")
    if UNIFIED_ERROR_RE.search(blob) or result.status == "404":
        fp.append("UNIFIED_ERROR"); reasons.append("error page signature or 404")
    if control:
        result.control_hash = control.digest
        result.similarity = body_similarity(result.body_path, control.body_path)
        same_status = result.status == control.status
        size_close = control.size > 0 and abs(result.size - control.size) / max(control.size, 1) < 0.08
        if result.digest and result.digest == control.digest:
            fp.append("EXACT_CONTROL_MATCH"); reasons.append("same hash as random control path")
        elif result.similarity >= 0.92 and same_status and size_close:
            if SPA_RE.search(text) or SPA_RE.search(read_text(control.body_path)):
                fp.append("SPA_FALLBACK"); reasons.append(f"similar to random control path similarity={result.similarity}")
            else:
                fp.append("UNIFIED_ERROR"); reasons.append(f"similar to random control path similarity={result.similarity}")
    result.fp_class = ",".join(dict.fromkeys(fp))
    result.reject_reason = "; ".join(dict.fromkeys(reasons))[:300]
    if result.fp_class:
        result.decision = "REJECT_FALSE_POSITIVE"
    elif result.hits and result.status.startswith("2"):
        result.decision = "PENDING_REVIEW"
    else:
        result.decision = "NEGATIVE_OR_LOW_SIGNAL"


HEADER_FIELDS = ["method", "url", "status", "size", "content_type", "hash", "title", "sensitive_hit", "control_result", "decision", "body_path", "header_path", "control_hash", "similarity", "fp_class", "reject_reason"]
HEADER = "\t".join(HEADER_FIELDS) + "\n"


def row_values(result: ProbeResult) -> list[str]:
    """Return TSV row as list of strings (safe for csv.writer)."""
    return [
        result.method,
        result.url,
        result.status,
        str(result.size),
        result.content_type,
        result.digest,
        result.title,
        result.hits,
        result.control_result or "",  # Was incorrectly reject_reason
        result.decision,
        str(result.body_path),
        str(result.header_path),
        result.control_hash,
        str(result.similarity),
        result.fp_class,
        result.reject_reason,
    ]


def row(result: ProbeResult) -> str:
    """Write TSV row safely using csv.writer (handles embedded tabs/newlines)."""
    import io
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter="\t", lineterminator="")
    writer.writerow(row_values(result))
    return buf.getvalue()


def existing_method_url_keys(path: Path) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if not path.exists():
        return keys
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            keys.add((parts[0], parts[1]))
    return keys


def ensure_output(path: Path, fresh: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fresh or not path.exists():
        path.write_text(HEADER, encoding="utf-8")


def origin_key(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe URLs into a Hermes SRC workspace")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("urls", help="Text file with one URL per line")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--fresh", action="store_true", help="reset probe_results.tsv before probing; intended for self-tests/one-shot reruns")
    parser.add_argument("--dedupe", action="store_true", help="skip method+url rows already present in probe_results.tsv")
    parser.add_argument("--method", default="GET", help="HTTP method for all URLs; default GET")
    parser.add_argument("--origin", default="", help="Optional Origin header for CORS probing")
    parser.add_argument("--control", action="store_true", help="fetch one random same-origin control URL per origin and classify SPA/WAF/login/unified-error false positives")
    parser.add_argument("--scope-domain", default="", help="comma-separated allowed domains; URLs outside scope are skipped (e.g. 'example.edu.cn,test.edu.cn')")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    out = workspace / "probe_results.tsv"
    ensure_output(out, args.fresh)
    seen = existing_method_url_keys(out) if args.dedupe else set()

    # v2.1: Scope enforcement
    scope_domains = set()
    if args.scope_domain:
        scope_domains = {d.strip().lower() for d in args.scope_domain.split(",") if d.strip()}

    urls = []
    skipped_scope = 0
    for line in Path(args.urls).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # Filter by scope if set
            if scope_domains:
                try:
                    host = urlparse(line.split()[0]).netloc.lower()
                    if not any(host == d or host.endswith(f".{d}") for d in scope_domains):
                        skipped_scope += 1
                        continue
                except Exception:
                    skipped_scope += 1
                    continue
            urls.append(line)
    if skipped_scope:
        print(f"[!] Skipped {skipped_scope} out-of-scope URLs")

    method = args.method.upper().strip()
    controls: dict[str, ProbeResult] = {}
    skipped = 0
    with out.open("a", encoding="utf-8") as f:
        for i, url in enumerate(urls, 1):
            key = (method, url)
            if args.dedupe and key in seen:
                skipped += 1
                continue
            control = None
            if args.control:
                ok = origin_key(url)
                if ok not in controls:
                    cu = random_control_url(url)
                    controls[ok] = probe("GET", cu, workspace, args.timeout, origin=args.origin)
                    classify_fp(controls[ok], None)
                control = controls[ok]
            result = probe(method, url, workspace, args.timeout, origin=args.origin)
            classify_fp(result, control)
            f.write(row(result) + "\n")
            seen.add(key)
            f.flush()
            if i % 20 == 0:
                print(f"probed {i}/{len(urls)}", flush=True)
    if skipped:
        print(f"skipped_duplicate_{method.lower()}_urls={skipped}")
    if controls:
        print(f"control_origins={len(controls)}")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
