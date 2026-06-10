#!/usr/bin/env python
"""Critic gate for authorized SRC findings.
Rejects low-evidence, duplicate, unsafe, or non-submittable findings before report output.
"""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

HIGH_VALUE_TYPES = [
    "RCE", "SQLi", "IDOR", "BOLA", "BFLA", "auth bypass", "unauthorized",
    "account takeover", "business logic", "SSRF", "sensitive data access", "secret-to-data"
]
LOW_VALUE_PATTERNS = [
    "jQuery", "TRACE", "robots.txt", "DMARC", "SPF", "clickjacking", "missing header",
    "version disclosure", "banner", "swagger fallback", "SPA fallback", "404", "403", "WAF blocked"
]
FORBIDDEN = ["persistence", "lateral movement", "reverse shell", "webshell", "real data exfiltration", "destructive"]

def load_jsonl(p: Path):
    if not p.exists():
        return []
    out=[]
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def text_of(obj):
    return json.dumps(obj, ensure_ascii=False).lower()

def assess(finding, evidence, validations):
    t = text_of(finding)
    reasons=[]
    score=0
    if any(x.lower() in t for x in HIGH_VALUE_TYPES):
        score += 3
    else:
        reasons.append("未命中高价值漏洞类型")
    if any(x.lower() in t for x in LOW_VALUE_PATTERNS):
        score -= 3; reasons.append("命中低价值/易误报模式")
    if any(x.lower() in t for x in FORBIDDEN):
        score -= 10; reasons.append("包含禁止的越界动作描述")
    parent = finding.get("parent") or finding.get("id")
    ev = [e for e in evidence if e.get("parent") == parent or e.get("id") == parent or e.get("url") == finding.get("url")]
    va = [v for v in validations if v.get("parent") == parent or v.get("url") == finding.get("url")]
    if ev:
        score += 2
    else:
        reasons.append("缺少 evidence 记录")
    if any((v.get("status") in ["verified", "pass", "confirmed"] or "verified" in text_of(v)) for v in va):
        score += 3
    else:
        reasons.append("缺少 verified validation 记录")
    if "impact" in t or "影响" in t or "business" in t or "数据" in t:
        score += 1
    else:
        reasons.append("缺少业务影响描述")
    verdict = "accept" if score >= 5 else "reject"
    return {"id": finding.get("id"), "title": finding.get("title"), "url": finding.get("url"), "score": score, "verdict": verdict, "reasons": reasons}

def main():
    ap = argparse.ArgumentParser(description="Run Chain Workspace critic gate")
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    ws=Path(args.workspace).expanduser().resolve()
    findings=load_jsonl(ws/"findings.jsonl")
    evidence=load_jsonl(ws/"evidence.jsonl")
    validations=load_jsonl(ws/"validations.jsonl")
    results=[assess(f,evidence,validations) for f in findings]
    summary={"workspace": str(ws), "total": len(results), "accepted": sum(r["verdict"]=="accept" for r in results), "rejected": sum(r["verdict"]=="reject" for r in results), "results": results}
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(f"workspace: {ws}\ntotal={summary['total']} accepted={summary['accepted']} rejected={summary['rejected']}")
        for r in results:
            print(f"[{r['verdict'].upper()} score={r['score']}] {r.get('title') or r.get('id')} {r.get('url') or ''}")
            for reason in r["reasons"]:
                print(f"  - {reason}")
    sys.exit(0 if summary["rejected"] == 0 else 2)

if __name__ == "__main__":
    main()
