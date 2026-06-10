#!/usr/bin/env python
"""Authorized A/B authz matrix tester.
Given a small JSON test plan with owner and non-owner cookies/tokens, performs safe GET/HEAD/OPTIONS
checks and records whether cross-user access is blocked. Designed for authorized SRC/enterprise testing.
"""
from __future__ import annotations
import argparse, json, time, urllib.request, urllib.error, ssl
from pathlib import Path

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

def req(url, method="GET", headers=None, timeout=10):
    headers=headers or {}
    r=urllib.request.Request(url, method=method, headers=headers)
    ctx=ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            body=resp.read(4096)
            return {"status": resp.status, "len": int(resp.headers.get("content-length") or len(body)), "content_type": resp.headers.get("content-type",""), "sample": body[:256].decode("utf-8","ignore")}
    except urllib.error.HTTPError as e:
        body=e.read(1024)
        return {"status": e.code, "len": len(body), "content_type": e.headers.get("content-type",""), "sample": body[:128].decode("utf-8","ignore")}
    except Exception as e:
        return {"status": 0, "error": type(e).__name__ + ": " + str(e)[:200], "len": 0, "content_type":"", "sample":""}

def auth_headers(identity):
    h={"User-Agent":"Hermes-Authorized-Authz-Matrix/1.0"}
    if identity.get("cookie"):
        h["Cookie"] = identity["cookie"]
    if identity.get("authorization"):
        h["Authorization"] = identity["authorization"]
    for k,v in identity.get("headers",{}).items():
        h[k]=v
    return h

def redacted_identity(identity):
    return {"name": identity.get("name",""), "has_cookie": bool(identity.get("cookie")), "has_authorization": bool(identity.get("authorization"))}

def main():
    ap=argparse.ArgumentParser(description="Authorized A/B authz matrix safe tester")
    ap.add_argument("plan", help="JSON plan: identities[], cases[]")
    ap.add_argument("--out", default="", help="output json path")
    ap.add_argument("--timeout", type=int, default=10)
    args=ap.parse_args()
    plan=json.loads(Path(args.plan).read_text(encoding="utf-8"))
    identities={x["name"]:x for x in plan.get("identities",[])}
    results=[]
    for case in plan.get("cases",[]):
        method=case.get("method","GET").upper()
        if method not in SAFE_METHODS:
            results.append({"case":case.get("name"),"skipped":True,"reason":"unsafe method not allowed by this tester"})
            continue
        owner=case.get("owner")
        url=case["url"]
        expected_block=set(case.get("expected_block",[]))
        baseline=None
        if owner in identities:
            baseline=req(url, method, auth_headers(identities[owner]), args.timeout)
        for name, ident in identities.items():
            res=req(url, method, auth_headers(ident), args.timeout)
            should_block = name in expected_block
            blocked = res.get("status") in [401,403,404]
            suspicious = should_block and not blocked and res.get("status") in [200,206,302]
            results.append({
                "case": case.get("name", url), "url": url, "method": method,
                "identity": redacted_identity(ident), "owner": owner,
                "status": res.get("status"), "len": res.get("len"), "content_type": res.get("content_type"),
                "expected_block": should_block, "blocked": blocked, "suspicious_authz_bypass": suspicious,
                "baseline_status": baseline.get("status") if baseline else None,
                "note": "potential IDOR/BOLA/BFLA: non-owner got accessible response" if suspicious else "",
            })
    summary={"ts":int(time.time()),"plan":str(Path(args.plan).resolve()),"total":len(results),"suspicious":sum(1 for r in results if r.get("suspicious_authz_bypass")),"results":results}
    text=json.dumps(summary, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text+"\n", encoding="utf-8")
        print(json.dumps({"ok":True,"out":str(Path(args.out).resolve()),"suspicious":summary["suspicious"]}, ensure_ascii=False))
    else:
        print(text)

if __name__ == "__main__":
    main()
