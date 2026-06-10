#!/usr/bin/env python3
"""Browser runtime capture helper for Hermes SRC workflows.

Low-risk browser automation for pages where curl/static JS is not enough. It
opens a URL in Chromium via Playwright, captures runtime network/API activity,
console messages, storage keys, forms, scripts, links, and a screenshot. It does
not fuzz or submit forms; it is an observation/evidence collection tool.

Usage:
  /usr/bin/python3 /root/.hermes/scripts/src-browser-capture.py https://target.example/page --outdir "$WS/browser/page1"
  /usr/bin/python3 /root/.hermes/scripts/src-browser-capture.py https://target.example/page --proxy http://127.0.0.1:8080 --ignore-https-errors
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SECRET_RE = re.compile(
    r"(?i)(authorization|cookie|set-cookie|x-.*token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|session|appsecret|api[_-]?key|password|passwd|pwd|secret)"
)
VALUE_SECRET_RE = re.compile(
    r"(?i)(Bearer\s+[A-Za-z0-9._~+/=-]{12,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{12,})"
)
API_HINT_RE = re.compile(r"/api/|/graphql|/v1/|/v2/|/v3/|ajax|json|token|login|user|order|file|upload|download|export|admin|oauth|sso|cas", re.I)


def redact_value(value: Any) -> Any:
    if value is None:
        return value
    text = str(value)
    text = VALUE_SECRET_RE.sub("[REDACTED]", text)
    if len(text) > 5000:
        text = text[:5000] + "...[TRUNCATED]"
    return text


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for k, v in (headers or {}).items():
        clean[k] = "[REDACTED]" if SECRET_RE.search(k) else str(redact_value(v))
    return clean


def chromium_path() -> str:
    for name in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]:
        p = shutil.which(name)
        if p:
            return p
    return ""


def safe_name(url: str) -> str:
    p = urlparse(url)
    base = (p.netloc + p.path).strip("/") or "capture"
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", base)[:120]
    return base or "capture"


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture runtime browser evidence for SRC pages")
    ap.add_argument("url")
    ap.add_argument("--outdir", default="", help="Output directory; default /tmp/src-browser-capture-<timestamp>")
    ap.add_argument("--wait", type=float, default=5.0, help="Seconds to wait after network idle/load for async requests")
    ap.add_argument("--timeout", type=int, default=30000, help="Navigation timeout in ms")
    ap.add_argument("--proxy", default="", help="Optional proxy server, e.g. http://127.0.0.1:8080 for Burp")
    ap.add_argument("--ignore-https-errors", action="store_true")
    ap.add_argument("--headed", action="store_true", help="Run visible browser when display is available")
    ap.add_argument("--full-page", action="store_true", help="Full page screenshot")
    ap.add_argument("--json", action="store_true", help="Print pretty JSON result")
    args = ap.parse_args()

    outdir = Path(args.outdir or f"/tmp/src-browser-capture-{datetime.now().strftime('%Y%m%d_%H%M%S')}-{safe_name(args.url)}").resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise SystemExit(f"Playwright is not available: {e}")

    network: list[dict[str, Any]] = []
    console: list[dict[str, Any]] = []
    page_errors: list[str] = []
    requests_seen: dict[str, dict[str, Any]] = {}

    with sync_playwright() as pw:
        launch_kwargs: dict[str, Any] = {
            "headless": not args.headed,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        exe = chromium_path()
        if exe:
            launch_kwargs["executable_path"] = exe
        if args.proxy:
            launch_kwargs["proxy"] = {"server": args.proxy}
        browser = pw.chromium.launch(**launch_kwargs)
        context = browser.new_context(
            ignore_https_errors=args.ignore_https_errors,
            viewport={"width": 1440, "height": 1000},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/139 Safari/537.36 HermesSRCBrowser/1.0",
        )
        page = context.new_page()

        def on_request(req):
            requests_seen[req.url] = {
                "method": req.method,
                "url": req.url,
                "resource_type": req.resource_type,
                "request_headers": redact_headers(req.headers),
                "post_data": redact_value(req.post_data or ""),
                "ts": time.time(),
            }

        def on_response(resp):
            item = requests_seen.pop(resp.url, {"url": resp.url})
            headers = redact_headers(resp.headers)
            ctype = headers.get("content-type", "") or headers.get("Content-Type", "")
            body_sample = ""
            body_path = ""
            interesting = bool(API_HINT_RE.search(resp.url) or re.search(r"json|javascript|text|html", ctype, re.I))
            if interesting:
                try:
                    body = resp.body()
                    body_sample = redact_value(body[:4000].decode("utf-8", errors="replace"))
                    key = re.sub(r"[^A-Za-z0-9_.-]+", "_", resp.url)[:160]
                    body_file = outdir / "responses" / f"{len(network):04d}_{key}.body"
                    body_file.parent.mkdir(parents=True, exist_ok=True)
                    body_file.write_bytes(body[:1_000_000])
                    body_path = str(body_file)
                except Exception as e:
                    body_sample = f"[body unavailable: {type(e).__name__}]"
            item.update({
                "status": resp.status,
                "status_text": resp.status_text,
                "response_headers": headers,
                "content_type": ctype,
                "api_hint": bool(API_HINT_RE.search(resp.url)),
                "body_sample": body_sample,
                "body_path": body_path,
            })
            network.append(item)

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("console", lambda msg: console.append({"type": msg.type, "text": redact_value(msg.text)[:2000]}))
        page.on("pageerror", lambda exc: page_errors.append(redact_value(str(exc))[:2000]))

        nav_error = ""
        status = None
        try:
            resp = page.goto(args.url, wait_until="domcontentloaded", timeout=args.timeout)
            status = resp.status if resp else None
            try:
                page.wait_for_load_state("networkidle", timeout=min(args.timeout, 15000))
            except Exception:
                pass
            if args.wait > 0:
                page.wait_for_timeout(int(args.wait * 1000))
        except Exception as e:
            nav_error = f"{type(e).__name__}: {e}"

        screenshot = outdir / "screenshot.png"
        try:
            page.screenshot(path=str(screenshot), full_page=args.full_page)
        except Exception as e:
            page_errors.append(f"screenshot failed: {type(e).__name__}: {e}")

        dom: dict[str, Any] = {}
        try:
            dom = page.evaluate(
                """() => ({
                    title: document.title,
                    url: location.href,
                    scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean),
                    links: Array.from(document.querySelectorAll('a')).slice(0,300).map(a => ({text:(a.innerText||'').trim().slice(0,120), href:a.href})),
                    forms: Array.from(document.forms).map(f => ({action:f.action, method:f.method, inputs:Array.from(f.querySelectorAll('input,select,textarea,button')).map(e => ({tag:e.tagName, type:e.type||'', name:e.name||'', id:e.id||'', placeholder:e.placeholder||'', text:(e.innerText||'').slice(0,80)}))})),
                    storage: {local:Object.keys(localStorage), session:Object.keys(sessionStorage)},
                    cookies: document.cookie ? '[REDACTED_PRESENT]' : ''
                })"""
            )
        except Exception as e:
            dom = {"error": f"{type(e).__name__}: {e}"}

        storage_values: dict[str, Any] = {"local": {}, "session": {}}
        try:
            storage_values = page.evaluate(
                """() => ({
                    local: Object.fromEntries(Object.keys(localStorage).slice(0,80).map(k => [k, String(localStorage.getItem(k)).slice(0,500)])),
                    session: Object.fromEntries(Object.keys(sessionStorage).slice(0,80).map(k => [k, String(sessionStorage.getItem(k)).slice(0,500)]))
                })"""
            )
            storage_values = json.loads(json.dumps(storage_values), object_hook=lambda d: {k: redact_value(v) for k, v in d.items()})
        except Exception:
            pass

        result = {
            "success": not bool(nav_error),
            "url": args.url,
            "final_url": dom.get("url", ""),
            "title": dom.get("title", ""),
            "navigation_status": status,
            "navigation_error": nav_error,
            "outdir": str(outdir),
            "screenshot": str(screenshot),
            "network_count": len(network),
            "api_like_count": sum(1 for n in network if n.get("api_hint")),
            "console_count": len(console),
            "page_error_count": len(page_errors),
            "proxy": args.proxy or "",
            "captured_at": datetime.now().isoformat(timespec="seconds"),
        }
        (outdir / "network.json").write_text(json.dumps(network, ensure_ascii=False, indent=2), encoding="utf-8")
        (outdir / "console.json").write_text(json.dumps(console, ensure_ascii=False, indent=2), encoding="utf-8")
        (outdir / "page_errors.json").write_text(json.dumps(page_errors, ensure_ascii=False, indent=2), encoding="utf-8")
        (outdir / "dom.json").write_text(json.dumps(dom, ensure_ascii=False, indent=2), encoding="utf-8")
        (outdir / "storage.json").write_text(json.dumps(storage_values, ensure_ascii=False, indent=2), encoding="utf-8")
        (outdir / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

        md = [
            "# SRC Browser Runtime Capture\n\n",
            f"URL: {args.url}\n",
            f"Final URL: {result['final_url']}\n",
            f"Title: {result['title']}\n",
            f"Navigation status: {result['navigation_status']}\n",
            f"Navigation error: {result['navigation_error']}\n",
            f"Screenshot: {screenshot}\n",
            f"Network requests: {len(network)}; API-like: {result['api_like_count']}\n",
            f"Console messages: {len(console)}; Page errors: {len(page_errors)}\n\n",
            "## API-like network requests\n",
        ]
        for n in [x for x in network if x.get("api_hint")][:80]:
            md.append(f"- {n.get('method','GET')} {n.get('status','')} {n.get('url','')} content-type={n.get('content_type','')} body={n.get('body_path','')}\n")
        md.append("\n## Forms\n")
        for f in dom.get("forms", [])[:30] if isinstance(dom, dict) else []:
            md.append(f"- {f.get('method','')} {f.get('action','')} inputs={len(f.get('inputs', []))}\n")
        md.append("\n## Storage keys\n")
        st = dom.get("storage", {}) if isinstance(dom, dict) else {}
        md.append(f"- localStorage: {', '.join(st.get('local', [])[:80])}\n")
        md.append(f"- sessionStorage: {', '.join(st.get('session', [])[:80])}\n")
        (outdir / "summary.md").write_text("".join(md), encoding="utf-8")
        browser.close()

    print(json.dumps(result, ensure_ascii=False, indent=2 if args.json else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
