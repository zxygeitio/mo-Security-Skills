#!/usr/bin/python3
"""
Daily vulnerability intelligence updater for Hermes.

Safe-by-default: collects public CVE/advisory/POC metadata and writes a local
knowledge base. It does not run exploits against targets.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Iterable

BASE = Path(os.environ.get("HERMES_VULN_INTEL_DIR", "/root/.hermes/vuln-intel"))
DB_PATH = BASE / "vuln_intel.db"
RAW_DIR = BASE / "raw"
LATEST_MD = BASE / "latest.md"
STATE_JSON = BASE / "state.json"


def load_dotenv(path: Path = Path("/root/.hermes/.env")) -> None:
    """Load simple KEY=VALUE lines without printing secrets."""
    if not path.exists():
        return
    try:
        for raw in path.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except Exception:
        return


load_dotenv()

PRODUCTS = [
    "spring boot", "spring cloud gateway", "apache tomcat", "nginx", "apache httpd",
    "apache struts", "weblogic", "confluence", "jira", "wordpress", "drupal",
    "jenkins", "gitlab", "fastjson", "shiro", "thinkphp", "laravel", "redis",
    "mysql", "postgresql", "elasticsearch", "kibana", "minio", "go-fastdfs",
    "apisix", "nacos", "xxl-job", "ruoyi", "jeecg", "druid", "swagger",
]

POC_KEYWORDS = re.compile(r"\b(poc|exploit|rce|exp|漏洞|复现|getshell|weaponized)\b", re.I)
HIGH_VALUE = re.compile(r"\b(remote code execution|rce|command injection|sql injection|sqli|authentication bypass|auth bypass|privilege escalation|deserialization|file upload|path traversal|ssrf|xxe|unauthenticated|未授权|命令执行|代码执行|注入|认证绕过|反序列化|任意文件|上传|越权)\b", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def request_json(url: str, headers: dict[str, str] | None = None, timeout: int = 25) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "Hermes-VulnIntel/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", "replace"))


def safe_get(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Hermes-VulnIntel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def warn(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"[warn] {message}", file=sys.stderr)


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT,
            last_modified TEXT,
            cvss REAL,
            severity TEXT,
            description TEXT,
            products TEXT,
            references_json TEXT,
            exploit_refs_json TEXT,
            tags TEXT,
            score INTEGER,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS poc_refs (
            id TEXT PRIMARY KEY,
            cve_id TEXT,
            source TEXT,
            title TEXT,
            url TEXT,
            stars INTEGER,
            updated_at TEXT,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT,
            finished_at TEXT,
            days INTEGER,
            cves_seen INTEGER,
            cves_upserted INTEGER,
            poc_refs INTEGER,
            status TEXT,
            error TEXT
        );
        """
    )
    conn.commit()


def cvss_and_sev(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        vals = metrics.get(key)
        if vals:
            data = vals[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = vals[0].get("baseSeverity") or data.get("baseSeverity") or ""
            try:
                return (float(score), str(sev))
            except Exception:
                return (None, str(sev))
    return (None, "")


def fetch_nvd(days: int, quiet: bool = False) -> list[dict[str, Any]]:
    end = utcnow()
    start = end - dt.timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": "2000",
    }
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        params["apiKey"] = api_key
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    try:
        data = request_json(url, timeout=20)
    except Exception as e:
        warn(f"NVD date-window fetch failed: {e}; falling back to recent unfiltered page", quiet)
        # Fallback keeps the daily cron useful even when NVD's date-window endpoint is slow.
        fallback = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"resultsPerPage": "50"})
        data = request_json(fallback, timeout=20)
    (RAW_DIR / f"nvd-{end.strftime('%Y%m%d')}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data.get("vulnerabilities", []) or []


def fetch_github_pocs(cve_ids: Iterable[str], limit: int = 40, quiet: bool = False) -> list[dict[str, Any]]:
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out: list[dict[str, Any]] = []
    ids = list(cve_ids)[:limit]
    for cve_id in ids:
        q = urllib.parse.quote(f"{cve_id} poc exploit")
        url = f"https://api.github.com/search/repositories?q={q}&sort=updated&order=desc&per_page=5"
        try:
            data = request_json(url, headers=headers, timeout=12)
            for repo in data.get("items", []) or []:
                title = repo.get("full_name") or ""
                desc = repo.get("description") or ""
                if not (POC_KEYWORDS.search(title) or POC_KEYWORDS.search(desc)):
                    continue
                out.append({
                    "cve_id": cve_id,
                    "source": "github",
                    "title": title,
                    "url": repo.get("html_url") or "",
                    "stars": int(repo.get("stargazers_count") or 0),
                    "updated_at": repo.get("updated_at") or "",
                    "description": desc,
                })
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                warn(f"github search rate-limited at {cve_id}; skipping remaining GitHub PoC lookups", quiet)
                break
            warn(f"github search failed for {cve_id}: {e}", quiet)
        except Exception as e:
            warn(f"github search failed for {cve_id}: {e}", quiet)
        # Keep cron under the 3-minute hard limit even without a GitHub token.
        time.sleep(0.25 if token else 0.8)
    return out


def fetch_cisa_kev(quiet: bool = False) -> set[str]:
    try:
        data = request_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        return {v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception as e:
        warn(f"CISA KEV fetch failed: {e}", quiet)
        return set()


def fetch_exploitdb_recent(quiet: bool = False) -> set[str]:
    # The official git mirror/raw CSV location occasionally changes; treat as opportunistic.
    # Keep this fast because Hermes cron jobs have a 3-minute hard interrupt.
    urls = [
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
    ]
    text = ""
    for url in urls:
        try:
            text = safe_get(url, timeout=10)
            break
        except Exception as e:
            warn(f"exploitdb fetch failed {url}: {e}", quiet)
    return {m.group(0).upper() for m in CVE_RE.finditer(text or "")}


def extract_products(cve: dict[str, Any], desc: str) -> list[str]:
    found = []
    low = desc.lower()
    for p in PRODUCTS:
        if p.lower() in low:
            found.append(p)
    configs = cve.get("configurations", []) or []
    cpes = json.dumps(configs, ensure_ascii=False).lower()
    for p in PRODUCTS:
        if p.lower().replace(" ", "_") in cpes or p.lower() in cpes:
            if p not in found:
                found.append(p)
    return found[:10]


def score_item(cvss: float | None, desc: str, refs: list[dict[str, Any]], poc_count: int, kev: bool, exploitdb: bool) -> tuple[int, list[str]]:
    score = 0
    tags = []
    if cvss is not None:
        if cvss >= 9:
            score += 40; tags.append("critical-cvss")
        elif cvss >= 7:
            score += 25; tags.append("high-cvss")
    if HIGH_VALUE.search(desc):
        score += 25; tags.append("high-value-vuln-type")
    if poc_count:
        score += min(25, 10 + poc_count * 5); tags.append("public-poc")
    if kev:
        score += 30; tags.append("cisa-kev")
    if exploitdb:
        score += 20; tags.append("exploitdb")
    ref_text = json.dumps(refs, ensure_ascii=False).lower()
    if any(k in ref_text for k in ["github", "exploit", "packetstorm", "metasploit", "nuclei"]):
        score += 10; tags.append("exploit-like-reference")
    return score, sorted(set(tags))


def upsert(conn: sqlite3.Connection, vulns: list[dict[str, Any]], pocs: list[dict[str, Any]], kev: set[str], exploitdb: set[str]) -> tuple[int, int]:
    poc_by_cve: dict[str, list[dict[str, Any]]] = {}
    for p in pocs:
        poc_by_cve.setdefault(p["cve_id"].upper(), []).append(p)
        pid = hashlib.sha256((p["cve_id"] + p["url"]).encode()).hexdigest()[:16]
        conn.execute(
            "INSERT OR REPLACE INTO poc_refs(id,cve_id,source,title,url,stars,updated_at,description) VALUES(?,?,?,?,?,?,?,?)",
            (pid, p["cve_id"].upper(), p["source"], p["title"], p["url"], p.get("stars", 0), p.get("updated_at", ""), p.get("description", "")),
        )
    count = 0
    now = utcnow().isoformat()
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = (cve.get("id") or "").upper()
        if not cve_id:
            continue
        descs = cve.get("descriptions", []) or []
        desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), descs[0].get("value", "") if descs else "")
        refs_obj = cve.get("references", {})
        if isinstance(refs_obj, dict):
            refs = refs_obj.get("referenceData", []) or []
        elif isinstance(refs_obj, list):
            refs = refs_obj
        else:
            refs = []
        cvss, sev = cvss_and_sev(cve)
        products = extract_products(cve, desc)
        exploit_refs = poc_by_cve.get(cve_id, [])
        score, tags = score_item(cvss, desc, refs, len(exploit_refs), cve_id in kev, cve_id in exploitdb)
        conn.execute(
            """INSERT OR REPLACE INTO cves
            (cve_id,published,last_modified,cvss,severity,description,products,references_json,exploit_refs_json,tags,score,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cve_id, cve.get("published", ""), cve.get("lastModified", ""), cvss, sev, desc,
                ", ".join(products), json.dumps(refs, ensure_ascii=False), json.dumps(exploit_refs, ensure_ascii=False),
                ",".join(tags), score, now,
            ),
        )
        count += 1
    conn.commit()
    return count, len(pocs)


def write_latest(conn: sqlite3.Connection, days: int, min_score: int) -> None:
    rows = conn.execute(
        "SELECT cve_id,published,cvss,severity,products,score,tags,description,exploit_refs_json FROM cves WHERE score >= ? ORDER BY score DESC, published DESC LIMIT 80",
        (min_score,),
    ).fetchall()
    generated = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    lines = [
        "# Hermes 漏洞情报每日更新",
        "",
        f"生成时间: {generated}",
        f"窗口: 最近 {days} 天新增/更新 CVE；展示 score >= {min_score} 的高价值候选。",
        "",
        "使用原则: 这是候选情报，不是漏洞结论。SRC 提交前必须结合目标版本、暴露面和安全 PoC 复核。",
        "",
        "## 高优先级候选",
        "",
    ]
    for r in rows:
        cve_id, published, cvss, severity, products, score, tags, desc, exploit_json = r
        pocs = json.loads(exploit_json or "[]")
        desc1 = re.sub(r"\s+", " ", desc or "")[:260]
        lines.append(f"### {cve_id} | score {score} | CVSS {cvss if cvss is not None else 'N/A'} {severity or ''}")
        lines.append(f"- published: {published}")
        lines.append(f"- products: {products or '未自动识别'}")
        lines.append(f"- tags: {tags or '-'}")
        lines.append(f"- desc: {desc1}")
        if pocs:
            lines.append("- public PoC refs:")
            for p in sorted(pocs, key=lambda x: x.get("stars", 0), reverse=True)[:5]:
                lines.append(f"  - {p.get('title')} ({p.get('stars',0)}★): {p.get('url')}")
        lines.append("")
    if not rows:
        lines.append("暂无满足阈值的新高优先级候选。")
    LATEST_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=2, help="NVD published window in days")
    ap.add_argument("--github-limit", type=int, default=40, help="max CVEs to query on GitHub")
    ap.add_argument("--min-score", type=int, default=45, help="latest.md minimum score")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    BASE.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    started = utcnow().isoformat()
    status = "ok"; err = ""
    seen = upserted = pocn = 0
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    try:
        vulns = fetch_nvd(args.days, quiet=args.quiet)
        seen = len(vulns)
        # query github only for likely high value CVEs first
        candidate_ids = []
        for item in vulns:
            cve = item.get("cve", {})
            cid = (cve.get("id") or "").upper()
            desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []) or [])
            cvss, _ = cvss_and_sev(cve)
            if cid and ((cvss or 0) >= 7 or HIGH_VALUE.search(desc)):
                candidate_ids.append(cid)
        kev = fetch_cisa_kev(quiet=args.quiet)
        exploitdb = fetch_exploitdb_recent(quiet=args.quiet)
        pocs = fetch_github_pocs(candidate_ids, args.github_limit, quiet=args.quiet)
        upserted, pocn = upsert(conn, vulns, pocs, kev, exploitdb)
        write_latest(conn, args.days, args.min_score)
        STATE_JSON.write_text(json.dumps({
            "last_run": utcnow().isoformat(),
            "days": args.days,
            "cves_seen": seen,
            "cves_upserted": upserted,
            "poc_refs": pocn,
            "latest_md": str(LATEST_MD),
            "db": str(DB_PATH),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        status = "error"; err = repr(e)
        raise
    finally:
        conn.execute(
            "INSERT INTO runs(started_at,finished_at,days,cves_seen,cves_upserted,poc_refs,status,error) VALUES(?,?,?,?,?,?,?,?)",
            (started, utcnow().isoformat(), args.days, seen, upserted, pocn, status, err),
        )
        conn.commit(); conn.close()
    if not args.quiet:
        print(f"updated: cves_seen={seen} cves_upserted={upserted} poc_refs={pocn}")
        print(f"db: {DB_PATH}")
        print(f"latest: {LATEST_MD}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
