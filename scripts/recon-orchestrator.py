#!/usr/bin/env python3
"""
Recon Orchestrator v3.0 — 异步并发侦察，结果写入统一图谱

替代 v1/v2 中分散的侦察脚本，统一使用 concurrent.futures 并发执行：
  - subfinder (子域枚举)
  - httpx (存活探测+指纹)
  - nmap (端口扫描)
  - crt.sh (证书透明度)
  - whatweb (Web指纹)
  - JS API 提取

用法:
  recon-orchestrator.py <domain> --graph <graph.db> [--mode fast|full|stealth] [--outdir /tmp/pentest]
  recon-orchestrator.py <domain> --graph <graph.db> --only subdomain,httpx  (仅运行指定模块)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Import graph engine
SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))
from importlib import import_module

# Dynamic import to avoid naming issues
_graph_engine = None
def _get_graph(db_path):
    global _graph_engine
    if _graph_engine is None:
        spec = import_module("vuln-graph-engine")
        _graph_engine = spec.PentestGraph
    return _graph_engine(db_path)


class ReconOrchestrator:
    """Concurrent reconnaissance orchestrator."""

    # Module timeout table (seconds)
    TIMEOUTS = {
        "fast": {"subdomain": 60, "httpx": 90, "nmap": 120, "crtsh": 30, "whatweb": 60},
        "full": {"subdomain": 180, "httpx": 300, "nmap": 600, "crtsh": 60, "whatweb": 180},
        "stealth": {"subdomain": 120, "httpx": 180, "nmap": 300, "crtsh": 30, "whatweb": 120},
    }

    def __init__(self, domain: str, graph_db: str, mode: str = "fast",
                 outdir: str = "/tmp/pentest"):
        self.domain = domain
        self.graph_db = graph_db
        self.mode = mode
        self.outdir = Path(outdir) / domain.replace(".", "_")
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.errors = []

    def run_all(self, only: list[str] = None) -> dict:
        """Run all recon modules concurrently."""
        modules = {
            "subdomain": self._run_subfinder,
            "crtsh": self._run_crtsh,
            "httpx": self._run_httpx,
            "nmap": self._run_nmap,
        }

        if only:
            modules = {k: v for k, v in modules.items() if k in only}

        timeout_table = self.TIMEOUTS.get(self.mode, self.TIMEOUTS["fast"])
        max_workers = min(len(modules), 4)

        print(f"[*] Recon v3.0: {self.domain} mode={self.mode}")
        print(f"[*] Modules: {', '.join(modules.keys())}")
        print(f"[*] Graph DB: {self.graph_db}")
        print()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for name, fn in modules.items():
                timeout = timeout_table.get(name, 120)
                futures[executor.submit(fn, timeout)] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result(timeout=timeout_table.get(name, 120) + 10)
                    self.results[name] = result
                    status = "OK" if result.get("success") else "FAIL"
                    print(f"  [{status}] {name}: {result.get('summary', '')}")
                except Exception as e:
                    self.errors.append({"module": name, "error": str(e)})
                    print(f"  [ERR] {name}: {e}")

        # Post-recon: auto-probe HTTP endpoints if httpx found hosts
        if "httpx" in self.results and self.results["httpx"].get("success"):
            self._auto_fingerprint()

        summary = {
            "domain": self.domain,
            "mode": self.mode,
            "modules": {k: v.get("summary", "") for k, v in self.results.items()},
            "errors": self.errors,
            "graph_db": self.graph_db,
        }
        print(f"\n[*] Recon complete. {len(self.errors)} errors.")
        return summary

    # ── Subfinder ──────────────────────────────────────────────────────────

    def _run_subfinder(self, timeout: int) -> dict:
        """Subdomain enumeration via subfinder."""
        outfile = self.outdir / "subs_subfinder.txt"
        cmd = f"subfinder -d {self.domain} -silent -timeout {min(timeout, 30)}"
        result = self._exec(cmd, timeout)

        subs = set()
        for line in result["stdout"].strip().splitlines():
            line = line.strip().lower()
            if line and "." in line and not line.startswith("#"):
                subs.add(line)

        # Add root domain
        subs.add(self.domain)

        outfile.write_text("\n".join(sorted(subs)))
        return {
            "success": len(subs) > 1,
            "count": len(subs),
            "summary": f"{len(subs)} subdomains",
            "file": str(outfile),
        }

    # ── crt.sh ─────────────────────────────────────────────────────────────

    def _run_crtsh(self, timeout: int) -> dict:
        """Certificate transparency lookup via crt.sh."""
        import urllib.request
        import urllib.error

        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        subs = set()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                for entry in data:
                    name = entry.get("name_value", "")
                    for part in name.split("\n"):
                        part = part.strip().lower().lstrip("*.")
                        if part and "." in part and part.endswith(self.domain):
                            subs.add(part)
        except Exception as e:
            return {"success": False, "summary": f"crt.sh error: {e}", "count": 0}

        outfile = self.outdir / "subs_crtsh.txt"
        outfile.write_text("\n".join(sorted(subs)))
        return {
            "success": len(subs) > 0,
            "count": len(subs),
            "summary": f"{len(subs)} crt.sh subdomains",
            "file": str(outfile),
        }

    # ── HTTPx ──────────────────────────────────────────────────────────────

    def _run_httpx(self, timeout: int) -> dict:
        """HTTP probing via httpx. Reads subdomain files if available."""
        # Collect subdomains
        input_file = self.outdir / "subs_subfinder.txt"
        if not input_file.exists():
            input_file = self.outdir / "subs_crtsh.txt"
        if not input_file.exists():
            # Use domain directly
            input_file = self.outdir / "subs_input.txt"
            input_file.write_text(self.domain)

        outfile = self.outdir / "httpx_results.json"
        cmd = (
            f"httpx -l {input_file} -silent -json -status-code -title -tech-detect "
            f"-server -content-length -content-type -follow-redirects "
            f"-timeout 10 -retries 1 -threads 20"
        )
        result = self._exec(cmd, timeout)

        hosts_added = 0
        endpoints_added = 0
        try:
            graph = _get_graph(self.graph_db)
            for line in result["stdout"].strip().splitlines():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                host = data.get("host", data.get("input", ""))
                url = data.get("url", "")
                status = data.get("status_code")
                title = data.get("title", "")
                server = data.get("webserver", "")
                tech = data.get("tech", [])
                content_type = data.get("content_type", "")
                content_length = data.get("content_length", 0)
                waf_name = data.get("waf", "")

                # Detect WAF from headers if httpx didn't
                if not waf_name:
                    waf_name = self._detect_waf_from_data(data)

                host_id = graph.add_host(
                    domain=host, cdn="yes" if data.get("cdn") else None,
                    waf=waf_name, http_server=server, title=title,
                )
                hosts_added += 1

                graph.add_endpoint(
                    host_id, url, "GET", status, content_type,
                    content_length, title, source="httpx",
                )
                endpoints_added += 1

                # Auto-fingerprint from tech
                for t in (tech if isinstance(tech, list) else []):
                    if t:
                        cat = self._classify_tech(t)
                        graph.add_fingerprint(host_id, cat, t, source="httpx")

            graph.close()
        except Exception as e:
            self.errors.append({"module": "httpx-graph", "error": str(e)})

        # Save raw output
        outfile.write_text(result["stdout"])

        return {
            "success": hosts_added > 0,
            "hosts": hosts_added,
            "endpoints": endpoints_added,
            "summary": f"{hosts_added} hosts, {endpoints_added} endpoints",
            "file": str(outfile),
        }

    # ── Nmap ───────────────────────────────────────────────────────────────

    def _run_nmap(self, timeout: int) -> dict:
        """Port scanning via nmap. Targets top hosts from httpx results."""
        # Get alive hosts from graph
        try:
            graph = _get_graph(self.graph_db)
            hosts = graph.get_hosts()
            graph.close()
        except Exception:
            hosts = []

        if not hosts:
            # Fallback: resolve domain
            ips = self._resolve_domain(self.domain)
            if not ips:
                return {"success": False, "summary": "No hosts to scan", "ports": 0}
            targets = " ".join(ips[:5])
        else:
            # Use IPs or domains, limit to top 10
            targets_list = []
            for h in hosts[:10]:
                if h.get("ip"):
                    targets_list.append(h["ip"])
                elif h.get("domain"):
                    targets_list.append(h["domain"])
            targets = " ".join(targets_list) if targets_list else self.domain

        outfile_xml = self.outdir / "nmap.xml"
        outfile_txt = self.outdir / "nmap.txt"

        top_ports = 100 if self.mode == "fast" else 1000
        cmd = (
            f"nmap -sV -sC --top-ports {top_ports} --open "
            f"-oX {outfile_xml} -oN {outfile_txt} "
            f"--host-timeout {min(timeout, 300)}s "
            f"{targets}"
        )
        result = self._exec(cmd, timeout)

        # Import into graph
        ports_added = 0
        try:
            graph = _get_graph(self.graph_db)
            if outfile_xml.exists():
                stats = graph.import_nmap_xml(str(outfile_xml))
                ports_added = stats.get("ports", 0)
            graph.close()
        except Exception as e:
            self.errors.append({"module": "nmap-graph", "error": str(e)})

        return {
            "success": ports_added > 0 or result["exit_code"] == 0,
            "ports": ports_added,
            "summary": f"{ports_added} open ports discovered",
            "file": str(outfile_xml) if outfile_xml.exists() else str(outfile_txt),
        }

    # ── Auto-fingerprint ───────────────────────────────────────────────────

    def _auto_fingerprint(self):
        """Probe endpoints for additional fingerprints (Shiro, Nacos, Spring, etc.)."""
        try:
            graph = _get_graph(self.graph_db)
            endpoints = graph.get_endpoints()
            hosts = {h["id"]: h for h in graph.get_hosts()}

            probed = 0
            for ep in endpoints[:50]:  # Limit to 50 probes
                url = ep.get("url", "")
                host_id = ep.get("host_id")
                if not url or not host_id:
                    continue

                # Check for Shiro
                try:
                    cmd = f'curl -sk -I "{url}" -m 5'
                    r = self._exec(cmd, 8)
                    headers = r["stdout"].lower()
                    if "rememberme=deleteme" in headers:
                        graph.add_fingerprint(host_id, "auth", "shiro", source="auto-probe")
                    if "x-application-context" in headers:
                        graph.add_fingerprint(host_id, "framework", "spring-boot", source="auto-probe")
                    probed += 1
                except Exception:
                    pass

            # Check common sensitive paths
            for host_id, host in list(hosts.items())[:10]:
                domain = host.get("domain") or host.get("ip", "")
                if not domain:
                    continue
                scheme = "https"  # Default to HTTPS

                for path, tech, cat in [
                    ("/actuator/env", "spring-boot", "framework"),
                    ("/actuator/health", "spring-boot", "framework"),
                    ("/nacos/", "nacos", "cms"),
                    ("/druid/index.html", "druid", "component"),
                    ("/swagger-ui.html", "swagger", "component"),
                    ("/api/swagger-ui.html", "swagger", "component"),
                    ("/graphql", "graphql", "component"),
                    ("/.git/HEAD", "git-leak", "component"),
                    ("/env", "spring-boot", "framework"),
                ]:
                    try:
                        cmd = f'curl -sk -o /dev/null -w "%{{http_code}}" "{scheme}://{domain}{path}" -m 5'
                        r = self._exec(cmd, 8)
                        code = r["stdout"].strip().strip('"')
                        if code in ("200", "301", "302", "401", "403"):
                            graph.add_fingerprint(host_id, cat, tech, source="path-probe")
                            graph.add_endpoint(
                                host_id, f"{scheme}://{domain}{path}",
                                "GET", int(code) if code.isdigit() else None,
                                source="path-probe",
                            )
                    except Exception:
                        pass

            graph.close()
        except Exception as e:
            self.errors.append({"module": "auto-fingerprint", "error": str(e)})

    # ── Helpers ────────────────────────────────────────────────────────────

    def _exec(self, cmd: str, timeout: int) -> dict:
        """Execute shell command with timeout."""
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "stdout": proc.stdout[:50000],
                "stderr": proc.stderr[:5000],
                "exit_code": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "TIMEOUT", "exit_code": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def _resolve_domain(self, domain: str) -> list[str]:
        """Resolve domain to IPs."""
        try:
            r = self._exec(f"dig +short {domain} A", 10)
            return [l.strip() for l in r["stdout"].splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]
        except Exception:
            return []

    def _detect_waf_from_data(self, data: dict) -> str:
        """Detect WAF from httpx response data."""
        headers = str(data.get("header", "")).lower()
        server = (data.get("webserver") or "").lower()
        if "cloudflare" in server or "cf-ray" in headers:
            return "cloudflare"
        if "tengine" in server:
            return "tengine"
        if "akamai" in headers or "akamai" in server:
            return "akamai"
        if "yunsuo" in headers:
            return "yunsuo"
        if "safeline" in headers:
            return "safeline"
        return ""

    def _classify_tech(self, tech: str) -> str:
        """Classify tech into fingerprint category."""
        t = tech.lower()
        if any(k in t for k in ("spring", "struts", "laravel", "django", "flask", "express", "next.js", "vue", "react", "angular")):
            return "framework"
        if any(k in t for k in ("wordpress", "drupal", "joomla", "liferay", "nacos")):
            return "cms"
        if any(k in t for k in ("nginx", "apache", "iis", "tengine", "tomcat")):
            return "server"
        if any(k in t for k in ("java", "python", "node", "php", "ruby", "go")):
            return "language"
        if any(k in t for k in ("shiro", "jwt", "oauth", "cas")):
            return "auth"
        return "component"


def main():
    p = argparse.ArgumentParser(description="Recon Orchestrator v3.0")
    p.add_argument("domain")
    p.add_argument("--graph", required=True, help="Path to graph.db")
    p.add_argument("--mode", choices=["fast", "full", "stealth"], default="fast")
    p.add_argument("--outdir", default="/tmp/pentest")
    p.add_argument("--only", help="Comma-separated module list: subdomain,crtsh,httpx,nmap")
    args = p.parse_args()

    only = args.only.split(",") if args.only else None
    orch = ReconOrchestrator(args.domain, args.graph, args.mode, args.outdir)
    result = orch.run_all(only=only)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
