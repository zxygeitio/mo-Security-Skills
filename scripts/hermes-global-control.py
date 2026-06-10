#!/usr/bin/env /usr/bin/python3
"""Hermes global control cockpit.

Safe read-only operational audit for the local Hermes/SRC/pentest workspace.
It checks framework health, skills, MCP, Burp/HexStrike surface, cron, git repo,
reports, VPN/process hints, and emits a compact terminal-friendly summary.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import socket
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

HOME = pathlib.Path(os.environ.get("HERMES_HOME", str(pathlib.Path.home() / ".hermes"))).expanduser()
REPO = HOME / "hermes-agent"
SKILLS = HOME / "skills"
BUILTIN_SKILLS = REPO / "skills"
REPORTS = pathlib.Path("/tmp/vuln_reports")


@dataclass
class CmdResult:
    cmd: str
    code: int
    out: str


def run(cmd: list[str], timeout: int = 20, cwd: pathlib.Path | None = None) -> CmdResult:
    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        out = p.stdout.strip()
        if len(out) > 6000:
            out = out[:6000] + "\n...[truncated]"
        return CmdResult(" ".join(cmd), p.returncode, out)
    except FileNotFoundError:
        return CmdResult(" ".join(cmd), 127, f"command not found: {cmd[0]}")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        return CmdResult(" ".join(cmd), 124, (out.strip() + "\n[TIMEOUT]").strip())
    except Exception as exc:
        return CmdResult(" ".join(cmd), 1, f"ERROR: {exc}")


def section(title: str) -> None:
    print(f"\n## {title}")


def one_line(text: str, max_len: int = 220) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def status(label: str, ok: bool | None, detail: str = "") -> None:
    if ok is True:
        mark = "OK"
    elif ok is False:
        mark = "FAIL"
    else:
        mark = "INFO"
    print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))


def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_skill_name(path: pathlib.Path) -> tuple[str | None, str]:
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return None, ""
    m = re.search(r"^name:\s*[\"']?([^\"'\n]+)", text, re.M)
    return (m.group(1).strip() if m else None), text


def iter_skill_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    """Find SKILL.md files without descending into heavyweight vendored trees."""
    if not root.exists():
        return
    skip = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", ".archive"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.endswith(".egg-info")]
        if "SKILL.md" in filenames:
            yield pathlib.Path(dirpath) / "SKILL.md"


def audit_skills(deep: bool = False) -> None:
    section("Skills")
    skill_files = list(iter_skill_files(SKILLS)) if SKILLS.exists() else []
    names: list[str] = []
    malformed: list[pathlib.Path] = []
    huge: list[tuple[pathlib.Path, int]] = []
    by_name: dict[str, list[pathlib.Path]] = defaultdict(list)
    for p in skill_files:
        name, text = parse_skill_name(p)
        if not name:
            malformed.append(p)
        else:
            names.append(name)
            by_name[name].append(p)
        size = p.stat().st_size
        if size > 80_000:
            huge.append((p, size))

    dupes = {k: v for k, v in by_name.items() if len(v) > 1}
    status("skill files", True, f"{len(skill_files)} files, {len(set(names))} unique names")
    status("malformed frontmatter", len(malformed) == 0, str(len(malformed)))
    status("duplicate names", len(dupes) == 0, ", ".join(sorted(dupes)[:8]) if dupes else "none")
    status("oversized skills >80KB", len(huge) == 0, ", ".join(f"{p.parent.name}:{n//1024}KB" for p, n in huge[:8]) if huge else "none")

    if BUILTIN_SKILLS.exists():
        built_hash: dict[str, str] = {}
        for bp in iter_skill_files(BUILTIN_SKILLS):
            name, text = parse_skill_name(bp)
            if name:
                built_hash[name] = hashlib.sha256(text.encode()).hexdigest()
        identical = []
        divergent = []
        for lp in skill_files:
            name, text = parse_skill_name(lp)
            if name and name in built_hash:
                h = hashlib.sha256(text.encode()).hexdigest()
                if h == built_hash[name]:
                    identical.append(lp)
                else:
                    divergent.append(lp)
        status("local vs builtin duplicates", None, f"identical={len(identical)}, divergent={len(divergent)}")
        if deep and identical:
            for p in identical[:20]:
                print(f"  identical: {p}")


def audit_hermes() -> None:
    section("Hermes Framework")
    for cmd in (["hermes", "--version"], ["hermes", "status", "--all"], ["hermes", "doctor"], ["hermes", "mcp", "list"], ["hermes", "cron", "list"]):
        # Keep the cockpit responsive: some health checks can hang on slow MCP/provider probes.
        timeout = 12 if cmd[1] in {"status", "doctor"} else 8
        r = run(list(cmd), timeout=timeout)
        ok = r.code == 0
        label = " ".join(cmd)
        detail = one_line(r.out.splitlines()[-1] if r.out else "", 240)
        status(label, ok, detail or f"exit={r.code}")

    cfg = HOME / "config.yaml"
    env = HOME / ".env"
    status("config.yaml", cfg.exists(), str(cfg))
    status(".env", env.exists(), str(env) if env.exists() else "missing")


def audit_repo() -> None:
    section("Hermes Repo")
    if not REPO.exists():
        status("repo", False, f"missing: {REPO}")
        return
    r1 = run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO)
    r2 = run(["git", "status", "--short"], cwd=REPO)
    branch = run(["git", "branch", "--show-current"], cwd=REPO)
    status("repo path", True, str(REPO))
    status("git head", r1.code == 0, f"{branch.out.strip()}@{r1.out.strip()}")
    dirty_lines = [x for x in r2.out.splitlines() if x.strip()]
    status("git working tree", len(dirty_lines) == 0, f"dirty files={len(dirty_lines)}")
    for line in dirty_lines[:20]:
        print("  " + line)


def audit_mcp_services() -> None:
    section("MCP / Local Services")
    status("Burp proxy 127.0.0.1:8080", tcp_open("127.0.0.1", 8080), "service-specific health; MCP config may still be OK")
    for port in (8888, 9999, 8000):
        if tcp_open("127.0.0.1", port):
            status(f"local service 127.0.0.1:{port}", True, "open")
    for cmd in (["which", "nmap"], ["which", "nuclei"], ["which", "sqlmap"], ["which", "ffuf"], ["which", "gobuster"], ["which", "masscan"], ["which", "openvpn"]):
        r = run(list(cmd), timeout=5)
        status(cmd[-1], r.code == 0, r.out or "missing")


def audit_ops() -> None:
    section("SRC / Pentest Ops")
    if REPORTS.exists():
        files = list(REPORTS.rglob("*"))
        report_files = [p for p in files if p.is_file() and p.suffix.lower() in {".txt", ".md", ".html", ".json"}]
        status("/tmp/vuln_reports", True, f"{len(report_files)} report-like files")
        newest = sorted(report_files, key=lambda p: p.stat().st_mtime, reverse=True)[:8]
        for p in newest:
            print(f"  {time.strftime('%Y-%m-%d %H:%M', time.localtime(p.stat().st_mtime))} {p}")
    else:
        status("/tmp/vuln_reports", False, "missing")

    r = run(["ip", "addr", "show", "tun0"], timeout=5)
    status("VPN tun0", r.code == 0 and "inet " in r.out, one_line(r.out, 180) if r.code == 0 else "not up")
    procs = run(["pgrep", "-af", "openvpn|burpsuite|java.*burp|hexstrike|mcp"], timeout=5)
    status("relevant processes", procs.code == 0, one_line(procs.out, 300) if procs.out else "none")


def recommend() -> None:
    section("Control Recommendations")
    print("1. 入口决策: 新任务先加载 global-control，再按任务域加载 Hermes/MCP/SRC/渗透/DevOps 专项技能。")
    print("2. 长任务: 用 todo + terminal(background, notify_on_complete) 或 cron/kanban；不要口头承诺后停止。")
    print("3. SRC: 只输出人工验证过的实质漏洞；同根因合并；报告直接给纯文本、单行 curl、截图位置。")
    print("4. Hermes 修改: 先 baseline → patch/write_file → Hermes venv pytest → doctor/status 验证。")
    print("5. VPN/代理: 连接 VPN 前后检查 split tunnel 和 API 连通，Burp/HexStrike 区分 MCP 连接与后端服务状态。")


def main() -> int:
    ap = argparse.ArgumentParser(description="Hermes global control cockpit")
    ap.add_argument("--deep", action="store_true", help="print more duplicate/diagnostic details")
    ap.add_argument("--json", action="store_true", help="reserved for future machine-readable output")
    ap.add_argument("--skip-hermes", action="store_true", help="skip slow Hermes CLI health commands")
    args = ap.parse_args()
    print("Hermes Global Control Audit", flush=True)
    print(f"time: {time.strftime('%Y-%m-%d %H:%M:%S %z')}", flush=True)
    print(f"home: {HOME}", flush=True)
    if not args.skip_hermes:
        audit_hermes()
    else:
        section("Hermes Framework")
        status("Hermes CLI checks", None, "skipped by --skip-hermes")
    audit_repo()
    audit_skills(deep=args.deep)
    audit_mcp_services()
    audit_ops()
    recommend()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
