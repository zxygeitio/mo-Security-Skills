#!/usr/bin/env python3
"""Layered MCP/local-service status snapshot for Hermes control tasks.

Read-only. Distinguishes MCP bridge availability from backend service availability.
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

SERVICES = {
    'burp_proxy': ('127.0.0.1', 8080, 'Burp GUI proxy listener; Burp MCP can be up while this is down'),
    'hexstrike_api': ('127.0.0.1', 8888, 'HexStrike backend API; MCP bridge depends on this'),
}
PROCESS_KEYWORDS = ['burp_mcp_server.py', 'hexstrike-mcp-bridge.py', 'hexstrike_server.py', 'gateway', 'cron']


def tcp(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(cmd: list[str], timeout: int = 8) -> dict:
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return {'cmd': cmd, 'exit': cp.returncode, 'stdout': cp.stdout[-4000:], 'stderr': cp.stderr[-2000:]}
    except Exception as e:
        return {'cmd': cmd, 'exit': 999, 'stdout': '', 'stderr': repr(e)}


def ps_snapshot() -> list[str]:
    r = run(['ps', '-eo', 'pid,cmd'], timeout=5)
    lines = []
    for line in r.get('stdout', '').splitlines():
        if any(k.lower() in line.lower() for k in PROCESS_KEYWORDS):
            lines.append(line.strip())
    return lines[:80]


def main() -> int:
    ap = argparse.ArgumentParser(description='Hermes MCP/local service status')
    ap.add_argument('--out', default='', help='Optional JSON output path')
    ap.add_argument('--include-hermes-cli', action='store_true', help='Also run hermes mcp/cron/status commands')
    args = ap.parse_args()

    data = {'time': time.strftime('%Y-%m-%d %H:%M:%S %z'), 'tcp_services': {}, 'processes': ps_snapshot(), 'hermes_cli': {}}
    for name, (host, port, note) in SERVICES.items():
        data['tcp_services'][name] = {'host': host, 'port': port, 'open': tcp(host, port), 'note': note}
    if args.include_hermes_cli and shutil.which('hermes'):
        data['hermes_cli']['mcp_list'] = run(['hermes', 'mcp', 'list'], timeout=15)
        data['hermes_cli']['cron_status'] = run(['hermes', 'cron', 'status'], timeout=15)
        data['hermes_cli']['status_all'] = run(['hermes', 'status', '--all'], timeout=20)
    elif not shutil.which('hermes'):
        data['hermes_cli']['error'] = 'hermes command not found in PATH'

    if args.out:
        Path(args.out).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(data, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
