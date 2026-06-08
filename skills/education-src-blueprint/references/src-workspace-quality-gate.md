# SRC workspace and quality-gate workflow

Use this workflow for continued SRC/pentest work where the user wants only verified, reportable vulnerabilities.

## Scripts

- `~/.agent/scripts/src-workspace-init.py` — creates a resumable workspace and target profile.
- `~/.agent/scripts/src-http-probe.py` — probes URL lists, saves headers/bodies by SHA1(url), appends normalized `probe_results.tsv`.
- `~/.agent/scripts/src-quality-gate.py` — conservative heuristic gate that classifies probe results as `DO_NOT_SUBMIT` or `NEED_MORE_EVIDENCE`.

## Required usage

```bash
export LC_ALL=C LANG=C
INIT_JSON=$(/usr/bin/python3 ~/.agent/scripts/src-workspace-init.py TARGET.edu.cn --scope 'public low-impact SRC verification')
WS=$(/usr/bin/python3 - <<'PY' "$INIT_JSON"
import json,sys
print(json.loads(sys.argv[1])['workspace'])
PY
)
```

Add candidate URLs:

```bash
cat > "$WS/urls.txt" <<'EOF'
https://TARGET.edu.cn/
https://TARGET.edu.cn/api/user/info
EOF
```

Probe and gate:

```bash
/usr/bin/python3 ~/.agent/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 10
/usr/bin/python3 ~/.agent/scripts/src-quality-gate.py "$WS/probe_results.tsv" --out "$WS/final_gate.md"
```

## Extended helpers

After probing URLs, parse saved HTML/JS bodies for API candidates and secret hints:

```bash
/usr/bin/python3 ~/.agent/scripts/src-js-api-extract.py "$WS"
```

This appends `$WS/endpoints.tsv` and writes `$WS/js_api_findings.json`. Treat extracted secrets/endpoints as candidates only; report only after proving exploit impact.

Merge durable target context for future sessions:

```bash
/usr/bin/python3 ~/.agent/scripts/src-target-profile-merge.py "$WS" --target TARGET.edu.cn
```

Before final output, run report format gate:

```bash
/usr/bin/python3 ~/.agent/scripts/src-report-format-gate.py "$WS/final_reports/report.txt"
```

For MCP-vs-self-control decisions, snapshot local service state:

```bash
/usr/bin/python3 ~/.agent/scripts/hermes-mcp-service-status.py --out "$WS/mcp_status.json"
```

## Decision rules

- `DO_NOT_SUBMIT`: do not write a report unless manual review finds proof outside the TSV.
- `NEED_MORE_EVIDENCE`: inspect response bodies and run controls before reporting.
- Never submit from quality-gate output alone; it is a triage filter.

## Controls before report

For each candidate:

1. Random nonexistent path hash/size/status comparison.
2. No token vs invalid token vs normal protected endpoint comparison.
3. Sensitive field proof and data-volume proof.
4. Same root-cause merge check.
5. Search `/tmp/vuln_reports` and loaded target references for duplicates.
6. Produce single-line curl and screenshot-position plan.

## Why this exists

This prevents repeated weak reports from:

- 401/403/404/login redirects;
- empty 200 responses;
- SPA fallback;
- public SAML/VPN/login configuration;
- invalid-session mail/API responses;
- private-IP DNS records with no external exploit path.
