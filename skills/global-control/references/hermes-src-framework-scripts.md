# Hermes SRC framework scripts

These scripts are local control-plane helpers for repeatable SRC/pentest work. They are designed to keep Hermes as the decision-making controller while making evidence collection reproducible and resumable.

## Paths

- `/root/.hermes/scripts/src-workspace-init.py`
- `/root/.hermes/scripts/src-http-probe.py`
- `/root/.hermes/scripts/src-quality-gate.py`
- `/root/.hermes/scripts/src-practical-next.py` — **v2.0** subdomain tiering (P0/P1/P2/SKIP) + auto-skip low-value hosts
- `/root/.hermes/scripts/src-think.py` — hypothesis synthesis from probe/API/JS/Burp evidence
- `/root/.hermes/scripts/src-browser-capture.py`
- `/root/.hermes/scripts/src-workflow-chain-builder.py`
- `/root/.hermes/scripts/agent-exec-monitor.py` — **v2.0** Loop Guard with semantic loop detection, time gate, rejected memory, stagnation detection

- `src-api-recon-ranker.py` turns noisy `endpoints.tsv` / `js_api_findings.json` into a business-prioritized API queue.
- `src-idor-check.py` performs low-impact BOLA/IDOR comparison with candidate IDs plus invalid/random controls.
- `src-browser-capture.py` captures runtime browser evidence: network/API requests, console, storage keys, forms, scripts, screenshots, and optional Burp proxy routing.
- `src-workflow-chain-builder.py` creates evidence skeletons for multi-step business logic chains such as reset password, SMS/register, upload/download, OAuth/SSO, export/download, and order/payment.

## 1. Create a workspace

```bash
export LC_ALL=C LANG=C
/usr/bin/python3 /root/.hermes/scripts/src-workspace-init.py bzuu.edu.cn --scope 'public low-impact SRC verification'
```

Output JSON contains:

- `workspace`: e.g. `/tmp/src-workspaces/bzuu.edu.cn/20260523`
- `target_profile`: e.g. `/tmp/vuln_reports/bzuu.edu.cn/target_profile.md`

Workspace files:

- `scope.md`
- `assets.tsv`
- `endpoints.tsv`
- `probe_results.tsv`
- `interesting.tsv`
- `negative.md`
- `final_gate.md`
- `state.json`
- `headers/`, `bodies/`, `screenshots/`, `candidate_reports/`, `final_reports/`, `logs/`

## 2. Probe URLs with stable evidence paths

Create URL list:

```bash
cat > "$WS/urls.txt" <<'EOF'
https://example.edu.cn/
https://example.edu.cn/api/user/info
EOF
```

Run probe:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 10
```

For repeatable self-tests or one-shot reruns where old probe rows would distort counts, reset the TSV first:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 10 --fresh
```

For idempotent reruns that should preserve existing history but not append duplicate `GET + URL` rows:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 10 --dedupe
```

Properties:

- Forces `LC_ALL=C`/`LANG=C` for subprocesses to avoid locale warning spam.
- Uses SHA1(method + URL) for header/body filenames rather than unsafe URL-derived filenames.
- Appends normalized rows to `probe_results.tsv`.
- Flushes after each request so partial results survive interruption.
- Optional `--control` fetches one random same-origin path per origin and writes `control_hash`, `similarity`, `fp_class`, and `reject_reason` columns. Use this for one-shot audits and noisy targets to pre-filter SPA fallback, WAF block pages, login pages, and unified error pages before quality gate review.

False-positive-aware probe example:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 10 --control --dedupe
```

CORS/header probe example:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 10 --origin https://evil.example --control
```

## 3. Rank API candidates before verification

After JS/API extraction, rank endpoints by business attack value instead of reviewing a flat noisy list:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-api-recon-ranker.py "$WS" --top 80
```

Outputs:

- `$WS/api_recon_ranked.tsv`
- `$WS/api_recon_ranked.md`

Priority categories include auth boundary, IDOR/PII, object access, upload/file, tenant/org, admin/config, business flow, and secret indicators. This is only a verification queue; Hermes must still prove no-token/low-privilege controls, object ownership, and real impact before report generation.

## 4. Low-impact IDOR/BOLA check

For a candidate object endpoint, compare several safe IDs plus invalid/random controls:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-idor-check.py 'https://target.example/api/detail?id={id}' --ids 1,2,3 --outdir "$WS/candidates/idor-detail"
```

For authenticated/low-privilege checks, add explicit headers:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-idor-check.py 'https://target.example/api/order/{id}' --ids 1001,1002 --header 'Authorization: Bearer <LOW_PRIV_TOKEN>' --outdir "$WS/candidates/order-idor"
```

Outputs:

- `idor_results.tsv`
- `idor_gate.md`
- saved request headers/bodies

A `NEED_MORE_EVIDENCE_IDOR_CANDIDATE` verdict is not a final vulnerability. Submit only after proving the authorization boundary with no-token/invalid-token/low-privilege controls and business impact.

## 5. Browser runtime capture

Use browser capture when curl/static JS cannot see runtime requests, login redirects, dynamic chunks, storage state, CORS browser behavior, or screenshots. This is observation-only by default: it does not submit forms or fuzz.

```bash
/usr/bin/python3 /root/.hermes/scripts/src-browser-capture.py 'https://target.example/page' --outdir "$WS/browser/page1" --ignore-https-errors
```

When Burp proxy is actually running and traffic needs GUI/manual review:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-browser-capture.py 'https://target.example/page' --outdir "$WS/browser/page1-burp" --proxy http://127.0.0.1:8080 --ignore-https-errors
```

Outputs:

- `summary.json` / `summary.md`
- `network.json`
- `console.json`
- `dom.json`
- `storage.json` with secret-like values redacted
- `screenshot.png`
- `responses/*.body` samples for API-like/runtime requests

Use this before declaring a dynamic target exhausted. Runtime evidence still must chain to unauthorized access, IDOR, authentication bypass, usable key impact, or sensitive browser-readable data before reporting.

## 6. Workflow-chain templates

Use workflow chains for business logic instead of isolated endpoint guessing:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-workflow-chain-builder.py target.example --outdir "$WS/workflow_chains" --chains all
```

Available chains:

- `reset-password`
- `register-sms`
- `upload-download`
- `export-download`
- `oauth-sso`
- `order-payment`

Each chain creates request/response/control/curl/screenshot directories plus a README with required steps, controls, submit gate, and evidence-gate command. Do not submit a workflow-chain candidate until its directory passes `src-evidence-gate.py` and Hermes has manually verified low-impact proof.

## 7. Run quality gate

```bash
/usr/bin/python3 /root/.hermes/scripts/src-quality-gate.py "$WS/probe_results.tsv" --target-profile /tmp/vuln_reports/example.edu.cn/target_profile.md --out "$WS/final_gate.md"
```

Verdicts:

- `DO_NOT_SUBMIT`: no high-confidence exploit/sensitive-data signal.
- `NEED_MORE_EVIDENCE`: potentially interesting indicators exist; Hermes must manually verify, dedupe, and prove impact before report generation.

Important: the quality gate is conservative heuristic filtering, not the final vulnerability judge. The Hermes main controller must still inspect bodies, run controls, check target history, merge root causes, and decide whether the report meets SRC standards.

## 8. Extract JS/API candidates offline

Use this after probing pages or saving JS/HTML bodies. It parses saved bodies only; it does not fetch the network.

```bash
/usr/bin/python3 /root/.hermes/scripts/src-js-api-extract.py "$WS"
```

Optional extra local files/directories can be parsed:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-js-api-extract.py "$WS" "$WS/raw" /tmp/app.js
```

Outputs:

- appends candidate rows to `$WS/endpoints.tsv`;
- writes `$WS/js_api_findings.json` with `scripts`, `urls`, `endpoints`, `secrets`;
- masks secret values by SHA256 prefix only. A secret finding is a candidate; report only after proving real impact such as data/API access.

## 9. Merge target profile

After a probe/extract/gate cycle, update the long-lived target profile so the next session starts with current negative evidence and API inventory:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-target-profile-merge.py "$WS" --target example.edu.cn
```

Default profile path: `/tmp/vuln_reports/<target-slug>/target_profile.md`.

## 10. Report format gate

Before giving the user a final SRC report, run the offline format checker:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-report-format-gate.py "$WS/final_reports/report.txt"
```

It checks the user's required fields, single-line curl, screenshot markers, HTML markup, vague/unverified wording, and weak-only evidence patterns. A PASS only means format is acceptable; Hermes still must verify the vulnerability manually.

## 11. MCP/local service status snapshot

Use this when deciding whether to use MCP or self-controlled tools:

```bash
/usr/bin/python3 /root/.hermes/scripts/hermes-mcp-service-status.py --out "$WS/mcp_status.json"
```

Add `--include-hermes-cli` only when full Hermes CLI checks are needed and acceptable. The snapshot distinguishes MCP bridge/process state from backend service state, e.g. Burp MCP may exist while `127.0.0.1:8080` is not listening.

## Required workflow for future SRC continuation

1. Load target-specific negative evidence first when available.
2. Initialize or resume workspace.
3. Put discovered URLs/API candidates in `urls.txt` or `endpoints.tsv`.
4. Probe with `src-http-probe.py` or a task-specific script that writes the same TSV shape.
5. Run `src-quality-gate.py`.
6. Only if `NEED_MORE_EVIDENCE`, manually verify with controls:
   - random nonexistent path/body hash;
   - invalid token/no token comparison;
   - same-system protected endpoint;
   - sensitive field and data-volume proof;
   - duplicate/root-cause check against `/tmp/vuln_reports` and skill references.
7. If no final proof, update `negative.md` and, for repeated target lessons, write a skill reference.

## 12. Practical next-step ranking (v2.0)

After alive URLs are known, rank and filter them by attack value before testing:

```bash
/usr/bin/python3 /root/.hermes/scripts/src-practical-next.py "$WS" --tiers --show-skipped --top 20
```

v2.0 tiering:
- **P0**: api/authserver/actuator/swagger/upload/graphql/grpc (score +40)
- **P1**: ehall/cas/sso/oa/admin/manage/pay (score +25)
- **P2**: app/mobile/h5/wechat (score +10)
- **SKIP**: cdn/static/www/news/test/dev/staging (auto-filtered)

Flags:
- `--skip-threshold N` — skip hosts scoring below N (default: 15)
- `--show-skipped` — show filtered low-value hosts
- `--tiers` — show tier distribution summary

## 13. Loop Guard v2.0 (agent-exec-monitor.py)

For SRC/penetration long tasks, use the execution monitor:

```bash
# Quick health check (all guards in one view)
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py health

# Record user's rejection of a finding (prevents repetition)
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py reject curl "target.com" "ip_leak" "user says no value"

# Log tool calls with evidence/hypothesis
/usr/bin/python3 /root/.hermes/scripts/agent-exec-monitor.py log curl "target.com" "found api endpoint" "possible IDOR"
```

v2.0 guards:
- Semantic loop detection: plan-level hash (warn@3x, force@5x)
- Time gate: minutes since last confirmed finding (warn@10min, force@20min)
- Rejected memory: persistent across calls, warns on same finding type
- Stagnation: consecutive no-evidence calls (warn@8, force@12)
- Same-tool loop: (warn@5, force@8)

## Self-test command

```bash
export LC_ALL=C LANG=C
RUN_ID=$(date +%Y%m%d%H%M%S)
INIT_JSON=$(/usr/bin/python3 /root/.hermes/scripts/src-workspace-init.py example.edu.cn --root "/tmp/src-framework-test-$RUN_ID" --scope 'framework self-test' --force)
WS=$(/usr/bin/python3 - <<'PY' "$INIT_JSON"
import json,sys
print(json.loads(sys.argv[1])['workspace'])
PY
)
printf '%s\n' 'https://example.com/' 'https://example.com/not-exist-hermes-src-test' > "$WS/urls.txt"
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 8 --fresh --control
/usr/bin/python3 /root/.hermes/scripts/src-quality-gate.py "$WS/probe_results.tsv" --out "$WS/final_gate.md"
/usr/bin/python3 /root/.hermes/scripts/src-js-api-extract.py "$WS"
/usr/bin/python3 /root/.hermes/scripts/src-api-recon-ranker.py "$WS" --top 20
head -40 "$WS/final_gate.md"
```

Expected: `Verdict: DO_NOT_SUBMIT` for example.com and generated header/body evidence files under the workspace. The command uses a timestamped root plus `--fresh` so repeated self-tests do not double-count old rows.

Operational note: `src-http-probe.py` appends to `probe_results.tsv` by default to preserve long-task evidence and support interruption recovery. Use `--fresh` for self-tests/one-shot audits and `--dedupe` for idempotent reruns that should keep existing history but skip duplicate `GET + URL` rows. For formal SRC continuation, keep append semantics unless you intentionally reset the workspace.
