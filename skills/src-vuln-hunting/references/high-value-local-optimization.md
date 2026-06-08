# SRC high-value local optimization checklist

Use this checklist when the user asks to improve vulnerability hunting efficiency or grant broad research permissions.

## Local control-plane readiness

Check and optimize only what is needed for the current task:

- Gateway/Burp/HexStrike readiness: `/root/.hermes/scripts/hermes-ensure-tools.sh --status`
- Evidence/report roots:
  - `/tmp/vuln_reports`
  - `/tmp/src-workspaces`
  - `/root/.hermes/src-control`
- Framework scripts:
  - `/root/.hermes/scripts/src-workspace-init.py`
  - `/root/.hermes/scripts/src-http-probe.py`
  - `/root/.hermes/scripts/src-js-api-extract.py`
  - `/root/.hermes/scripts/src-quality-gate.py`
  - `/root/.hermes/scripts/src-report-format-gate.py`

Do not persist transient missing-tool failures as permanent negative rules. Capture the fix or checklist instead.

## High-impact inputs to request or use when available

- Two low-privilege accounts A/B for horizontal authorization tests.
- One special-role account if in scope: supplier, merchant, student, teacher, low-admin.
- Burp/mobile/small-program traffic for login, query, create, update, upload, export, download, password reset.
- Self-owned object IDs: orderId, fileId, userId, orgId, applicationId, invoiceId, ticketId.
- Program scope, exclusions, and allowed verification limits.

## Per-target workspace pattern

```bash
export LC_ALL=C LANG=C
TARGET='example.com'
INIT_JSON=$(/usr/bin/python3 /root/.hermes/scripts/src-workspace-init.py "$TARGET" --scope 'authorized low-impact SRC verification')
WS=$(/usr/bin/python3 - <<'PY' "$INIT_JSON"
import json,sys
print(json.loads(sys.argv[1])['workspace'])
PY
)
echo "$WS"
```

Then store assets, endpoints, probes, negative evidence, candidate reports, and final reports in the generated workspace.

## Default high-yield tests after traffic capture

- Remove Authorization/Cookie and replay.
- Replace A account object IDs in B session.
- Replace `orgId`, `tenantId`, `deptId`, `schoolId`, `companyId`.
- Test mass-assignment fields: `user_id`, `ownerId`, `role`, `status`, `quota`, `price`, `amount`, `isAdmin`, `auditStatus`.
- Check list/export endpoints with conservative page size changes.
- Test file download URLs for predictable IDs or missing signatures.
- Test upload endpoint auth, content-type, access URL, browser rendering, and cleanup.
- Test API key creation/update for quota/role/status mass assignment, prove one minimal usable call, then delete created key.
- Test JWT/session signing only with owned accounts.

## External keys that improve asset discovery

If the user provides them, add to `/root/.hermes/.env` and never paste secrets into reports:

- FOFA_KEY / FOFA_EMAIL
- HUNTER_API_KEY
- QUAKE_TOKEN
- SHODAN_API_KEY
- CENSYS_API_ID / CENSYS_API_SECRET
- ZOOMEYE_API_KEY
- SECURITYTRAILS_API_KEY
- CHAOS_KEY
- GITHUB_TOKEN

## Report gate reminder

Only produce final reports after:

- command actually executed locally;
- response body/header evidence saved;
- no-token/invalid-token or A/B account control performed;
- duplicate/root cause checked against `/tmp/vuln_reports`;
- screenshot locations identified;
- single-line curl commands verified.
