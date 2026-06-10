# GitHub token for daily CVE/POC intelligence

Use this when the user provides a GitHub PAT to improve the daily vulnerability intelligence updater's GitHub PoC search coverage.

## Safe handling

- Treat the PAT as a secret. Never echo it back, include it in logs, or write it into skill/memory text.
- Store it in `/root/.hermes/.env` as `GITHUB_TOKEN=...` with mode `0600`.
- Prefer file updates through Python or a non-echoing write path so the token is not exposed in shell history or terminal output.
- Do not save the token value in memory or references.

## Validation without leaking the token

Validate using GitHub's rate-limit endpoint and print only limits/remaining counts:

```bash
set -a
. /root/.hermes/.env
set +a
/root/.hermes/hermes-agent/venv/bin/python - <<'PY'
import json, os, urllib.request, urllib.error
headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
}
req = urllib.request.Request('https://api.github.com/rate_limit', headers=headers)
with urllib.request.urlopen(req, timeout=20) as r:
    data = json.loads(r.read().decode())
core = data.get('resources', {}).get('core', {})
search = data.get('resources', {}).get('search', {})
print('github_auth_ok=1')
print('core_limit=%s remaining=%s' % (core.get('limit'), core.get('remaining')))
print('search_limit=%s remaining=%s' % (search.get('limit'), search.get('remaining')))
PY
```

Expected authenticated baseline: `core_limit=5000`; GitHub search is often separately rate-limited, commonly `search_limit=30`.

## Script integration pattern

The daily updater should load `/root/.hermes/.env` itself at runtime before reading `GITHUB_TOKEN`. Do not rely on the currently running Gateway process inheriting new environment variables, because restarting Gateway can kill active agent/gateway work and may be blocked by smart approvals.

Minimal loader pattern:

```python
def load_dotenv(path=Path('/root/.hermes/.env')):
    if not path.exists():
        return
    for raw in path.read_text(errors='ignore').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
```

Call `load_dotenv()` near the top of `/root/.hermes/scripts/update-vuln-intel.py` before GitHub lookups.

## Functional PoC lookup smoke test

Use a known public CVE such as `CVE-2021-44228` to test `fetch_github_pocs()` and print only repository names/star counts, not the token.

```bash
/root/.hermes/hermes-agent/venv/bin/python - <<'PY'
import importlib.util
p = '/root/.hermes/scripts/update-vuln-intel.py'
spec = importlib.util.spec_from_file_location('uvi', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
refs = m.fetch_github_pocs(['CVE-2021-44228'], limit=1, quiet=False)
print('github_poc_lookup_ok=1')
print('refs_count=%d' % len(refs))
for r in refs[:3]:
    print('ref=%s stars=%s' % (r.get('title'), r.get('stars')))
PY
```

## Gateway/Cron note

If the updater self-loads `.env`, no Gateway restart is needed for the next no-agent Cron run to see the token. Verify Cron remains scheduled with `hermes cron status` when normal tools are available. Only restart Gateway when a change truly requires process-level env refresh and it is safe to interrupt running gateway sessions.
