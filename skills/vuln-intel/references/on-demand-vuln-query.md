# On-demand vulnerability intelligence query

## Why this exists

The user corrected the earlier design: Hermes is not guaranteed to run 7×24, so daily CVE/POC cron jobs can create a false sense of freshness. Vulnerability intelligence should be queried when it matters: after a target fingerprint, product name, version, component, or CVE appears during SRC/pentest work.

## Current rule

Do not create long-running daily CVE/POC cron jobs by default. Treat local SQLite/latest.md as a cache only. For active SRC/pentest tasks, refresh/query on demand and then validate against the target.

## Primary command

```bash
/root/.hermes/scripts/hermes-vuln-query.sh --refresh --keyword "<product-or-CVE>" --days 30 --github-limit 10
```

Useful variants:

```bash
/root/.hermes/scripts/hermes-vuln-query.sh --local --limit 20 "nginx"
/root/.hermes/scripts/hermes-vuln-query.sh --refresh --keyword "CVE-2021-44228" --github-limit 5
/root/.hermes/scripts/hermes-vuln-query.sh --local --json "wordpress"
```

## Workflow for future agents

1. Identify product/version/CVE from recon, JS, headers, paths, error messages, package metadata, or fingerprinting.
2. Run `hermes-vuln-query.sh --refresh --keyword ...` for that exact item.
3. Read results as candidate intelligence only.
4. Confirm target exposure: affected version, reachable vulnerable endpoint, authentication context, and safe PoC evidence.
5. Exclude non-submittable findings: unverified CVE match, generic version info, WAF blocks, failed exploit responses, SPA fallback, or public PoC existence without target impact.
6. Only turn it into a report after target-specific validation.

## Security and token handling

`GITHUB_TOKEN` is stored in `/root/.hermes/.env`; scripts load it automatically and must not echo it. If GitHub search is rate-limited, skip or reduce `--github-limit`; do not treat rate-limit warnings as task failure.

## Cron policy

The former daily job `Daily CVE/POC Intelligence Update` was removed. Do not recreate it unless the user explicitly asks for a truly persistent monitoring mode and understands that Hermes/Gateway must be running for it to fire.
