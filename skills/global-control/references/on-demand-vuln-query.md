# On-demand vulnerability intelligence query

This global-control reference forwards to the dedicated `vuln-intel` skill reference.

Use when a target product/version/CVE is identified during SRC/pentest work. Do not rely on long-running daily cron; refresh on demand.

Primary command:

```bash
/root/.hermes/scripts/hermes-vuln-query.sh --keyword "<product-or-CVE>" --refresh --days 30 --github-limit 10
```

Authoritative detailed reference: `vuln-intel` skill, `references/on-demand-vuln-query.md`.
