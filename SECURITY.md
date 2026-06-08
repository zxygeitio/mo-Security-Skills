# Security Policy

## Reporting Vulnerabilities

If you find a vulnerability in this repository's tooling (not in the skills' target systems), please report it responsibly:

1. Open a GitHub issue with `[security]` tag
2. Or email: zxygeitio@users.noreply.github.com

## Scope

This repository contains **offensive security skills** — they are designed to find vulnerabilities in authorized targets. The skills themselves should not contain:

- Hardcoded credentials or API keys
- Real target IP addresses or domains (use placeholders)
- Unredacted vulnerability reports with real data

## Skill Security Guidelines

All skills must:
- Use placeholder values (e.g., `example.com`, `TARGET_IP`, `YOUR_TOKEN`)
- Include authorization warnings
- Not include real exploit payloads against specific production systems
- Sanitize any example output from real engagements
