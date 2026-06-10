# Contributing to mo-Security-Skills

## How to Add a New Skill

1. Create a new directory: `skills/your-skill-name/`
2. Add a `SKILL.md` file with required YAML frontmatter:

```yaml
---
name: your-skill-name
description: >-
  Clear description of what this skill does and when
  an AI agent should activate it. Include keywords.
domain: cybersecurity
subdomain: penetration-testing
tags:
- tag1
- tag2
- tag3
version: '1.0'
author: your-github-username
license: Apache-2.0
mitre_attack:
- T1190
- T1059
nist_csf:
- DE.CM-01
- ID.RA-01
---
```

3. Write clear, step-by-step instructions in the Markdown body using these sections:
   - `## When to Use` — Trigger conditions
   - `## Prerequisites` — Tools, access, environment
   - `## Steps` — Numbered steps with real commands
   - `## Key Concepts` — Table of techniques/concepts
   - `## Expected Output` — What the agent should produce

4. (Optional) Add supporting files:
   - `references/` — Deep technical references, standards mappings
   - `scripts/` — Working helper scripts
   - `assets/` — Templates, checklists
   - `LICENSE` — Apache 2.0 (copy from root)

5. Regenerate the catalog and validate before committing:

   ```bash
   pip install -r requirements-dev.txt     # one-time (pyyaml, pytest, ruff)
   python scripts/build_index.py           # rewrite index.json from frontmatter
   python scripts/validate_skills.py       # check the frontmatter contract
   ruff check . --select F401,F541,F811,F821,F601,F632,F706,F502  # lint helpers
   pytest tests/ -q                        # run tooling unit tests
   ```

   `index.json` is generated — never hand-edit it. CI runs the validator and
   `python scripts/build_index.py --check` on every PR, so a stale or invalid
   index will fail the build.

6. Submit a PR with title: `Add skill: your-skill-name`

## Skill Quality Checklist

- [ ] Name is lowercase with hyphens (kebab-case), 1–64 characters
- [ ] Description is clear and includes agent-discovery keywords
- [ ] Instructions are actionable with real commands and tool names
- [ ] Domain is `cybersecurity` and subdomain is set correctly
- [ ] Tags include relevant tools, frameworks, and techniques
- [ ] MITRE ATT&CK technique IDs are included where applicable
- [ ] NIST CSF categories are mapped where applicable
- [ ] No hardcoded credentials, tokens, or internal IPs
- [ ] No company-specific names in public-facing content
- [ ] Agent-agnostic: works with any AI agent framework

## Subdomains

Choose the most appropriate subdomain:

| Subdomain | Focus |
|:----------|:------|
| `web-application-security` | OWASP Top 10, XSS, SQLi, SSRF, auth bypass |
| `api-security` | REST/GraphQL/gRPC, BOLA, IDOR, rate limiting |
| `network-security` | IDS/IPS, firewall, traffic analysis, segmentation |
| `penetration-testing` | General pentest methodology, recon, exploitation |
| `red-teaming` | Adversary simulation, C2, lateral movement |
| `digital-forensics` | Disk, memory, network, mobile forensics |
| `malware-analysis` | Static/dynamic analysis, reverse engineering |
| `threat-intelligence` | IOC, CTI, threat actors, TTPs |
| `cloud-security` | AWS, Azure, GCP, CSPM, cloud forensics |
| `container-security` | Docker, Kubernetes, image scanning |
| `identity-access-management` | IAM, PAM, SSO, SAML, OAuth, CAS |
| `vulnerability-management` | Scanning, prioritization, CVE tracking |
| `devsecops` | CI/CD security, SAST, DAST, supply chain |
| `soc-operations` | SIEM, alert triage, detection engineering |
| `incident-response` | Breach containment, forensics, recovery |
| `threat-hunting` | Hypothesis-driven hunts, behavioral analytics |

## Agent Compatibility

These skills are designed to work with **any AI agent framework**:
- Anthropic Claude (Computer Use, Tool Use)
- OpenAI GPT (Function Calling)
- Hermes Agent (by Nous Research)
- LangChain / LangGraph agents
- AutoGPT / CrewAI / MetaGPT
- Custom agents reading YAML frontmatter

YAML frontmatter enables ~30 token fast scanning for skill discovery. The Markdown body is self-contained and requires no framework-specific runtime.

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
