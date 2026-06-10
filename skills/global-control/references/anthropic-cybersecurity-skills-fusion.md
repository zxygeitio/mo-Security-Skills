# Anthropic Cybersecurity Skills Fusion

Source repository: `https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git`
Local clone used for audit: `/tmp/Anthropic-Cybersecurity-Skills`
Audit output: `/tmp/anthropic-cybersecurity-skills-audit/audit.{json,md}`
Hermes query cache: `/root/.hermes/data/external-skill-corpora/anthropic-cybersecurity/`

## What This Project Adds

The external project is a large agentskills.io-style cybersecurity corpus:

- 754 cybersecurity skills.
- Strong frontmatter discipline: `name`, `description`, `domain`, `subdomain`, `tags`, `license`, framework mappings.
- Full MITRE ATT&CK and NIST CSF mapping on all sampled skills.
- Strong blue-team coverage: DFIR, memory forensics, malware reverse engineering, SIEM/threat hunting, cloud, identity, supply-chain, AI security, governance/risk.
- Useful AppSec/SRC material exists, but the repo is broader and more defensive than our existing SRC system.

Do not import all 754 skills into active Hermes context. Treat it as an external corpus and retrieve only 5-12 task-relevant source skills.

## Hermes Fusion Entry

Use the external corpus router:

```bash
/usr/bin/python3 /root/.hermes/scripts/anthropic-cyber-skills-router.py \
  --query '<task description>' \
  --limit 10
```

Output:

- `/root/.hermes/data/external-skill-corpora/anthropic-cybersecurity/last-query.json`
- `/root/.hermes/data/external-skill-corpora/anthropic-cybersecurity/last-query.md`

The router returns:

- `bridge`: the Hermes fusion mode.
- `hermes_load_first`: local Hermes skills to load first.
- `external_skills`: task-relevant source skills with score, source path, frameworks, matched terms.

## Bridge Modes

### `src-pentest`

Trigger terms: SRC, pentest, web, API, IDOR/BOLA, OAuth, JWT, SAML, CORS, CVE, KEV, exploit prioritization.

Load first:

- `global-control`
- `src-vuln-hunting`
- `pentest-unified-engine`
- `web-pentest-fast`
- `vuln-intel`

External skills are used as procedure enrichment only. Keep Hermes gates authoritative:

- `src-http-probe --control`
- `src-quality-gate.py`
- `src-practical-next.py`
- `src-think.py`
- `src-evidence-gate.py`

Good external source patterns to retrieve:

- `testing-api-for-broken-object-level-authorization`
- `testing-api-authentication-weaknesses`
- `testing-jwt-token-security`
- `exploiting-jwt-algorithm-confusion-attack`
- `testing-api-security-with-owasp-top-10`
- `performing-cve-prioritization-with-kev-catalog`
- `analyzing-api-gateway-access-logs`

### `blue-team-dfir`

Trigger terms: DFIR, incident response, memory forensics, Volatility, SIEM, Sigma, YARA, IOC, malware traffic.

Load first:

- `global-control`
- `pentest-unified-engine`
- `native-mcp`

Use this when the task needs defensive validation, incident evidence review, malware/forensics, or log-based detection. It fills a gap in our SRC-heavy skill system.

### `cloud-identity`

Trigger terms: AWS, Azure, GCP, Kubernetes, Docker, Entra, IAM, Active Directory, Kerberos, OAuth/SAML, zero trust.

Load first:

- `global-control`
- `native-mcp`
- `pentest-unified-engine`

Use for cloud permission reviews, identity abuse hypotheses, bucket/storage exposure, cloud logs, and cloud-specific attack surface mapping.

### `ai-security`

Trigger terms: LLM, prompt injection, jailbreak, RAG, AI security, model poisoning, guardrails, MITRE ATLAS, AI RMF.

Load first:

- `global-control`
- `hermes-agent`
- `hermes-agent-self-evolution`

Use for Hermes/plugin/prompt-injection hardening, LLM application testing, RAG safety, and agent tool-permission threat modeling.

### `risk-compliance`

Trigger terms: NIST, MITRE, ATT&CK, D3FEND, CSF, risk, compliance, governance, KEV, EPSS, CVE prioritization.

Load first:

- `global-control`
- `vuln-intel`
- `hermes-agent-self-evolution`

Use when prioritizing vulnerability candidates, mapping findings to ATT&CK/NIST, or writing remediation strategy.

## Integration Rules

1. External skills are source material, not final truth.
2. Never bypass Hermes verification gates with external procedure claims.
3. Pull small slices: retrieve 5-12 external skills for the current task, not the full repo.
4. Preserve licensing attribution when copying substantial text; prefer distilled procedure notes in our own words.
5. For SRC reports, external mappings may support impact/remediation, but reportability still requires real evidence, A/B controls, and reproducible PoC.
6. For defensive/DFIR tasks, external skills can become primary methodology, but file/log facts must still be verified with tools.
7. When a retrieved external pattern repeatedly proves useful, distill it into an existing Hermes umbrella skill reference rather than creating hundreds of one-off skills.

## Why Not Direct Bulk Import

Bulk importing 754 skills would degrade Hermes by:

- Inflating skill list and context selection noise.
- Duplicating existing SRC/渗透 skills.
- Mixing defensive playbooks into offensive workflows without evidence gates.
- Making skill curation and update checks expensive.

The correct architecture is corpus indexing + task router + distilled references.

## Verification Commands

```bash
/usr/bin/python3 /root/.hermes/scripts/anthropic-cyber-skills-router.py --query 'SRC API IDOR BOLA OAuth JWT CORS CVE KEV exploit prioritization' --limit 10
/usr/bin/python3 /root/.hermes/scripts/anthropic-cyber-skills-router.py --query 'DFIR incident response memory forensics volatility SIEM Sigma YARA IOC' --limit 10
/usr/bin/python3 /root/.hermes/scripts/anthropic-cyber-skills-router.py --query 'LLM prompt injection guardrail RAG AI security jailbreak detection' --limit 10
```
