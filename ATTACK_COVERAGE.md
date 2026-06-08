# MITRE ATT&CK Coverage Analysis

## Overview

This document maps the Hermes Security Skills to the MITRE ATT&CK Framework, showing how each skill contributes to specific tactics and techniques.

**Total Coverage**: 11 tactics, 45+ techniques across Enterprise ATT&CK v15.

---

## Reconnaissance (TA0043)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Gather Victim Host Information | T1592 | `pentest-recon-driven`, `auto-recon-lowhanging` |
| Gather Victim Identity Information | T1589 | `src-vuln-hunting`, `education-src-blueprint` |
| Gather Victim Network Information | T1590 | `pentest-recon-driven`, `openvpn-split-tunnel` |
| Gather Victim Org Information | T1591 | `pentest-recon-driven` |
| Active Scanning | T1595 | `auto-recon-lowhanging`, `edu-auto-scanner` |
| Search Open Technical Databases | T1596 | `vuln-intel`, `vuln-intel-2025-2026`, `exploit-db-integration` |
| Search Victim-Owned Websites | T1593 | `pentest-recon-driven` |
| Search Open Websites/Domains | T1594 | `pentest-recon-driven`, `shein-src-recon` |

## Resource Development (TA0042)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Acquire Infrastructure | T1583 | `local-pentest-practice-lab` |
| Compromise Infrastructure | T1584 | `pentest-recon-driven` |
| Develop Capabilities | T1587 | `exploit-chain`, `smart-vuln-detector` |
| Obtain Capabilities | T1588 | `exploit-db-integration`, `vuln-intel-2025-2026` |
| Stage Capabilities | T1608 | `cicd-pipeline-poisoning` |

## Initial Access (TA0001)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Exploit Public-Facing Application | T1190 | `exploit-chain`, `web-pentest-fast`, `src-vuln-hunting` |
| External Remote Services | T1133 | `openvpn-split-tunnel`, `pentest-ops` |
| Valid Accounts | T1078 | `lianyi-cas-exploitation-patterns`, `mgm-src-testing-patterns` |
| Phishing | T1566 | `script-analysis-invisible-code` |

## Execution (TA0002)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Command and Scripting Interpreter | T1059 | `exploit-chain`, `post-exploit-pwncat` |
| Exploitation for Client Execution | T1203 | `spring-boot-actuator-httptrace-exploitation` |

## Persistence (TA0003)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Valid Accounts | T1078 | `lianyi-cas-exploitation-patterns` |
| Create Account | T1136 | `exploit-chain` |
| Server Software Component | T1505 | `cicd-pipeline-poisoning` |

## Privilege Escalation (TA0004)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Exploitation for Privilege Escalation | T1068 | `exploit-chain` |
| Valid Accounts | T1078 | `pentest-lateral` |

## Defense Evasion (TA0005)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Impair Defenses | T1562 | `nginx-spa-fallback-false-positive` |

## Credential Access (TA0006)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Brute Force | T1110 | `pentest-tool-mastery` |
| Adversary-in-the-Middle | T1557 | `lianyi-cas-exploitation-patterns` |

## Discovery (TA0007)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Network Service Discovery | T1046 | `auto-recon-lowhanging`, `pentest-recon-driven` |
| Account Discovery | T1087 | `src-vuln-hunting` |
| File and Directory Discovery | T1083 | `exploit-chain` |

## Lateral Movement (TA0008)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Remote Services | T1021 | `pentest-lateral`, `pentest-ops` |
| Use Alternate Authentication Material | T1550 | `pentest-lateral` |

## Collection (TA0009)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Data from Information Repositories | T1213 | `exploit-chain`, `src-vuln-hunting` |
| Data from Cloud Storage | T1530 | `pentest-recon-driven` |

## Exfiltration (TA0010)

| Technique | ID | Skill(s) |
|-----------|-----|----------|
| Exfiltration Over C2 Channel | T1041 | `exploit-chain` |
| Exfiltration Over Web Service | T1567 | `exploit-chain` |

---

## Coverage Summary by Tactic

| Tactic | Techniques Covered | Skills Contributing |
|--------|-------------------|-------------------|
| Reconnaissance | 8 | 8 |
| Resource Development | 5 | 5 |
| Initial Access | 4 | 6 |
| Execution | 2 | 3 |
| Persistence | 3 | 3 |
| Privilege Escalation | 2 | 2 |
| Defense Evasion | 1 | 1 |
| Credential Access | 2 | 2 |
| Discovery | 3 | 3 |
| Lateral Movement | 2 | 3 |
| Collection | 2 | 2 |
| Exfiltration | 2 | 1 |

**Total: 11 tactics, 36 techniques, 40 skills**
