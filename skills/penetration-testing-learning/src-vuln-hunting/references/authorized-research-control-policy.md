# Broad authorization handling for SRC research

When the user says all research/optimization actions are allowed, treat it as authorization to optimize the local research workflow and conduct low-impact testing within stated SRC/owned/lab scope — not as permission for destructive or out-of-scope activity.

## Operational interpretation

Allowed by default in an authorized SRC context:

- Optimize local Hermes tooling, workspaces, scripts, skills, evidence storage, Burp/HexStrike/Gateway readiness.
- Run passive recon and conservative active probes on in-scope assets.
- Use user-provided or self-created test accounts, cookies, tokens, and captured traffic.
- Perform A/B account authorization checks when both accounts are owned/authorized.
- Upload harmless proof files when the program allows upload testing; clean up if possible.
- Generate only verified, reproducible reports.

Not allowed by a blanket statement alone:

- Destructive changes, persistence, malware/webshells, credential theft, lateral movement, or testing excluded assets.
- High-volume brute force, password spraying, SMS/email bombing, DoS, or mass scraping.
- Financially impactful operations or modification/deletion of real user data.
- Large data exfiltration; collect only minimal redacted proof.

## Default low-impact limits

Unless the program explicitly permits more:

- IDOR/object enumeration: at most 20 object IDs per endpoint; stop once the boundary failure is proven.
- Sensitive data: save the minimum proof, redact identifiers in reports.
- File upload: harmless HTML/text/image only; no webshell or executable payload.
- SMS/email: at most 2 proof sends per flow/recipient; no loops.
- Auth testing: no credential stuffing; only provided/self-owned credentials.
- Business APIs: prefer single controls and A/B comparisons over noisy scanners.

## High-value priority under this authorization

Use the extra latitude to shift from anonymous scanning to permission-bound business logic testing:

1. RCE/SQLi with safe proof only.
2. Authentication bypass, unsigned/forgable session, token misuse.
3. A/B account IDOR and vertical/horizontal privilege bypass.
4. Unauthenticated sensitive business data APIs.
5. Mass assignment of `user_id`, `ownerId`, `role`, `status`, `quota`, `price`, `amount`, `tenantId`, `orgId`.
6. File upload that creates accessible/renderable impact within rules.
7. API Key/AppSecret exposure only after proving real API/data/usage access.

## Required controller behavior

- Do not ask the user to manually run local setup when Hermes can safely optimize it.
- If key context is missing, proceed with anonymous recon but label account-state tests as pending instead of inventing proof.
- Keep a per-target profile with scope, exclusions, account matrix, allowed limits, prior submissions, and negative evidence.
- Keep final report standards strict: verified single-line curl, saved response evidence, control request, dedupe, screenshot markers.
