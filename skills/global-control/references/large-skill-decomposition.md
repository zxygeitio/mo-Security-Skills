# Large Skill Decomposition and Reference Routing

## Problem signal

A frequently loaded skill above roughly 80KB makes the agent slower and noisier because historical cases, payloads, and platform-specific details enter the default context even when irrelevant.

## Refactor pattern

1. Preserve the full original as `references/legacy-full-skill-YYYY-MM-DD.md` before shrinking.
2. Replace the main `SKILL.md` with a class-level lightweight entry:
   - trigger conditions
   - durable principles
   - minimal decision tree
   - false-positive gates
   - explicit pointers to the most useful references
3. Keep session-specific examples, payload banks, platform-specific SRC notes, historical case studies, and long command collections under `references/`.
4. After editing, verify with `skill_view` and the global control audit. The expected audit improvement is `oversized skills >80KB — none`.

## Applied case

The web/SRC pentest skills were split this way:

- `web-pentest-fast/SKILL.md` became a small fast-entry decision tree; the prior full text is in `web-pentest-fast/references/legacy-full-skill-2026-05-23.md`.
- `pentest-recon-driven/SKILL.md` became a small recon-entry workflow; the prior full text is in `pentest-recon-driven/references/legacy-full-skill-2026-05-23.md`.

## General rule

Do not create many narrow one-session skills. Prefer updating the class-level umbrella skill and adding support files under `references/`, `templates/`, or `scripts/`.
