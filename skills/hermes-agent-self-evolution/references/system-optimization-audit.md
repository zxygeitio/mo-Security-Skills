# Hermes System Optimization Audit Pattern

Use this reference when the user asks to inspect or optimize the whole Hermes Agent system: skills, framework, MCP, cron, repo health, and local operational state.

## Proven workflow

1. Load the Hermes/system skills that govern the task before acting: `hermes-agent`, `native-mcp`, `hermes-agent-self-evolution`, and skill-authoring guidance if editing skills.
2. Capture a baseline:
   - `hermes --version`
   - `hermes status --all`
   - `hermes doctor`
   - `hermes tools list`
   - `hermes mcp list`
   - `hermes cron list`
   - `git status --short` and current HEAD in `/root/.hermes/hermes-agent`
3. Audit skills by comparing `~/.hermes/skills/**/SKILL.md` against `/root/.hermes/hermes-agent/skills/**/SKILL.md`:
   - Count total SKILL.md files, unique `name:` values, duplicate names, malformed frontmatter, and over-large skills.
   - If a local skill is byte-identical to a builtin skill, back it up and remove the local duplicate.
   - Keep local duplicates that intentionally diverge, especially locally enhanced `native-mcp` or `hermes-agent`.
4. Verify after skill cleanup with the Hermes venv, not the system Python:
   - `/root/.hermes/hermes-agent/venv/bin/python -m pytest tests/tools/test_skill_manager_tool.py tests/tools/test_skills_tool.py -q -o addopts=`
5. For repo validation, prefer the Hermes venv:
   - `/root/.hermes/hermes-agent/venv/bin/python -m pytest ...`
   - System Python can miss optional repo dependencies such as `mcp` and produce false import failures.
6. Before `git pull --ff-only`, make the repo clean. If a lockfile was modified only by local package-manager normalization, back it up under `~/.hermes/backups/` and revert it before updating.
7. MCP health checks:
   - `hermes mcp test <server>` proves the MCP bridge connects and discovers tools.
   - A tool-specific health probe may still fail if the backing service is not running (for example Burp proxy on 127.0.0.1:8080). Treat that as service state, not an MCP config failure.
8. Cron hygiene:
   - If gateway/scheduler is stopped and jobs have historical `next_run_at`, pause stale jobs before starting gateway to avoid surprise catch-up runs.
   - Resume only after confirming the task is still wanted.

## Skill dedupe script shape

Use this pattern for byte-identical local-vs-builtin duplicates:

```python
import hashlib, pathlib, re, shutil, tarfile, time
home = pathlib.Path('/root/.hermes')
local = home / 'skills'
builtin = home / 'hermes-agent' / 'skills'
backup = home / 'backups' / f'identical-local-skill-dedupe-{time.strftime("%Y%m%d-%H%M%S")}.tar.gz'
backup.parent.mkdir(parents=True, exist_ok=True)

def skill_name(path):
    text = path.read_text(errors='replace')
    m = re.search(r'^name:\s*["\']?([^"\'\n]+)', text, re.M)
    return m.group(1).strip() if m else None, text

built = {}
for bp in builtin.rglob('SKILL.md'):
    name, text = skill_name(bp)
    if name:
        built[name] = hashlib.sha256(text.encode()).hexdigest()

remove_dirs = []
for lp in local.rglob('SKILL.md'):
    if '.archive' in lp.parts:
        continue
    name, text = skill_name(lp)
    if name in built and hashlib.sha256(text.encode()).hexdigest() == built[name]:
        remove_dirs.append(lp.parent)

with tarfile.open(backup, 'w:gz') as tar:
    for d in remove_dirs:
        tar.add(d, arcname=str(d.relative_to(home)))
for d in remove_dirs:
    shutil.rmtree(d)
print('removed', len(remove_dirs), 'backup', backup)
```

## Pitfalls

- Do not delete local duplicates that diverge from builtin content; they may contain user-specific operational knowledge.
- Do not run repository tests with bare `python -m pytest` unless you have confirmed it is the Hermes venv Python.
- Do not start a stopped gateway until stale cron jobs have been reviewed or paused.
- Do not record transient setup failures as durable negative claims; capture the fix or health-check sequence instead.
