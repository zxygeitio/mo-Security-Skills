# Skill/library integrity self-test pattern

Use this reference during Hermes global-control or SRC-framework maintenance when skills or support files are changed.

## What to verify

1. Loaded/modified skills can be `skill_view` loaded.
2. `SKILL.md` references to `references/...` and `scripts/...` exist inside that skill directory.
3. Cross-skill references are either duplicated intentionally or represented by a short forwarding file in the current skill's `references/` directory.
4. Shell helper scripts referenced as executable have `+x` and pass `bash -n`.
5. Python helper scripts pass `py_compile`.
6. Framework smoke tests exercise the actual chain, not just `--help`.

## Reference-check script (cross-skill aware)

**重要:** SKILL.md中引用其他skill文件时格式为"见 `other-skill` skill 的 `references/xxx.md`"，这会产生反引号内含 `references/xxx.md` 的模式。检查脚本必须区分**本地引用**和**跨skill转发引用**，否则误报率高。

```python
import os, re, json
skills = {
    'global-control': '/root/.hermes/skills/ai-development/global-control',
    'src-vuln-hunting': '/root/.hermes/skills/penetration-testing-learning/src-vuln-hunting',
    'education-src-blueprint': '/root/.hermes/skills/penetration-testing-learning/education-src-blueprint',
}
summary = {}
for name, d in skills.items():
    text = open(os.path.join(d, 'SKILL.md'), encoding='utf-8', errors='ignore').read()
    # 所有反引号引用
    all_refs = sorted(set(
        re.findall(r'`(references/[^`]+)`', text) +
        re.findall(r'`(scripts/[^`]+)`', text)
    ))
    # 跨skill引用: 匹配 "见 `skill-name` skill 的 `references/xxx.md`" 模式
    cross_skill_pattern = re.compile(r'见\s*`[^`]+`\s*skill\s*的\s*`(references/[^`]+)`')
    cross_skill_refs = set(cross_skill_pattern.findall(text))
    # glob模式（含*）不检查存在性
    glob_refs = {r for r in all_refs if '*' in r}
    # 本地引用 = 所有引用 - 跨skill引用 - glob模式
    local_refs = [r for r in all_refs if r not in cross_skill_refs and r not in glob_refs]
    missing = [r for r in local_refs if not os.path.exists(os.path.join(d, r.strip()))]
    summary[name] = {
        'total_refs': len(all_refs),
        'cross_skill': len(cross_skill_refs),
        'glob_patterns': len(glob_refs),
        'local_refs': len(local_refs),
        'missing': missing
    }
print(json.dumps(summary, ensure_ascii=False, indent=2))
```

## Forwarding reference pattern

当一个skill的SKILL.md引用另一个skill的`references/xxx.md`时，有三种处理方式：

1. **保持跨skill引用格式**（推荐）: SKILL.md中写"见 `other-skill` skill 的 `references/xxx.md`"，不做本地文件。检查脚本已能识别此格式。
2. **创建forwarding stub**: 在当前skill的`references/`下创建简短文件，内容标注"Forwarding: 完整内容见 `other-skill` skill 的 `references/xxx.md`"并附核心摘要。适用于被频繁访问或需要离线可用的场景。
3. **复制内容**: 将完整内容复制到当前skill。适用于内容会随skill独立演进的场景。

## Common fixes

- Missing reference that exists in a related umbrella skill: copy concise reference content or add a forwarding reference (see pattern above) in the current skill.
- False positive on cross-skill refs: check if the reference line contains "见 `xxx` skill 的" pattern; if so, it's a valid cross-skill reference, not a missing local file.
- Missing executable bit on a skill script: `chmod +x skill_dir/scripts/name.sh` and verify with `bash -n`.
- `src-http-probe.py` fails on a new workspace path: ensure it creates `workspace.mkdir(parents=True, exist_ok=True)` before writing `probe_results.tsv`.

## Final smoke-test chain

```bash
export LC_ALL=C LANG=C
BASE=/tmp/src-framework-retest-$(date +%s)
INIT_JSON=$(/usr/bin/python3 /root/.hermes/scripts/src-workspace-init.py example.edu.cn --root "$BASE" --scope 'framework retest' --force)
WS=$(/usr/bin/python3 - <<'PY' "$INIT_JSON"
import json,sys
print(json.loads(sys.argv[1])['workspace'])
PY
)
printf '%s\n' 'https://example.com/' 'https://example.com/not-exist-hermes-src-test' > "$WS/urls.txt"
/usr/bin/python3 /root/.hermes/scripts/src-http-probe.py "$WS" "$WS/urls.txt" --timeout 8
/usr/bin/python3 /root/.hermes/scripts/src-quality-gate.py "$WS/probe_results.tsv" --out "$WS/final_gate.md"
/usr/bin/python3 /root/.hermes/scripts/src-js-api-extract.py "$WS" --out "$WS/js_api_findings.json"
head -50 "$WS/final_gate.md"
```

Expected for example.com: `DO_NOT_SUBMIT`, generated headers/bodies, and successful JS/API extraction output.

## ExploitDB integration verification

```bash
# 验证引擎可用
/usr/bin/python3 /root/.hermes/scripts/exploitdb_engine.py stats

# 验证pipeline可用
/usr/bin/python3 /root/.hermes/scripts/edb-pipeline.py --help

# 使用nmap结果运行pipeline
/usr/bin/python3 /root/.hermes/scripts/edb-pipeline.py --nmap /tmp/scan.xml --target HOST --script /tmp/attack.sh
```

当前引擎数据: 47048 exploits, 1065 shellcodes, 33978 verified, 27351 with CVE.
