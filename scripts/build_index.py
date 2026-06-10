#!/usr/bin/env python3
"""Regenerate index.json from every top-level skill's SKILL.md frontmatter.

`index.json` is the machine-readable catalog agents scan (~30 tokens/skill)
to pick a skill to load, so it MUST stay in sync with the frontmatter in each
``skills/<name>/SKILL.md``. Run after adding, removing, or editing a skill:

    python scripts/build_index.py            # rewrite index.json
    python scripts/build_index.py --check    # CI mode: fail if stale

Only *direct* children of ``skills/`` that contain a SKILL.md are catalogued.
Helper folders (e.g. ``skills/references``) and skills bundled inside another
skill (e.g. ``skills/penetration-testing-learning/<sub>``) are intentionally
not given separate entries — the bundle itself is the catalogued skill.

The frontmatter schema across this repo is heterogeneous, so every known field
is copied through only when present rather than being required.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
INDEX_PATH = REPO_ROOT / "index.json"

# Optional fields copied verbatim into each entry when present, in this order.
PASSTHROUGH_FIELDS = (
    "category",
    "domain",
    "subdomain",
    "tags",
    "platforms",
    "triggers",
    "related_skills",
    "version",
    "author",
    "created_by",
    "license",
    "mitre_attack",
    "nist_csf",
)


def parse_frontmatter(skill_md: Path) -> dict:
    """Return the YAML frontmatter of a SKILL.md as a dict."""
    text = skill_md.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise ValueError(f"{skill_md}: missing opening '---' frontmatter fence")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{skill_md}: missing closing '---' frontmatter fence")
    data = yaml.safe_load(parts[1])
    if not isinstance(data, dict):
        raise ValueError(f"{skill_md}: frontmatter is not a key/value mapping")
    return data


def normalize_str(value) -> str:
    """Collapse a folded/multi-line scalar into a single clean line."""
    if value is None:
        return ""
    return " ".join(str(value).split())


def build_entry(skill_dir: Path) -> dict:
    fm = parse_frontmatter(skill_dir / "SKILL.md")
    entry = {
        "path": f"skills/{skill_dir.name}",
        "name": fm.get("name", skill_dir.name),
        "description": normalize_str(fm.get("description")),
    }
    for field in PASSTHROUGH_FIELDS:
        if field in fm and fm[field] not in (None, ""):
            entry[field] = fm[field]
    return entry


def discover_skill_dirs() -> list[Path]:
    return sorted(d for d in SKILLS_DIR.iterdir() if (d / "SKILL.md").is_file())


def build_index() -> dict:
    skills = [build_entry(d) for d in discover_skill_dirs()]
    return {
        "version": "2.0.0",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": "https://github.com/zxygeitio/mo-Security-Skills",
        "standard": "agentskills.io",
        "domain": "cybersecurity",
        "total_skills": len(skills),
        "skills": skills,
    }


def serialize(index: dict) -> str:
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"


def _strip_generated(text: str) -> str:
    """Drop the timestamp line, which legitimately changes every run."""
    return "\n".join(l for l in text.splitlines() if '"generated"' not in l)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify index.json is up to date without writing (CI mode).",
    )
    args = parser.parse_args()

    new_text = serialize(build_index())

    if args.check:
        current = INDEX_PATH.read_text(encoding="utf-8") if INDEX_PATH.exists() else ""
        if _strip_generated(current) != _strip_generated(new_text):
            print(
                "index.json is out of date. Run: python scripts/build_index.py",
                file=sys.stderr,
            )
            return 1
        count = json.loads(new_text)["total_skills"]
        print(f"index.json is up to date ({count} skills).")
        return 0

    INDEX_PATH.write_text(new_text, encoding="utf-8")
    print(f"Wrote {INDEX_PATH.name} with {json.loads(new_text)['total_skills']} skills.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
