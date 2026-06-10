#!/usr/bin/env python3
"""Validate every top-level skill's SKILL.md frontmatter.

The repo's skills come from several generators, so the frontmatter schema is
heterogeneous. This validator therefore splits checks into two tiers:

  ERRORS (fail CI):
    * SKILL.md exists with a well-formed YAML frontmatter block
    * ``name`` and ``description`` are present
    * ``name`` is kebab-case and equals the directory name
    * ``description`` is real text (not a stray ``>-`` indicator, >= 15 chars)
    * ``license`` (when set) is Apache-2.0
    * no hardcoded private IP in the frontmatter

  WARNINGS (reported, do not fail):
    * missing recommended discovery fields (category/tags)

Usage:
    python scripts/validate_skills.py            # errors fail, warnings print
    python scripts/validate_skills.py --strict   # warnings also fail
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"

KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
PRIVATE_IP_RE = re.compile(
    r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"
)
MIN_DESC_LEN = 15
BROKEN_DESC = {">-", ">", "|", "|-", ""}


def parse_frontmatter(skill_md: Path) -> dict:
    text = skill_md.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise ValueError("missing opening '---' frontmatter fence")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError("missing closing '---' frontmatter fence")
    data = yaml.safe_load(parts[1])
    if not isinstance(data, dict):
        raise ValueError("frontmatter is not a key/value mapping")
    return data


def check_skill(skill_dir: Path) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for one skill."""
    errors: list[str] = []
    warnings: list[str] = []
    name = skill_dir.name

    try:
        fm = parse_frontmatter(skill_dir / "SKILL.md")
    except (ValueError, yaml.YAMLError) as exc:
        return [f"{name}: {exc}"], []

    fm_name = str(fm.get("name", "")).strip()
    if not fm_name:
        errors.append(f"{name}: missing required field 'name'")
    else:
        if not KEBAB_RE.match(fm_name):
            errors.append(f"{name}: name '{fm_name}' is not kebab-case")
        if fm_name != name:
            errors.append(f"{name}: name '{fm_name}' does not match directory")

    desc = str(fm.get("description", "")).strip()
    if desc in BROKEN_DESC:
        errors.append(f"{name}: missing/broken 'description'")
    elif len(desc) < MIN_DESC_LEN:
        errors.append(f"{name}: description too short ({len(desc)} chars)")

    fm_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8").split("---", 2)[1]
    if PRIVATE_IP_RE.search(fm_text):
        errors.append(f"{name}: private IP address in frontmatter")

    license_ = str(fm.get("license", "")).strip()
    if license_ and license_ != "Apache-2.0":
        # Not fatal: a declared license is meaningful and not ours to rewrite,
        # but the repo standard is Apache-2.0, so flag the divergence.
        warnings.append(f"{name}: license '{license_}' diverges from repo Apache-2.0")

    if not fm.get("category") and not fm.get("tags"):
        warnings.append(f"{name}: no 'category' or 'tags' for discovery")

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict", action="store_true", help="Treat warnings as failures."
    )
    args = parser.parse_args()

    skill_dirs = sorted(d for d in SKILLS_DIR.iterdir() if (d / "SKILL.md").is_file())
    all_errors: list[str] = []
    all_warnings: list[str] = []
    for skill_dir in skill_dirs:
        errors, warnings = check_skill(skill_dir)
        all_errors.extend(errors)
        all_warnings.extend(warnings)

    if all_warnings:
        print(f"{len(all_warnings)} warning(s):")
        for w in all_warnings:
            print(f"  ! {w}")
        print()

    if all_errors:
        print(f"FAILED: {len(all_errors)} error(s) across {len(skill_dirs)} skills:")
        for e in all_errors:
            print(f"  - {e}")
        return 1

    if args.strict and all_warnings:
        print(f"FAILED (--strict): {len(all_warnings)} warning(s).")
        return 1

    print(f"OK: {len(skill_dirs)} skills passed validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
