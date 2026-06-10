"""Unit tests for the skill maintenance tooling in ``scripts/``.

These exercise the pure helpers (frontmatter parsing, index entry building,
and the per-skill validator) against throwaway temp directories, so they run
without touching the real ``skills/`` tree.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


def _load(module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name, SCRIPTS_DIR / f"{module_name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_index = _load("build_index")
validate_skills = _load("validate_skills")


def make_skill(root: Path, name: str, frontmatter: str, body: str = "# Title\n") -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\n{frontmatter}\n---\n{body}", encoding="utf-8"
    )
    return skill_dir


# --- parse_frontmatter -----------------------------------------------------

def test_parse_frontmatter_valid(tmp_path):
    sd = make_skill(tmp_path, "demo", "name: demo\ndescription: hello world here")
    fm = build_index.parse_frontmatter(sd / "SKILL.md")
    assert fm["name"] == "demo"
    assert fm["description"] == "hello world here"


def test_parse_frontmatter_missing_closing_fence(tmp_path):
    sd = tmp_path / "bad"
    sd.mkdir()
    (sd / "SKILL.md").write_text("---\nname: bad\n", encoding="utf-8")
    with pytest.raises(ValueError):
        build_index.parse_frontmatter(sd / "SKILL.md")


# --- normalize_str ---------------------------------------------------------

def test_normalize_str_folds_whitespace():
    assert build_index.normalize_str("a\n  b\n   c") == "a b c"


def test_normalize_str_handles_none():
    assert build_index.normalize_str(None) == ""


# --- build_entry -----------------------------------------------------------

def test_build_entry_passthrough_and_normalization(tmp_path):
    sd = make_skill(
        tmp_path,
        "recon-tool",
        "name: recon-tool\n"
        "description: >-\n  multi\n  line\n  description\n"
        "category: penetration-testing\n"
        "tags:\n- recon\n- enum\n",
    )
    entry = build_index.build_entry(sd)
    assert entry["path"] == "skills/recon-tool"
    assert entry["name"] == "recon-tool"
    assert entry["description"] == "multi line description"
    assert entry["category"] == "penetration-testing"
    assert entry["tags"] == ["recon", "enum"]
    # Absent optional fields must not appear.
    assert "mitre_attack" not in entry


# --- check_skill (validator) ----------------------------------------------

def test_check_skill_valid_has_no_errors(tmp_path):
    sd = make_skill(
        tmp_path,
        "good-skill",
        "name: good-skill\n"
        "description: a sufficiently long and clear description\n"
        "tags:\n- web\n",
    )
    errors, warnings = validate_skills.check_skill(sd)
    assert errors == []
    assert warnings == []


def test_check_skill_name_mismatch(tmp_path):
    sd = make_skill(
        tmp_path, "dir-name", "name: other-name\ndescription: long enough description text"
    )
    errors, _ = validate_skills.check_skill(sd)
    assert any("does not match directory" in e for e in errors)


def test_check_skill_short_description(tmp_path):
    sd = make_skill(tmp_path, "shorty", "name: shorty\ndescription: tiny")
    errors, _ = validate_skills.check_skill(sd)
    assert any("description too short" in e for e in errors)


def test_check_skill_broken_description(tmp_path):
    sd = tmp_path / "broken"
    sd.mkdir()
    (sd / "SKILL.md").write_text(
        '---\nname: broken\ndescription: ">-"\n---\n# x\n', encoding="utf-8"
    )
    errors, _ = validate_skills.check_skill(sd)
    assert any("description" in e for e in errors)


def test_check_skill_private_ip_in_frontmatter(tmp_path):
    sd = make_skill(
        tmp_path,
        "leaky",
        "name: leaky\ndescription: description mentioning 192.168.1.50 host inline",
    )
    errors, _ = validate_skills.check_skill(sd)
    assert any("private IP" in e for e in errors)


def test_check_skill_license_divergence_is_warning(tmp_path):
    sd = make_skill(
        tmp_path,
        "mit-skill",
        "name: mit-skill\ndescription: long enough description here\n"
        "license: MIT\ntags:\n- x\n",
    )
    errors, warnings = validate_skills.check_skill(sd)
    assert errors == []
    assert any("license" in w for w in warnings)


def test_check_skill_missing_tags_is_warning(tmp_path):
    sd = make_skill(
        tmp_path, "no-tags", "name: no-tags\ndescription: long enough description here"
    )
    errors, warnings = validate_skills.check_skill(sd)
    assert errors == []
    assert any("category" in w or "tags" in w for w in warnings)


def test_check_skill_non_kebab_name(tmp_path):
    sd = make_skill(
        tmp_path, "Bad_Name", "name: Bad_Name\ndescription: long enough description here"
    )
    errors, _ = validate_skills.check_skill(sd)
    assert any("kebab-case" in e for e in errors)
