# tests/unit/test_devin_wiki_validator.py
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The validator is a stdlib script under scripts/; put it on the path so we can
# import its check functions directly (mirrors how docs_check.py is structured).
_SCRIPTS = Path(__file__).parents[2] / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import validate_devin_wiki as vw  # noqa: E402

_FIX = Path(__file__).parent / "fixtures" / "devin_wiki"


def _load(name: str) -> dict[str, object]:
    return vw.load_wiki(_FIX / name)


def test_valid_minimal_has_no_structure_errors() -> None:
    assert vw.check_structure_and_limits(_load("valid_minimal.json")) == []


def test_empty_title_is_flagged() -> None:
    errs = vw.check_structure_and_limits(_load("bad_empty_title.json"))
    assert any("title" in e.lower() and "empty" in e.lower() for e in errs)


def test_more_than_30_pages_is_flagged() -> None:
    errs = vw.check_structure_and_limits(_load("bad_too_many_pages.json"))
    assert any("30" in e for e in errs)


def test_load_wiki_raises_on_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(vw.WikiError):
        vw.load_wiki(bad)


def test_dangling_parent_is_flagged() -> None:
    errs = vw.check_references(_load("bad_dangling_parent.json"))
    assert any("parent" in e.lower() and "Nonexistent" in e for e in errs)


def test_self_parent_is_flagged() -> None:
    errs = vw.check_references(_load("bad_self_parent.json"))
    assert any("cycle" in e.lower() or "ancestor" in e.lower() for e in errs)


def test_parent_cycle_is_flagged() -> None:
    errs = vw.check_references(_load("bad_parent_cycle.json"))
    assert any("cycle" in e.lower() for e in errs)


def test_valid_minimal_has_no_reference_errors() -> None:
    assert vw.check_references(_load("valid_minimal.json")) == []
