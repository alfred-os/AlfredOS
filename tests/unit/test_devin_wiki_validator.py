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


def test_more_than_max_notes_is_flagged() -> None:
    errs = vw.check_structure_and_limits(_load("bad_max_notes.json"))
    assert any("too many notes" in e for e in errs)


def test_note_over_max_chars_is_flagged() -> None:
    errs = vw.check_structure_and_limits(_load("bad_note_too_long.json"))
    assert any("code points" in e for e in errs)


def test_duplicate_page_title_is_flagged() -> None:
    errs = vw.check_structure_and_limits(_load("bad_duplicate_title.json"))
    assert any("duplicate page title" in e.lower() for e in errs)


def test_empty_purpose_is_flagged() -> None:
    errs = vw.check_structure_and_limits(_load("bad_empty_purpose.json"))
    assert any("purpose" in e.lower() and "empty" in e.lower() for e in errs)


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


_REPO_ROOT = Path(__file__).parents[2]


def test_extract_anchors_finds_each_kind() -> None:
    # Backtick-wrapped PRD anchor is the REAL authoring format used throughout
    # .devin/wiki.json — a non-backtick "PRD.md §N" would mask a regex hole.
    note = "Ground in `docs/subsystems/security.md`, ADR-0017, `PRD.md` §7.1, glossary.md#tier."
    kinds = {a.kind for a in vw.extract_anchors(note)}
    assert kinds == {"path", "adr", "prd", "glossary"}


def test_extract_anchors_prd_backtick_form_resolves_values() -> None:
    # `.devin/wiki.json` always writes PRD anchors as `` `PRD.md` §N `` — the
    # closing backtick sits between ".md" and the section marker.
    note = "Ground in `PRD.md` §7.1 and `PRD.md` §6.2 for the details."
    values = {a.value for a in vw.extract_anchors(note) if a.kind == "prd"}
    assert values == {"7.1", "6.2"}


def test_extract_anchors_prd_bare_form_still_resolves() -> None:
    note = "Ground in PRD §5 for the overview."
    values = {a.value for a in vw.extract_anchors(note) if a.kind == "prd"}
    assert values == {"5"}


def test_extract_anchors_splits_slash_compound_adr() -> None:
    # `.devin/wiki.json` writes multi-ADR references as a single
    # slash-compound token, e.g. "ADR-0040/0042/0043" — every ADR number in
    # the compound must be extracted, not just the first.
    note = "Ground in ADR-0040/0042/0043 and docs/ARCHITECTURE.md."
    values = {a.value for a in vw.extract_anchors(note) if a.kind == "adr"}
    assert values == {"0040", "0042", "0043"}


def test_real_tracked_anchors_resolve() -> None:
    data = {
        "repo_notes": [],
        "pages": [
            {
                "title": "Sec",
                "purpose": "p",
                "page_notes": [
                    "-> `docs/subsystems/security.md`, ADR-0017, glossary.md#trust-tier"
                ],
            },
        ],
    }
    assert vw.check_anchors(data, _REPO_ROOT) == []


def test_gitignored_anchor_is_flagged() -> None:
    # Root CLAUDE.md is a gitignored rulesync output — Devin cannot see it.
    errs = vw.check_anchors(_load("bad_gitignored_anchor.json"), _REPO_ROOT)
    assert any("CLAUDE.md" in e and ("not tracked" in e or "gitignored" in e) for e in errs)


def test_bad_adr_and_slug_are_flagged() -> None:
    data = {
        "repo_notes": [],
        "pages": [
            {
                "title": "X",
                "purpose": "p",
                "page_notes": ["ADR-9999 and glossary.md#no-such-heading"],
            },
        ],
    }
    errs = vw.check_anchors(data, _REPO_ROOT)
    assert any("ADR-9999" in e for e in errs)
    assert any("no-such-heading" in e for e in errs)


def test_bad_prd_section_backtick_form_is_flagged() -> None:
    # Real authoring format (`` `PRD.md` §N ``) referencing a section that
    # doesn't exist in PRD.md — proves the PRD-anchor guard actually fires
    # now that _PRD_RE tolerates the closing backtick.
    errs = vw.check_anchors(_load("bad_prd_section.json"), _REPO_ROOT)
    assert any("99.9" in e for e in errs)


def test_compound_adr_reference_partially_broken_is_flagged() -> None:
    # "ADR-0040/9999": 0040 is real, 9999 is not — only the broken one should
    # be flagged, proving every ADR in the slash-compound is resolved
    # individually rather than just the first.
    errs = vw.check_anchors(_load("bad_adr_compound.json"), _REPO_ROOT)
    assert any("9999" in e for e in errs)
    assert not any("ADR-0040 has no file" in e for e in errs)


def test_token_shaped_string_is_flagged() -> None:
    data = {"repo_notes": [{"content": "example key sk-" + "a" * 40}], "pages": []}
    assert any("token-shaped" in e for e in vw.check_secret_shapes(data))


def test_clean_notes_have_no_secret_findings() -> None:
    assert vw.check_secret_shapes(_load("valid_minimal.json")) == []


def test_validate_file_aggregates_and_main_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert vw.main([str(_FIX / "valid_minimal.json"), "--repo-root", str(_REPO_ROOT)]) == 0
    assert vw.main([str(_FIX / "bad_empty_title.json"), "--repo-root", str(_REPO_ROOT)]) == 1


def test_real_devin_wiki_file_is_valid() -> None:
    path = _REPO_ROOT / ".devin" / "wiki.json"
    assert path.exists(), ".devin/wiki.json must exist"
    errs = vw.validate_file(path, _REPO_ROOT)
    assert errs == [], "real .devin/wiki.json failed validation:\n" + "\n".join(errs)
