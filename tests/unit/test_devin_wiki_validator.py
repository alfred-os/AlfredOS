# tests/unit/test_devin_wiki_validator.py
from __future__ import annotations

import json
import subprocess
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


def test_valid_minimal_has_no_shape_errors() -> None:
    assert vw.check_shapes(_load("valid_minimal.json")) == []


def test_nondict_page_is_flagged() -> None:
    # `_pages()` silently drops a non-dict `pages[]` entry so every other
    # check can assume well-formed page objects — `check_shapes` is what
    # restores the loud failure for that dropped entry.
    errs = vw.check_shapes(_load("bad_nondict_page.json"))
    assert any("page[1]" in e and "object" in e.lower() for e in errs)


def test_nonlist_page_notes_is_flagged() -> None:
    errs = vw.check_shapes(_load("bad_nonlist_page_notes.json"))
    assert any("page_notes" in e and "list" in e.lower() for e in errs)


def test_pages_not_a_list_is_flagged() -> None:
    errs = vw.check_shapes({"repo_notes": [], "pages": "not-a-list"})
    assert any(e.startswith("pages:") and "list" in e.lower() for e in errs)


def test_repo_notes_not_a_list_is_flagged() -> None:
    errs = vw.check_shapes({"repo_notes": "not-a-list", "pages": []})
    assert any(e.startswith("repo_notes:") and "list" in e.lower() for e in errs)


def test_nonstring_page_note_entry_is_flagged() -> None:
    data = {
        "repo_notes": [],
        "pages": [{"title": "X", "purpose": "p", "page_notes": ["ok", 42]}],
    }
    errs = vw.check_shapes(data)
    assert any("page_notes[1]" in e and "string" in e.lower() for e in errs)


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


def test_extract_anchors_splits_compound_prd_refs() -> None:
    # `.devin/wiki.json` chains multiple PRD sections onto one reference using
    # a mix of separators: a slash ("6.5/6.6") and an en dash range (U+2013,
    # visually near-identical to a hyphen-minus, hence the noqa below). Every
    # section number in a compound must resolve, not just the first - the
    # same completeness gap already fixed for the ADR slash-compound form.
    note = "Ground in `PRD.md` §6.5/§6.6 and `PRD.md` §1–§2"  # noqa: RUF001
    values = {a.value for a in vw.extract_anchors(note) if a.kind == "prd"}
    assert values == {"6.5", "6.6", "1", "2"}


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


def test_check_anchors_missing_prd_and_glossary_files_no_crash(tmp_path: Path) -> None:
    # `check_anchors` used to do an unguarded `(repo_root/"PRD.md").read_text()`
    # / `(repo_root/"docs/glossary.md").read_text()` — an unhandled
    # `FileNotFoundError` (traceback) if either was absent/renamed. `git init`
    # so the (unrelated) tracked-file preload doesn't itself raise — this
    # test is isolating the PRD/glossary guard, not git availability.
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # noqa: S607
    errs = vw.check_anchors({"repo_notes": [], "pages": []}, tmp_path)
    assert isinstance(errs, list)
    assert all(isinstance(e, str) for e in errs)
    assert any("PRD.md" in e and "not found" in e for e in errs)
    assert any("glossary" in e.lower() and "not found" in e for e in errs)


def test_token_shaped_string_is_flagged() -> None:
    data = {"repo_notes": [{"content": "example key sk-" + "a" * 40}], "pages": []}
    assert any("token-shaped" in e for e in vw.check_secret_shapes(data))


def test_gh_token_is_flagged() -> None:
    # Assembled from fragments at runtime so no token-shaped literal lands in
    # this file (the repo's Gitleaks gate scans literals, not runtime values).
    token = "ghp_" + "a" * 36
    data = {"repo_notes": [{"content": f"example {token}"}], "pages": []}
    errs = vw.check_secret_shapes(data)
    assert any("GitHub token" in e for e in errs)


def test_aws_access_key_is_flagged() -> None:
    token = "AKIA" + "A" * 16
    data = {"repo_notes": [{"content": f"example {token}"}], "pages": []}
    errs = vw.check_secret_shapes(data)
    assert any("AWS access key" in e for e in errs)


def test_slack_token_is_flagged() -> None:
    token = "xoxb-" + "1" * 12
    data = {"repo_notes": [{"content": f"example {token}"}], "pages": []}
    errs = vw.check_secret_shapes(data)
    assert any("Slack token" in e for e in errs)


def test_hyphenated_anthropic_key_is_flagged() -> None:
    # Anthropic keys are hyphen-heavy (`sk-ant-api03-...`) — the widened
    # OpenAI/Anthropic pattern must still match a run containing hyphens,
    # not just a bare alphanumeric run.
    token = "sk-ant-api03-" + "a" * 32
    data = {"repo_notes": [{"content": f"example {token}"}], "pages": []}
    errs = vw.check_secret_shapes(data)
    assert any("OpenAI/Anthropic" in e for e in errs)


def test_secret_in_page_title_or_purpose_is_flagged() -> None:
    # Guardrail C previously only scanned page_notes/repo_notes content — a
    # secret pasted into a page's title or purpose sailed through unscanned.
    token = "AKIA" + "B" * 16
    data = {
        "repo_notes": [],
        "pages": [{"title": f"Leaky {token}", "purpose": "p"}],
    }
    errs = vw.check_secret_shapes(data)
    assert any("title" in e and "AWS access key" in e for e in errs)


def test_secret_in_purpose_is_flagged() -> None:
    # `purpose` (not `title`) carries the secret this time — guardrail C must
    # scan both fields, and the finding must still never echo the match.
    token = "AKIA" + "H" * 16
    data = {
        "repo_notes": [],
        "pages": [{"title": "Clean Title", "purpose": f"Leaky {token}"}],
    }
    errs = vw.check_secret_shapes(data)
    assert any("purpose" in e and "AWS access key" in e for e in errs)
    assert not any(token in e for e in errs)


def test_secret_error_does_not_echo_the_matched_token() -> None:
    token = "AKIA" + "C" * 16
    data = {"repo_notes": [{"content": f"example {token}"}], "pages": []}
    errs = vw.check_secret_shapes(data)
    assert errs
    assert not any(token in e for e in errs)


def test_secret_in_page_title_does_not_echo_the_title() -> None:
    # A page title carrying the secret must not be used as its own display
    # label — that would print the very token the finding exists to redact.
    token = "AKIA" + "D" * 16
    data = {
        "repo_notes": [],
        "pages": [{"title": f"Leaky {token}", "purpose": "p"}],
    }
    errs = vw.check_secret_shapes(data)
    assert errs
    assert not any(token in e for e in errs)


def test_secret_in_title_not_echoed_via_sibling_note_finding(tmp_path: Path) -> None:
    # Repro for the sibling-echo regression: a page's TITLE carries a secret,
    # and the SAME page's page_notes independently carries a DIFFERENT
    # secret. `check_secret_shapes`'s own finding for the note secret is
    # already safe (it labels by index) — but before the fix, `_all_notes`
    # built that finding's locator from the raw TITLE, leaking the AWS key
    # even though the message only ever named the GitHub-token match.
    aws_key = "AKIA" + "E" * 16
    gh_token = "ghp_" + "e" * 36
    data = {
        "pages": [
            {
                "title": f"Leaky {aws_key}",
                "purpose": "p",
                "page_notes": [f"here is {gh_token}"],
            }
        ]
    }
    errs = vw.check_secret_shapes(data)
    assert errs
    assert not any(aws_key in e for e in errs)

    # Same guarantee must hold end-to-end through `validate_file`, not just
    # the single check function in isolation.
    wiki_path = tmp_path / "wiki.json"
    wiki_path.write_text(json.dumps(data), encoding="utf-8")
    file_errs = vw.validate_file(wiki_path, _REPO_ROOT)
    assert not any(aws_key in e for e in file_errs)


def test_secret_in_title_not_echoed_via_empty_note_error() -> None:
    # Repro for the sibling-echo regression via a DIFFERENT check function:
    # the page_notes entry here carries NO secret at all — it trips a plain
    # structural finding (empty content). Before the fix,
    # `check_structure_and_limits` still built that finding's locator from
    # the raw title, leaking the AWS key from an entirely unrelated error.
    aws_key = "AKIA" + "F" * 16
    data = {
        "pages": [{"title": f"Leaky {aws_key}", "purpose": "p", "page_notes": [""]}],
    }
    errs = vw.check_structure_and_limits(data)
    assert errs
    assert not any(aws_key in e for e in errs)


def test_note_error_locates_repo_note_source() -> None:
    data = {"repo_notes": [{"content": ""}], "pages": []}
    errs = vw.check_structure_and_limits(data)
    assert any(e.startswith("repo_notes[0]:") for e in errs)


def test_note_error_locates_page_note_source() -> None:
    # `Sec` (the title) must NOT appear in the label — page_notes errors are
    # located by raw positional index only, so a secret pasted into a page's
    # title can never leak via a sibling page_notes finding.
    data = {
        "repo_notes": [],
        "pages": [{"title": "Sec", "purpose": "p", "page_notes": [""]}],
    }
    errs = vw.check_structure_and_limits(data)
    assert any("page[0] page_notes[0]" in e for e in errs)
    assert not any("Sec" in e for e in errs)


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
