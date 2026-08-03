"""#539 — the ``tokenize``-anchored suppression rule.

Loaded via ``spec_from_file_location`` against the REAL script path, for the reason the
sibling suites give: a ``tmp_path`` copy recomputes ``_REPO_ROOT`` and silently inverts
every exemption.

WHY ``tokenize`` AND NOT A WIDER REGEX, in the order the alternatives fail:

1. **The naive widening is the likely wrong implementation, and it is catastrophic.**
   Written with a top-level alternation — ``TaggedContent.*#\\s*(?:type|pyright):\\s*ignore|noqa``
   — the ``noqa`` arm binds at the TOP level and matches any line containing the word
   anywhere, including inside a string. Measured across both scan roots: **98 hits against
   1** correctly grouped, so **97 pure false positives** on a repo-wide gate.
2. **A "token regex" is WORSE than the naive form on one case.** Searching a comment's text
   readmits prose: ``# we do not noqa here`` is a sentence ABOUT a directive, not one.
   Anchoring at the START of a real COMMENT token's body is what separates them.
3. **The rule this replaces needed the suppressor and ``TaggedContent`` on the same
   PHYSICAL line**, so reformatting a call across lines and putting the suppressor on the
   closing paren made it blind. The LOGICAL line is the correct scope, and only the
   tokenizer knows where one ends.

A NOTE ON ONE FIXTURE, because a plan review floor got it backwards: ``# noqa is the wrong
tool`` is NOT prose. It begins where a directive begins, so every linter that reads the
file treats it as a bare ``noqa`` — and so does this rule, correctly. The prose fixtures
below are ones where the word is genuinely mid-sentence.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "check_tag_t3.py"

_spec = importlib.util.spec_from_file_location("check_tag_t3_suppression", _SCRIPT)
assert _spec is not None and _spec.loader is not None
check_tag_t3 = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = check_tag_t3
_spec.loader.exec_module(check_tag_t3)

assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded the wrong script: {check_tag_t3._REPO_ROOT} != {_REPO_ROOT}"
)

_PROBE = Path("/nonexistent/probe.py")

# Assembled at runtime, never written out. A literal `# noqa` in this file's source is read
# as a real directive by ruff (it does not care that it sits inside a string), which reds
# RUF100 for an unused suppression — the same phenomenon this module tests, one layer up.
_HASH = "#"


def _messages(source: str, path: Path = _PROBE) -> list[str]:
    """Violation MESSAGE lines only — odd-indexed entries are code snippets."""
    return [v for v in check_tag_t3._scan_text(source, path) if not v.startswith("  ")]


def _tripped(source: str) -> bool:
    return any(check_tag_t3._TYPE_IGNORE_MESSAGE in m for m in _messages(source))


@pytest.mark.parametrize(
    ("label", "comment"),
    [
        ("type-ignore", "type: ignore[arg-type]"),
        ("type-ignore-bare", "type: ignore"),
        ("pyright-ignore", "pyright: ignore[reportGeneralTypeIssues]"),
        ("mypy-ignore", "mypy: ignore"),
        ("mypy-ignore-errors", "mypy: ignore-errors"),
        ("noqa-coded", "noqa: E501"),
        ("noqa-bare", "noqa"),
        ("ruff-noqa", "ruff: noqa"),
        ("flake8-noqa", "flake8: noqa"),
        ("spaced", "type:  ignore"),
    ],
)
def test_every_real_suppressor_trips_on_a_taggedcontent_line(label: str, comment: str) -> None:
    """``ruff: noqa``, ``flake8: noqa`` and ``mypy: ignore-errors`` are FILE-WIDE.

    They are the strongest members of the family and were invisible to every earlier draft
    of this rule, which is the wrong way round: the broader the suppression, the more it
    matters that it cannot be pointed at a TaggedContent line unnoticed.
    """
    assert _tripped(f"x = TaggedContent[T2](y)  {_HASH} {comment}\n"), label


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("prose-mid-sentence", "x = TaggedContent[T2](y)  {h} we do not {w} here\n"),
        ("prose-standalone", "{h} suppressing a {w} on TaggedContent is banned\n"),
        ("prose-about-type", "x = TaggedContent[T2](y)  {h} do not write type ignore here\n"),
    ],
)
def test_prose_in_a_comment_is_clean(label: str, source: str) -> None:
    """THE 97-FALSE-POSITIVE CASE, and the one a token regex gets wrong.

    ``re.match`` and not ``re.search``: the word appears, but not where a directive starts.
    """
    assert not _tripped(source.format(h=_HASH, w="noqa")), label


def test_prose_in_a_string_is_clean() -> None:
    """No COMMENT token exists here at all — the regex this replaces matched the text."""
    assert not _tripped(f'MSG = "TaggedContent  {_HASH} type: ignore is banned"\n')


def test_docstring_prose_is_clean() -> None:
    assert not _tripped(f'"""Never write TaggedContent  {_HASH} noqa in this repo."""\n')


def test_a_suppressor_on_a_line_with_no_taggedcontent_is_clean() -> None:
    """The rule is about suppressing a TaggedContent type error, not about suppressors."""
    assert not _tripped(f"x = plain_call(y)  {_HASH} type: ignore[arg-type]\n")


def test_a_suppressor_on_the_closing_paren_of_a_multiline_call_trips() -> None:
    """THE BLIND SPOT NOBODY RAISED, closed by scoping to the LOGICAL line.

    The rule this replaces required both on the same physical line, so an author who let
    the formatter split the call and put the suppressor on the closing paren silenced the
    gate without meaning to — and an author who meant to would not have had to try hard.
    """
    source = "x = TaggedContent[T2](\n    content='a',\n    source='b',\n)  {h} type: ignore\n"

    assert _tripped(source.format(h=_HASH))


def test_a_standalone_suppressor_comment_is_decided_by_its_own_line() -> None:
    """A comment-only line emits ``NL``, not ``NEWLINE``, so it belongs to no logical line.

    The degenerate span is not a defensive default: it is what stops a standalone comment
    inheriting the statement that happens to follow it. Here the comment names no
    TaggedContent and the NEXT line does — it must stay clean.
    """
    assert not _tripped(f"{_HASH} type: ignore\nx = TaggedContent[T2](y)\n")


def test_the_suppression_pass_appends_rather_than_replaces() -> None:
    """A suppressed line that ALSO carries a real construction reports BOTH.

    Ordering property: the pass runs after the AST walk, so findings already collected
    survive. Reporting only the suppression would downgrade a T3-laundering finding.
    """
    messages = _messages(f"TaggedContent[T3](x)  {_HASH} type: ignore\n")

    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in messages)
    assert any(check_tag_t3._TYPE_IGNORE_MESSAGE in m for m in messages)


def test_the_anchor_requires_a_word_boundary() -> None:
    """``noqable`` is not ``noqa``. Without ``\\b`` the anchor matches any word starting so."""
    assert not _tripped(f"x = TaggedContent[T2](y)  {_HASH} noqative mood\n")


def test_a_suppressor_inside_a_multiline_statement_body_trips() -> None:
    """Mid-statement, not just on the closing paren — the whole logical line is in scope."""
    source = "x = TaggedContent[T2](\n    content='a',  {h} noqa: E501\n    source='b',\n)\n"

    assert _tripped(source.format(h=_HASH))


def test_the_real_tree_scans_clean_with_an_assert_ran_census() -> None:
    """THE MEASURED FLOOR: 97 pure false positives if the non-capturing group is dropped.

    ASSERT-RAN in the same invocation, because "the real tree is clean" is a tautology on a
    rule that never fires. The one live hit under both scan roots is inside the whole-file
    exempt ``security/tiers.py`` — unchanged from the rule this replaces.
    """
    paths = check_tag_t3._collect_paths([])

    assert len(paths) >= check_tag_t3._MIN_SCANNED_FILES
    assert [v for p in paths for v in check_tag_t3._scan_file(p)] == []


def test_an_untokenizable_file_is_reported_by_the_existing_unscannable_arm() -> None:
    """NO NEW ARM, and that is the finding rather than a shortcut.

    A plan-review floor asserted that a tokenize failure gets its own report, using
    ``"x = (\\n"`` as the fixture. That input fails ``ast.parse`` FIRST, so the scanner
    returns on the unparseable branch and the tokenizer never runs — the assertion passed
    while proving nothing, and the mutant it was meant to kill survived. A search for an
    input that parses but does not tokenize found none, so a dedicated arm would be
    unreachable, and an unreachable arm under this file's REQUIRED 100% no-pragma gate is a
    design fault rather than a safe default.

    So the pass sits inside the existing ``try``: whatever the tokenizer raises is reported
    by the arm that already exists. This test pins the OUTCOME — the file is reported, not
    silently clean — which is the property that actually matters.
    """
    violations = check_tag_t3._scan_text("x = (\n", _PROBE)

    assert violations, "an unterminated construct must never scan clean"
    assert any(check_tag_t3._UNPARSEABLE_MESSAGE in v for v in violations)


def test_a_file_wide_suppressor_covers_a_taggedcontent_line_anywhere_below_it() -> None:
    """FILE-WIDE means file-wide. Scoping these to their own line inverts the family.

    ``# ruff: noqa`` at the top of a module disables ruff for every line in it, so a
    ``TaggedContent`` construction fifty lines down IS suppressed by it. A line-scoped
    reading would make the broadest suppressors the easiest to hide behind — the exact
    opposite of the property this rule exists to have.
    """
    for directive in ("ruff: noqa", "flake8: noqa", "mypy: ignore-errors"):
        source = f"{_HASH} {directive}\nimport os\n\n\nx = TaggedContent[T2](y)\n"
        assert _tripped(source), directive


def test_a_file_wide_suppressor_in_a_file_with_no_taggedcontent_is_clean() -> None:
    """The twin. File-wide scope must not mean "always trips"."""
    assert not _tripped(f"{_HASH} ruff: noqa\nimport os\nx = plain(y)\n")


def test_a_standalone_line_scoped_suppressor_below_the_construction_is_clean() -> None:
    """The mirror of the standalone case: order must not rescue a line-scoped directive."""
    assert not _tripped(f"x = TaggedContent[T2](y)\n{_HASH} type: ignore\n")
