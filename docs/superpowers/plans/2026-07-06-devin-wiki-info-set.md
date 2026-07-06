# Devin DeepWiki Info Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Devin DeepWiki steering file (`.devin/wiki.json`) plus a tested validator, a de-staled `ARCHITECTURE.md` anchor, and a DeepWiki README badge, so the public auto-generated wiki reflects AlfredOS's real, security-forward architecture and stays drift-checked in CI.

**Architecture:** A stdlib-only Python validator (`scripts/validate_devin_wiki.py`) enforces the file's structure, limits, referential integrity, anchor **resolution** (against the git-tracked tree, reusing `scripts/docs_check.py`'s slugifier), and a secret-shape scan. The validator's own tests plus a "validate the real file" test run under the **already-required** `Python (lint, types, unit)` CI check — so validation gates the merge button with no new workflow or branch-protection change. The steering file itself is authored verbatim from the design spec.

**Tech Stack:** Python 3.14+ (stdlib only for the validator — no third-party deps, mirroring `docs_check.py`), pytest, JSON, git plumbing (`git ls-files`), GitHub-flavoured Markdown.

## Global Constraints

- **Design source of truth:** `docs/superpowers/specs/2026-07-06-devin-wiki-info-set-design.md`. Page tree, `repo_notes`, and anchor decisions are copied verbatim from it.
- **Devin schema (hard limits):** `.devin/wiki.json` = `{ repo_notes: [{content, author?}], pages: [{title, purpose, parent?, page_notes?}] }`. ≤30 pages; ≤100 notes total (`repo_notes` + all `page_notes`); ≤10,000 **code points** per note; page `title`s unique + non-empty; `purpose` non-empty.
- **Validator = stdlib only.** No third-party imports. Must run on a fresh checkout before `uv sync`. Fully typed (`from __future__ import annotations`), ruff/mypy-clean, mirroring `scripts/docs_check.py`.
- **Anchors resolve against the git-tracked tree**, not the working tree — a gitignored file (e.g. root `CLAUDE.md`) must FAIL, because Devin only sees committed/tracked files. Use `git ls-files --error-unmatch <path>`.
- **Commit convention:** every commit subject is `<type>(<scope>): <desc> (#398)` — literal `#398` required (CI gate). End every commit body with `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.
- **No `git add -A`** — stage named paths only (untracked rulesync/tool outputs must not be swept in).
- **i18n:** the validator is a dev-tooling script, not runtime `src/alfred/` code; its operator-facing strings are English `print()` diagnostics like `docs_check.py` (no `t()` requirement).

---

### Task 1: Validator — structure & limits

**Files:**

- Create: `scripts/validate_devin_wiki.py`
- Create: `tests/unit/test_devin_wiki_validator.py`
- Create: `tests/unit/fixtures/devin_wiki/valid_minimal.json`
- Create: `tests/unit/fixtures/devin_wiki/bad_empty_title.json`
- Create: `tests/unit/fixtures/devin_wiki/bad_too_many_pages.json`

**Interfaces:**

- Produces: `load_wiki(path: Path) -> dict[str, object]` (raises `WikiError` on invalid JSON); `check_structure_and_limits(data: Mapping[str, object]) -> list[str]` (returns human-readable error strings, empty = OK); `class WikiError(Exception)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_devin_wiki_validator.py
from __future__ import annotations

import json
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
```

- [ ] **Step 2: Create the fixtures**

`tests/unit/fixtures/devin_wiki/valid_minimal.json`:

```json
{
  "repo_notes": [{ "content": "AlfredOS is a security-hardened agentic OS." }],
  "pages": [
    { "title": "Overview", "purpose": "Front-door router." },
    { "title": "Architecture", "purpose": "Structural spine.", "parent": "Overview" }
  ]
}
```

`tests/unit/fixtures/devin_wiki/bad_empty_title.json`:

```json
{ "repo_notes": [], "pages": [{ "title": "", "purpose": "Has an empty title." }] }
```

`tests/unit/fixtures/devin_wiki/bad_too_many_pages.json` — generate 31 pages (paste the full array; each entry `{"title": "P<N>", "purpose": "p"}` for N in 1..31):

```json
{ "repo_notes": [], "pages": [
  {"title":"P1","purpose":"p"},{"title":"P2","purpose":"p"},{"title":"P3","purpose":"p"},
  {"title":"P4","purpose":"p"},{"title":"P5","purpose":"p"},{"title":"P6","purpose":"p"},
  {"title":"P7","purpose":"p"},{"title":"P8","purpose":"p"},{"title":"P9","purpose":"p"},
  {"title":"P10","purpose":"p"},{"title":"P11","purpose":"p"},{"title":"P12","purpose":"p"},
  {"title":"P13","purpose":"p"},{"title":"P14","purpose":"p"},{"title":"P15","purpose":"p"},
  {"title":"P16","purpose":"p"},{"title":"P17","purpose":"p"},{"title":"P18","purpose":"p"},
  {"title":"P19","purpose":"p"},{"title":"P20","purpose":"p"},{"title":"P21","purpose":"p"},
  {"title":"P22","purpose":"p"},{"title":"P23","purpose":"p"},{"title":"P24","purpose":"p"},
  {"title":"P25","purpose":"p"},{"title":"P26","purpose":"p"},{"title":"P27","purpose":"p"},
  {"title":"P28","purpose":"p"},{"title":"P29","purpose":"p"},{"title":"P30","purpose":"p"},
  {"title":"P31","purpose":"p"}
] }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'validate_devin_wiki'`.

- [ ] **Step 4: Write the minimal implementation**

```python
# scripts/validate_devin_wiki.py
#!/usr/bin/env python3
"""Validator for `.devin/wiki.json` — the Devin DeepWiki steering file.

Stdlib-only (runs on a fresh checkout, like scripts/docs_check.py). Enforces the
Devin schema + hard limits, referential integrity, anchor RESOLUTION against the
git-tracked tree, and a secret-shape scan. Exit 0 when clean, 1 on any error.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

MAX_PAGES = 30
MAX_NOTES = 100
MAX_NOTE_CHARS = 10_000


class WikiError(Exception):
    """Raised when `.devin/wiki.json` cannot be loaded as the expected shape."""


def load_wiki(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WikiError(f"{path}: not loadable as JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise WikiError(f"{path}: top-level value must be a JSON object")
    return data


def _pages(data: Mapping[str, object]) -> list[dict[str, object]]:
    raw = data.get("pages", [])
    return [p for p in raw if isinstance(p, dict)] if isinstance(raw, list) else []


def _all_notes(data: Mapping[str, object]) -> list[str]:
    """Every note string: repo_notes[].content + pages[].page_notes[]."""
    notes: list[str] = []
    repo_notes = data.get("repo_notes", [])
    if isinstance(repo_notes, list):
        for n in repo_notes:
            if isinstance(n, dict) and isinstance(n.get("content"), str):
                notes.append(n["content"])
    for page in _pages(data):
        pnotes = page.get("page_notes", [])
        if isinstance(pnotes, list):
            notes.extend(x for x in pnotes if isinstance(x, str))
    return notes


def check_structure_and_limits(data: Mapping[str, object]) -> list[str]:
    errs: list[str] = []
    pages = _pages(data)

    if len(pages) > MAX_PAGES:
        errs.append(f"too many pages: {len(pages)} > {MAX_PAGES}")

    titles: list[str] = []
    for i, page in enumerate(pages):
        title = page.get("title")
        purpose = page.get("purpose")
        if not isinstance(title, str) or not title.strip():
            errs.append(f"page[{i}]: title is missing or empty")
        else:
            titles.append(title)
        if not isinstance(purpose, str) or not purpose.strip():
            errs.append(f"page[{i}] ({title!r}): purpose is missing or empty")

    seen: set[str] = set()
    for t in titles:
        if t in seen:
            errs.append(f"duplicate page title: {t!r}")
        seen.add(t)

    notes = _all_notes(data)
    if len(notes) > MAX_NOTES:
        errs.append(f"too many notes: {len(notes)} > {MAX_NOTES}")
    for j, content in enumerate(notes):
        if not content.strip():
            errs.append(f"note[{j}]: content is empty")
        if len(content) > MAX_NOTE_CHARS:
            errs.append(f"note[{j}]: {len(content)} code points > {MAX_NOTE_CHARS}")

    # repo_notes must be objects with a string `content`.
    repo_notes = data.get("repo_notes", [])
    if isinstance(repo_notes, list):
        for k, n in enumerate(repo_notes):
            if not isinstance(n, dict) or not isinstance(n.get("content"), str):
                errs.append(f"repo_notes[{k}]: must be an object with a string `content`")

    return errs
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: PASS (4 passed).

- [ ] **Step 6: Commit**

```bash
git add scripts/validate_devin_wiki.py tests/unit/test_devin_wiki_validator.py tests/unit/fixtures/devin_wiki/
git commit -m "feat(scripts): devin wiki validator — structure + limits (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 2: Validator — referential integrity (parent + cycles)

**Files:**

- Modify: `scripts/validate_devin_wiki.py`
- Modify: `tests/unit/test_devin_wiki_validator.py`
- Create: `tests/unit/fixtures/devin_wiki/bad_dangling_parent.json`
- Create: `tests/unit/fixtures/devin_wiki/bad_self_parent.json`
- Create: `tests/unit/fixtures/devin_wiki/bad_parent_cycle.json`

**Interfaces:**

- Produces: `check_references(data: Mapping[str, object]) -> list[str]` — flags dangling `parent`, self-parent, and any parent cycle.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/test_devin_wiki_validator.py

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
```

- [ ] **Step 2: Create the fixtures**

`bad_dangling_parent.json`:

```json
{ "repo_notes": [], "pages": [
  { "title": "Child", "purpose": "p", "parent": "Nonexistent" }
] }
```

`bad_self_parent.json`:

```json
{ "repo_notes": [], "pages": [
  { "title": "Loop", "purpose": "p", "parent": "Loop" }
] }
```

`bad_parent_cycle.json`:

```json
{ "repo_notes": [], "pages": [
  { "title": "A", "purpose": "p", "parent": "B" },
  { "title": "B", "purpose": "p", "parent": "A" }
] }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: FAIL — `AttributeError: module 'validate_devin_wiki' has no attribute 'check_references'`.

- [ ] **Step 4: Add the implementation**

```python
# add to scripts/validate_devin_wiki.py

def check_references(data: Mapping[str, object]) -> list[str]:
    errs: list[str] = []
    pages = _pages(data)
    title_to_parent: dict[str, str | None] = {}
    for page in pages:
        title = page.get("title")
        if not isinstance(title, str) or not title.strip():
            continue  # structure check already flags this
        parent = page.get("parent")
        title_to_parent[title] = parent if isinstance(parent, str) else None

    for title, parent in title_to_parent.items():
        if parent is None:
            continue
        if parent not in title_to_parent:
            errs.append(f"page {title!r}: parent {parent!r} is not an existing page title")
            continue
        # Walk ancestors; a revisit of `title` (or any node twice) is a cycle.
        seen: set[str] = set()
        cursor: str | None = title
        while cursor is not None:
            if cursor in seen:
                errs.append(f"page {title!r}: parent chain forms a cycle (via {cursor!r})")
                break
            seen.add(cursor)
            cursor = title_to_parent.get(cursor)
    return errs
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: PASS (8 passed).

- [ ] **Step 6: Commit**

```bash
git add scripts/validate_devin_wiki.py tests/unit/test_devin_wiki_validator.py tests/unit/fixtures/devin_wiki/
git commit -m "feat(scripts): devin wiki validator — referential integrity (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 3: Validator — anchor extraction & resolution (git-tracked tree)

This is the drift guard: it extracts anchor tokens from free-text `page_notes` and resolves each against the **git-tracked** tree (so a gitignored file fails), reusing `docs_check.py`'s slugifier for `PRD §N` / glossary `#slug` heading resolution.

**Anchor-extraction contract** (this is the `test-003` contract the spec deferred here — `page_notes` are authored to follow it):

- **Repo path** — any backtick-quoted token ending in a known extension (`.md .py .yaml .yml .json .toml`) or ending in `/` (a directory). Resolve: `git ls-files --error-unmatch <path>` must succeed (tracked = Devin-visible).
- **ADR** — `ADR-NNNN`, or a slash-compound reference chaining multiple ADR numbers onto one token (e.g. `ADR-0040/0042/0043`) → every ADR number in the reference is split out and resolved independently against a tracked file matching `docs/adr/NNNN-*.md`.
- **PRD section** — `` `PRD.md` §X `` / `` `PRD.md` §X.Y `` (backtick-wrapped, the real authoring form) or the bare `PRD §X` form, optionally chained into a compound tail via `/`, a hyphen, or an en dash (e.g. `` `PRD.md` §6.5/§6.6 `` or `` `PRD.md` §1–§2 ``) → every section number in the compound is resolved independently: `PRD.md` must have an ATX heading whose text (after stripping a leading `§`) starts with that number.
- **Glossary slug** — `glossary.md#slug` → `slug` must be in `extract_headings(docs/glossary.md)`.

**Files:**

- Modify: `scripts/validate_devin_wiki.py`
- Modify: `tests/unit/test_devin_wiki_validator.py`
- Create: `tests/unit/fixtures/devin_wiki/bad_gitignored_anchor.json`

**Interfaces:**

- Consumes: `docs_check.slugify`, `docs_check.extract_headings` (both already in `scripts/docs_check.py`).
- Produces: `extract_anchors(note: str) -> list[Anchor]` (`Anchor` = frozen dataclass `{kind: str, value: str}`); `check_anchors(data, repo_root: Path) -> list[str]`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/test_devin_wiki_validator.py

_REPO_ROOT = Path(__file__).parents[2]


def test_extract_anchors_finds_each_kind() -> None:
    note = "Ground in `docs/subsystems/security.md`, ADR-0017, PRD.md §7.1, glossary.md#trust-tier."
    kinds = {a.kind for a in vw.extract_anchors(note)}
    assert kinds == {"path", "adr", "prd", "glossary"}


def test_real_tracked_anchors_resolve() -> None:
    data = {"repo_notes": [], "pages": [
        {"title": "Sec", "purpose": "p",
         "page_notes": ["-> `docs/subsystems/security.md`, ADR-0017, glossary.md#trust-tier"]},
    ]}
    assert vw.check_anchors(data, _REPO_ROOT) == []


def test_gitignored_anchor_is_flagged() -> None:
    # Root CLAUDE.md is a gitignored rulesync output — Devin cannot see it.
    errs = vw.check_anchors(_load("bad_gitignored_anchor.json"), _REPO_ROOT)
    assert any("CLAUDE.md" in e and ("not tracked" in e or "gitignored" in e) for e in errs)


def test_bad_adr_and_slug_are_flagged() -> None:
    data = {"repo_notes": [], "pages": [
        {"title": "X", "purpose": "p",
         "page_notes": ["ADR-9999 and glossary.md#no-such-heading"]},
    ]}
    errs = vw.check_anchors(data, _REPO_ROOT)
    assert any("ADR-9999" in e for e in errs)
    assert any("no-such-heading" in e for e in errs)
```

- [ ] **Step 2: Create the fixture**

`bad_gitignored_anchor.json`:

```json
{ "repo_notes": [], "pages": [
  { "title": "CLI", "purpose": "p", "page_notes": ["anchor to `CLAUDE.md` command table"] }
] }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'extract_anchors'`.

- [ ] **Step 4: Add the implementation**

```python
# add near the top of scripts/validate_devin_wiki.py, after the constants:
import re
import subprocess
from dataclasses import dataclass

# docs_check.py lives beside this script; reuse its GitHub-accurate slugifier.
from docs_check import extract_headings, slugify  # noqa: E402

_PATH_RE = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*(?:\.(?:md|py|ya?ml|json|toml)|/))`")
_ADR_RE = re.compile(r"\bADR-(\d{4})\b")
_PRD_RE = re.compile(r"PRD(?:\.md)?\s+§(\d+(?:\.\d+)?)")
_GLOSSARY_RE = re.compile(r"glossary(?:\.md)?#([a-z0-9_-]+)")


@dataclass(frozen=True)
class Anchor:
    kind: str  # "path" | "adr" | "prd" | "glossary"
    value: str


def extract_anchors(note: str) -> list[Anchor]:
    out: list[Anchor] = []
    out += [Anchor("path", m.group(1)) for m in _PATH_RE.finditer(note)]
    out += [Anchor("adr", m.group(1)) for m in _ADR_RE.finditer(note)]
    out += [Anchor("prd", m.group(1)) for m in _PRD_RE.finditer(note)]
    out += [Anchor("glossary", m.group(1)) for m in _GLOSSARY_RE.finditer(note)]
    return out


def _is_tracked(repo_root: Path, rel: str) -> bool:
    """True iff `rel` is tracked (committed or staged) — i.e. Devin-visible."""
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", rel.rstrip("/")],
        cwd=repo_root, capture_output=True, text=True, check=False,
    )
    if result.returncode == 0:
        return True
    # A directory anchor (trailing "/") lists >0 tracked files underneath.
    listing = subprocess.run(
        ["git", "ls-files", "--", rel], cwd=repo_root, capture_output=True, text=True, check=False,
    )
    return bool(listing.stdout.strip())


def _prd_heading_numbers(repo_root: Path) -> set[str]:
    text = (repo_root / "PRD.md").read_text(encoding="utf-8")
    nums: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"^#{1,6}\s+§?\s*(\d+(?:\.\d+)*)\b", line)
        if m:
            nums.add(m.group(1))
    return nums


def check_anchors(data: Mapping[str, object], repo_root: Path) -> list[str]:
    errs: list[str] = []
    glossary_slugs = extract_headings((repo_root / "docs/glossary.md").read_text(encoding="utf-8"))
    prd_nums = _prd_heading_numbers(repo_root)
    adr_dir = repo_root / "docs/adr"

    for page in _pages(data):
        title = page.get("title")
        pnotes = page.get("page_notes", [])
        if not isinstance(pnotes, list):
            continue
        for note in (n for n in pnotes if isinstance(n, str)):
            for a in extract_anchors(note):
                if a.kind == "path":
                    if not _is_tracked(repo_root, a.value):
                        errs.append(f"page {title!r}: `{a.value}` is not tracked (gitignored/absent — Devin cannot see it)")
                elif a.kind == "adr":
                    if not any(adr_dir.glob(f"{a.value}-*.md")):
                        errs.append(f"page {title!r}: ADR-{a.value} has no file under docs/adr/")
                elif a.kind == "prd":
                    if not any(n == a.value or n.startswith(a.value + ".") for n in prd_nums):
                        errs.append(f"page {title!r}: PRD §{a.value} resolves to no heading in PRD.md")
                elif a.kind == "glossary" and a.value not in glossary_slugs:
                    errs.append(f"page {title!r}: glossary.md#{a.value} resolves to no heading")
    return errs
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: PASS (12 passed).

- [ ] **Step 6: Commit**

```bash
git add scripts/validate_devin_wiki.py tests/unit/test_devin_wiki_validator.py tests/unit/fixtures/devin_wiki/
git commit -m "feat(scripts): devin wiki validator — anchor resolution over tracked tree (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 4: Validator — secret-shape scan + `main()` CLI

Disclosure guardrail C's in-repo backstop: scan the steering file's own note text for token-shaped literals (repo-wide secret hygiene stays gitleaks' job). Then wire the CLI.

**Files:**

- Modify: `scripts/validate_devin_wiki.py`
- Modify: `tests/unit/test_devin_wiki_validator.py`

**Interfaces:**

- Produces: `check_secret_shapes(data) -> list[str]`; `validate_file(path: Path, repo_root: Path) -> list[str]` (runs all checks); `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/test_devin_wiki_validator.py

def test_token_shaped_string_is_flagged() -> None:
    data = {"repo_notes": [{"content": "example key sk-" + "a" * 40}], "pages": []}
    assert any("token-shaped" in e for e in vw.check_secret_shapes(data))


def test_clean_notes_have_no_secret_findings() -> None:
    assert vw.check_secret_shapes(_load("valid_minimal.json")) == []


def test_validate_file_aggregates_and_main_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert vw.main([str(_FIX / "valid_minimal.json"), "--repo-root", str(_REPO_ROOT)]) == 0
    assert vw.main([str(_FIX / "bad_empty_title.json"), "--repo-root", str(_REPO_ROOT)]) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: FAIL — `has no attribute 'check_secret_shapes'`.

- [ ] **Step 3: Add the implementation**

```python
# add to scripts/validate_devin_wiki.py

# Token shapes we never want pasted into steering text. Deliberately narrow to
# avoid false positives on prose: provider key prefixes + long base64-ish runs.
_SECRET_RES = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)


def check_secret_shapes(data: Mapping[str, object]) -> list[str]:
    errs: list[str] = []
    for j, note in enumerate(_all_notes(data)):
        for rx in _SECRET_RES:
            if rx.search(note):
                errs.append(f"note[{j}]: token-shaped literal matched {rx.pattern!r} — remove it (guardrail C)")
    return errs


def validate_file(path: Path, repo_root: Path) -> list[str]:
    data = load_wiki(path)
    return [
        *check_structure_and_limits(data),
        *check_references(data),
        *check_anchors(data, repo_root),
        *check_secret_shapes(data),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Path to .devin/wiki.json")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        errs = validate_file(args.path, args.repo_root.resolve())
    except WikiError as exc:
        print(f"devin-wiki-check: {exc}", file=sys.stderr)
        return 1
    if errs:
        print(f"devin-wiki-check: {len(errs)} problem(s) in {args.path}:", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"devin-wiki-check: OK ({args.path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: PASS (16 passed).

- [ ] **Step 5: Lint + type-check the validator**

Run: `uv run ruff check scripts/validate_devin_wiki.py && uv run mypy scripts/validate_devin_wiki.py`
Expected: no errors. (If ruff flags the mid-file imports in Task 3, move them to the top import block; keep `# noqa: E402` only where the `sys.path` shim requires it in the test.)

- [ ] **Step 6: Commit**

```bash
git add scripts/validate_devin_wiki.py tests/unit/test_devin_wiki_validator.py
git commit -m "feat(scripts): devin wiki validator — secret-shape scan + CLI (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 5: Author `.devin/wiki.json` + the real-file gating test + make target

The steering file is transcribed verbatim from the spec. The "validate the real file" test runs under the already-required `Python (lint, types, unit)` check — this is what gates the merge button.

**Files:**

- Create: `.devin/wiki.json`
- Modify: `tests/unit/test_devin_wiki_validator.py`
- Modify: `Makefile`

**Interfaces:**

- Consumes: `validate_file` (Task 4).

- [ ] **Step 1: Write the failing gating test**

```python
# append to tests/unit/test_devin_wiki_validator.py

def test_real_devin_wiki_file_is_valid() -> None:
    path = _REPO_ROOT / ".devin" / "wiki.json"
    assert path.exists(), ".devin/wiki.json must exist"
    errs = vw.validate_file(path, _REPO_ROOT)
    assert errs == [], "real .devin/wiki.json failed validation:\n" + "\n".join(errs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py::test_real_devin_wiki_file_is_valid -q`
Expected: FAIL — `.devin/wiki.json must exist`.

- [ ] **Step 3: Author `.devin/wiki.json`**

Transcribe from the spec (`docs/superpowers/specs/2026-07-06-devin-wiki-info-set-design.md`), which is the content source of truth:

1. **`repo_notes`** — copy all **12** notes verbatim from the spec's "`repo_notes`" section (numbered 1–12) into `repo_notes: [{ "content": "...", "author": "AlfredOS maintainers" }]`. Preserve exact wording (they are the load-bearing anti-pattern invariants). Each is one array element.
2. **`pages`** — one object per row across all six root sections of the spec's "Page tree (29 pages)". For each page:
   - `title` = the page name (use `Personas & Addressing`, not "& Routing").
   - `parent` = the root/section it sits under (roots `Overview`/`Architecture`/`Security Model`/`Operating & Deploying`/`Extending & Contributing`/`Reference` have no `parent`).
   - `purpose` = the spec's "purpose (one line)" column.
   - `page_notes` = built from the spec's "anchor / caveat" column, following the anchor-extraction contract (Task 3) so the validator resolves them: a steer sentence naming the anchor(s) as backtick paths / `ADR-NNNN` / `PRD.md §N` / `glossary.md#slug`, plus any `⚠` caveat, plus (only for pages with neither a deep-doc nor an ADR — Memory, Personas, Providers, Audit, Orchestrator) the anchor-gap "treat as unverified" sentence. Keep ≤3 page_notes per page.

Worked examples (follow these patterns exactly for every row):

```json
{
  "repo_notes": [
    { "content": "Dual-LLM / trust flow. The privileged orchestrator sees only T0-T2. The quarantined LLM is the ONLY consumer of raw T3 (web/email/file/tool-output) and emits ONLY schema-validated structured data — never tool calls, never free text fed back as instructions. All external content is tagged T3 at ingest. Never write 'the orchestrator reads a web page / processes tool output': T3 reaches the privileged side only as structured extraction via the T3->T2 dispatch chokepoint. Non-negotiable (PRD §5, DEC-007).", "author": "AlfredOS maintainers" }
  ],
  "pages": [
    { "title": "Overview", "purpose": "Front-door router: a three-sentence pitch, the trust-boundary diagram, and an audience fork (self-hosters -> Security Model, operators -> Operating, contributors -> Extending).", "page_notes": ["Ground in `PRD.md` §1-§2. Keep it a router, not a throat-clear."] },
    { "title": "Architecture", "purpose": "Structural spine — what it is, structurally.", "page_notes": ["Ground in `docs/ARCHITECTURE.md` and `PRD.md` §5 (the 8 non-negotiable invariants)."] },
    { "title": "Dual-LLM Split & Quarantine", "parent": "Security Model", "purpose": "Privileged orchestrator never sees raw T3; the quarantined LLM is the only T3 consumer; the single sanctioned T3->T2 dispatch chokepoint.", "page_notes": ["Ground in `docs/subsystems/quarantine.md` and ADR-0046. The purpose MUST name the T3->T2 crossing."] },
    { "title": "Memory Model (6 Layers)", "parent": "Architecture", "purpose": "Working, episodic, summarized, semantic, vector, knowledge-graph layers and consolidation.", "page_notes": ["No curated deep-doc exists yet — anchor to `PRD.md` §6.2 + `src/alfred/memory/`; treat claims as unverified until a deep-doc lands.", "Working + episodic are live; semantic/vector/graph are partial/planned — describe as designed, not shipped."] },
    { "title": "CLI & Operator Surface", "parent": "Operating & Deploying", "purpose": "The alfred command tree by area (user, plugin, web, config, supervisor, audit, gateway).", "page_notes": ["Anchor to the `.rulesync/rules/CLAUDE.md` command table (the committed source; root CLAUDE.md is a gitignored rulesync output Devin cannot see) + `src/alfred/cli/`.", "Honour slice markers — alfred memory show / alfred cost report are Slice 4+ / not implemented."] }
  ]
}
```

Note: use `T0-T2` / `->` (ASCII) inside JSON strings only if you prefer, but the anchor tokens (`` `path` ``, `ADR-NNNN`, `PRD.md §N`, `glossary.md#slug`) MUST match the Task-3 regexes exactly. The full file has 12 repo_notes and 29 pages.

- [ ] **Step 4: Run the validator against the real file**

Run: `python3 scripts/validate_devin_wiki.py .devin/wiki.json --repo-root "$(pwd)"`
Expected: `devin-wiki-check: OK (.devin/wiki.json)`. Fix any reported anchor/limit errors (e.g. a mistyped `§` number or an ADR that doesn't exist) until clean.

- [ ] **Step 5: Run the gating test**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -q`
Expected: PASS (17 passed) — including `test_real_devin_wiki_file_is_valid`.

- [ ] **Step 6: Add a `make wiki-check` target**

In `Makefile`, next to the `docs-check` target, add:

```makefile
wiki-check: ## Validate .devin/wiki.json (schema, limits, anchor resolution, secret shapes).
 python3 scripts/validate_devin_wiki.py .devin/wiki.json --repo-root "$(CURDIR)"
```

Run: `make wiki-check`
Expected: `devin-wiki-check: OK (.devin/wiki.json)`.

- [ ] **Step 7: Commit**

```bash
git add .devin/wiki.json tests/unit/test_devin_wiki_validator.py Makefile
git commit -m "feat(devin): add .devin/wiki.json steering file + gating test (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 6: De-stale `docs/ARCHITECTURE.md`

`ARCHITECTURE.md` is the wiki's Architecture-spine anchor but still presents Spec B as "in progress" and Spec C as "future"; both are merged (#288, #333). Update the status claims (not a full narrative rewrite) so the anchor stops contradicting `repo_notes` #2/#6.

**Files:**

- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Read the stale regions**

Run: `grep -nE "Spec B|Spec C|In progress|Future, gated|Still ahead|G6-[0-9]|in progress" docs/ARCHITECTURE.md`
Note every line that asserts Spec B/C is incomplete (the roadmap table rows ~56-57, the inline "(in progress)" at ~67, the "Spec B (G6) progress" / "Still ahead" section ~72-101, and the D1/D2 tension notes ~144-201 that say Spec C is future).

- [ ] **Step 2: Update the status markers**

Edit each noted region so it reads as complete:

- Roadmap table: Spec B status cell → `Complete (#288)`; Spec C status cell → `Complete (#333)`.
- Inline "(in progress)" / "Future, gated on B" → past tense ("merged").
- Collapse the "Spec B (G6) progress" / "Still ahead: G6-3 … G6-6" detail into a one-paragraph "Spec B complete (G6-0…G6-7, #288); Spec C complete (G7, #333). The PRD §5 egress-invariant rewrite has landed." Remove the "Still ahead" bullet list (that work is done).
- D1/D2 notes that gate on "Spec C / G7 (future)" → note Spec C shipped; keep any genuinely-open decision (e.g. inbound remote management) but stop framing it as blocked on unshipped specs.

Do NOT invent new architecture claims — only flip status and trim now-historical detail. When unsure whether a claim is still true, cross-check the project state in `.rulesync/rules/CLAUDE.md` (current-state section).

- [ ] **Step 3: Verify no stale Spec B/C status remains**

Run: `grep -nE "in progress|Future, gated|Still ahead|gated on B" docs/ARCHITECTURE.md`
Expected: no lines that describe Spec B or Spec C as incomplete.

- [ ] **Step 4: Link-check the edited doc**

Run: `python3 scripts/docs_check.py docs/ARCHITECTURE.md --repo-root "$(pwd)"`
Expected: `docs-check: OK`.

- [ ] **Step 5: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): de-stale Spec B/C status — both merged (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 7: DeepWiki README badge

The one set-and-forget refresh lever (~weekly auto-regeneration) + discoverability.

**Files:**

- Modify: `README.md:3` (immediately after the existing Discord badge line)

- [ ] **Step 1: Add the badge**

After the Discord badge line (line 3 of `README.md`), add:

```markdown
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/alfred-os/AlfredOS)
```

(The badge image + link are hosted by DeepWiki; the repo slug `alfred-os/AlfredOS` matches `git remote get-url origin`.)

- [ ] **Step 2: Verify the README still link-checks**

Run: `python3 scripts/docs_check.py README.md --repo-root "$(pwd)"`
Expected: `docs-check: OK` (the badge is an external `https://` link — skipped by the checker, which is correct).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): add DeepWiki badge for weekly wiki auto-refresh (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

### Task 8: Record gating in the required-checks manifest + full-suite verification

Validation gates via the **existing** `Python (lint, types, unit)` required check (it runs `tests/unit/`, which now includes `test_real_devin_wiki_file_is_valid`). No new GitHub context is emitted, so **no new required-checks row and no branch-protection change** — adding a phantom context would block all PRs (per the manifest's own warning). Record the coverage in prose so the gating is auditable.

**Files:**

- Modify: `docs/ci/required-checks.md`

- [ ] **Step 1: Add a prose note under "Currently required"**

In `docs/ci/required-checks.md`, in the `Python (lint, types, unit)` row's Rationale (or a short note beneath the table), append: "Also runs `tests/unit/test_devin_wiki_validator.py`, including `test_real_devin_wiki_file_is_valid`, which validates `.devin/wiki.json` (schema, limits, anchor resolution over the tracked tree, secret-shape scan) — so DeepWiki-steering drift blocks merge under this existing check (no separate context)."

- [ ] **Step 2: Run the full local quality bar**

Run: `make check`
Expected: lint + format + type + tests all pass. (Note: the macOS integration lane can be flaky under load — if a non-wiki integration test flakes, verify the suspect in isolation and trust Linux CI; the wiki work is pure unit + docs.)

- [ ] **Step 3: Confirm the whole wiki suite is green together**

Run: `python3 -m pytest tests/unit/test_devin_wiki_validator.py -v && make wiki-check && python3 scripts/docs_check.py docs/ README.md PRD.md --repo-root "$(pwd)"`
Expected: all pass; `devin-wiki-check: OK`; `docs-check: OK`.

- [ ] **Step 4: Commit**

```bash
git add docs/ci/required-checks.md
git commit -m "docs(ci): record devin wiki validation under the Python unit check (#398)

$(printf 'MrReasonable <4990954+MrReasonable@users.noreply.github.com>')"
```

---

## Self-Review

**Spec coverage:**

- Deliverable 1 (`.devin/wiki.json`) → Task 5. ✅
- Deliverable 2 (tested validator + required check) → Tasks 1–4 (validator + fixtures + red-path tests), Task 5 (gating test + make target), Task 8 (manifest note + gating via existing required check). ✅ Resolves test-001 (fixtures), test-002/arch-009 (anchor resolution), test-004 (real required check, not paper), test-005 (cycle/non-empty), test-003 (extraction contract defined in Task 3). ✅
- Deliverable 3 (`ARCHITECTURE.md` de-stale) → Task 6 (arch-004/docs-003/rev-001). ✅
- Deliverable 4 (README badge) → Task 7. ✅
- `repo_notes` incl. secrets+DLP (arch-005/sec-002), guardrails (sec-001/003), vocab-lock gap fail-safe (docs-004/005) → authored in Task 5 step 3 from the spec. ✅
- CLAUDE.md → `.rulesync/rules/CLAUDE.md` (docs-001), committed-tree resolution → Task 3 `_is_tracked` + Task 5 example. ✅
- Hooks page, ADR-pin map, Telegram/naming Lows → carried in the spec's page tree, transcribed in Task 5. ✅

**Placeholder scan:** No "TBD"/"handle edge cases". The one non-inline content is the 29-page transcription in Task 5 step 3 — deliberately delegated to the committed spec (the content source of truth) with the exact construction rule + five worked examples covering every page pattern, since duplicating 300 lines of JSON here would risk hand-transcription drift from the spec.

**Type consistency:** `load_wiki` → `dict`; every `check_*` takes `Mapping[str, object]` and returns `list[str]`; `check_anchors`/`validate_file` also take `repo_root: Path`; `extract_anchors` → `list[Anchor]`. `main` signature matches `docs_check.main`. Consistent across tasks.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-06-devin-wiki-info-set.md`.
