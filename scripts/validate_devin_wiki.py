#!/usr/bin/env python3
"""Validator for `.devin/wiki.json` — the Devin DeepWiki steering file.

Stdlib-only (runs on a fresh checkout, like scripts/docs_check.py). Enforces the
Devin schema + hard limits, referential integrity, anchor RESOLUTION against the
git-tracked tree, and a secret-shape scan. Exit 0 when clean, 1 on any error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# docs_check.py lives beside this script; reuse its GitHub-accurate slugifier
# and heading extractor rather than re-implementing them here.
from docs_check import extract_headings, slugify

MAX_PAGES = 30
MAX_NOTES = 100
MAX_NOTE_CHARS = 10_000

# Repo path — any backtick-quoted token ending in a known extension or in `/`
# (a directory reference).
_PATH_RE = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*(?:\.(?:md|py|ya?ml|json|toml)|/))`")
_ADR_RE = re.compile(r"\bADR-(\d{4})\b")
_PRD_RE = re.compile(r"PRD(?:\.md)?\s+§(\d+(?:\.\d+)?)")
_GLOSSARY_RE = re.compile(r"glossary(?:\.md)?#([a-z0-9_-]+)")


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


@dataclass(frozen=True)
class Anchor:
    """A single anchor token found in free-text `page_notes`.

    `kind` distinguishes the four anchor shapes the Devin wiki schema
    supports; `value` is the extracted, kind-specific payload (a repo-relative
    path, an ADR number, a PRD section number, or a glossary slug).
    """

    kind: str  # "path" | "adr" | "prd" | "glossary"
    value: str


def extract_anchors(note: str) -> list[Anchor]:
    """Extract every anchor token embedded in a free-text `page_notes` string.

    Anchors are the drift-guard surface: each one is later resolved against
    the git-tracked tree by `check_anchors`, so a stale or gitignored
    reference is caught before Devin ingests the wiki.
    """
    out: list[Anchor] = []
    out += [Anchor("path", m.group(1)) for m in _PATH_RE.finditer(note)]
    out += [Anchor("adr", m.group(1)) for m in _ADR_RE.finditer(note)]
    out += [Anchor("prd", m.group(1)) for m in _PRD_RE.finditer(note)]
    out += [Anchor("glossary", m.group(1)) for m in _GLOSSARY_RE.finditer(note)]
    return out


def _is_tracked(repo_root: Path, rel: str) -> bool:
    """True iff `rel` is tracked (committed or staged) — i.e. Devin-visible.

    Devin's DeepWiki ingests the git-tracked tree only; a gitignored file
    (e.g. root `CLAUDE.md`, a rulesync output) is invisible to it even
    though it exists on disk. `git ls-files --error-unmatch` is the direct
    tracked-file check; `check=False` because a non-zero exit is the
    "not tracked" signal we branch on, not an exceptional condition.
    """
    # ruff S603/S607: fixed-literal git argv, no shell, no untrusted input —
    # `rel` is an anchor token authored by a trusted repo maintainer in
    # `.devin/wiki.json` (not T3 content), `--` guards a leading-dash path,
    # and PATH-resolved `git` is the standard invocation (its absolute path
    # is platform-variable). Scoped inline (not a per-file ignore) so a
    # future subprocess call in this module is still flagged.
    result = subprocess.run(  # noqa: S603
        ["git", "ls-files", "--error-unmatch", "--", rel.rstrip("/")],  # noqa: S607
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return True
    # A directory anchor (trailing "/") is tracked iff `git ls-files` lists
    # one or more tracked paths underneath it — `--error-unmatch` alone can't
    # answer that for a directory.
    listing = subprocess.run(  # noqa: S603
        ["git", "ls-files", "--", rel],  # noqa: S607
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(listing.stdout.strip())


def _prd_heading_numbers(repo_root: Path) -> set[str]:
    """Return every numeric section prefix found in a `PRD.md` ATX heading.

    Matches both `## 7. Cross-Cutting Concerns` (bare number) and
    `### 7.1 Security & Prompt Injection Defense` (dotted number), with or
    without a leading `§`.
    """
    text = (repo_root / "PRD.md").read_text(encoding="utf-8")
    nums: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"^#{1,6}\s+§?\s*(\d+(?:\.\d+)*)\b", line)
        if m:
            nums.add(m.group(1))
    return nums


def check_anchors(data: Mapping[str, object], repo_root: Path) -> list[str]:
    """Resolve every anchor in every `page_notes` entry against the repo.

    This is the drift guard: anchors are authored as free text and can go
    stale (a renamed ADR, a moved doc, a gitignored path) without any other
    check catching it. Resolution is against the **git-tracked** tree, not
    the working tree, so a file that exists on disk but is gitignored (e.g.
    root `CLAUDE.md`) is correctly flagged as invisible to Devin.
    """
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
                        errs.append(
                            f"page {title!r}: `{a.value}` is not tracked "
                            "(gitignored/absent — Devin cannot see it)"
                        )
                elif a.kind == "adr":
                    if not any(adr_dir.glob(f"{a.value}-*.md")):
                        errs.append(f"page {title!r}: ADR-{a.value} has no file under docs/adr/")
                elif a.kind == "prd":
                    if not any(n == a.value or n.startswith(a.value + ".") for n in prd_nums):
                        errs.append(
                            f"page {title!r}: PRD §{a.value} resolves to no heading in PRD.md"
                        )
                elif a.kind == "glossary" and slugify(a.value) not in glossary_slugs:
                    errs.append(f"page {title!r}: glossary.md#{a.value} resolves to no heading")
    return errs


# Token shapes we never want pasted into steering text. Deliberately narrow to
# avoid false positives on prose: provider key prefixes + long base64-ish runs.
_SECRET_RES = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)


def check_secret_shapes(data: Mapping[str, object]) -> list[str]:
    """Flag token-shaped literals in note text (guardrail C in-repo backstop).

    Repo-wide secret hygiene is gitleaks' job; this is narrowly scoped to the
    steering file's own free text, which gitleaks doesn't specially inspect.
    """
    errs: list[str] = []
    for j, note in enumerate(_all_notes(data)):
        for rx in _SECRET_RES:
            if rx.search(note):
                errs.append(
                    f"note[{j}]: token-shaped literal matched {rx.pattern!r} — "
                    "remove it (guardrail C)"
                )
    return errs


def validate_file(path: Path, repo_root: Path) -> list[str]:
    """Load `.devin/wiki.json` and run every check, in order, against it."""
    data = load_wiki(path)
    return [
        *check_structure_and_limits(data),
        *check_references(data),
        *check_anchors(data, repo_root),
        *check_secret_shapes(data),
    ]


def main(argv: Sequence[str] | None = None) -> int:
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
