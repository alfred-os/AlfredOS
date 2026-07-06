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
# A single ADR reference or a slash-compound one, e.g. "ADR-0040/0042/0043" —
# the compound form is how `.devin/wiki.json` pins multiple load-bearing ADRs
# on one concept page. `group(1)` is split on "/" in `extract_anchors` so
# every ADR number in the compound is resolved individually.
_ADR_RE = re.compile(r"\bADR-(\d{4}(?:/\d{4})*)\b")
# `.devin/wiki.json` always backtick-wraps the path, e.g. `` `PRD.md` §7.1 ``
# — the optional closing backtick sits between ".md" and the section marker.
# Also tolerates the bare "PRD §N" form with no path at all, and a compound
# tail of further sections chained onto the first one, e.g. "§6.5/§6.6",
# "§1-§2", "§9/§10" — separators seen in practice are "/", a hyphen-minus, or
# an en dash (U+2013, used as a range dash, visually near-identical to a
# hyphen-minus so it's excluded from the ambiguous-character lint below).
# `group(1)` captures the *whole* compound tail (first section plus every
# chained one), and `extract_anchors` pulls every `\d+(?:\.\d+)?` run out of
# it so each section in the compound is resolved individually, not just the
# first.
_PRD_RE = re.compile(r"PRD(?:\.md)?`?\s+§(\d+(?:\.\d+)?(?:[/\-–]§?\d+(?:\.\d+)?)*)")  # noqa: RUF001
_GLOSSARY_RE = re.compile(r"glossary(?:\.md)?#([a-z0-9_-]+)")


class WikiError(Exception):
    """Raised when `.devin/wiki.json` cannot be loaded as the expected shape,
    or when an environment precondition validation depends on (git, the
    files anchors resolve against) is broken — never conflated with a
    content problem the checks can report as an ordinary error string.
    """


def load_wiki(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WikiError(f"{path}: not loadable as JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise WikiError(f"{path}: top-level value must be a JSON object")
    return data


def _pages(data: Mapping[str, object]) -> list[dict[str, object]]:
    """Every well-formed page object.

    Silently drops anything that isn't a dict — callers past this point may
    assume every element is a page object. `check_shapes` is what LOUDLY
    flags the dropped (malformed) entries; every other check is free to
    build on this filtered view without re-checking shape itself.
    """
    return [p for _, p in _indexed_pages(data)]


def _indexed_pages(data: Mapping[str, object]) -> list[tuple[int, dict[str, object]]]:
    """Every well-formed page object, paired with its RAW index in `data["pages"]`.

    Enumerating the raw array (not a `_pages()`-filtered list) and skipping
    non-dict entries via list-comprehension filtering keeps every `page[i]`
    label anchored to the SAME physical position `check_shapes` uses for its
    own `page[i]: must be an object` error. Enumerating a filtered list
    instead would drift: a malformed entry earlier in the array shifts every
    later page's filtered-list position out of step with its raw index, so
    two different physical entries could surface under the same `page[i]`
    label. `check_shapes` LOUDLY flags the dropped (malformed) entries
    separately; every index-based check here just skips them.
    """
    raw = data.get("pages", [])
    if not isinstance(raw, list):
        return []
    return [(i, p) for i, p in enumerate(raw) if isinstance(p, dict)]


@dataclass(frozen=True)
class _Note:
    """A note's text plus a human-locatable source label.

    A flat `list[str]` (the prior shape of `_all_notes`) loses which
    repo_notes entry or which page's page_notes a given string came from —
    every downstream error read back as an opaque `note[7]`. `source` is
    that context, e.g. `"repo_notes[2]"` or `"page[3] page_notes[0]"`.

    `source` is deliberately built from the page's RAW positional index, never
    its title — a page's `title` is untrusted free text a secret can be
    pasted into, and this label is echoed verbatim in every error string this
    note's content produces. Echoing the title here would defeat the "never
    echo a matched secret" guarantee `check_secret_shapes` gives: a SIBLING
    finding on the same note (e.g. "content is empty") would leak the title's
    secret even though the secret scan itself never printed it.
    """

    source: str
    content: str


def _all_notes(data: Mapping[str, object]) -> list[_Note]:
    """Every note string, labelled: repo_notes[].content + pages[].page_notes[]."""
    notes: list[_Note] = []
    repo_notes = data.get("repo_notes", [])
    if isinstance(repo_notes, list):
        for k, n in enumerate(repo_notes):
            if isinstance(n, dict) and isinstance(n.get("content"), str):
                notes.append(_Note(f"repo_notes[{k}]", n["content"]))
    for i, page in _indexed_pages(data):
        pnotes = page.get("page_notes", [])
        if isinstance(pnotes, list):
            notes.extend(
                _Note(f"page[{i}] page_notes[{m}]", x)
                for m, x in enumerate(pnotes)
                if isinstance(x, str)
            )
    return notes


def check_shapes(data: Mapping[str, object]) -> list[str]:
    """Flag malformed `pages` / `repo_notes` / `page_notes` shapes LOUDLY.

    `_pages()` and `_all_notes()` silently filter out anything that doesn't
    match the expected shape so every other check can assume well-formed
    input — but that means a non-dict `pages[]` entry, a non-list `pages` /
    `repo_notes` / `page_notes`, or a non-string `page_notes[]` entry would
    otherwise vanish without a trace and the file would pass validation
    clean. This restores the loud failure the rest of the module is allowed
    to skip.
    """
    errs: list[str] = []

    raw_pages = data.get("pages", [])
    if not isinstance(raw_pages, list):
        errs.append(f"pages: must be a list, got {type(raw_pages).__name__}")
    else:
        for i, page in enumerate(raw_pages):
            if not isinstance(page, dict):
                errs.append(f"page[{i}]: must be an object, got {type(page).__name__}")
                continue
            pnotes = page.get("page_notes", [])
            if not isinstance(pnotes, list):
                errs.append(f"page[{i}]: page_notes must be a list, got {type(pnotes).__name__}")
                continue
            for j, note in enumerate(pnotes):
                if not isinstance(note, str):
                    errs.append(
                        f"page[{i}] page_notes[{j}]: must be a string, got {type(note).__name__}"
                    )

    raw_repo_notes = data.get("repo_notes", [])
    if not isinstance(raw_repo_notes, list):
        errs.append(f"repo_notes: must be a list, got {type(raw_repo_notes).__name__}")

    return errs


def check_structure_and_limits(data: Mapping[str, object]) -> list[str]:
    errs: list[str] = []
    indexed_pages = _indexed_pages(data)

    if len(indexed_pages) > MAX_PAGES:
        errs.append(f"too many pages: {len(indexed_pages)} > {MAX_PAGES}")

    # (index, title) pairs only — never the bare title list — so a duplicate
    # can be reported by position without ever re-printing the title text
    # (title is untrusted free text a secret can be pasted into; see `_Note`).
    titled: list[tuple[int, str]] = []
    for i, page in indexed_pages:
        title = page.get("title")
        purpose = page.get("purpose")
        if not isinstance(title, str) or not title.strip():
            errs.append(f"page[{i}]: title is missing or empty")
        else:
            titled.append((i, title))
        if not isinstance(purpose, str) or not purpose.strip():
            errs.append(f"page[{i}]: purpose is missing or empty")

    first_index_by_title: dict[str, int] = {}
    for i, t in titled:
        if t in first_index_by_title:
            errs.append(f"duplicate page title at page[{first_index_by_title[t]}] and page[{i}]")
        else:
            first_index_by_title[t] = i

    notes = _all_notes(data)
    if len(notes) > MAX_NOTES:
        errs.append(f"too many notes: {len(notes)} > {MAX_NOTES}")
    for note in notes:
        if not note.content.strip():
            errs.append(f"{note.source}: content is empty")
        if len(note.content) > MAX_NOTE_CHARS:
            errs.append(f"{note.source}: {len(note.content)} code points > {MAX_NOTE_CHARS}")

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
    # Split the slash-compound capture ("0040/0042/0043") into one Anchor per
    # ADR number so each is resolved independently by `check_anchors`.
    out += [
        Anchor("adr", adr_num) for m in _ADR_RE.finditer(note) for adr_num in m.group(1).split("/")
    ]
    # `m.group(1)` is the whole compound tail (e.g. "6.5/§6.6" or "1-§2");
    # pull every section number out of it independently, mirroring the ADR
    # slash-compound handling above.
    out += [
        Anchor("prd", num)
        for m in _PRD_RE.finditer(note)
        for num in re.findall(r"\d+(?:\.\d+)?", m.group(1))
    ]
    out += [Anchor("glossary", m.group(1)) for m in _GLOSSARY_RE.finditer(note)]
    return out


def _tracked_files(repo_root: Path) -> frozenset[str]:
    """Every git-tracked path in `repo_root`, relative to it.

    Loaded ONCE per `check_anchors` call rather than once (or twice, for a
    directory anchor) per path anchor — a single `git ls-files -z` instead
    of a `git ls-files --error-unmatch` subprocess per anchor. `-z` NUL-
    delimits so a path containing whitespace can't be mis-split.

    A failure here (git unavailable, `repo_root` not a repo) is an
    environment problem, not a "nothing is tracked" content finding —
    conflating the two would silently flag every path anchor as untracked
    instead of surfacing the real cause loudly.
    """
    # ruff S603/S607: fixed-literal git argv, no shell, no untrusted input —
    # `repo_root` comes from the CLI/test harness (not T3 content). Scoped
    # inline (not a per-file ignore) so a future subprocess call in this
    # module is still flagged.
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],  # noqa: S607
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise WikiError(f"cannot resolve path anchors: git is unavailable: {exc}") from exc
    if result.returncode != 0:
        raise WikiError(
            f"cannot resolve path anchors: `git ls-files` failed in {repo_root} "
            f"(exit {result.returncode}): {result.stderr.strip()}"
        )
    return frozenset(p for p in result.stdout.split("\0") if p)


def _is_tracked(tracked: frozenset[str], rel: str) -> bool:
    """True iff `rel` is tracked (committed or staged) — i.e. Devin-visible.

    Devin's DeepWiki ingests the git-tracked tree only; a gitignored file
    (e.g. root `CLAUDE.md`, a rulesync output) is invisible to it even
    though it exists on disk. A trailing "/" anchor is a directory
    reference, tracked iff any tracked path sits underneath it.
    """
    if rel.endswith("/"):
        return any(p.startswith(rel) for p in tracked)
    return rel in tracked


def _prd_heading_numbers(text: str) -> set[str]:
    """Return every numeric section prefix found in a `PRD.md` ATX heading.

    Matches both `## 7. Cross-Cutting Concerns` (bare number) and
    `### 7.1 Security & Prompt Injection Defense` (dotted number), with or
    without a leading `§`. Takes the already-read file text (rather than
    `repo_root`) so a missing-file guard lives in exactly one place:
    `check_anchors`.
    """
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

    A missing `PRD.md` / `docs/glossary.md` is reported as a clear error
    (that anchor kind is then skipped, not crashed on) rather than an
    unhandled `FileNotFoundError` — `.devin/wiki.json` still needs to be
    validatable even if one of those anchor targets has been renamed away.
    """
    errs: list[str] = []

    glossary_path = repo_root / "docs/glossary.md"
    try:
        glossary_text = glossary_path.read_text(encoding="utf-8")
    except OSError:
        glossary_slugs: set[str] = set()
        errs.append(f"cannot resolve glossary anchors: {glossary_path} not found")
    else:
        glossary_slugs = extract_headings(glossary_text)

    prd_path = repo_root / "PRD.md"
    try:
        prd_text = prd_path.read_text(encoding="utf-8")
    except OSError:
        prd_nums: set[str] = set()
        errs.append(f"cannot resolve PRD anchors: {prd_path} not found")
    else:
        prd_nums = _prd_heading_numbers(prd_text)

    adr_dir = repo_root / "docs/adr"
    tracked = _tracked_files(repo_root)

    for i, page in _indexed_pages(data):
        pnotes = page.get("page_notes", [])
        if not isinstance(pnotes, list):
            continue
        for note in (n for n in pnotes if isinstance(n, str)):
            for a in extract_anchors(note):
                if a.kind == "path":
                    if not _is_tracked(tracked, a.value):
                        errs.append(
                            f"page[{i}]: `{a.value}` is not tracked "
                            "(gitignored/absent — Devin cannot see it)"
                        )
                elif a.kind == "adr":
                    if not any(adr_dir.glob(f"{a.value}-*.md")):
                        errs.append(f"page[{i}]: ADR-{a.value} has no file under docs/adr/")
                elif a.kind == "prd":
                    if not any(n == a.value or n.startswith(a.value + ".") for n in prd_nums):
                        errs.append(f"page[{i}]: PRD §{a.value} resolves to no heading in PRD.md")
                elif a.kind == "glossary" and slugify(a.value) not in glossary_slugs:
                    errs.append(f"page[{i}]: glossary.md#{a.value} resolves to no heading")
    return errs


# Token shapes we never want pasted into steering text. Deliberately narrow to
# avoid false positives on prose: provider key prefixes + long base64-ish runs.
# Each entry pairs a human-readable label (used in the error message so a
# human doesn't have to decode a raw regex) with the pattern itself.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # `-` is allowed in the run (not just alphanumerics) so this also catches
    # hyphenated Anthropic keys, e.g. `sk-ant-api03-...`, not just OpenAI's
    # `sk-<alphanumeric>` shape.
    ("OpenAI/Anthropic-style key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9-]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
)


def _secret_findings(source: str, text: str) -> list[str]:
    """Every `_SECRET_PATTERNS` match in `text`, as a labelled, non-echoing error."""
    return [
        f"{source}: token-shaped literal matched {label} — remove it (guardrail C)"
        for label, rx in _SECRET_PATTERNS
        if rx.search(text)
    ]


def check_secret_shapes(data: Mapping[str, object]) -> list[str]:
    """Flag token-shaped literals in page/note text (guardrail C in-repo backstop).

    Repo-wide secret hygiene is gitleaks' job; this is narrowly scoped to
    this steering file's own free text — `page_notes`/`repo_notes` content
    AND page `title`/`purpose` (a secret pasted into either of the latter
    would otherwise sail through unscanned) — which gitleaks doesn't
    specially inspect. The matched literal itself is never echoed back, only
    a human-readable label for which pattern tripped.
    """
    # Deliberately locate a title/purpose finding by page RAW INDEX only,
    # never by the page's own title — the title is exactly what may be
    # carrying the secret this loop is scanning `title` for, and echoing it
    # as the label would defeat the "never echo the matched secret" guarantee
    # below. `_indexed_pages` (not `enumerate(_pages(data))`) so this index
    # is anchored to the same raw `data["pages"]` position every other
    # index-based check uses — see `_indexed_pages`'s docstring.
    errs: list[str] = []
    for i, page in _indexed_pages(data):
        for field in ("title", "purpose"):
            value = page.get(field)
            if isinstance(value, str):
                errs.extend(_secret_findings(f"page[{i}] {field}", value))
    for note in _all_notes(data):
        errs.extend(_secret_findings(note.source, note.content))
    return errs


def validate_file(path: Path, repo_root: Path) -> list[str]:
    """Load `.devin/wiki.json` and run every check, in order, against it."""
    data = load_wiki(path)
    return [
        *check_shapes(data),
        *check_structure_and_limits(data),
        *check_references(data),
        *check_anchors(data, repo_root),
        *check_secret_shapes(data),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Path to .devin/wiki.json")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help=(
            "Repository root to resolve anchors (paths/ADRs/PRD sections/glossary "
            "slugs) and git-tracked status against. Defaults to the current "
            "working directory."
        ),
    )
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
