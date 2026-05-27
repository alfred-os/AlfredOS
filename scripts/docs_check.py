#!/usr/bin/env python3
"""Anchor-aware markdown link checker for AlfredOS docs.

Walks the given roots (files or directories) and, for each markdown file,
extracts every `[text](path)` and `[text](path#anchor)` link whose target is
local (not `http(s)://`, not `mailto:`, not a pure anchor on the same page).
For each local link:

  - The target file must exist relative to the source file.
  - If the link carries an `#anchor` fragment, the anchor must be present as a
    heading slug in the target file's heading set.

The slugifier mirrors GitHub's algorithm closely enough for our docs surface:

  1. Lower-case the heading text.
  2. Strip every character that is not alphanumeric, hyphen, underscore, or
     whitespace.
  3. Collapse whitespace runs to single `-` characters.

The script exits 0 when every link resolves, 1 on any broken link. Errors are
reported as `<source>:<line>: <message>` lines for editor jump-to-line
compatibility.

No third-party dependencies: this is stdlib-only so `make docs-check` works on
a fresh checkout before `uv sync --dev` runs.

Per the AlfredOS PR-E plan (Task 8, Open Question Q3), this script is the
canonical link-checker because the available Node markdown-link-check actions
do not verify `#anchor` fragments — and AlfredOS's glossary anchors
(`#authorization-role`, `#canonical-user-id`) are load-bearing surfaces that
the spec forward-references.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

# Match `[text](target)` where target may carry `#anchor`. The text and target
# groups are non-greedy on `]` and `)` respectively so adjacent links don't
# collapse into one match. Reference-style links (`[text][ref]`) and bare
# autolinks (`<https://...>`) are intentionally out of scope — AlfredOS docs
# use inline `[text](url)` exclusively.
_LINK_RE = re.compile(r"\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")

# Match ATX-style headings `# Heading text` through `###### Heading text`. The
# trailing `#` syntax (`# Heading #`) is also recognised; we strip trailing
# `#` runs before slugifying. Setext headings (underline-style) are NOT
# matched — AlfredOS docs use ATX exclusively.
_HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<text>.+?)\s*#*\s*$")

# Match fenced code blocks (```...``` or ~~~...~~~). Links inside fences are
# code samples, not real links, so they must not be link-checked.
_FENCE_RE = re.compile(r"^(?P<fence>```|~~~)")


@dataclass(frozen=True)
class Link:
    """A single `[text](target#anchor)` occurrence in a markdown file."""

    source: Path
    line_no: int
    target: str
    anchor: str | None


@dataclass(frozen=True)
class BrokenLink:
    """A link that failed to resolve, with a human-readable reason."""

    source: Path
    line_no: int
    raw_target: str
    reason: str


def slugify(heading_text: str) -> str:
    """Slugify a heading per GitHub's algorithm (close-enough subset).

    The real algorithm is more involved (it preserves CJK characters,
    normalises certain emoji, etc.), but for AlfredOS's English-only docs the
    rules collapse to:

      1. Strip markdown emphasis markers (`*`, `` ` ``) so headings like
         ``## `OutboundDlp` `` slug to `outbounddlp` rather than to a
         backtick-laden mess. Underscores are NOT stripped — GitHub keeps
         them as part of the slug (e.g. `#foo_bar` is a valid anchor for
         a heading containing `foo_bar`).
      2. Lower-case.
      3. Drop every character that is not alphanumeric, hyphen,
         underscore, or whitespace.
      4. Replace each whitespace character with a single `-` (NOT a
         collapse: GitHub preserves consecutive hyphens that arise when
         punctuation between words is stripped — e.g. "Security & Prompt"
         becomes `security--prompt` because the `&` is removed and the two
         surrounding spaces each map to one `-`).

    Step 4 is the load-bearing detail: collapsing runs of whitespace into a
    single hyphen produces slugs that DON'T match what GitHub renders,
    silently making correct links look broken.
    """
    text = re.sub(r"[*`]", "", heading_text)
    text = text.lower()
    # GitHub's slug rules keep underscores (they're part of `\w`); anchors
    # like `#foo_bar` resolve to a heading with `_` intact. We allow
    # alphanumerics, hyphen, underscore, and whitespace; everything else
    # is dropped. Whitespace becomes a single `-` (no collapse — see the
    # docstring's step 4).
    text = re.sub(r"[^a-z0-9_\-\s]", "", text)
    text = text.strip()
    return re.sub(r"\s", "-", text)


def extract_headings(md_text: str) -> set[str]:
    """Return the slug set for every ATX heading in `md_text`.

    Headings inside fenced code blocks are skipped — `# foo` inside a `bash`
    fence is shell syntax, not a heading.
    """
    slugs: set[str] = set()
    in_fence = False
    for line in md_text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = _HEADING_RE.match(line)
        if m is None:
            continue
        slugs.add(slugify(m.group("text")))
    return slugs


def _strip_inline_code(line: str) -> str:
    """Remove backtick-delimited inline code spans from a line.

    Inline code such as ``TaggedContent[T2](msg.content)`` (a Python
    type-application + call, not a markdown link) trips the link regex
    otherwise. We delete the span contents in-place so the remaining text
    preserves column-for-column shape (replacement keeps the line length
    where it can — we substitute with spaces).
    """
    return re.sub(r"`+[^`]*`+", lambda m: " " * len(m.group(0)), line)


def extract_links(source: Path, md_text: str) -> Iterator[Link]:
    """Yield every `[text](target)` occurrence in `md_text`.

    Skips:

      - Links inside fenced code blocks (those are documentation of link
        syntax, not real links to verify).
      - Link-shaped substrings inside inline code spans (`` ` `` …) — those
        are code samples or Python type-application syntax such as
        ``TaggedContent[T2](msg.content)``, not markdown links.
    """
    in_fence = False
    for line_no, raw_line in enumerate(md_text.splitlines(), start=1):
        if _FENCE_RE.match(raw_line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        line = _strip_inline_code(raw_line)
        for m in _LINK_RE.finditer(line):
            target = m.group("target")
            # Pure same-page anchor links (`[…](#section)`) carry no file
            # component — split on the first `#`.
            if "#" in target:
                file_part, _, anchor = target.partition("#")
            else:
                file_part, anchor = target, ""
            yield Link(
                source=source,
                line_no=line_no,
                target=file_part,
                anchor=anchor or None,
            )


def _is_external(target: str) -> bool:
    """Return True for URLs we don't try to verify (http/https/mailto/tel/etc.)."""
    return bool(re.match(r"^[a-z][a-z0-9+.-]*:", target))


def check_link(
    repo_root: Path,
    link: Link,
    _heading_cache: dict[Path, set[str]],
) -> BrokenLink | None:
    """Resolve `link` and return a BrokenLink on failure, or None on success.

    `_heading_cache` is mutated in-place to memoise heading extraction across
    multiple links pointing at the same target file.
    """
    if _is_external(link.target):
        return None

    # Same-page anchor — target is empty, anchor is set. Resolve against the
    # source file itself. Always `.resolve()` so the relative_to() guard
    # below is comparing two absolute paths.
    if link.target == "" and link.anchor:
        target_path = link.source.resolve()
    else:
        # The link is relative to the source file's parent directory.
        target_path = (link.source.parent / link.target).resolve()

    # Reject obvious traversal escapes outside the repo (defence-in-depth;
    # nothing in our docs should `../` above the repo root).
    try:
        target_path.relative_to(repo_root)
    except ValueError:
        return BrokenLink(
            source=link.source,
            line_no=link.line_no,
            raw_target=link.target + (f"#{link.anchor}" if link.anchor else ""),
            reason=f"link escapes repo root: {target_path}",
        )

    if not target_path.exists():
        return BrokenLink(
            source=link.source,
            line_no=link.line_no,
            raw_target=link.target + (f"#{link.anchor}" if link.anchor else ""),
            reason=f"target file does not exist: {target_path}",
        )

    # Non-markdown targets (images, JSON fixtures, .py files, .yaml configs)
    # only get the exists() check — no anchor lookup possible.
    if target_path.suffix.lower() != ".md":
        if link.anchor:
            return BrokenLink(
                source=link.source,
                line_no=link.line_no,
                raw_target=link.target + f"#{link.anchor}",
                reason=f"anchor on non-markdown target: {target_path}",
            )
        return None

    if link.anchor is None:
        return None

    # Heading lookup — memoise.
    if target_path not in _heading_cache:
        _heading_cache[target_path] = extract_headings(target_path.read_text(encoding="utf-8"))

    if link.anchor not in _heading_cache[target_path]:
        return BrokenLink(
            source=link.source,
            line_no=link.line_no,
            raw_target=link.target + f"#{link.anchor}",
            reason=(
                f"anchor #{link.anchor} not found in {target_path.relative_to(repo_root)} "
                "(headings are slugified with GitHub's algorithm)"
            ),
        )
    return None


_DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
    }
)


def iter_markdown_files(roots: Iterable[Path], exclude: Iterable[Path]) -> Iterator[Path]:
    """Yield every `*.md` file rooted at the given paths.

    A root may be a file (yielded as-is if it's `.md`) or a directory (walked
    recursively). Hidden cache/build directories (`.git`, `.venv`,
    `node_modules`, …) are always skipped. Per-invocation excludes (passed
    via `--exclude`) skip explicit subtrees — `docs/superpowers/plans/` is
    the typical caller-supplied skip because those are working/draft docs
    whose internal forward-references churn at every PR.
    """
    exclude_resolved = {p.resolve() for p in exclude}
    for root in roots:
        if root.is_file() and root.suffix.lower() == ".md":
            if root.resolve() in exclude_resolved:
                continue
            yield root
            continue
        if not root.is_dir():
            continue
        for path in root.rglob("*.md"):
            if any(part in _DEFAULT_SKIP_DIRS for part in path.parts):
                continue
            # Exclude if the path lives under any excluded subtree.
            path_resolved = path.resolve()
            if any(
                exc in path_resolved.parents or exc == path_resolved for exc in exclude_resolved
            ):
                continue
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "roots",
        nargs="+",
        type=Path,
        help="Files and/or directories to scan recursively for *.md.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repo root used for path-escape detection (default: cwd).",
    )
    parser.add_argument(
        "--exclude",
        type=Path,
        action="append",
        default=[],
        help=(
            "Subtree or file to skip. May be given multiple times. Typical use: "
            "exclude docs/superpowers/plans/ to keep working-doc churn out of "
            "the link-checker's scope."
        ),
    )
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    heading_cache: dict[Path, set[str]] = {}
    broken: list[BrokenLink] = []
    scanned_files = 0
    scanned_links = 0

    for md_path in iter_markdown_files(args.roots, args.exclude):
        scanned_files += 1
        text = md_path.read_text(encoding="utf-8")
        for link in extract_links(md_path, text):
            scanned_links += 1
            err = check_link(repo_root, link, heading_cache)
            if err is not None:
                broken.append(err)

    if broken:
        header = f"docs-check: {len(broken)} broken link(s) across {scanned_files} file(s):"
        print(header, file=sys.stderr)
        for b in broken:
            try:
                src_display = b.source.resolve().relative_to(repo_root)
            except ValueError:
                src_display = b.source
            print(f"  {src_display}:{b.line_no}: [{b.raw_target}] — {b.reason}", file=sys.stderr)
        return 1

    print(f"docs-check: OK ({scanned_links} link(s) across {scanned_files} file(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
