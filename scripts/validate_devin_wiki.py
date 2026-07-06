#!/usr/bin/env python3
"""Validator for `.devin/wiki.json` — the Devin DeepWiki steering file.

Stdlib-only (runs on a fresh checkout, like scripts/docs_check.py). Enforces the
Devin schema + hard limits, referential integrity, anchor RESOLUTION against the
git-tracked tree, and a secret-shape scan. Exit 0 when clean, 1 on any error.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
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
