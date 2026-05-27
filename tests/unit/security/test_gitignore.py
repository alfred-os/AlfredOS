"""Verify ``.gitignore`` carries the secrets.toml exclusion patterns.

If the patterns drift out of the .gitignore, a developer who accidentally
``git add``s a real ``secrets.toml`` would commit it. The patterns themselves
are simple; the test exists to keep the .gitignore from regressing during
future re-shuffles.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GITIGNORE = _REPO_ROOT / ".gitignore"

_REQUIRED_PATTERNS = ("secrets.toml", "secrets.*.toml", "**/secrets.toml")


def test_gitignore_contains_secrets_patterns() -> None:
    text = _GITIGNORE.read_text()
    for pattern in _REQUIRED_PATTERNS:
        assert pattern in text, f"missing pattern in .gitignore: {pattern}"
    # Must sit under a "# Secrets" heading so future re-shuffles keep them grouped.
    assert re.search(r"^# Secrets", text, flags=re.MULTILINE)


def test_i18n_three_secrets_keys_registered() -> None:
    po_path = _REPO_ROOT / "locale" / "en" / "LC_MESSAGES" / "alfred.po"
    text = po_path.read_text()
    for key in (
        "secrets.file_perms_too_open",
        "secrets.file_missing_required",
        "secrets.path_is_directory",
    ):
        assert f'msgid "{key}"' in text, f"missing i18n key: {key}"
