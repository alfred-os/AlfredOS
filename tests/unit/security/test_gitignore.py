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


def test_gitignore_contains_secrets_patterns() -> None:
    """Patterns must appear in order under the ``# Secrets`` heading.

    A single multi-line regex enforces both presence AND grouping — checking
    each pattern independently of the heading would let a future re-shuffle
    move the patterns out from under the section comment without failing.
    """
    text = _GITIGNORE.read_text()
    assert re.search(
        r"(?ms)^# Secrets.*?^secrets\.toml$.*?^secrets\.\*\.toml$.*?^\*\*/secrets\.toml$",
        text,
    ), "secrets patterns must appear in order beneath '# Secrets' heading"


def test_i18n_three_secrets_keys_registered() -> None:
    po_path = _REPO_ROOT / "locale" / "en" / "LC_MESSAGES" / "alfred.po"
    text = po_path.read_text()
    for key in (
        "secrets.file_perms_too_open",
        "secrets.file_missing_required",
        "secrets.path_is_directory",
    ):
        assert f'msgid "{key}"' in text, f"missing i18n key: {key}"
