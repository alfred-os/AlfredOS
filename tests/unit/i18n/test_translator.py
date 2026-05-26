"""Tests for the AlfredOS i18n translator."""

from __future__ import annotations

import pytest

from alfred.i18n import set_language, t
from alfred.i18n.translator import _resolve_locale_dir


@pytest.fixture(autouse=True)
def _reset_language() -> None:
    set_language("en-US")


class TestTranslator:
    def test_returns_message_for_known_key_in_english(self) -> None:
        # The catalog defines status.primary_provider as "primary provider: {provider}".
        assert t("status.primary_provider", provider="deepseek") == "primary provider: deepseek"

    def test_returns_key_as_fallback_for_unknown_message(self) -> None:
        # Missing-message strategy: return the key so the developer sees what to add.
        assert t("missing.key.example") == "missing.key.example"

    def test_substitutes_kwargs_into_message(self) -> None:
        assert "1.50" in t("status.daily_budget", amount="1.50")

    def test_set_language_switches_active_catalog(self) -> None:
        # Switching to a language with no catalog falls back to English.
        set_language("fr-FR")
        # English catalog still wins because no fr-FR catalog exists yet.
        assert "primary provider" in t("status.primary_provider", provider="deepseek")


class TestLocaleResolver:
    """Coverage for the multi-candidate locale-dir resolver.

    Closes devops-1 on PR #89: the prior ``Path(__file__).parents[3] / "locale"``
    resolved to ``/app/.venv/lib/python3.12/locale`` once the package was
    installed into a venv. The resolver now walks a candidate list and returns
    the first existing dir; these tests prove the walk and the empty-list
    fallback behaviour.
    """

    def test_finds_real_locale_dir_in_dev_layout(self) -> None:
        # The worktree itself satisfies candidate 1 (parents[3] / "locale").
        resolved = _resolve_locale_dir()
        assert resolved is not None
        assert (resolved / "en" / "LC_MESSAGES" / "alfred.mo").is_file()

    def test_returns_none_when_no_candidate_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Drive the REAL `_resolve_locale_dir()` down its None-fallback branch
        # by patching `Path.is_dir` to always return False. The previous shape
        # of this test asserted a local fake_resolve() instead of the
        # production function, so a real regression in the production resolver
        # would have slipped through unnoticed.
        from pathlib import Path

        monkeypatch.setattr(Path, "is_dir", lambda _self: False)
        assert _resolve_locale_dir() is None
