"""Tests for the AlfredOS i18n translator."""

from __future__ import annotations

import pytest

from alfred.i18n import set_language, t


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
