"""Tests for AlfredOS configuration loading."""

from __future__ import annotations

import os
from unittest.mock import patch

from alfred.config.settings import Settings


class TestSettings:
    def test_loads_with_defaults_when_env_missing(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "test-key"}, clear=True):
            s = Settings()
            assert s.deepseek_api_key.get_secret_value() == "test-key"
            assert s.daily_budget_usd == 1.0  # default
            assert s.primary_provider == "deepseek"  # default
            assert s.fallback_provider == "anthropic"  # default

    def test_database_url_defaults_to_localhost_postgres(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x"}, clear=True):
            s = Settings()
            assert "postgresql" in s.database_url.unicode_string()

    def test_anthropic_api_key_is_optional(self) -> None:
        with patch.dict(os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x"}, clear=True):
            s = Settings()
            assert s.anthropic_api_key is None
