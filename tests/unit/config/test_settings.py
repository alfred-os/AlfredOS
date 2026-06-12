"""Tests for AlfredOS configuration loading."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from alfred.config.settings import Settings, SettingsError


class TestSettings:
    def test_loads_with_defaults_when_env_missing(self) -> None:
        with patch.dict(
            os.environ,
            {"ALFRED_DEEPSEEK_API_KEY": "test-key", "ALFRED_ENVIRONMENT": "test"},
            clear=True,
        ):
            s = Settings()
            assert s.deepseek_api_key.get_secret_value() == "test-key"
            assert s.daily_budget_usd == 1.0  # default
            assert s.primary_provider == "deepseek"  # default
            assert s.fallback_provider == "anthropic"  # default

    def test_database_url_defaults_to_localhost_postgres(self) -> None:
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            # Pin the FULL default DSN — a substring `"postgresql"` check would
            # also pass on a stale or pointed-at-prod URL, which defeats the
            # purpose of asserting the localhost-default contract.
            assert (
                s.database_url.unicode_string()
                == "postgresql+asyncpg://alfred:alfred@localhost:5432/alfred"
            )

    def test_redis_url_defaults_to_localhost(self) -> None:
        """PR-S4-235-1: the daemon-owned ContentStore reads its Redis URL from here."""
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            assert s.redis_url == "redis://localhost:6379/0"

    def test_redis_url_reads_alfred_redis_url_env(self) -> None:
        """The docker-compose stack sets ALFRED_REDIS_URL to the internal service URL."""
        with patch.dict(
            os.environ,
            {
                "ALFRED_DEEPSEEK_API_KEY": "x",
                "ALFRED_ENVIRONMENT": "test",
                "ALFRED_REDIS_URL": "redis://alfred-redis:6379/0",
            },
            clear=True,
        ):
            s = Settings()
            assert s.redis_url == "redis://alfred-redis:6379/0"

    def test_anthropic_api_key_is_optional(self) -> None:
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            assert s.anthropic_api_key is None

    def test_proposal_dispatch_interval_s_defaults_to_30(self) -> None:
        """ADR-0021 #171 — supervisor's dispatch cycle cadence defaults to 30s."""
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            assert s.proposal_dispatch_interval_s == 30

    def test_proposal_dispatch_interval_s_reads_env_override(self) -> None:
        """Operators can lower the cadence via ALFRED_PROPOSAL_DISPATCH_INTERVAL_S."""
        with patch.dict(
            os.environ,
            {
                "ALFRED_DEEPSEEK_API_KEY": "x",
                "ALFRED_ENVIRONMENT": "test",
                "ALFRED_PROPOSAL_DISPATCH_INTERVAL_S": "5",
            },
            clear=True,
        ):
            s = Settings()
            assert s.proposal_dispatch_interval_s == 5

    def test_proposal_dispatch_interval_s_rejects_zero(self) -> None:
        """A zero / negative interval would tight-loop — pin gt=0 at the schema."""
        from pydantic import ValidationError

        with (
            patch.dict(
                os.environ,
                {
                    "ALFRED_DEEPSEEK_API_KEY": "x",
                    "ALFRED_ENVIRONMENT": "test",
                    "ALFRED_PROPOSAL_DISPATCH_INTERVAL_S": "0",
                },
                clear=True,
            ),
            pytest.raises((SettingsError, ValidationError)),
        ):
            Settings()


class TestPlaceholderApiKeyValidator:
    """DEVEX-001 (PR #89) — Settings rejects the literal `.env.example` placeholder.

    The setup script catches this first for the typical first-run path; the
    validator backstops every other path (direct `docker compose run`, CI
    bootstrap that forgot to override the env, hand-edited compose file).
    """

    def test_rejects_literal_placeholder(self) -> None:
        # Sentinel string is `sk-...` exactly, matching .env.example line 5.
        with patch.dict(
            os.environ,
            {"ALFRED_DEEPSEEK_API_KEY": "sk-...", "ALFRED_ENVIRONMENT": "test"},
            clear=True,
        ):
            with pytest.raises(SettingsError) as excinfo:
                Settings()
            # Validator raises with the `placeholder_api_key` sentinel string
            # so the CLI catch site (cli/main.py::_load_settings_or_die) can
            # branch on it without parsing the full pydantic error blob.
            assert "placeholder_api_key" in str(excinfo.value)

    def test_accepts_real_looking_key(self) -> None:
        # Any string other than the literal placeholder is accepted at this
        # layer — the provider call validates further (auth failure surfaces
        # later via the friendly provider-error path).
        with patch.dict(
            os.environ,
            {"ALFRED_DEEPSEEK_API_KEY": "sk-real-1234", "ALFRED_ENVIRONMENT": "test"},
            clear=True,
        ):
            s = Settings()
            assert s.deepseek_api_key.get_secret_value() == "sk-real-1234"
