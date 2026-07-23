"""Tests for AlfredOS configuration loading."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog.testing
from pydantic_settings import DotEnvSettingsSource, EnvSettingsSource, SecretsSettingsSource

from alfred.config._environment_loader import EnvironmentLoadResult, EnvironmentSource
from alfred.config.settings import Settings, SettingsError, _Without


class TestSettings:
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
    def test_redis_url_defaults_to_localhost(self) -> None:
        """PR-S4-235-1: the daemon-owned ContentStore reads its Redis URL from here."""
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            assert s.redis_url == "redis://localhost:6379/0"

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
    def test_anthropic_api_key_is_optional(self) -> None:
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            assert s.anthropic_api_key is None

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
    def test_proposal_dispatch_interval_s_defaults_to_30(self) -> None:
        """ADR-0021 #171 — supervisor's dispatch cycle cadence defaults to 30s."""
        with patch.dict(
            os.environ, {"ALFRED_DEEPSEEK_API_KEY": "x", "ALFRED_ENVIRONMENT": "test"}, clear=True
        ):
            s = Settings()
            assert s.proposal_dispatch_interval_s == 30

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX-only: Path.home() has no non-env fallback on Windows "
            "(clear=True strips USERPROFILE; POSIX falls back via the pwd db)"
        ),
    )
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


class TestSettingsDelegatesEnvironmentResolution:
    """#469 Blocker 1: ``environment`` is resolved ONLY via ``resolve_environment()``.

    ``Settings.settings_customise_sources`` strips ``environment`` out of the
    env/dotenv/secrets-file sources entirely (the ``_Without`` filter), so pydantic
    itself can never populate the field from ``ALFRED_ENVIRONMENT``/``.env``/the
    secrets file — the ``mode="wrap"`` ``_resolve_environment`` validator is the
    ONLY path that can set it. This closes a security-downgrade surface: before
    this change, a stray ``ALFRED_ENVIRONMENT=development`` in a misplaced ``.env``
    could silently win over an intended ``production`` /etc value via pydantic's
    own env-file source, bypassing the dual-source loader's precedence and
    conflict-audit logic entirely.
    """

    def test_settings_resolves_from_dotenv(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No env var, no /etc file: Settings() reads .env via resolve_environment()."""
        monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
        monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
        # M-7 (final-review): without pinning _DEFAULT_ETC_PATH away from the real
        # host default, a host with an actual /etc/alfred/environment present would
        # green this test VACUOUSLY via the ETC_FILE layer, not the DOTENV layer
        # this test claims to exercise. Point it at an absent tmp path so the .env
        # layer is the only source that can possibly resolve a value here.
        monkeypatch.setattr(
            "alfred.config._environment_loader._DEFAULT_ETC_PATH",
            tmp_path / "no-such-file",
        )
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")

        settings = Settings()
        assert settings.environment == "production"
        result = settings.environment_load_result
        assert result is not None
        assert result.source is EnvironmentSource.DOTENV

    def test_pydantic_cannot_populate_environment_from_dotenv(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """/etc beats .env even though pydantic-settings' own dotenv source sees .env first.

        Exclusion airtight: pydantic-settings' built-in ``env_file=".env"`` source would,
        absent the ``_Without`` filter, populate ``environment`` directly from the CWD
        ``.env`` (``development``) BEFORE ``resolve_environment()``'s /etc-beats-.env
        precedence ever runs. Asserting ``production`` (the /etc value, not the .env
        value) proves the source-level exclusion is airtight, not merely
        validator-order luck.
        """
        monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
        monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
        etc_path = tmp_path / "etc"
        etc_path.write_text("production\n", encoding="utf-8")
        monkeypatch.setattr("alfred.config._environment_loader._DEFAULT_ETC_PATH", etc_path)
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")

        assert Settings().environment == "production"  # NOT development

    def test_explicit_environment_kwarg_wins_over_conflicting_env_var(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An explicit ``environment=`` kwarg wins even over an ACTIVELY RESOLVABLE env var.

        Distinct from ``test_environment_explicit_kwarg_bypasses_loader`` (which has no
        conflicting source to bypass): here ``ALFRED_ENVIRONMENT=production`` is set and
        would resolve cleanly via ``resolve_environment()`` if consulted. This proves the
        ``"environment" not in data`` half of the wrap-validator's guard actually gates
        the loader call, not just the ``isinstance(data, dict)`` half.

        A mutant that drops the ``"environment" not in data`` clause (i.e.
        ``if isinstance(data, dict):``) would call ``resolve_environment()``
        unconditionally, resolve ``"production"`` from the env var, and overwrite the
        explicit ``"test"`` kwarg with it before ``handler(data)`` ever runs —
        ``settings.environment`` would come back ``"production"``, failing the first
        assertion outright. The mutant would also leave ``environment_load_result``
        populated (non-``None``) instead of ``None``, since the loader was consulted;
        the second assertion is a second, independent tripwire on the same mutant.
        """
        monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
        monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")

        settings = Settings(environment="test")

        assert settings.environment == "test"
        assert settings.environment_load_result is None

    def test_environment_load_result_divergence_logs_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M4 (fleet review): a resolver/validated-field divergence logs, not silences.

        The loader and the Literal field validate against the same value set, so this
        "cannot happen today" per the wrap validator's own docstring — proving it
        requires a fake :func:`resolve_environment` whose ``.value`` differs between
        the injection read and the post-validation comparison read (a real
        :class:`~alfred.config._environment_loader.EnvironmentLoadResult` is frozen and
        cannot do this). Before this fix the mismatch silently left
        ``environment_load_result`` at ``None`` with no signal the two had diverged;
        now it logs a structlog warning naming BOTH values (never silently skips).
        """
        monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")

        class _FlakyResult:
            """Duck-types EnvironmentLoadResult with a ``.value`` that changes on
            each read. The wrap validator reads ``.value`` THREE times: twice
            during injection (the ``is not None`` guard, then the dict-assignment
            itself) and once more during the post-validation comparison — so the
            first TWO reads must agree (``"development"``, injected into the
            field) and only the THIRD (the comparison) must diverge
            (``"test"``)."""

            def __init__(self) -> None:
                self._reads = 0

            @property
            def value(self) -> str:
                self._reads += 1
                return "development" if self._reads <= 2 else "test"

            source = EnvironmentSource.ENV_VAR

        fake_result = _FlakyResult()

        def _fake_resolve_environment(**_kwargs: object) -> EnvironmentLoadResult:
            return fake_result  # type: ignore[return-value]

        monkeypatch.setattr("alfred.config.settings.resolve_environment", _fake_resolve_environment)

        with structlog.testing.capture_logs() as logs:
            settings = Settings()

        assert settings.environment == "development"
        assert settings.environment_load_result is None
        warnings = [
            entry for entry in logs if entry["event"] == "settings.environment_load_result_diverged"
        ]
        assert len(warnings) == 1, logs
        assert warnings[0]["resolved_value"] == "test"
        assert warnings[0]["validated_value"] == "development"


class TestWithoutSourceIdentity:
    """I-2 (final-review): ``_Without`` wrappers must not collide under one state-dict key.

    pydantic-settings 2.14.2 keys its per-source ``states`` dict by
    ``source.__name__ if hasattr(source, "__name__") else type(source).__name__``
    (``pydantic_settings/main.py:469``). Before this fix, every ``_Without``
    instance lacked its own ``__name__``, so ``type(source).__name__`` fell back to
    the literal class name ``"_Without"`` for ALL THREE wrappers returned by
    ``settings_customise_sources`` — they collided under one key instead of the
    three distinct keys the wrapped ``EnvSettingsSource`` / ``DotEnvSettingsSource``
    / ``SecretsSettingsSource`` would occupy unwrapped. This is the concrete
    failure mode behind ADR-0053 §6's "forwards the per-source state protocol
    faithfully" claim — faithful forwarding requires distinct identity, not just
    the two ``_set_*`` passthrough methods.
    """

    @staticmethod
    def _state_dict_key(source: object) -> str:
        """Mirror pydantic-settings' own key-derivation formula exactly (main.py:469)."""
        return source.__name__ if hasattr(source, "__name__") else type(source).__name__

    def test_three_wrapped_sources_have_distinct_state_dict_keys(self) -> None:
        env_source = EnvSettingsSource(Settings)
        dotenv_source = DotEnvSettingsSource(Settings)
        secrets_source = SecretsSettingsSource(Settings)

        wrapped = (
            _Without(env_source, ("environment",)),
            _Without(dotenv_source, ("environment",)),
            _Without(secrets_source, ("environment",)),
        )

        keys = [self._state_dict_key(source) for source in wrapped]
        assert len(set(keys)) == 3, f"_Without wrappers collided under one state-dict key: {keys}"
        # Identity mirrors the corresponding UNWRAPPED stock source exactly — the
        # wrapper is invisible to pydantic-settings' own per-source bookkeeping.
        assert keys == ["EnvSettingsSource", "DotEnvSettingsSource", "SecretsSettingsSource"]
