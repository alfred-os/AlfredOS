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


class TestQuarantineProviderSettings:
    """#586/#587: quarantine provider selection and enforcement settings."""

    @staticmethod
    def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up minimal env for Settings construction."""
        monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
        monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")

    def test_quarantine_provider_defaults_to_anthropic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._base_env(monkeypatch)
        settings = Settings()
        assert settings.quarantine_provider == "anthropic"

    def test_quarantine_provider_accepts_deepseek(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
        settings = Settings()
        assert settings.quarantine_provider == "deepseek"

    def test_quarantine_provider_rejects_unknown_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "openai")
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)):
            Settings()

    def test_require_quarantine_provider_separation_defaults_to_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._base_env(monkeypatch)
        settings = Settings()
        assert settings.require_quarantine_provider_separation is False

    def test_require_quarantine_provider_separation_accepts_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")
        settings = Settings()
        assert settings.require_quarantine_provider_separation is True

    def test_quarantine_provider_literal_matches_allowed_quarantined_providers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Drift cross-check (prov-003): THREE independently-maintained copies of the
        quarantine-provider closed set — Settings.quarantine_provider's Literal,
        alfred.cli._validators._ALLOWED_QUARANTINED_PROVIDERS (the CLI validator), and
        alfred.state.proposal_payloads._ALLOWED_QUARANTINED_PROVIDERS (the Pydantic
        proposal-payload validator, the non-CLI producer path) — must stay equal.

        All three are pinned HERE because nothing else pins them: proposal_payloads'
        own source comment claims a lockstep test in tests.unit.state.test_proposal_payloads,
        but no such test exists (verified by grep at the time this was extended) — a
        comment asserting a gate that isn't there is worse than no comment, so this test
        is now that gate. Widening the closed set for a new provider must touch all three
        constants in one commit or this fails.

        A three-way equality, not a chain of two-way ones: a chain lets a middle copy be
        edited and drag both ends along without the drift ever surfacing as a failure."""
        from typing import get_args

        from alfred.cli import _validators
        from alfred.state import proposal_payloads

        self._base_env(monkeypatch)
        literal_values = frozenset(
            get_args(Settings.model_fields["quarantine_provider"].annotation)
        )
        assert (
            literal_values
            == _validators._ALLOWED_QUARANTINED_PROVIDERS
            == proposal_payloads._ALLOWED_QUARANTINED_PROVIDERS
        )
        # Oracle guard: a three-way equality of three empty/None-ish objects would also
        # pass. Pin the live content so the test cannot go vacuous if a refactor turns
        # any copy into an empty container.
        assert literal_values == frozenset({"anthropic", "deepseek"})

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n"])
    def test_deepseek_base_url_rejects_blank(
        self, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        """A blank ``ALFRED_DEEPSEEK_BASE_URL`` refuses at Settings construction.

        Both consumers treat "present" as "usable" — ``build_router`` for the privileged
        DeepSeek client, ``_resolve_quarantine_base_url`` for the #587 quarantine child —
        and ``AsyncOpenAI(base_url="")`` constructs happily, failing only per call, where
        the quarantine retry loop launders it into a generic ``cannot_extract``. Refusing
        here puts the failure on the audited ``settings_invalid`` boot path instead.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", blank)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)):
            Settings()

    def test_deepseek_base_url_accepts_a_real_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Oracle guard for the blank-rejection above: a normal override still passes,
        so the test pair cannot both stay green under a validator that rejects
        everything."""
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", "https://proxy.internal/v1")
        assert Settings().deepseek_base_url == "https://proxy.internal/v1"

    @pytest.mark.parametrize(
        "credentialed",
        [
            "https://apikey:@relay.internal/v1",  # the nginx/Envoy inline-basic-auth shape
            "https://user:hunter2@relay.internal:8443/v1",  # full user:pass
            "https://token@relay.internal/v1",  # bare user, no password
            "http://user:pass@127.0.0.1:8080",  # no path, plain http
        ],
    )
    def test_deepseek_base_url_rejects_embedded_credentials(
        self, monkeypatch: pytest.MonkeyPatch, credentialed: str
    ) -> None:
        """A userinfo-bearing ``ALFRED_DEEPSEEK_BASE_URL`` refuses at Settings construction.

        Not a hypothetical: an egress-relay-fronted deployment fronting a self-hosted proxy
        with inline basic auth (``https://apikey:@relay.internal/v1``) is the conventional
        nginx/Envoy shape, and exactly the flexibility this setting exists to give. #587
        threads the value into the quarantine child's SPAWN ENVIRONMENT as
        ``ALFRED_QUARANTINE_BASE_URL``, so it would cross a process boundary and become
        readable via ``/proc/<pid>/environ`` (CodeRabbit r3). Redacting the
        ``_ProviderFactory`` repr fixed the DISPLAY of that value, not the data flow —
        refusing at the boundary does, on the audited ``settings_invalid`` boot path.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", credentialed)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)) as exc_info:
            Settings()

        # The refusal must not itself become the leak it prevents. Asserted against the
        # VALIDATOR'S OWN ``msg``, with pydantic's ``input`` echo excluded — the same
        # ``errors(include_input=False)`` idiom, and the same reasoning, as
        # ``alfred.cli.daemon._commands._settings_error_field_name``: pydantic's envelope
        # re-prints the offending value for EVERY field on this model (the already-
        # documented ``database_url``-DSN-password case), so the daemon boot path never
        # interpolates ``str(exc)`` at all. What is in scope here is that the message this
        # PR adds does not ALSO carry the credential into the one sink that does render it
        # (``load_settings_or_die``'s interactive echo, operator-terminal only).
        raised = exc_info.value
        validation_error = raised if isinstance(raised, ValidationError) else raised.__cause__
        assert isinstance(validation_error, ValidationError), raised
        messages = " ".join(
            error["msg"]
            for error in validation_error.errors(include_input=False, include_url=False)
        )
        assert "hunter2" not in messages, messages
        assert "apikey" not in messages, messages
        # Actionable, not merely loud: names the field and where the credential belongs.
        assert "deepseek_base_url" in messages, messages
        assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in messages, messages

    @pytest.mark.parametrize(
        "benign",
        [
            "https://api.deepseek.com/v1",  # the shipped default
            "https://relay.internal",  # no path at all
            "https://relay.internal:8443/team-a/v1",  # path-based routing prefix
            "http://127.0.0.1:8080/v1",  # plain-http loopback relay
        ],
    )
    def test_deepseek_base_url_accepts_urls_without_userinfo(
        self, monkeypatch: pytest.MonkeyPatch, benign: str
    ) -> None:
        """Oracle guard: the credential check does not over-reach into a PATH.

        A path (relay routing prefix) is legitimate for real proxy setups and is not
        credential-shaped the way ``user:pass@`` is — an over-broad guard would refuse
        working deployments, and the rejection tests above/below would stay green under
        it. Each row here must still construct.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", benign)
        assert Settings().deepseek_base_url == benign

    @pytest.mark.parametrize(
        "query_or_fragment",
        [
            "https://relay.internal/v1?api_key=sk-abcd1234",  # a real API-credential shape
            "https://relay.internal/v1?region=eu",  # not credential-shaped, still rejected
            "https://relay.internal/v1#token=sk-abcd1234",  # fragment, same exposure vector
        ],
    )
    def test_deepseek_base_url_rejects_query_or_fragment(
        self, monkeypatch: pytest.MonkeyPatch, query_or_fragment: str
    ) -> None:
        """A query string or fragment refuses too — CodeRabbit PR-review r1.

        ``?api_key=...`` is at least as common a real credential shape as inline
        userinfo, and empirically has NO legitimate function on this field: the openai
        SDK's URL-joining silently drops everything from the query onward (verified via
        ``AsyncOpenAI(base_url=...).base_url.join(...)`` — a query-bearing base_url never
        reaches DeepSeek's API with its query OR its preceding path intact), while still
        crossing into the child's spawn environment and this factory's repr. Pure risk,
        zero function — reject it regardless of whether THIS particular value looks
        credential-shaped, since the mechanism that would leak it doesn't care.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", query_or_fragment)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)) as exc_info:
            Settings()
        assert "deepseek_base_url" in str(exc_info.value)

    def test_deepseek_base_url_rejects_an_unparseable_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An un-``urlsplit``-able value refuses too, typed and field-named.

        Fail-closed: a URL we cannot parse is exactly the one we cannot prove is
        credential-free. Letting ``urlsplit``'s own ``ValueError`` escape would still
        refuse, but the operator would read "Invalid IPv6 URL" with no field name.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", "https://[::1/v1")
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)) as exc_info:
            Settings()
        assert "deepseek_base_url" in str(exc_info.value)

    def test_deepseek_base_url_rejects_a_malformed_port(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A syntactically-parseable URL with a non-numeric port still refuses.

        ``urlsplit()`` itself does not eagerly validate the port — only touching the
        lazy ``.port`` property does — so without this check a value like
        ``https://host:notaport/v1`` would sail through Settings and only fail later,
        deep in the httpx/openai SDK, as a confusing runtime error instead of a
        boot-time refusal naming the field (CodeRabbit r4).
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", "https://relay.internal:notaport/v1")
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)) as exc_info:
            Settings()
        assert "deepseek_base_url" in str(exc_info.value)

    @pytest.mark.parametrize(
        "unusable",
        [
            "not-a-url",  # no scheme, no hostname — parses "clean" with everything empty
            "ftp://relay.internal/v1",  # a scheme the SDK cannot dial
            "https://",  # scheme present, hostname empty
        ],
    )
    def test_deepseek_base_url_rejects_scheme_or_hostname_missing(
        self, monkeypatch: pytest.MonkeyPatch, unusable: str
    ) -> None:
        """A syntactically-valid-but-undialable URL refuses too.

        Neither the blank check nor the credential check catches a value like
        "not-a-url" (parses clean, no userinfo, but no scheme/host to dial either) —
        it would otherwise reach the SAME laundered-into-``cannot_extract`` failure
        mode the blank-value guard exists to prevent (CodeRabbit r4).
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", unusable)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)) as exc_info:
            Settings()
        assert "deepseek_base_url" in str(exc_info.value)

    def test_deepseek_base_url_strips_surrounding_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A value with incidental leading/trailing whitespace is stored stripped.

        Whitespace survives the ``not v.strip()`` blank check if it wraps real content
        (e.g. a copy-paste artifact from ``.env``) — strip it before storing so the
        stored value is exactly what gets threaded into HTTP clients and the child's
        spawn environment, not a string with invisible leading/trailing bytes.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", "  https://relay.internal/v1  ")
        assert Settings().deepseek_base_url == "https://relay.internal/v1"

    def test_deepseek_model_strips_surrounding_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The sibling field gets the same strip-and-STORE treatment (CodeRabbit).

        ``_reject_blank_deepseek_model`` originally tested ``v.strip()`` but returned
        the RAW value, so ``" deepseek-chat "`` passed the blank check and reached both
        the privileged and quarantine provider paths as an invalid model id — a 4xx on
        every extraction, which the quarantine dispatch loop launders into a generic
        ``cannot_extract``. That is precisely the boot-misconfiguration-wearing-a-
        runtime-failure-costume this validator exists to stop, so the whitespace case
        has to be pinned, not just the empty one.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", "  deepseek-chat  ")
        assert Settings().deepseek_model == "deepseek-chat"

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n"])
    def test_deepseek_model_rejects_blank(
        self, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        """A blank ``ALFRED_DEEPSEEK_MODEL`` refuses at Settings construction.

        The structural twin of the ``deepseek_base_url`` pair above, on the other
        ``deepseek_*`` field BOTH provider paths reuse — ``build_router`` for the
        privileged DeepSeek client, ``_resolve_quarantine_model`` for the #587 quarantine
        child. Nothing downstream can catch it: the field is a required ``str``, so no
        ``is None`` refusal fires, and the blank simply becomes an unusable model id that
        fails per call, where the quarantine retry loop launders it into a generic
        ``cannot_extract``.

        This validator is the PRIMARY guard specifically because the resolver-level
        ``ValueError`` in ``_resolve_quarantine_model`` is caught by NO arm of the daemon
        boot cascade — on its own it crashed the boot uncaught (exit 1, zero
        ``daemon.boot.failed`` rows, the #368 anti-pattern). Refusing here routes it to
        the audited ``settings_invalid`` refusal instead
        (``test_boot_refuses_audited_when_deepseek_model_is_blank`` pins the end-to-end
        boot behaviour).
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", blank)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)):
            Settings()

    def test_deepseek_model_accepts_a_real_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Oracle guard for the blank-rejection above: a normal override still passes,
        so the test pair cannot both stay green under a validator that rejects
        everything."""
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_DEEPSEEK_MODEL", "deepseek-reasoner")
        assert Settings().deepseek_model == "deepseek-reasoner"

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n"])
    def test_primary_provider_rejects_blank(
        self, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        """A blank ``ALFRED_PRIMARY_PROVIDER`` refuses at Settings construction.

        Not a laundering problem like the ``deepseek_*`` pair above — a WRONG-REASON
        problem. ``_comms_boot``'s separation check wraps every ``AlfredError`` out of
        ``assert_provider_separation`` as a collision, but that function's blank-id arm
        runs BEFORE its collision test, so a blank ``primary_provider`` was reported to
        the operator and the audit row as ``quarantine_provider_separation_violated``
        when nothing had collided. Refusing here answers accurately
        (``settings_invalid``, field named) and makes that blank arm unreachable from
        the call site.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", blank)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)):
            Settings()

    def test_primary_provider_accepts_a_real_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Oracle guard for the blank-rejection above: a normal override still passes."""
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", "anthropic")
        assert Settings().primary_provider == "anthropic"

    @pytest.mark.parametrize(
        "value",
        [
            "not-a-real-secret-primary-provider-test-placeholder",
            "openai",
            "Anthropic",
            "not-a-provider",
        ],
    )
    def test_primary_provider_rejects_unsupported_value(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """A ``primary_provider`` outside the closed set refuses at Settings construction.

        CodeRabbit (Major/Security): before ``primary_provider`` was a ``Literal``, ANY
        non-blank string passed here and reached several boot-time log/audit lines
        verbatim (``comms.comms_boot.quarantine_provider_resolved`` among them) under the
        claim that the field was "non-secret closed-set routing config". A credential
        mistakenly pasted into ``ALFRED_PRIMARY_PROVIDER`` — the placeholder-shaped case
        here stands in for that — would have been logged. Closing the set at the type
        level means a credential-shaped value never reaches ANY consumer, log site or
        otherwise; ``test_boot_refuses_credential_shaped_primary_provider_without_logging_it``
        in ``test_daemon_boot_egress_refuse.py`` pins the end-to-end no-log-line
        guarantee. Case-sensitive on purpose, matching ``quarantine_provider``'s sibling
        Literal and ``alfred.cli._validators.validate_quarantined_provider`` —
        ``"Anthropic"`` is therefore also a rejection case, not just structurally invalid
        values.
        """
        self._base_env(monkeypatch)
        monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", value)
        from pydantic import ValidationError

        with pytest.raises((ValidationError, SettingsError)):
            Settings()

    def test_primary_provider_literal_matches_quarantine_provider_literal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Drift cross-check: ``primary_provider``'s closed set must match
        ``quarantine_provider``'s (pinned to the CLI + proposal-payload copies by
        ``test_quarantine_provider_literal_matches_allowed_quarantined_providers`` above).

        Both fields draw from the same universe — the two provider adapters this
        codebase actually implements (``src/alfred/providers/``) — so a widened
        ``quarantine_provider`` set that leaves ``primary_provider`` behind (or vice
        versa) is a drift this test catches, kept independent of the three-way pin above
        so neither test's failure is masked by the other's.
        """
        from typing import get_args

        self._base_env(monkeypatch)
        primary_literal_values = frozenset(
            get_args(Settings.model_fields["primary_provider"].annotation)
        )
        quarantine_literal_values = frozenset(
            get_args(Settings.model_fields["quarantine_provider"].annotation)
        )
        assert primary_literal_values == quarantine_literal_values
        # Oracle guard: pin the live content so this cannot go vacuous.
        assert primary_literal_values == frozenset({"anthropic", "deepseek"})
