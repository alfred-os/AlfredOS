"""#410 PR1: role-scoped Postgres pool sizing + the connection-budget validator.

The unconfigured pre-#410 pool ("15", never justified anywhere) is replaced by
named, budget-validated fields. The budget constant's arithmetic lives in its
own docstring in settings.py; these tests pin the enforcement, the defaults,
and the field bounds.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.config.settings import (
    DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET,
    Settings,
    SettingsError,
)


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    for var in (
        "ALFRED_DB_TURN_POOL_MAX_CONNECTIONS",
        "ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS",
        "ALFRED_DB_POOL_CHECKOUT_TIMEOUT_SECONDS",
        "ALFRED_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)


def test_defaults_match_db_pool_tuning_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    # The DbPoolTuning dataclass in alfred.memory.db mirrors these values so a
    # stub config without the fields behaves like un-overridden Settings.
    from alfred.memory.db import DbPoolTuning

    _base_env(monkeypatch)
    s = Settings()
    tuning = DbPoolTuning()
    assert s.db_turn_pool_max_connections == tuning.turn_pool_max_connections == 32
    assert s.db_side_pool_max_connections == tuning.side_pool_max_connections == 16
    assert s.db_pool_checkout_timeout_seconds == tuning.checkout_timeout_seconds == 10.0
    assert (
        s.db_idle_in_transaction_timeout_seconds
        == tuning.idle_in_transaction_timeout_seconds
        == 5.0
    )


def test_defaults_fit_inside_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    s = Settings()
    assert (
        s.db_turn_pool_max_connections + s.db_side_pool_max_connections
        <= DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET
    )


def test_over_budget_combination_is_refused_at_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Settings.__init__ translates every ValidationError into SettingsError —
    # callers never see a raw ValidationError, so the refusal is pinned on
    # SettingsError with the ValidationError as __cause__.
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_TURN_POOL_MAX_CONNECTIONS", "64")
    monkeypatch.setenv("ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS", "64")  # 128 > 60
    with pytest.raises(SettingsError, match="connection budget") as excinfo:
        Settings()
    # Fleet finding H-3: the refusal carries the deliberately-authored
    # PydanticCustomError slug so the daemon boundary
    # (_settings_error_field_name) can name WHICH constraint failed without
    # interpolating any operator-configured value. `str(exc)` (with the
    # numbers) still reaches the INTERACTIVE path via load_settings_or_die.
    cause = excinfo.value.__cause__
    assert isinstance(cause, ValidationError)
    assert cause.errors()[0]["type"] == "db_pool_connection_budget_exceeded"
    assert cause.errors()[0]["loc"] == ()


def test_exactly_at_budget_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_TURN_POOL_MAX_CONNECTIONS", "44")
    monkeypatch.setenv("ALFRED_DB_SIDE_POOL_MAX_CONNECTIONS", "16")  # 60 == budget
    s = Settings()
    assert s.db_turn_pool_max_connections == 44


def test_turn_pool_floor_is_two(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 1-connection TURN pool would serialize Phase A/C across ALL users.
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_TURN_POOL_MAX_CONNECTIONS", "1")
    with pytest.raises(SettingsError):
        Settings()


def test_idle_timeout_floor_is_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    # Below ~2x the worst-case in-transaction hook-chain time (0.5 s) the
    # timeout would reap HEALTHY Phase A/C transactions; ge=1.0 enforces it.
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS", "0.5")
    with pytest.raises(SettingsError):
        Settings()


def test_settings_structurally_satisfies_the_tuning_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # _tuning_for() dispatches on this isinstance check; a rename of any of
    # the four fields would silently fall back to DbPoolTuning() defaults —
    # operator overrides discarded with no error, the exact "unconfigured
    # pool by accident" failure class #410 exists to remove.
    from alfred.memory._config_protocols import MemoryDbTuningConfig

    _base_env(monkeypatch)
    assert isinstance(Settings(), MemoryDbTuningConfig)
