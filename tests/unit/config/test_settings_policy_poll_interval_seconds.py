"""Verify Settings.policy_poll_interval_seconds (PR-S4-4 §3.5 / Component F).

The PolicyWatcher's mtime-poll cadence comes from this field. 0.5s floor
(CPU/disk noise), 10s ceiling (operator patience), 1s default.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.config.settings import Settings


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_POLICY_POLL_INTERVAL_SECONDS", raising=False)


def test_default_is_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    assert Settings().policy_poll_interval_seconds == 1.0


def test_minimum_half_second_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_POLICY_POLL_INTERVAL_SECONDS", "0.5")
    assert Settings().policy_poll_interval_seconds == 0.5


def test_maximum_ten_seconds_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_POLICY_POLL_INTERVAL_SECONDS", "10.0")
    assert Settings().policy_poll_interval_seconds == 10.0


def test_below_minimum_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_POLICY_POLL_INTERVAL_SECONDS", "0.4")
    with pytest.raises((ValidationError, ValueError)):
        Settings()


def test_above_maximum_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("ALFRED_POLICY_POLL_INTERVAL_SECONDS", "10.1")
    with pytest.raises((ValidationError, ValueError)):
        Settings()
