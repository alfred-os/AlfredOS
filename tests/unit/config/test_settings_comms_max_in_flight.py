"""``Settings.comms_max_in_flight_notifications`` (Task 31).

Per-adapter cap on concurrent inbound notification handlers (perf-003).
Default 32, constrained to ``Field(ge=1, le=1024)``, env-overridable via
``ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS``.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings, SettingsError


@pytest.fixture(autouse=True)
def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the minimum required Settings env so the field under test loads."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS", raising=False)


def test_default() -> None:
    assert Settings().comms_max_in_flight_notifications == 32


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS", "64")
    assert Settings().comms_max_in_flight_notifications == 64


def test_rejects_zero() -> None:
    # Settings.__init__ wraps pydantic ValidationError into SettingsError
    # (a ValueError subclass) so the CLI can render it.
    with pytest.raises(SettingsError):
        Settings(comms_max_in_flight_notifications=0)


def test_rejects_over_1024() -> None:
    with pytest.raises(SettingsError):
        Settings(comms_max_in_flight_notifications=2048)


def test_accepts_boundaries() -> None:
    assert Settings(comms_max_in_flight_notifications=1).comms_max_in_flight_notifications == 1
    assert (
        Settings(comms_max_in_flight_notifications=1024).comms_max_in_flight_notifications == 1024
    )
