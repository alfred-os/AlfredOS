"""``Settings.egress_relay_url`` (Spec C / G7-2c, #333).

When set, the core wires a :class:`alfred.egress.relay_client.RelayEgressClient`
pointed at the gateway's mode-(b) inspecting tool-egress relay; UNSET => the relay
client is not wired (no mode-b egress). A blank / whitespace env value normalizes
to ``None`` so a common ``ALFRED_EGRESS_RELAY_URL=`` typo preserves the unset
posture instead of constructing a client with an empty URL (which would crash on
the first dial). Mirrors ``test_settings_egress_proxy_url`` (the G7-1 precedent).
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings


@pytest.fixture(autouse=True)
def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_EGRESS_RELAY_URL", raising=False)


def test_default_is_none() -> None:
    assert Settings().egress_relay_url is None


def test_real_url_is_preserved() -> None:
    assert Settings(egress_relay_url="http://alfred-gateway:8890").egress_relay_url == (
        "http://alfred-gateway:8890"
    )


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_blank_or_whitespace_normalizes_to_none(blank: str) -> None:
    assert Settings(egress_relay_url=blank).egress_relay_url is None


def test_blank_env_normalizes_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_RELAY_URL", "")
    assert Settings().egress_relay_url is None


def test_env_url_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_RELAY_URL", "http://alfred-gateway:8890")
    assert Settings().egress_relay_url == "http://alfred-gateway:8890"


def test_surrounding_whitespace_is_stripped() -> None:
    assert Settings(egress_relay_url="  http://alfred-gateway:8890  ").egress_relay_url == (
        "http://alfred-gateway:8890"
    )
