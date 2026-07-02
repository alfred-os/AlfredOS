"""Structural-satisfaction proof for the egress config Protocol (#351).

The identity-return function is a COMPILE-TIME proof (never called at runtime): mypy
--strict accepts ``Settings -> EgressProxyConfig`` iff ``Settings`` satisfies the
Protocol, so a real ``Settings`` can be passed wherever ``EgressProxyConfig`` is
required — and a future ``Settings.egress_proxy_url`` rename fails the type-check
instead of silently drifting. The stub tests prove the DIP win: the ``from_settings``
seam works against a trivial double, not just a full ``Settings``.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings
from alfred.egress._config_protocols import EgressProxyConfig
from alfred.egress.client import EgressClient
from alfred.egress.errors import IOPlaneUnavailableError


def _settings_satisfies(settings: Settings) -> EgressProxyConfig:
    # Compile-time proof only; mypy --strict type-checks the return. Needs no
    # Settings() construction (avoids env/secret requirements).
    return settings


class _StubCfg:
    """A trivial config double — NOT a Settings — supplying the one field the seam reads."""

    def __init__(self, *, egress_proxy_url: str | None) -> None:
        self.egress_proxy_url = egress_proxy_url


def test_plain_stub_satisfies_egress_proxy_config() -> None:
    """The DIP win: a trivial stub — not a full Settings — satisfies the Protocol."""
    cfg: EgressProxyConfig = _StubCfg(egress_proxy_url="http://alfred-gateway:8889")
    assert cfg.egress_proxy_url == "http://alfred-gateway:8889"


def test_from_settings_accepts_a_plain_stub() -> None:
    """from_settings consumes EgressProxyConfig — a stub drives the seam end-to-end."""
    client = EgressClient.from_settings(_StubCfg(egress_proxy_url="http://alfred-gateway:8889"))
    assert client.proxy_url == "http://alfred-gateway:8889"


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_from_settings_blank_proxy_fails_closed(blank: str | None) -> None:
    """Fail-closed (G7-3, ADR-0042) holds for every blank value against the narrow Protocol.

    Narrowing the param to EgressProxyConfig admits an unnormalized stub value (a blank
    string) that a real Settings never produces (the mode="before" normalizer collapses
    blank/whitespace->None); the consumer self-defends against None, "", and whitespace-only
    so a blank proxy URL never silently builds a client.
    """
    with pytest.raises(IOPlaneUnavailableError):
        EgressClient.from_settings(_StubCfg(egress_proxy_url=blank))
