from __future__ import annotations

import pytest

from alfred.cli._bootstrap import build_router
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.providers.router import ProviderRouter


class _StubBroker:
    """Minimal SecretBroker surface build_router touches."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, name: str) -> str:
        self.calls.append(f"get:{name}")
        return "sk-test-dummy"

    def has(self, name: str) -> bool:
        self.calls.append(f"has:{name}")
        return False  # no anthropic fallback — keep the wiring single-provider


class _StubSettings:
    deepseek_base_url = "https://api.deepseek.com/v1"
    deepseek_model = "deepseek-chat"
    anthropic_model = "claude-sonnet-4-6"

    def __init__(self, proxy: str | None) -> None:
        self.egress_proxy_url = proxy


def test_build_router_refuses_without_proxy() -> None:
    # build_router calls EgressClient.from_settings FIRST, so an unset proxy URL
    # fails closed before any provider/broker access.
    broker = _StubBroker()
    with pytest.raises(IOPlaneUnavailableError):
        build_router(broker, _StubSettings(None))  # type: ignore[arg-type]
    assert broker.calls == [], (
        "broker must not be touched on the no-proxy path — "
        "EgressClient.from_settings must raise before any provider/broker access."
    )


def test_build_router_wires_a_router_when_proxy_set() -> None:
    router = build_router(_StubBroker(), _StubSettings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert isinstance(router, ProviderRouter)
