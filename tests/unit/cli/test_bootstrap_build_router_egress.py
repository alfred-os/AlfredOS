from __future__ import annotations

from unittest.mock import Mock

import httpx
import pytest

from alfred.cli._bootstrap import build_router
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.providers.deepseek import DeepSeekProvider
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
    with pytest.raises(IOPlaneUnavailableError, match="ALFRED_EGRESS_PROXY_URL"):
        build_router(broker, _StubSettings(None))  # type: ignore[arg-type]
    assert broker.calls == [], (
        "broker must not be touched on the no-proxy path — "
        "EgressClient.from_settings must raise before any provider/broker access."
    )


def test_build_router_injects_the_proxied_client_into_the_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Prove the happy path actually INJECTS the proxied http_client into the provider —
    # not merely that build_router returns a ProviderRouter. A regression that dropped the
    # injection (reverting to an un-proxied/direct client at the source) must FAIL here, not
    # slip past with HARD rule #9 only appearing covered (CR cloud, Functional Correctness).
    captured: dict[str, object] = {}

    def _spy(**kwargs: object) -> Mock:
        captured["http_client"] = kwargs.get("http_client")
        return Mock()  # ProviderRouter only stores `primary`; never validates it here

    monkeypatch.setattr(DeepSeekProvider, "from_settings", _spy)
    router = build_router(_StubBroker(), _StubSettings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert isinstance(router, ProviderRouter)
    # The proxied client is a real httpx.AsyncClient (proxy=…); an un-proxied regression
    # would inject None here and the SDK would build a direct client.
    assert isinstance(captured["http_client"], httpx.AsyncClient)
