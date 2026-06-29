from __future__ import annotations

from unittest.mock import Mock

import httpx
import pytest

from alfred.cli._bootstrap import build_router
from alfred.config.settings import Settings
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter


class _RecordingBroker:
    """A recording double that structurally satisfies build_router's ``_SecretBrokerLike``
    Protocol (``get``/``has``) — so it type-checks with no suppression — and tracks calls so
    the no-proxy path can assert the broker was never touched."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, name: str) -> str:
        self.calls.append(f"get:{name}")
        return "sk-test-dummy"

    def has(self, name: str) -> bool:
        self.calls.append(f"has:{name}")
        return False  # no anthropic fallback — keep the wiring single-provider


def _settings(*, egress_proxy_url: str | None) -> Settings:
    # A real, properly-typed Settings instance via Pydantic's validation-bypassing
    # constructor — no env/secrets needed and no type suppression at the call site.
    # ``model_construct`` fills the other fields build_router reads (deepseek_base_url /
    # deepseek_model / anthropic_model) from their declared defaults.
    return Settings.model_construct(egress_proxy_url=egress_proxy_url)


def test_build_router_refuses_without_proxy() -> None:
    # build_router calls EgressClient.from_settings FIRST, so an unset proxy URL
    # fails closed before any provider/broker access.
    broker = _RecordingBroker()
    with pytest.raises(IOPlaneUnavailableError, match="ALFRED_EGRESS_PROXY_URL"):
        build_router(broker, _settings(egress_proxy_url=None))
    assert broker.calls == [], (
        "broker must not be touched on the no-proxy path — "
        "EgressClient.from_settings must raise before any provider/broker access."
    )


@pytest.mark.asyncio
async def test_build_router_injects_the_proxied_client_into_the_provider(
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
    router = build_router(
        _RecordingBroker(), _settings(egress_proxy_url="http://alfred-gateway:8889")
    )
    # Stubbing the provider means the SDK never took ownership of the proxied client, so
    # the test must close it (else it leaks). The proxied client is a real
    # httpx.AsyncClient (proxy=…); an un-proxied regression would inject None here.
    client = captured["http_client"]
    try:
        assert isinstance(router, ProviderRouter)
        assert isinstance(client, httpx.AsyncClient)
    finally:
        if isinstance(client, httpx.AsyncClient):
            await client.aclose()
