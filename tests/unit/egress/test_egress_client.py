from __future__ import annotations

import httpx
import pytest

from alfred.egress.client import EgressClient


class _Settings:
    deepseek_base_url = "https://api.deepseek.com/v1"

    def __init__(self, proxy: str | None) -> None:
        self.egress_proxy_url = proxy


def test_no_proxy_returns_none_client() -> None:
    client = EgressClient.from_settings(_Settings(None))  # type: ignore[arg-type]
    assert client.proxy_url is None
    assert client.build_provider_http_client() is None


@pytest.mark.asyncio
async def test_proxy_builds_a_non_redirecting_httpx_client() -> None:
    client = EgressClient.from_settings(_Settings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert client.proxy_url == "http://alfred-gateway:8889"
    http_client = client.build_provider_http_client()
    assert isinstance(http_client, httpx.AsyncClient)
    assert http_client.follow_redirects is False  # rider 2: redirect-escape closed
    assert http_client.trust_env is False  # ambient HTTP_PROXY/NO_PROXY must not bypass the pin
    await http_client.aclose()  # the SDK/process owns lifecycle; closeable here for the test
