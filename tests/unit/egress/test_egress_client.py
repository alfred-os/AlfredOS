from __future__ import annotations

import httpx
import pytest

from alfred.egress.client import EgressClient
from alfred.egress.errors import IOPlaneUnavailableError


class _Settings:
    deepseek_base_url = "https://api.deepseek.com/v1"

    def __init__(self, proxy: str | None) -> None:
        self.egress_proxy_url = proxy


def test_unset_proxy_raises_io_plane_unavailable() -> None:
    # G7-3: the connectivity-free core has no direct-egress fallback — an unset
    # ALFRED_EGRESS_PROXY_URL is fail-closed, and the message names the variable.
    with pytest.raises(IOPlaneUnavailableError) as exc_info:
        EgressClient.from_settings(_Settings(None))  # type: ignore[arg-type]
    assert "ALFRED_EGRESS_PROXY_URL" in exc_info.value.detail


@pytest.mark.asyncio
async def test_proxy_builds_a_non_redirecting_httpx_client() -> None:
    client = EgressClient.from_settings(_Settings("http://alfred-gateway:8889"))  # type: ignore[arg-type]
    assert client.proxy_url == "http://alfred-gateway:8889"
    http_client = client.build_provider_http_client()
    assert isinstance(http_client, httpx.AsyncClient)
    assert http_client.follow_redirects is False  # rider 2: redirect-escape closed
    assert http_client.trust_env is False  # ambient HTTP_PROXY/NO_PROXY must not bypass the pin
    await http_client.aclose()  # the SDK/process owns lifecycle; closeable here for the test
