"""``Settings.egress_proxy_url`` (Spec C / G7-1, #333).

When set, the core builds provider SDK clients with an httpx proxy pointed at the
gateway L7 CONNECT proxy; UNSET => direct egress (today's behaviour). A blank /
whitespace env value normalizes to ``None`` so a common ``ALFRED_EGRESS_PROXY_URL=``
typo preserves the documented direct-egress fallback instead of forcing the
proxied path with an empty URL.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings


@pytest.fixture(autouse=True)
def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_URL", raising=False)


def test_default_is_none() -> None:
    assert Settings().egress_proxy_url is None


def test_real_url_is_preserved() -> None:
    assert Settings(egress_proxy_url="http://alfred-gateway:8889").egress_proxy_url == (
        "http://alfred-gateway:8889"
    )


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_blank_or_whitespace_normalizes_to_none(blank: str) -> None:
    assert Settings(egress_proxy_url=blank).egress_proxy_url is None


def test_blank_env_normalizes_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_URL", "")
    assert Settings().egress_proxy_url is None


def test_env_url_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_URL", "http://alfred-gateway:8889")
    assert Settings().egress_proxy_url == "http://alfred-gateway:8889"


def test_surrounding_whitespace_is_stripped() -> None:
    assert Settings(egress_proxy_url="  http://alfred-gateway:8889  ").egress_proxy_url == (
        "http://alfred-gateway:8889"
    )
