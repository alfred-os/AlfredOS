"""``Settings.web_fetch_canary_tokens`` (#339 PR4a).

Core-side inbound-reflection canary token source for web.fetch. The gateway runs
the OUTBOUND exfil scan from ALFRED_CANARY_TOKENS; this is the DISTINCT core env
for the inbound tripwire (a seeded canary reflected in a fetched RESPONSE body).
Default () arms the ResponsePolicy canary seam with an empty (no-op) matcher;
operators populate it to enable the reflection tripwire.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings


def test_web_fetch_canary_tokens_defaults_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_WEB_FETCH_CANARY_TOKENS", raising=False)
    assert Settings().web_fetch_canary_tokens == ()


def test_web_fetch_canary_tokens_comma_split_skips_blanks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_WEB_FETCH_CANARY_TOKENS", " tok-a , ,tok-b, ")
    assert Settings().web_fetch_canary_tokens == ("tok-a", "tok-b")


def test_web_fetch_canary_tokens_blank_env_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_WEB_FETCH_CANARY_TOKENS", "   ")
    assert Settings().web_fetch_canary_tokens == ()


def test_web_fetch_canary_tokens_direct_tuple_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    assert Settings(web_fetch_canary_tokens=("x", "y")).web_fetch_canary_tokens == ("x", "y")
