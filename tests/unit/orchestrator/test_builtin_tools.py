"""Unit tests for the AlfredOS builtin tools (#339 PR2 Task 4 + Task 5).

Covers the ``clock.now`` internal demo tool: the happy path (returns the
injected time) and the ≤T2/allowlist membership claim the ``ToolRegistry``
construction-time check relies on (sec-001). The refusal/error paths for
tool dispatch live at the ``dispatch_tool`` layer (Task 6) — this tool has
no external input to refuse.

Also covers the ``web.fetch`` T3 tool (Task 5): the ``ExternalToolSpec``
wiring claim (name, result_tier, extraction_schema, input_schema) and the
adapter's parameter-threading into ``dispatch_web_fetch`` (url, headers,
call_index, egress_ctx, schema, extractor, user_id, correlation_id). The
downgrade + final DLP-scan of the returned ``EgressExtractOutcome`` happens
at the ``dispatch_tool`` layer (Task 6), not here — these tests only assert
wiring, never running the real extractor.
"""

from datetime import UTC, datetime
from typing import Any

import pytest

from alfred.egress.egress_id import TurnEgressContext
from alfred.orchestrator.builtin_tools import (
    WebFetchExtraction,
    build_clock_tool,
    build_web_fetch_tool,
)
from alfred.orchestrator.tool_registry import (
    FIRST_PARTY_LE_T2_TOOL_ALLOWLIST,
    ExternalToolSpec,
    InternalToolSpec,
    ToolInvocation,
)
from alfred.plugins.web_fetch.auth_allowlist import WEB_FETCH_AUTH_SECRET_ALLOWLIST


def _inv(args: dict[str, object]) -> ToolInvocation:
    return ToolInvocation(
        arguments=args,
        ctx=TurnEgressContext(adapter_id="a", inbound_id="i", session_id="s"),
        call_index=0,
        user_id="u",
        correlation_id="c",
        language="en",
    )


class _SpyHandleCap:
    """Permissive fake ``HandleCap`` — never refuses. These tests only assert
    the ``build_web_fetch_tool`` closure's parameter wiring (Task 5), not the
    real per-user cap's reserve/refuse behaviour (unit-covered at
    ``handle_cap.py`` itself)."""

    async def try_reserve(self, *, user_id: str, handle_id: str, handle_ttl_seconds: int) -> None:
        return None

    async def release(
        self, *, user_id: str, handle_id: str, correlation_id: str | None = None
    ) -> None:
        return None


class _PassthroughBroker:
    """Minimal ``_SecretSubstituter``-shaped fake — these tests only assert
    the ``build_web_fetch_tool`` closure's parameter wiring (#339 PR4b-broker
    Task 3), not the real broker's allowlist/substitution behaviour
    (unit-covered at ``fetch_dispatcher.py`` / ``secrets.py`` themselves)."""

    def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
        return text


@pytest.mark.asyncio
async def test_clock_tool_is_internal_and_allowlisted() -> None:
    spec = build_clock_tool(now=lambda: datetime(2026, 7, 6, tzinfo=UTC))
    assert isinstance(spec, InternalToolSpec)
    assert spec.name == "clock.now"
    assert spec.name in FIRST_PARTY_LE_T2_TOOL_ALLOWLIST


@pytest.mark.asyncio
async def test_clock_tool_returns_injected_time() -> None:
    spec = build_clock_tool(now=lambda: datetime(2026, 7, 6, 12, 0, tzinfo=UTC))
    out = await spec.dispatch(_inv({}))
    assert out == "2026-07-06T12:00:00+00:00"


@pytest.mark.asyncio
async def test_web_fetch_tool_is_external_t3() -> None:
    spec = build_web_fetch_tool(
        extractor=object(),
        config=object(),
        rate_limiter=object(),
        handle_cap=_SpyHandleCap(),
        outbound_dlp=object(),
        broker=_PassthroughBroker(),
        audit=object(),
    )
    assert isinstance(spec, ExternalToolSpec)
    assert spec.name == "web.fetch"
    assert spec.result_tier == "T3"
    assert spec.extraction_schema is WebFetchExtraction
    assert "url" in spec.definition.input_schema["required"]  # type: ignore[index]


@pytest.mark.asyncio
async def test_web_fetch_adapter_threads_ctx_and_call_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def _fake_dispatch(**kwargs: Any) -> object:
        seen.update(kwargs)
        return "SENTINEL_OUTCOME"

    monkeypatch.setattr("alfred.orchestrator.builtin_tools.dispatch_web_fetch", _fake_dispatch)
    spy = _SpyHandleCap()
    broker = _PassthroughBroker()
    spec = build_web_fetch_tool(
        extractor="EXT",
        config="CFG",
        rate_limiter="RL",
        handle_cap=spy,
        outbound_dlp="DLP",
        broker=broker,
        audit="AUD",
    )
    out = await spec.dispatch(_inv({"url": "https://example.com", "headers": {"X": "1"}}))
    assert out == "SENTINEL_OUTCOME"
    assert seen["url"] == "https://example.com"
    assert seen["headers"] == {"X": "1"}
    assert seen["call_index"] == 0
    assert seen["egress_ctx"].adapter_id == "a"
    assert seen["schema"] is WebFetchExtraction
    assert seen["extractor"] == "EXT"
    assert seen["user_id"] == "u"
    assert seen["correlation_id"] == "c"
    # FIX-2: prove the closure forwards `handle_cap` unchanged through to
    # `dispatch_web_fetch` — not just that it's accepted as a parameter.
    assert seen["handle_cap"] is spy
    # #339 PR4b-broker Task 3: prove `broker` (and its default
    # `auth_secret_allowlist`) forward unchanged too — not just that `broker`
    # is accepted as a parameter.
    assert seen["broker"] is broker
    assert seen["auth_secret_allowlist"] == WEB_FETCH_AUTH_SECRET_ALLOWLIST


@pytest.mark.asyncio
async def test_web_fetch_adapter_coerces_non_dict_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-dict ``headers`` tool-call arg (a model-supplied trust-boundary
    input) is silently dropped to ``{}`` — no custom headers sent — rather than
    refused. Pins the deliberate defensive-coercion ``else {}`` branch (which
    coverage.py's ternary-arc blind spot doesn't otherwise instrument). See the
    ``# TODO(#339 follow-up)`` note in ``builtin_tools.py``."""
    seen: dict[str, Any] = {}

    async def _fake_dispatch(**kwargs: Any) -> object:
        seen.update(kwargs)
        return "SENTINEL_OUTCOME"

    monkeypatch.setattr("alfred.orchestrator.builtin_tools.dispatch_web_fetch", _fake_dispatch)
    spec = build_web_fetch_tool(
        extractor="EXT",
        config="CFG",
        rate_limiter="RL",
        handle_cap=_SpyHandleCap(),
        outbound_dlp="DLP",
        broker=_PassthroughBroker(),
        audit="AUD",
    )
    out = await spec.dispatch(_inv({"url": "https://example.com", "headers": "not-a-dict"}))
    assert out == "SENTINEL_OUTCOME"
    assert seen["url"] == "https://example.com"
    assert seen["headers"] == {}
