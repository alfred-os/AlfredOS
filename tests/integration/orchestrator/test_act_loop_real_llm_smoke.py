"""Nightly real-LLM smoke: the #339 act-phase loop drives a REAL deepseek-chat
tool-call end-to-end (issue #339 PR4c).

This is the real-provider sibling of test_act_loop_real_chain.py. It swaps the
scripted planner for a real DeepSeekProvider (deepseek-chat — the only DeepSeek
model with TOOL_USE) built with http_client=None: an IN-HARNESS egress-proxy
bypass, NOT a production path (production always injects the proxied client;
the direct path is dead-by-kernel on the connectivity-free core). The extractor
STAYS a mock echo (the real quarantine child is #340) — so the smoke proves the
tool-calling LOOP drives a real provider tool-call end-to-end, NOT extraction
quality or prompt-injection robustness (that is #340's concern).

Skipped unless ALFRED_SMOKE_PROVIDER_KEY is set (unset/empty/whitespace => SKIP,
never spend). Marked ``real_llm`` so per-commit lanes deselect it; run only by
the nightly ``real-llm-smoke`` job.
"""

from __future__ import annotations

import json
import os
import uuid
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.identity.version_counter import IdentityVersionCounter
from alfred.memory.db import session_scope
from alfred.memory.models import AuditEntry
from alfred.memory.working import Turn
from alfred.orchestrator.core import Orchestrator
from alfred.orchestrator.tool_assembly import build_tool_registry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.plugins.web_fetch.handle_cap import HandleCap
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.providers.base import CompletionRequest, CompletionResponse
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter
from alfred.security.quarantine import Extracted, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.secrets import SecretBroker
from alfred.security.tiers import T2, CapabilityGateNonce, tag
from tests.helpers.dlp import identity_outbound_dlp
from tests.integration.orchestrator.conftest import _assembly_gate, _settings, boot_loopback_relay

pytestmark = [pytest.mark.integration, pytest.mark.real_llm]

_PROVIDER_KEY_ENV = "ALFRED_SMOKE_PROVIDER_KEY"
_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
_DEEPSEEK_MODEL = "deepseek-chat"  # the only DeepSeek model with TOOL_USE

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})
_FIXED_NOW = datetime(2026, 7, 7, 12, 0, 0, tzinfo=UTC)
_MARKER = "raw-upstream-secret"
_FIXED_TRACE_ID = "5b1d0b8e-0339-4b3c-9a1e-00000000040c"


def _provider_key_present() -> bool:
    raw = os.getenv(_PROVIDER_KEY_ENV)
    return raw is not None and raw.strip() != ""


skip_unless_key = pytest.mark.skipif(
    not _provider_key_present(),
    reason=(
        f"{_PROVIDER_KEY_ENV} is unset, empty, or whitespace-only; this smoke "
        "spends real provider tokens against deepseek-chat and is skipped on "
        "fork PRs / unconfigured local boxes (GitHub Actions resolves a missing "
        "secret to '', not undefined)."
    ),
)


def _stub_user() -> MagicMock:
    user = MagicMock()
    user.slug = "bruce"
    user.display_name = "Bruce"
    user.language = "en-US"
    return user


def _make_working_memory() -> MagicMock:
    buffer: list[Turn] = []

    async def _append(*, role: str, content: str) -> None:
        buffer.append(Turn(role=role, content=content))  # type: ignore[arg-type]

    async def _turns() -> list[Turn]:
        return list(buffer)

    return MagicMock(
        turns=AsyncMock(side_effect=_turns),
        append=AsyncMock(side_effect=_append),
        clear=AsyncMock(),
    )


def _make_episodic() -> MagicMock:
    episodic = MagicMock()
    episodic.record = AsyncMock()
    return episodic


def _real_low_cap_budget() -> BudgetGuard:
    """A REAL BudgetGuard as a runaway-cost backstop: a $1 daily budget and a
    $0.05 per-call cap. A tiny smoke turn (fractions of a cent on deepseek-chat)
    never trips it; a runaway charges-raise which the loop force-records + breaks."""
    return BudgetGuard(
        user_loader=lambda user_id: SimpleNamespace(slug=user_id, daily_budget_usd=1.0),
        per_call_max_usd=0.05,
        version_counter=IdentityVersionCounter(),
    )


class _CapturingRouter:
    """Thin spy wrapping the real ProviderRouter: records every CompletionRequest
    (so the containment assertions can scan what the PLANNER received — a real
    ProviderRouter does not expose this), delegates .complete to the real
    provider. Mirrors the template's request-capturing _ScriptedRouter seam so
    the FIX-11 non-vacuous containment triple survives the real-provider swap."""

    def __init__(self, inner: ProviderRouter) -> None:
        self._inner = inner
        self.requests: list[CompletionRequest] = []

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.requests.append(request)
        return await self._inner.complete(request)


@skip_unless_key
@pytest.mark.asyncio
async def test_real_deepseek_drives_web_fetch_loop_end_to_end(
    migrated_url: str,
    redis_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directive prompt induces a real deepseek-chat web.fetch call; the loop
    dispatches it over the real T3 chain (echo extractor), feeds the structured
    T2 back, and the provider's next completion answers. Proves a REAL provider
    tool-call drives the loop end-to-end; containment (HARD #5) holds."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = _assembly_gate()
    extracted = Extracted(
        data=T3DerivedData({"text": "hello from the echo child", "intent": "informational"}),
        extraction_mode="native_constrained",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted)

    rate_limiter = RateLimiter(redis_url=redis_url)
    handle_cap = HandleCap(redis_url=redis_url)

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    def _real_session_scope() -> AbstractAsyncContextManager[AsyncSession]:
        return session_scope(factory)

    audit_writer = AuditWriter(session_factory=_real_session_scope)
    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        operator_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        session_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        manifest_commit_hash="test-commit",
    )

    # REAL provider: http_client=None is the in-harness egress bypass (NOT a
    # prod path). deepseek-chat is the only DeepSeek model with TOOL_USE.
    provider = DeepSeekProvider.from_settings(
        api_key=os.environ[_PROVIDER_KEY_ENV],
        base_url=_DEEPSEEK_BASE_URL,
        model=_DEEPSEEK_MODEL,
        http_client=None,
    )
    # Wrap the real router so the containment assertions can inspect what the
    # planner received (the real ProviderRouter, unlike _ScriptedRouter, does
    # not capture requests).
    capturing = _CapturingRouter(ProviderRouter(primary=provider, fallback=provider))

    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=_stub_user())
    monkeypatch.setattr(
        "alfred.orchestrator.core.uuid.uuid4",
        lambda: uuid.UUID(_FIXED_TRACE_ID),
    )

    try:
        async with boot_loopback_relay(allowlist=_FAKE_ALLOWLIST) as (
            _relay,
            port,
            fire_counter,
            canned,
        ):
            canned.body = f"upstream page containing {_MARKER}".encode()
            registry = build_tool_registry(
                settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
                gate=gate,
                extractor=mock_extractor,
                recorder=recorder,
                outbound_dlp=identity_outbound_dlp(),
                broker=SecretBroker(env={}),
                audit_writer=audit_writer,
                session_scope=_real_session_scope,
                rate_limiter=rate_limiter,
                handle_cap=handle_cap,
                config=config,
                now=lambda: _FIXED_NOW,
            )
            orch = Orchestrator(
                identity_resolver=resolver,
                session_scope=_real_session_scope,
                # ``Orchestrator.router`` is typed as the concrete
                # ``ProviderRouter``; ``_CapturingRouter`` satisfies the one
                # method the loop calls (``.complete``). Same honest test-double
                # cast the template uses.
                router=cast(ProviderRouter, capturing),
                budget=_real_low_cap_budget(),
                episodic_factory=lambda _s: _make_episodic(),
                tool_registry=registry,
                gate=gate,
                outbound_dlp=identity_outbound_dlp(),
            )

            # A directive prompt that reliably induces a web.fetch of the
            # loopback URL from an instruction-following model.
            prompt = (
                "Use the web.fetch tool to retrieve the URL "
                f"{_FAKE_URL} and then tell me, in one sentence, what it "
                "contains. Do not answer from your own knowledge; you MUST "
                "call web.fetch first."
            )
            reply = await orch.handle_user_message(
                user=_stub_user(),
                content=tag(T2, prompt, source="test.adapter"),
                working_memory=_make_working_memory(),
            )

            # --- liveness: a real provider tool-call drove the loop ----------
            assert isinstance(reply, str) and reply.strip() != ""
            async with engine.connect() as conn:
                dispatch_rows = (
                    await conn.execute(
                        sa.select(AuditEntry.subject).where(
                            AuditEntry.trace_id == _FIXED_TRACE_ID,
                            AuditEntry.event == "tool.dispatch",
                        )
                    )
                ).fetchall()
            tool_names = {r.subject["tool_name"] for r in dispatch_rows}
            assert dispatch_rows, (
                "the real provider emitted no tool call — the loop never dispatched"
            )
            assert "web.fetch" in tool_names, (
                "the directive prompt did not induce a web.fetch tool call "
                f"(dispatched: {sorted(tool_names)})"
            )

            # --- containment (HARD #5, FIX-11 non-vacuous triple over the
            #     CAPTURED planner requests — not the model's final reply) -----
            # (c) the fetch really fired (>=1, not ==1: a real model may
            #     re-fetch across the loop's iterations; containment holds for
            #     any fire count).
            assert fire_counter.value >= 1
            mock_extractor.extract.assert_awaited()
            # (b) the raw upstream marker NEVER appears in ANY message of ANY
            #     request the planner received (system + history + tool msgs) —
            #     the exact place a T3 leak would land (spec §4.3). Scanning the
            #     final reply alone would miss a leak the model paraphrased away.
            for request in capturing.requests:
                assert all(_MARKER not in str(message.content) for message in request.messages)
            # (a) the planner received the STRUCTURED echo extract for web.fetch
            #     (the {text,intent} JSON, not the raw body) — match on content,
            #     since the model chooses the tool_call id. (a)+(b)+(c) together
            #     are the non-vacuous containment guard; each alone is weak.
            fed_back_tool_messages = [
                m for request in capturing.requests for m in request.messages if m.role == "tool"
            ]
            assert any(
                json.loads(m.content)
                == {"text": "hello from the echo child", "intent": "informational"}
                for m in fed_back_tool_messages
            )
    finally:
        try:
            await rate_limiter.close()
        finally:
            try:
                await handle_cap.aclose()
            finally:
                await engine.dispose()
