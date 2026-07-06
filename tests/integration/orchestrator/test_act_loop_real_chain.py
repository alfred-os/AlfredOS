"""Integration: the #339 PR3 agentic act-phase loop drives the REAL tool chain
end-to-end (spec §11 PR3 acceptance criterion).

A scripted planner asks for ``web.fetch`` (T3) then ``clock.now`` (internal
<=T2) in a single completion; ``Orchestrator._handle_turn``'s loop dispatches
each via the merged ``dispatch_tool`` chokepoint over the REAL
``build_tool_registry`` chain (the exact harness ``test_tool_assembly.py``
proves — real loopback ``EgressRelay``, real Postgres audit ledger, the ONE
quarantine graph, never a permissive gate shim per CLAUDE.md hard rule #2),
feeds the extracted T2 back to the planner, and re-completes to a final
answer. ``build_orchestrator`` stays unwired (ADR-0041 / #338 wires the live
comms-inbound caller) — this test IS the proof the loop's tool leg composes
over the real chain, mirroring the "test is the proof, not a live caller"
precedent ``test_tool_assembly.py`` established for ``build_tool_registry``
itself.

FIX-11 — the NON-VACUOUS containment-regression guard
------------------------------------------------------
The mock echo extractor (shared with ``test_tool_assembly.py``) returns a
FIXED ``{text, intent}`` regardless of the real upstream body, so "the
upstream marker is absent from the fed-back tool_result" would be a VACUOUS
assertion on its own — it would pass even if the extraction step were
skipped entirely, because the mock never looks at its input either way.
The three assertions below are only meaningful TOGETHER:

(a) the fed-back ``web.fetch`` tool_result content EQUALS the extracted
    ``{text, intent}`` JSON (the planner got the STRUCTURED extract, not
    some other shape);
(b) the literal marker ``"raw-upstream-secret"`` — which the faked upstream
    was configured to serve — is NOT present in ANY fed-back tool message
    content;
(c) the fetch ACTUALLY fired (``fire_counter.value == 1``), so the
    marker-bearing upstream bytes were genuinely produced, not skipped.

Together, (a)+(b)+(c) prove a containment regression that fed the RAW T3
upstream body to the planner (bypassing the quarantine/extraction chokepoint
entirely) WOULD be caught: the marker would then appear in the fed-back
content and (b) would fail. This test validates STRUCTURAL containment only
— the extractor is a mock, so it says nothing about prompt-injection
robustness of a REAL quarantined LLM; that is #340's concern.
"""

from __future__ import annotations

import json
import uuid
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.db import session_scope
from alfred.memory.models import AuditEntry
from alfred.memory.working import Turn
from alfred.orchestrator.core import Orchestrator
from alfred.orchestrator.tool_assembly import build_tool_registry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.providers.base import CompletionRequest, CompletionResponse, ToolCall
from alfred.providers.router import ProviderRouter
from alfred.security.quarantine import Extracted, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import T2, CapabilityGateNonce, tag
from tests.helpers.dlp import identity_outbound_dlp
from tests.integration.orchestrator.conftest import _assembly_gate, _settings, boot_loopback_relay

pytestmark = pytest.mark.integration

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})
_FIXED_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)
_MARKER = "raw-upstream-secret"
# A fixed turn identity so the ``tool.dispatch`` audit query below can filter
# on the EXACT trace_id this turn produced, rather than relying on "this is
# the only turn in a fresh container" (true today, but filtering explicitly
# is the same discipline test_tool_assembly.py's per-call correlation_ids use).
_FIXED_TRACE_ID = "5b1d0b8e-0339-4b3c-9a1e-000000000005"


class _ScriptedRouter:
    """Fake planner: replays pre-scripted ``CompletionResponse``s in order and
    captures every ``CompletionRequest`` it received — so the test can inspect
    the SECOND request's fed-back ``role="tool"`` messages (FIX-11)."""

    def __init__(self, responses: list[CompletionResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[CompletionRequest] = []

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.requests.append(request)
        return self._responses.pop(0)


def _tool_use_response(*calls: ToolCall, cost: float = 0.01) -> CompletionResponse:
    """A non-terminal provider completion requesting one or more tool calls."""
    return CompletionResponse(
        content="",
        tokens_in=5,
        tokens_out=3,
        cost_usd=cost,
        model="fake",
        stop_reason="tool_use",
        tool_calls=calls,
    )


def _text_response(content: str, cost: float = 0.01) -> CompletionResponse:
    """A terminal (no-tools) provider completion — the loop's final answer."""
    return CompletionResponse(
        content=content,
        tokens_in=5,
        tokens_out=3,
        cost_usd=cost,
        model="fake",
        stop_reason="end_turn",
        tool_calls=(),
    )


def _stub_user() -> MagicMock:
    """A duck-typed ``UserLike`` with real str attributes (mirrors
    ``test_act_loop.py``'s ``_stub_user`` — a bare ``MagicMock`` would hand
    ``render_persona_prompt`` a MagicMock for f-string interpolation)."""
    user = MagicMock()
    user.slug = "bruce"
    user.display_name = "Bruce"
    user.language = "en-US"
    return user


def _make_working_memory() -> MagicMock:
    """An in-memory ``WorkingMemory`` stand-in (mirrors ``test_act_loop.py``).

    This test's property under test is the tool-dispatch leg over the real
    quarantine chain, not working-memory/episodic persistence (those are
    unit-covered in ``test_act_loop.py``'s negative-persistence test) — a
    fake buffer keeps the harness from needing a seeded ``User`` row.
    """
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
    """A mocked ``EpisodicMemory`` — see ``_make_working_memory``'s rationale."""
    episodic = MagicMock()
    episodic.record = AsyncMock()
    return episodic


def _make_no_op_budget() -> MagicMock:
    """A budget mock that never blocks and never overruns (mirrors
    ``test_act_loop.py``) — budget behaviour is unit-covered; this test's
    concern is the real tool chain, not the budget gate."""
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=0.0)
    budget.would_exceed = MagicMock(return_value=False)
    budget.check_and_charge = MagicMock(return_value=None)
    return budget


@pytest.mark.asyncio
async def test_loop_drives_real_web_fetch_then_clock_then_answers(
    migrated_url: str,
    redis_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One turn: the planner asks for web.fetch + clock.now in iteration 0,
    the loop dispatches both over the real chain, feeds the results back, and
    the planner's SECOND completion gives the final answer.
    """
    # --- The daemon's ONE quarantine graph (reused, never re-spawned) — same
    #     composition as test_tool_assembly.py's proof. ------------------------
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

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    def _real_session_scope() -> AbstractAsyncContextManager[AsyncSession]:
        return session_scope(factory)

    # The Orchestrator's OWN AuditWriter (default audit_factory) is built off
    # this SAME real session_scope, so the tool.dispatch rows dispatch_tool
    # writes via self._audit land in the SAME Postgres this test queries below.
    audit_writer = AuditWriter(session_factory=_real_session_scope)

    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        operator_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        session_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        manifest_commit_hash="test-commit",
    )

    planner = _ScriptedRouter(
        [
            _tool_use_response(
                ToolCall(id="w", name="web.fetch", arguments={"url": _FAKE_URL}),
                ToolCall(id="k", name="clock.now", arguments={}),
            ),
            _text_response("synthesized answer"),
        ]
    )

    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=_stub_user())

    # A fixed turn trace_id so the audit query below can filter precisely
    # (see the module-level _FIXED_TRACE_ID docstring note).
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
            # FIX-11: the faked upstream serves a body CONTAINING a known
            # marker. The mock echo extractor's OWN output is fixed
            # regardless of this body — see the module docstring for why
            # this is only a meaningful guard combined with assertions
            # (a)/(c) below, not a vacuous "marker absent" check on its own.
            canned.body = f"upstream page containing {_MARKER}".encode()

            registry = build_tool_registry(
                settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
                gate=gate,
                extractor=mock_extractor,
                recorder=recorder,
                outbound_dlp=identity_outbound_dlp(),
                audit_writer=audit_writer,
                session_scope=_real_session_scope,
                rate_limiter=rate_limiter,
                config=config,
                now=lambda: _FIXED_NOW,
            )

            orch = Orchestrator(
                identity_resolver=resolver,
                session_scope=_real_session_scope,
                # ``Orchestrator.router`` is typed as the concrete
                # ``ProviderRouter`` (not a Protocol); ``_ScriptedRouter``
                # satisfies the ONE method the loop actually calls
                # (``.complete``) but isn't nominally that class. The cast
                # is the honest test-double seam — ``test_act_loop.py``'s
                # unit tests get the same pass-through via an ``Any``-typed
                # helper parameter; here the call site is direct.
                router=cast(ProviderRouter, planner),
                budget=_make_no_op_budget(),
                episodic_factory=lambda _s: _make_episodic(),
                tool_registry=registry,
                gate=gate,
                outbound_dlp=identity_outbound_dlp(),
            )

            reply = await orch.handle_user_message(
                user=_stub_user(),
                content=tag(T2, "please fetch and tell me the time", source="test.adapter"),
                working_memory=_make_working_memory(),
            )

            # --- spec §11 PR3: reply + completion count ----------------------
            assert reply == "synthesized answer"
            assert len(planner.requests) == 2  # one tool iteration + the final re-completion

            # --- ordered call_index across an egress + a non-egress dispatch -
            async with engine.connect() as conn:
                dispatch_rows = (
                    await conn.execute(
                        sa.select(AuditEntry.subject).where(
                            AuditEntry.trace_id == _FIXED_TRACE_ID,
                            AuditEntry.event == "tool.dispatch",
                        )
                    )
                ).fetchall()
            # Sort by call_index (row fetch order is not guaranteed without an
            # ORDER BY) — proves call_index took EXACTLY {0, 1} AND that the
            # LOWER index landed on web.fetch (dispatched first, matching the
            # tool_calls order in the scripted completion) while clock.now (a
            # non-egress internal dispatch) got the next one.
            ordered = sorted(dispatch_rows, key=lambda r: r.subject["call_index"])
            assert [r.subject["call_index"] for r in ordered] == [0, 1]
            assert [r.subject["tool_name"] for r in ordered] == ["web.fetch", "clock.now"]

            # --- HARD #5 (FIX-11 non-vacuous containment-regression guard) --
            second_request = planner.requests[1]
            fed_back_tool_messages = [m for m in second_request.messages if m.role == "tool"]
            assert len(fed_back_tool_messages) == 2
            fed_back_by_call_id = {m.tool_call_id: m.content for m in fed_back_tool_messages}

            # (a) the planner received the STRUCTURED extract for web.fetch —
            #     the echo child's {text, intent} JSON, not the raw body nor
            #     any other shape.
            assert json.loads(fed_back_by_call_id["w"]) == {
                "text": "hello from the echo child",
                "intent": "informational",
            }
            # (b) the upstream marker never reaches ANY fed-back tool content.
            assert all(_MARKER not in content for content in fed_back_by_call_id.values())
            # (c) the fetch REALLY fired — the marker-bearing upstream bytes
            #     were genuinely produced (not skipped/short-circuited), so
            #     (b) is a meaningful containment proof, not a vacuous one.
            assert fire_counter.value == 1
            # The mock extractor was genuinely invoked on the fetched body
            # (not bypassed) — (a)'s exact-match assertion already implies
            # this, but pin it directly for the same rigor
            # test_tool_assembly.py's proof uses.
            mock_extractor.extract.assert_awaited_once()
    finally:
        await rate_limiter.close()
        await engine.dispose()
