"""Integration: a REAL action-deadline timeout, end-to-end, over the daemon's
one quarantine graph + a real Postgres idempotency ledger (the #347 blocker-2
required test, #339 PR4b-audit Task 7).

This is a cross-layer proof, not a unit test of ``dispatch_web_fetch``'s
``except TimeoutError`` arm in isolation (that arm already has focused unit
coverage in ``tests/unit/plugins/web_fetch/test_fetch_dispatcher.py`` —
``test_action_deadline_timeout_in_doubt_true_when_committed_no_response`` and
its FIX-1 siblings — where ``extractor.handle`` itself is mocked to hang).
Here the relay ACTUALLY fires through a real loopback ``EgressRelay`` (the
idempotency ``commit_intent`` genuinely commits a ``committed_no_response``
row and the fire counter genuinely increments) and only the innermost
quarantined-child ``.extract`` call hangs — so the deadline fires DURING
extraction, after the side effect is already in doubt. The three properties
this proves together, which no unit test can:

1. ``dispatch_tool`` (the trust-boundary chokepoint) writes EXACTLY ONE
   enriched ``tool.dispatch`` row for the timeout, carrying the forensic
   fields the exception packaged (``egress_id`` / ``destination_host`` /
   ``in_doubt`` / ``ledger_state``) — no URL/path leak (HARD rule #5).
2. The REAL Postgres idempotency ledger is left ``committed_no_response``
   (in-doubt, not dangling) — never advanced to ``committed_with_response``,
   because ``record_response`` never ran (extraction never completed).
3. The relay genuinely fired once (``fire_counter.value == 1``) — the
   ``in_doubt=True`` classification is meaningful, not vacuous (the side
   effect really may have happened upstream).

FIX-2 corrections baked into this harness (see ``.superpowers/sdd/task-7-brief.md``
Task 7 — do NOT revert to the pre-FIX-2 broken shapes):

(a) The mock quarantined child's ``.extract`` is a REAL ``async def`` hanging
    on a never-set ``asyncio.Event()`` (mirrors the FIX-1 unit-test pattern
    above) — NOT an ``AsyncMock(side_effect=lambda: asyncio.sleep(10))``,
    which returns an un-awaited coroutine object and does not hang at all
    (the deadline would never fire, and the test would hang or falsely pass).
(b) ``build_web_fetch_egress_extractor`` takes ``session_scope=`` (it builds
    the ``PostgresEgressIdempotencyStore`` internally) — there is no
    ``ledger=`` kwarg on that factory. A SEPARATE
    ``PostgresEgressIdempotencyStore`` is built on the SAME ``session_scope``
    purely to read back the ledger state for the final assertion.
(c) ``action_deadline_seconds=0.5`` (0.1 races the real commit + round-trip
    under container-load jitter); the loopback-relay allowlist is a
    ``frozenset[tuple[str, int]]`` — ``{("example.com", 443)}`` — matching
    ``AllowlistEntry(domain="example.com")`` in all three
    ``FetchDispatchConfig`` allowlist tiers.

Harness reuse: ``migrated_url`` / ``redis_url`` / ``authorized_t3_nonce`` /
``boot_loopback_relay`` / ``_assembly_gate`` / ``_settings`` are the SAME
directory ``conftest.py`` fixtures and helpers
``test_act_loop_real_chain.py`` and ``test_tool_assembly.py`` use — never a
second hand-rolled harness (CLAUDE.md hard rule #2: never a permissive gate
shim for a security-gated assertion).

Deviation from the task-7-brief pseudocode: the brief's illustrative sketch
uses helper names (``_real_session_scope``, ``_real_audit_writer``,
``_real_limiters``, ``_mock_quarantined_child``, ``_select_audit``,
``_config``, ``_tool_call``) that do not exist anywhere in the tree — they
were the brief's shorthand for "build this the way the sibling tests do",
not a pinned public contract. This file inlines those exactly as
``test_act_loop_real_chain.py`` / ``test_tool_assembly.py`` already do (a
local closure over ``engine``/``factory``, ``AuditWriter(session_factory=...)``,
etc.), and the audit-row query (``_select_audit``) mirrors those two
files' inline ``engine.connect()`` + ``sa.select(AuditEntry.subject)``
pattern rather than routing through the session-scope factory — the read
is a plain Core select, no session/transaction semantics needed. Likewise
``ToolRegistry`` takes a single positional ``Iterable[ToolSpec]``
(``ToolRegistry([spec])``), not the brief sketch's
``ToolRegistry(external={...}, internal={...})`` kwargs — the real
constructor signature (see ``alfred.orchestrator.tool_registry.ToolRegistry.__init__``)
predates this task and both sibling integration tests already call it the
``ToolRegistry([...])`` way.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import AbstractAsyncContextManager
from typing import Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.egress.egress_id import TurnEgressContext, compute_egress_id
from alfred.i18n import t
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.memory.models import AuditEntry
from alfred.orchestrator.builtin_tools import build_web_fetch_tool
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.plugins.web_fetch.handle_cap import HandleCap
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.providers.base import ToolCall
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.dlp import identity_outbound_dlp
from tests.integration.orchestrator.conftest import _assembly_gate, _settings, boot_loopback_relay

pytestmark = pytest.mark.integration

_HOST = "example.com"
_PORT = 443
_URL = f"https://{_HOST}/slow"
_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_HOST, _PORT)})
# A fixed turn identity so the audit query below filters on the EXACT
# trace_id this call produced (same discipline as the sibling tests'
# _FIXED_TRACE_ID — never rely on "this is the only row in a fresh
# container").
_TRACE = "5b1d0b8e-0339-4b3c-9a1e-0000000000a7"


def _mock_quarantined_child() -> AsyncMock:
    """A duck-typed ``QuarantinedExtractor`` double.

    Mirrors the bare ``AsyncMock()`` the sibling tests build (they never
    pass ``spec=QuarantinedExtractor`` either) — ``quarantined_to_structured``
    only ever calls ``.extract(handle, schema)`` positionally, so no other
    attribute needs to be real.
    """
    return AsyncMock()


async def _select_audit_subjects(
    engine: Any, *, event: str, trace_id: str
) -> list[dict[str, Any]]:
    """Query ``audit_log.subject`` JSON payloads for one (event, trace_id) pair.

    Mirrors the inline ``engine.connect()`` + ``sa.select(AuditEntry.subject)``
    pattern ``test_tool_assembly.py`` / ``test_act_loop_real_chain.py`` already
    use — a plain Core read, no session/transaction semantics needed.
    """
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                sa.select(AuditEntry.subject).where(
                    AuditEntry.trace_id == trace_id,
                    AuditEntry.event == event,
                )
            )
        ).fetchall()
    return [r.subject for r in rows]


@pytest.mark.asyncio
async def test_action_deadline_timeout_emits_enriched_in_doubt_row(
    migrated_url: str,
    redis_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A relay fire that overruns the action deadline during extraction
    produces exactly one enriched, in-doubt ``tool.dispatch`` timeout row,
    and the Postgres idempotency ledger is left ``committed_no_response``
    (not dangling, not advanced to ``committed_with_response``)."""
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    def _real_session_scope() -> AbstractAsyncContextManager[AsyncSession]:
        return session_scope(factory)

    audit_writer = AuditWriter(session_factory=_real_session_scope)
    # A SEPARATE store instance on the SAME session_scope, purely for the
    # final ledger-state assertion (FIX-2b) — the extractor built below
    # builds its OWN internal ledger from session_scope; this is not that
    # instance, but both read/write the same underlying Postgres rows.
    ledger_reader = PostgresEgressIdempotencyStore(session_scope=_real_session_scope)

    rate_limiter = RateLimiter(redis_url=redis_url)
    handle_cap = HandleCap(redis_url=redis_url)

    # The daemon's ONE quarantine graph (reused, never re-spawned) — same
    # composition as the sibling integration tests.
    gate = _assembly_gate()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=QuarantineStagingMap())

    # FIX-2(a): a REAL async hang on a never-set event. An
    # ``AsyncMock(side_effect=lambda: asyncio.sleep(10))`` would return an
    # un-awaited coroutine and NOT hang — the action deadline would never
    # fire and this test would give a false pass (or hang forever on the
    # unawaited-coroutine warning path).
    never_set = asyncio.Event()

    async def _hang(*_args: object, **_kwargs: object) -> object:
        await never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    mock_extractor = _mock_quarantined_child()
    mock_extractor.extract = _hang

    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_HOST),),
        operator_allowed_entries=(AllowlistEntry(domain=_HOST),),
        session_allowed_entries=(AllowlistEntry(domain=_HOST),),
        manifest_commit_hash="test-commit",
    )

    ctx = TurnEgressContext(adapter_id="orchestrator.synthetic", inbound_id=_TRACE, session_id="u1")
    egress_id = compute_egress_id(ctx, call_index=0)

    try:
        # FIX-2(c): frozenset[tuple[str, int]] allowlist, NOT a bare set[str].
        async with boot_loopback_relay(allowlist=_ALLOWLIST) as (
            _relay,
            port,
            fire_counter,
            _canned,
        ):
            extractor = build_web_fetch_egress_extractor(
                settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
                gate=gate,
                extractor=mock_extractor,
                recorder=recorder,
                outbound_dlp=identity_outbound_dlp(),
                audit_writer=audit_writer,
                session_scope=_real_session_scope,
            )
            spec = build_web_fetch_tool(
                extractor=extractor,
                config=config,
                rate_limiter=rate_limiter,
                handle_cap=handle_cap,
                outbound_dlp=identity_outbound_dlp(),
                audit=audit_writer,
                # FIX-2(c): 0.5s — long enough to clear the real commit +
                # round-trip under container-load jitter (0.1s races it),
                # short enough to keep the test fast (well under the
                # relay's 30s upstream deadline / 10s upstream_deadline_s).
                action_deadline_seconds=0.5,
            )
            registry = ToolRegistry([spec])

            out = await dispatch_tool(
                ToolCall(id="call-timeout", name="web.fetch", arguments={"url": _URL}),
                0,
                ctx=ctx,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="u1",
                correlation_id=_TRACE,
                language="en",
            )

            # (1) Recoverable string to the planner — the turn is NOT halted.
            assert out == t("orchestrator.tool.timeout", tool="web.fetch")

            # (2) Exactly ONE enriched tool.dispatch timeout row, in-doubt,
            #     host-only (no URL/path leak — HARD rule #5).
            subjects = await _select_audit_subjects(engine, event="tool.dispatch", trace_id=_TRACE)
            timeout_rows = [s for s in subjects if s["dispatch_outcome"] == "timeout"]
            assert len(timeout_rows) == 1
            row = timeout_rows[0]
            assert row["egress_id"] == egress_id
            assert row["destination_host"] == _HOST
            assert row["in_doubt"] is True
            assert row["ledger_state"] == "committed_no_response"
            assert "slow" not in json.dumps(row)

            # (3) The relay actually fired (the side effect is genuinely in
            #     doubt, not a vacuous classification) and the ledger is
            #     left in-doubt, not dangling.
            assert fire_counter.value == 1
            assert await ledger_reader.get_state(egress_id=egress_id) == "committed_no_response"

            # (4) FIX-1 negative property: record_response NEVER ran — no row
            #     for this egress_id ever reached committed_with_response.
            async with engine.connect() as conn:
                with_response_count = (
                    await conn.execute(
                        sa.text(
                            "SELECT count(*) FROM egress_idempotency "
                            "WHERE egress_id = :egress_id "
                            "AND state = 'committed_with_response'"
                        ),
                        {"egress_id": egress_id},
                    )
                ).scalar_one()
            assert with_response_count == 0
    finally:
        # CR trivial: guard each close INDEPENDENTLY — mirrors the sibling
        # tests' nested try/finally teardown so a failure in one close
        # cannot skip the others.
        try:
            await rate_limiter.close()
        finally:
            try:
                await handle_cap.aclose()
            finally:
                await engine.dispose()
