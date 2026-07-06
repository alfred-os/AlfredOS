"""Integration: ``build_tool_registry`` — the orchestrator's tool-registry
composition root, driven end-to-end through ``dispatch_tool`` (#339 PR2 Task 7).

Mirrors ``tests/integration/egress/test_web_fetch_assembly.py``'s pattern (real
Postgres ledger via testcontainers, a real loopback ``EgressRelay`` with a faked
upstream, the recorded-LLM-response ``AsyncMock`` extractor double) but drives the
FULL stack ``build_tool_registry`` wires — ``dispatch_tool`` → ``ToolRegistry`` →
``ExternalToolSpec``/``InternalToolSpec`` → ``dispatch_web_fetch`` /
``EgressResponseExtractor`` — rather than exercising the egress extractor alone.

This is the first integration point where the REAL fetch+extract quarantine
chain (``EgressResponseExtractor.handle`` → ``quarantined_to_structured``) runs
UNDER ``dispatch_tool``. ``dispatch_tool``'s own two gate surfaces
(``tool.dispatch`` + ``t3.downgrade_to_orchestrator``, covered by
``tests.helpers.gates.make_tool_dispatch_gate()``) are therefore not the only
grant the shared gate needs — the ONE ``CapabilityGate`` object threaded through
``build_tool_registry`` (reused for both the extractor's gate-first T3→T2
dereference check AND ``dispatch_tool``'s own checks, never a per-tool copy) also
needs the ``quarantine.dereference`` content-T3 grant
(``QuarantinedExtractor._PLUGIN_ID = "alfred.quarantined-llm"``) that
``quarantined_to_structured`` consults before calling the extractor.
``_assembly_gate()`` (``tests/integration/orchestrator/conftest.py`` — #339 PR3
FIX-12 DRY extraction, shared with ``test_act_loop_real_chain.py``) composes
``make_tool_dispatch_gate()``'s two grants with that third grant on a single
real ``RealGate``, never a permissive shim (CLAUDE.md hard rule #2), mirroring
the established composed-gate precedent in
``tests/integration/cli/daemon/test_chat_gateway_socket_turn.py``
(``_boot_gate_with_tui_load_grant``).

``build_tool_registry`` has **test callers only** in PR2 — this integration test
IS the proof of the wiring, not a stand-in for a live caller (PR3 wires the Act
phase; ``test_act_loop_real_chain.py`` is that proof).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.egress.egress_id import TurnEgressContext
from alfred.memory.db import session_scope
from alfred.memory.models import AuditEntry
from alfred.orchestrator.tool_assembly import build_tool_registry
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.plugins.web_fetch.handle_cap import HandleCap
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.providers.base import ToolCall
from alfred.security.quarantine import Extracted, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.dlp import identity_outbound_dlp
from tests.integration.orchestrator.conftest import _assembly_gate, _settings, boot_loopback_relay

pytestmark = pytest.mark.integration

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})
_FORBIDDEN_HOST = "attacker.example.net"
_FORBIDDEN_URL = f"https://{_FORBIDDEN_HOST}/steal"
_FIXED_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_build_tool_registry_end_to_end(
    migrated_url: str,
    redis_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``build_tool_registry`` assembles a working registry over the daemon's
    one quarantine graph; ``dispatch_tool`` drives both tools end-to-end.

    (a) ``reg.definitions()`` advertises both ``web.fetch`` and ``clock.now``.
    (b) An allowlisted ``web.fetch`` call flows all the way to a T2 string (the
        echo-extracted + downgraded + DLP-scanned ``{text, intent}`` JSON).
    (c) The internal ``clock.now`` call returns the injected fixed timestamp.
    (d) An off-allowlist URL refuses with the ``domain_not_allowed`` recoverable
        string + a ``refused`` ``tool.dispatch`` audit row, and the relay is
        NEVER fired for it (the allowlist check runs before the relay fire).
    """
    # --- The daemon's ONE quarantine graph (reused, never re-spawned). --------
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
    audit_writer = AuditWriter(session_factory=lambda: session_scope(factory))

    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        operator_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        session_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        manifest_commit_hash="test-commit",
    )

    try:
        async with boot_loopback_relay(allowlist=_FAKE_ALLOWLIST) as (
            _relay,
            port,
            fire_counter,
            _canned,
        ):
            registry = build_tool_registry(
                settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
                gate=gate,
                extractor=mock_extractor,
                recorder=recorder,
                outbound_dlp=identity_outbound_dlp(),
                audit_writer=audit_writer,
                session_scope=lambda: session_scope(factory),
                rate_limiter=rate_limiter,
                handle_cap=handle_cap,
                config=config,
                now=lambda: _FIXED_NOW,
            )

            # (a) The registry advertises exactly the two builtin tools.
            advertised = {d.name for d in registry.definitions()}
            assert advertised == {"web.fetch", "clock.now"}

            # (b) An allowlisted web.fetch call flows end-to-end to a T2 string.
            ctx_b = TurnEgressContext(adapter_id="ada-b", inbound_id="in-b", session_id="sess-b")
            out_b = await dispatch_tool(
                ToolCall(id="call-b", name="web.fetch", arguments={"url": _FAKE_URL}),
                0,
                ctx=ctx_b,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-1",
                correlation_id="corr-b",
                language="en",
            )
            assert json.loads(out_b) == {
                "text": "hello from the echo child",
                "intent": "informational",
            }
            mock_extractor.extract.assert_awaited_once()
            assert fire_counter.value == 1

            # (c) The internal clock.now call returns the injected fixed timestamp.
            ctx_c = TurnEgressContext(adapter_id="ada-c", inbound_id="in-c", session_id="sess-c")
            out_c = await dispatch_tool(
                ToolCall(id="call-c", name="clock.now", arguments={}),
                0,
                ctx=ctx_c,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-1",
                correlation_id="corr-c",
                language="en",
            )
            assert out_c == _FIXED_NOW.isoformat()

            # (d) An off-allowlist URL refuses recoverably; the relay never fires
            #     for it — the allowlist check runs BEFORE the relay fire (Step 2
            #     precedes Step 4 in dispatch_web_fetch).
            ctx_d = TurnEgressContext(adapter_id="ada-d", inbound_id="in-d", session_id="sess-d")
            out_d = await dispatch_tool(
                ToolCall(id="call-d", name="web.fetch", arguments={"url": _FORBIDDEN_URL}),
                0,
                ctx=ctx_d,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-1",
                correlation_id="corr-d",
                language="en",
            )
            assert "not allowed" in out_d
            # The relay fire count is STILL 1 — the forbidden-domain call never
            # reached the relay.
            assert fire_counter.value == 1

            async with engine.connect() as conn:
                rows = (
                    await conn.execute(
                        sa.select(AuditEntry.result, AuditEntry.subject).where(
                            AuditEntry.trace_id == "corr-d",
                            AuditEntry.event == "tool.dispatch",
                        )
                    )
                ).fetchall()
            assert len(rows) == 1
            assert rows[0].result == "refused"
            assert rows[0].subject["dispatch_outcome"] == "domain_not_allowed"
    finally:
        # CR trivial: guard each close INDEPENDENTLY — a failure in
        # ``rate_limiter.close()`` must not skip ``handle_cap.aclose()`` /
        # ``engine.dispose()`` (nested try/finally mirrors the
        # shutdown/serve_task + engine.dispose() nesting in
        # ``test_web_fetch_assembly.py``).
        try:
            await rate_limiter.close()
        finally:
            try:
                await handle_cap.aclose()
            finally:
                await engine.dispose()
