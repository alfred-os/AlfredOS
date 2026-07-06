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
``_assembly_gate()`` below composes ``make_tool_dispatch_gate()``'s two grants
with that third grant on a single real ``RealGate`` — never a permissive shim
(CLAUDE.md hard rule #2), mirroring the established composed-gate precedent in
``tests/integration/cli/daemon/test_chat_gateway_socket_turn.py``
(``_boot_gate_with_tui_load_grant``).

``build_tool_registry`` has **test callers only** in PR2 — this integration test
IS the proof of the wiring, not a stand-in for a live caller (PR3 wires the Act
phase).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from testcontainers.redis import RedisContainer

from alfred.audit.log import AuditWriter
from alfred.config.settings import Settings
from alfred.egress.egress_id import TurnEgressContext
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.hooks.capability import CapabilityGate
from alfred.memory.db import session_scope
from alfred.memory.models import AuditEntry
from alfred.orchestrator.tool_assembly import build_tool_registry
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.providers.base import ToolCall
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.egress_doubles import _await_relay_ready, make_fake_external_world
from tests.helpers.gates import (
    _make_in_memory_backend,
    _make_no_op_audit_sink,
    make_tool_dispatch_gate,
)

pytestmark = pytest.mark.integration

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})
_FORBIDDEN_HOST = "attacker.example.net"
_FORBIDDEN_URL = f"https://{_FORBIDDEN_HOST}/steal"
_FIXED_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> Any:
    # The C2 pre-extract seam runs ``inspect_response`` via ``asyncio.to_thread``;
    # reap the default executor so no worker thread outlives the test loop.
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    from alembic import command, config

    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_url


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:8-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest.fixture
def authorized_t3_nonce() -> Any:
    """Install a fresh CapabilityGateNonce as the authorised slot."""
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


def _settings(monkeypatch: pytest.MonkeyPatch, *, relay_url: str) -> Settings:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    return Settings(egress_relay_url=relay_url)


def _assembly_gate() -> CapabilityGate:
    """Compose ``make_tool_dispatch_gate()``'s two grants with the THIRD grant
    the real fetch+extract quarantine chain needs on the SAME shared gate — see
    the module docstring. Built from the exact grant set
    ``make_tool_dispatch_gate()`` returns (no re-derivation / drift risk) plus
    one additional ``GrantRow``, mirroring the composed-gate precedent in
    ``tests/integration/cli/daemon/test_chat_gateway_socket_turn.py``.
    """
    base = make_tool_dispatch_gate()
    assert isinstance(base, RealGate)
    grants = set(base._policy.grants)
    grants.add(
        GrantRow(
            plugin_id="alfred.quarantined-llm",
            subscriber_tier="system",
            hookpoint="quarantine.dereference",
            content_tier="T3",
            proposal_branch="test-fixture",
        )
    )
    frozen_grants = frozenset(grants)
    return RealGate(
        policy=GatePolicy(grants=frozen_grants),
        backend=_make_in_memory_backend(grants=frozen_grants),
        audit_sink=_make_no_op_audit_sink(),
    )


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
    open_client_factory, fire_counter, _canned = make_fake_external_world()

    # --- Boot a real loopback gateway EgressRelay (upstream faked). -----------
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    gateway_dlp = OutboundDlp(
        broker=None, audit=lambda **_kw: None, canary=CanaryMatcher(tokens=[])
    )
    relay = EgressRelay(
        tool_allowlist=_FAKE_ALLOWLIST,
        dlp=gateway_dlp,
        audit=record_egress_relay,
        bind_host="127.0.0.1",
        port=port,
        resolve=lambda _h: "1.1.1.1",
        open_client=open_client_factory,
        response_byte_cap=4096,
        upstream_deadline_s=10.0,
    )
    shutdown = asyncio.Event()
    serve_task: asyncio.Task[Any] = asyncio.ensure_future(relay.serve(shutdown))
    try:
        await _await_relay_ready(port, serve_task)
    except BaseException:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
        raise

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
        registry = build_tool_registry(
            settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
            gate=gate,
            extractor=mock_extractor,
            recorder=recorder,
            outbound_dlp=identity_outbound_dlp(),
            audit_writer=audit_writer,
            session_scope=lambda: session_scope(factory),
            rate_limiter=rate_limiter,
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
        try:
            shutdown.set()
            await asyncio.wait_for(serve_task, timeout=5)
        finally:
            await rate_limiter.close()
            await engine.dispose()
