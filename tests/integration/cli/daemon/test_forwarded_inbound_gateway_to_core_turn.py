"""Spec B G6-7-6 Task A1 — a forwarded discord inbound over a REAL socket reaches core dispatch.

The G6-7-6 A1 closer: a forwarded **discord** inbound, shaped as the gateway's
``gateway.adapter.inbound`` JSON-RPC NOTIFICATION, traverses the REAL ``comms-tui.sock``
socket + the REAL seq codec into the REAL daemon HOST runner, where the disposition's
``_route_forwarded_inbound`` hands it to the per-boot
:class:`~alfred.comms_mcp.forwarded_inbound_receiver.GatewayForwardedInboundReceiver`, which
re-parses + dispatches it through ``process_inbound_message(commit_at_dispatch_edge=True)``
against a REAL Postgres testcontainer — landing (a) a **discord** ``comms.inbound.t3_promoted``
audit row resolved to the seeded discord user and (b) a committed G0 ``inbound_idempotency``
row on the composite ``(discord, <inbound_id>)`` key (the dispatched-edge commit fired AFTER
a successful dispatch).

Why A1 over A2
--------------
The A2 closer (``tests/integration/comms/test_forwarded_poison_ceiling_postgres.py`` and the
adversarial poison companions) injects DIRECTLY at ``GatewayForwardedInboundReceiver.receive()``
over real Postgres — proving the receiver + the ledger composition, but NOT the wire. A1's
UNIQUE value is the frame riding a REAL socket: the gateway's ``LegRouter`` -> the leg
scheduler's drain -> ``GatewayCoreLink.write_leg_unit`` -> the seq codec -> ``comms-tui.sock``
-> the daemon pump -> the disposition's ``dispatch(gateway.adapter.inbound, ...)`` method-peek
-> ``_route_forwarded_inbound``. Nothing between the gateway's ``forward_adapter_inbound`` and
the receiver is stubbed.

Injection mechanism (PRESCRIBED — option (b), direct leg-write)
---------------------------------------------------------------
We reuse the daemon-boot + gateway-core-leg scaffold from
``test_chat_gateway_socket_turn.py`` and drive it until the gateway core leg is
:attr:`~alfred.gateway.link_state.GatewayLinkState.UP`. THEN we put the forwarded frame onto
the UP core leg via the REAL production forward API
:meth:`~alfred.gateway.core_link.GatewayCoreLink.forward_adapter_inbound` — the SAME method the
G6-7-3 forward-runner's disposition calls. That method routes through the link's ``LegRouter``,
which requires a REGISTERED leg for ``adapter_id="discord"``; the only deviation from the
chat-gateway scaffold is a single extra ``scheduler.register_leg(build_adapter_leg("discord"))``
so the discord frame routes to its own per-leg buffer + the fair scheduler drains it onto the
single core writer (the plan-sanctioned ≤1-line discord-leg registration). The full G6-7-3
per-adapter supervisor scaffold (``_register_adapter_legs`` + ``GatewayAdapterSupervisor`` +
spawn) is OUT OF SCOPE — and the gateway-side forward *production* (a hosted child's
``inbound.message`` -> ``forward_adapter_inbound``) is intentionally NOT re-covered here: that
is adversarially covered by the C1 pump test.

The frame bytes mirror ``core_link.forward_adapter_inbound`` exactly — a
``GatewayAdapterInboundEnvelope(adapter_id="discord", body=<opaque discord
InboundMessageNotification JSON str>)`` serialized as a ``gateway.adapter.inbound`` JSON-RPC
notification — because we CALL that production method rather than hand-building the frame
(so a drifted wire contract would be carried here and fail loud, never silently pass).

Off-Linux substitution + skip posture mirror the chat-gateway proof: the ``alfred_tui`` manifest
is ``sandbox.kind = "none"`` (no UID-drop on the socket carrier), so this runs locally on macOS +
the root CI integration runner; the ONLY off-Linux substitution is the quarantined-child spawn
(an in-proc echo double in place of the bwrap child this leg cannot spawn). The discord receiver
is wired UNCONDITIONALLY at boot (``_FORWARDED_INBOUND_KINDS = ("discord",)``) with a real
``PostgresForwardedDispatchAttemptStore`` + ``PostgresInboundIdempotencyStore``, so booting with
only ``alfred_tui`` enabled still yields a discord-capable receiver — no extra daemon config.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import struct
import uuid
from collections.abc import AsyncIterator, Coroutine, Iterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any

import pytest
from alfred_tui.cohost import _make_socket_inbound_sink, _serve_wire
from alfred_tui.server import TuiServer
from alfred_tui.session import TuiSession
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from alfred.audit.log import AuditWriter
from alfred.bootstrap.lifecycle_epoch import mint_boot_epoch, reset_boot_epoch_for_tests
from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.cli.daemon._commands import (
    LifecycleBroadcaster,
    _build_boot_outbound_dlp,
    _build_comms_boot_graph,
    _CommsBootGraph,
    _listen_socket_comms_adapter,
)
from alfred.comms_mcp.protocol import (
    InboundMessageNotification,
)
from alfred.config.settings import Settings
from alfred.gateway.client_link import client_handshake as _gateway_client_handshake
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.link_state import GatewayLinkState
from alfred.gateway.process import build_adapter_leg, build_tui_leg, wire_leg_scheduler
from alfred.gateway.relay import GatewayRelay
from alfred.hooks.boot import install_boot_hook_registry
from alfred.hooks.registry import get_registry, set_registry
from alfred.identity import Authorization, Platform
from alfred.identity.models import PlatformIdentity, User
from alfred.memory.hooks_audit_sink import EpisodicAuditSink
from alfred.memory.models import Base
from alfred.plugins.comms_socket_transport import CommsSocketListener, dial_comms_socket
from alfred.security import tiers as _tiers
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import _make_in_memory_backend, _make_no_op_audit_sink

pytestmark = pytest.mark.integration

# The TUI socket-carrier adapter (binds ``comms-tui.sock`` via adapter_kind="tui") — the
# carrier the gateway's core leg dials. The FORWARDED inbound's adapter id is "discord".
_ADAPTER_ID = "alfred_tui"
_PLUGIN_ID = "alfred_tui"
_PLUGIN_MANIFEST_TIER = "operator"  # plugins/alfred_tui/manifest.toml subscriber_tier

# The forwarded inbound is a DISCORD frame — its envelope + body adapter_id is "discord".
_FORWARDED_ADAPTER_ID = "discord"

# Discriminating discord inbound values so a dropped field surfaces as the wrong canonical
# id / a refused body rather than passing by luck. The platform user id is what the seeded
# discord binding maps to ``alice``; the inbound id is the G0 composite-key half asserted on
# the committed ``inbound_idempotency`` row.
_PLATFORM_USER_ID = "discord:victim-9931"
_INBOUND_ID = f"g6-7-6-a1-forward-{uuid.uuid4().hex}"
_INBOUND_CONTENT = "hello from the g6-7-6 a1 forwarded-discord proof"
_CANONICAL_SLUG = "alice"
_USER_LANGUAGE = "en-GB"

# A >=32-byte pepper for the audit_hash HKDF (matches the harness floor).
_AUDIT_HASH_PEPPER = "integration-test-pepper-0123456789abcdef-padding"

# Generous bounds so a wedged leg fails loud rather than hanging the suite.
_TIMEOUT_S = 20.0

_LAUNCHER_TEST_UID = getpass.getuser()
_LAUNCHER_REQUIRES_ROOT = os.uname().sysname == "Linux" and os.geteuid() != 0


class _EchoingChildDouble:
    """In-proc length-prefixed quarantined-child double echoing the ingested body.

    The daemon's comms boot graph spawns a REAL bwrap quarantined child; this leg runs
    off-Linux (no bwrap), so the spawn seam is monkeypatched to this double. The daemon's
    real ``QuarantineStdioTransport`` drives it exactly as it would the live child. Mirrors
    ``test_chat_gateway_socket_turn._EchoingChildDouble``.
    """

    def __init__(self, *, provider_key: str) -> None:
        self.provider_key = provider_key
        self._ingested: dict[str, str] = {}
        self._reply: bytes | None = None

    def write_frame(self, frame: bytes) -> None:
        length = struct.unpack(">I", frame[:4])[0]
        obj = json.loads(frame[4 : 4 + length])
        method, params = obj["method"], obj["params"]
        if method == "quarantine.ingest":
            self._ingested[params["handle_id"]] = params["context"]
        elif method == "quarantine.extract":
            try:
                context = self._ingested.pop(params["handle_id"])
            except KeyError as exc:  # pragma: no cover - defensive; a mismatch fails the test
                raise AssertionError(
                    f"unexpected quarantine handle_id {params['handle_id']!r}"
                ) from exc
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "kind": "extracted",
                        "data": {"text": context, "intent": "greeting"},
                        "extraction_mode": "native_constrained",
                    },
                }
            ).encode("utf-8")
            self._reply = struct.pack(">I", len(body)) + body

    async def read_frame(self) -> bytes:
        assert self._reply is not None
        reply, self._reply = self._reply, None
        return reply

    async def aclose(self) -> None:
        return None


class _RecordingSupervisor:
    """Captures the carrier's accept-and-pump coroutine + the breaker/restart seams.

    Stands in for the real ``Supervisor`` at the one seam this proof does not exercise — the
    supervised TaskGroup. ``_listen_socket_comms_adapter`` calls
    ``register_plugin_task(_accept_and_pump())``; we capture it so the TEST owns driving the
    carrier (and reaps it on teardown). Mirrors ``test_chat_gateway_socket_turn``'s double;
    carries the ``shutdown_event`` the carrier races ``accept()`` against.
    """

    def __init__(self) -> None:
        self.registered: list[asyncio.Task[None]] = []
        self.trip_calls: list[dict[str, str]] = []
        self.restart_calls: list[dict[str, str]] = []
        self.shutdown_event = asyncio.Event()

    def register_plugin_task(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self.registered.append(task)
        return task

    async def trip_breaker(self, *, component_id: str, reason: str) -> None:
        self.trip_calls.append({"component_id": component_id, "reason": reason})

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None:
        self.restart_calls.append({"adapter_id": adapter_id, "reason": reason})


def _boot_gate_with_tui_load_grant() -> RealGate:
    """Return a REAL RealGate seeded for BOTH chains the carrier exercises.

    CLAUDE.md hard rule #2 — a real :class:`RealGate` over scoped fixture grants, NEVER a
    permissive shim. Two grants, both evaluated by the SAME production ``GatePolicy.check`` the
    hot path uses: the system-tier ``security.quarantined.extract`` grant so the
    ``QuarantinedExtractor``'s post-stage DLP subscriber registers; and an
    ``(alfred_tui, operator, "*")`` grant authorizing the TUI socket carrier's plugin load at
    handshake (``check_plugin_load`` delegates to ``check(..., hookpoint="*", ...)``). Mirrors
    ``test_chat_gateway_socket_turn._boot_gate_with_tui_load_grant``.
    """
    grants = frozenset(
        {
            GrantRow(
                plugin_id="alfred.security._extract_dlp_subscriber",
                subscriber_tier="system",
                hookpoint="security.quarantined.extract",
                content_tier=None,
                proposal_branch="test-fixture",
            ),
            GrantRow(
                plugin_id=_PLUGIN_ID,
                subscriber_tier=_PLUGIN_MANIFEST_TIER,
                hookpoint="*",
                content_tier=None,
                proposal_branch="test-fixture",
            ),
        }
    )
    return RealGate(
        policy=GatePolicy(grants=grants),
        backend=_make_in_memory_backend(grants=grants),
        audit_sink=_make_no_op_audit_sink(),
    )


def _seed_discord_bound_user(sync_url: str) -> None:
    """Seed a Discord-bound ``alice`` so the resolver maps the forwarded inbound to her.

    The forwarded receiver dispatches with the per-``discord`` collaborator set, whose resolver
    bridge maps the wire ``adapter_kind`` -> :attr:`Platform.DISCORD`. So seed a
    ``Platform.DISCORD`` binding (NOT TUI) for the discord platform user id — mirrors
    ``test_daemon_comms_inbound_turn._seed_discord_bound_user``.
    """
    sync_engine = create_engine(sync_url, future=True)
    try:
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        with sync_factory.begin() as session:
            user = User(
                slug=_CANONICAL_SLUG,
                display_name=_CANONICAL_SLUG,
                authorization=Authorization.STANDARD.value,
                daily_budget_usd=5.0,
                language=_USER_LANGUAGE,
            )
            session.add(user)
            session.flush()
            session.add(
                PlatformIdentity(
                    user_id=user.id,
                    platform=Platform.DISCORD.value,
                    platform_id=_PLATFORM_USER_ID,
                )
            )
    finally:
        sync_engine.dispose()


@asynccontextmanager
async def _boot_audit_writer(postgres_url: str) -> AsyncIterator[AuditWriter]:
    """Create the schema, seed the discord user, and yield a real Postgres AuditWriter."""
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        _seed_discord_bound_user(sync_url)

        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        yield AuditWriter(session_factory=session_scope)
    finally:
        await engine.dispose()


@pytest.fixture
def _boot_env(monkeypatch: pytest.MonkeyPatch, postgres_url: str) -> Iterator[None]:
    """Set the env the production Settings + broker + carrier boot read."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_ENV", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-integration-placeholder")
    monkeypatch.setenv("ALFRED_AUDIT.HASH_PEPPER", _AUDIT_HASH_PEPPER)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ADAPTER_ID}"]')
    monkeypatch.setenv("ALFRED_PLUGIN_UID", _LAUNCHER_TEST_UID)
    yield


async def _wait_for(
    predicate: Any,
    timeout: float,
    *,
    watch: tuple[asyncio.Task[Any], ...] = (),
) -> None:
    """Poll ``predicate`` (a 0-arg bool callable) until true or the deadline.

    If any ``watch`` background task (the relay / accept-pump / cohost-wire loops)
    crashes mid-wait, re-raise its exception IMMEDIATELY so the ACT phase surfaces
    the REAL fault (a wire / dispatch break) loudly, instead of masking it as an
    opaque "condition never became true" timeout — the teardown ``suppress`` would
    otherwise swallow it entirely (err-002).
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        for task in watch:
            if task.done() and not task.cancelled() and (exc := task.exception()) is not None:
                raise exc
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise TimeoutError("forwarded-inbound condition never became true")


def _fetch_t3_promotion_rows(sync_url: str) -> list[dict[str, Any]]:
    """Return every ``comms.inbound.t3_promoted`` audit row's subject + attribution."""
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    "SELECT subject, trace_id, actor_user_id, trust_tier_of_trigger, result "
                    "FROM audit_log WHERE event = :event"
                ),
                {"event": "comms.inbound.t3_promoted"},
            )
            return [dict(row._mapping) for row in result]
    finally:
        engine.dispose()


def _fetch_audit_rows_by_event(sync_url: str, *, event: str) -> list[dict[str, Any]]:
    """Return every ``audit_log`` row for ``event`` (for happy-path negative assertions)."""
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT event, result FROM audit_log WHERE event = :event"),
                {"event": event},
            )
            return [dict(row._mapping) for row in result]
    finally:
        engine.dispose()


def _fetch_inbound_idempotency(
    sync_url: str, *, adapter_id: str, inbound_id: str
) -> list[dict[str, Any]]:
    """Return the committed G0 ``inbound_idempotency`` rows for the composite key.

    The dispatched-edge ``commit_once`` writes this row AFTER a successful dispatch — so a
    present row proves the forwarded inbound reached AND completed core dispatch (not merely
    the receiver's admission). Keyed on the COMPOSITE ``(adapter_id, inbound_id)`` PK so a
    cross-adapter id collision could never false-pass it.
    """
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    "SELECT adapter_id, inbound_id FROM inbound_idempotency "
                    "WHERE adapter_id = :adapter_id AND inbound_id = :inbound_id"
                ),
                {"adapter_id": adapter_id, "inbound_id": inbound_id},
            )
            return [dict(row._mapping) for row in result]
    finally:
        engine.dispose()


def _discord_inbound_body_json() -> str:
    """Serialize one plain-text discord ``InboundMessageNotification`` to the opaque JSON body.

    This is the gateway's opaque T3 ``body`` — the hosted discord child's already-parsed
    ``inbound.message`` ``params``, serialized verbatim. The core's re-parse is the SOLE body
    parser; it enforces the §3.3 F3 envelope==body ``adapter_id`` equality, so the body
    ``adapter_id`` MUST be ``"discord"`` (matching the envelope). A plain ``{"content": ...}``
    body carries NO discord sub-payloads (no embeds/polls), so the real discord
    ``SubPayloadPromoter`` classifies it, finds nothing to promote, and dispatch proceeds —
    exercising the classifier-bearing path without needing a live content-store write.
    """
    return InboundMessageNotification(
        adapter_id=_FORWARDED_ADAPTER_ID,
        inbound_id=_INBOUND_ID,
        platform_user_id=_PLATFORM_USER_ID,
        body={"content": _INBOUND_CONTENT},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    ).model_dump_json()


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="parity with the launcher-spawn legs; runs locally + on the root CI runner",
)
@pytest.mark.usefixtures("_boot_env")
async def test_forwarded_discord_inbound_over_socket_reaches_core_dispatch(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REAL socket: a forwarded discord ``gateway.adapter.inbound`` reaches core dispatch.

    Boots the REAL daemon socket carrier + the REAL gateway core leg (the chat-gateway
    scaffold), drives the core leg to UP, then puts a forwarded DISCORD frame onto the leg via
    the production ``core_link.forward_adapter_inbound`` — and asserts it lands a discord
    ``comms.inbound.t3_promoted`` row resolved to ``alice`` AND a committed G0
    ``inbound_idempotency`` row on ``(discord, <inbound_id>)`` (the dispatched-edge commit
    fired AFTER a successful dispatch). The gateway-side forward PRODUCTION (a hosted child's
    ``inbound.message`` -> ``forward_adapter_inbound``) is intentionally NOT re-covered here —
    that is adversarially covered by the C1 pump test. Do NOT weaken the assertions.
    """
    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")

    # Mint the per-boot epoch the daemon carrier's lifecycle.start handshake carries (the
    # gateway captures + reconciles it). Reset on teardown so a sibling starts clean.
    mint_boot_epoch()

    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
    gate = _boot_gate_with_tui_load_grant()
    supervisor = _RecordingSupervisor()
    broadcaster = LifecycleBroadcaster()

    graph: _CommsBootGraph | None = None
    listener: CommsSocketListener | None = None
    gateway_client_listener: GatewayClientListener | None = None
    relay_task: asyncio.Task[None] | None = None
    cohost_wire_task: asyncio.Task[None] | None = None
    accept_task: asyncio.Future[Any] | None = None
    gateway_shutdown = asyncio.Event()
    cohost_transport: Any = None

    async def _instant_sleep(_delay: float) -> None:
        await asyncio.sleep(0)

    def _no_jitter(hi: float) -> float:
        return hi

    try:
        async with _boot_audit_writer(postgres_url) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            # ---- Build daemon comms graph (real Postgres, real path, real discord receiver) ----
            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
            with _NONCE_LOCK:
                nonce = CapabilityGateNonce()
                _tiers._set_authorized_t3_nonce(nonce)

            async def _fake_spawn(*, provider_key: str) -> _EchoingChildDouble:
                return _EchoingChildDouble(provider_key=provider_key)

            monkeypatch.setattr(
                "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
            )
            graph = await _build_comms_boot_graph(
                settings=settings,
                audit=audit,
                outbound_dlp=outbound_dlp,
                t3_nonce=nonce,
                policies_ref=None,
            )

            # ---- Boot the REAL daemon socket carrier (binds comms-tui.sock + auto-wires the
            # forwarded-inbound receiver via with_forwarded_inbound_receiver=True) ----
            listener = await _listen_socket_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="g6-7-6-a1-forward-proof",
                environment_source="env_var",
                broadcaster=broadcaster,
            )
            assert len(supervisor.registered) == 1

            # ---- Start the REAL gateway: dial comms-tui.sock, bind comms-gateway.sock ----
            gateway_client_listener = GatewayClientListener()
            await gateway_client_listener.bind()

            tui_leg = build_tui_leg()
            core_link = GatewayCoreLink(
                client_listener=gateway_client_listener,
                dial_adapter_id="tui",  # dial the daemon's comms-tui.sock
                sleep=_instant_sleep,  # M3 — deterministic reconnect
                jitter=_no_jitter,  # M3 — read the bare (clamped) schedule
                shutdown_event=gateway_shutdown,
                tui_leg=tui_leg,
            )
            gateway_scheduler = wire_leg_scheduler(core_link, tui_leg)
            # The plan-sanctioned ≤1-line discord-leg registration so the production
            # ``core_link.forward_adapter_inbound(adapter_id="discord", ...)`` LegRouter
            # finds a registered leg to route the forwarded frame onto (the same BINDING leg
            # ``GatewayProcess._register_adapter_legs`` builds per configured hosted adapter).
            # The full G6-7-3 supervisor/spawn scaffold is OUT OF SCOPE.
            gateway_scheduler.register_leg(build_adapter_leg(_FORWARDED_ADAPTER_ID))

            # ---- Dial the gateway from a minimal cohost (over comms-gateway.sock) ----
            # The cohost only needs to ANSWER the gateway's client-leg lifecycle.start so the
            # relay leg comes up; this proof drives the FORWARDED path on the CORE leg, not a
            # cohost-originated turn, so no TuiServer is needed.
            async def _accept_and_handshake_client() -> Any:
                await gateway_client_listener.accept()
                client_transport = gateway_client_listener.transport
                assert client_transport is not None
                client_seq_enabled = await _gateway_client_handshake(client_transport)
                return client_transport, client_seq_enabled

            accept_task = asyncio.ensure_future(_accept_and_handshake_client())
            cohost_transport = await dial_comms_socket("gateway")

            # The REAL cohost serve loop ANSWERS the gateway's client-leg lifecycle.start
            # (a valid ``LifecycleStartResult``) so ``client_handshake`` returns. This proof
            # drives the FORWARDED path on the CORE leg, not a cohost-originated turn, so the
            # session emits nothing — but reusing the production serve loop guarantees a
            # conformant handshake reply (a hand-built result would have to mirror the strict
            # ``LifecycleStartResult`` shape). Mirrors ``test_chat_gateway_socket_turn``.
            session = TuiSession(notify=_make_socket_inbound_sink(cohost_transport))
            tui_server = TuiServer(session=session)
            cohost_wire_task = asyncio.ensure_future(_serve_wire(cohost_transport, tui_server))

            client_transport, client_seq_enabled = await asyncio.wait_for(
                accept_task, timeout=_TIMEOUT_S
            )
            assert isinstance(client_seq_enabled, bool)

            # ---- Build + run the REAL relay (core leg dial + handshake + pump) ----
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
                scheduler=gateway_scheduler,
            )
            relay_task = asyncio.ensure_future(relay.run())

            # The gateway<->daemon CORE leg handshake completed AND HELD: the gateway dialed
            # comms-tui.sock, read the daemon's lifecycle.start, captured its epoch, sent the
            # ack, and the daemon ACCEPTED it (the leg stays UP). Assert UP explicitly + fast
            # so a handshake-framing failure surfaces loud here, not as a downstream timeout.
            await _wait_for(lambda: core_link._core_epoch is not None, _TIMEOUT_S)
            await asyncio.sleep(0.2)  # let an ack-rejection tear the leg if it will
            assert core_link._machine.state is GatewayLinkState.UP, (
                "gateway core leg did not HOLD UP after the handshake — the daemon rejected "
                f"the gateway's lifecycle.start ack. Link state: {core_link._machine.state}"
            )

            # ---- ACT: put the FORWARDED discord frame onto the UP core leg via the REAL
            # production forward API. This routes through the link's LegRouter -> the discord
            # leg's scheduler queue -> the scheduler drain -> write_leg_unit -> the seq codec
            # -> comms-tui.sock -> the daemon pump -> the disposition's gateway.adapter.inbound
            # method-peek -> _route_forwarded_inbound -> the receiver -> dispatch. ----
            await core_link.forward_adapter_inbound(
                adapter_id=_FORWARDED_ADAPTER_ID, body=_discord_inbound_body_json()
            )

            # ASSERT (real Postgres): the discord T3-promotion row lands — the forwarded
            # inbound crossed the socket, re-parsed, resolved to alice, and promoted to T3.
            # Watch the live background loops so a mid-ACT crash surfaces loud, not as a
            # timeout (err-002).
            act_watch = tuple(
                t for t in (relay_task, cohost_wire_task, accept_task) if t is not None
            )
            await _wait_for(
                lambda: bool(_fetch_t3_promotion_rows(sync_url)), _TIMEOUT_S, watch=act_watch
            )
            rows = _fetch_t3_promotion_rows(sync_url)
            assert len(rows) == 1, rows
            row = rows[0]
            subject = row["subject"]
            assert subject["adapter_id"] == _FORWARDED_ADAPTER_ID, subject
            assert subject["canonical_user_id"] == _CANONICAL_SLUG, subject
            assert row["actor_user_id"] == _CANONICAL_SLUG, row
            assert subject["language"] == _USER_LANGUAGE, subject
            assert row["trust_tier_of_trigger"] == "T3", row
            assert row["result"] == "promoted", row
            # The platform user id crosses the audit boundary ONLY as a peppered hash.
            pid_hash = subject["platform_user_id_hash"]
            assert isinstance(pid_hash, str) and pid_hash
            assert _PLATFORM_USER_ID not in pid_hash

            # ASSERT (real Postgres): the G0 inbound_idempotency row is COMMITTED on the
            # composite (discord, <inbound_id>) key — the dispatched-edge commit_once fired
            # AFTER a successful dispatch, so a present row proves the forwarded inbound
            # completed core dispatch, not merely passed admission.
            await _wait_for(
                lambda: bool(
                    _fetch_inbound_idempotency(
                        sync_url, adapter_id=_FORWARDED_ADAPTER_ID, inbound_id=_INBOUND_ID
                    )
                ),
                _TIMEOUT_S,
                watch=act_watch,
            )
            idem_rows = _fetch_inbound_idempotency(
                sync_url, adapter_id=_FORWARDED_ADAPTER_ID, inbound_id=_INBOUND_ID
            )
            assert len(idem_rows) == 1, idem_rows
            assert idem_rows[0]["adapter_id"] == _FORWARDED_ADAPTER_ID, idem_rows[0]
            assert idem_rows[0]["inbound_id"] == _INBOUND_ID, idem_rows[0]

            # The forwarded frame took the CLEAN dispatch edge and ONLY that edge: assert no
            # poisoned dead-letter row exists for it, so a spurious refusal that ALSO happened
            # to promote + commit can't slip past this happy-path proof undetected (test-102).
            assert _fetch_audit_rows_by_event(sync_url, event="comms.inbound.poisoned") == [], (
                "unexpected poisoned dead-letter row on the happy path"
            )
    finally:
        # Reap EVERY acquired resource on EVERY exit path (mirror the chat-gateway proof's
        # discipline) regardless of how far boot got.
        gateway_shutdown.set()
        supervisor.shutdown_event.set()
        for maybe_task in (relay_task, cohost_wire_task, accept_task):
            if maybe_task is not None:
                maybe_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await asyncio.wait_for(maybe_task, timeout=_TIMEOUT_S)
        if cohost_transport is not None:
            with suppress(Exception):
                await cohost_transport.close()
        if gateway_client_listener is not None:
            with suppress(Exception):
                await gateway_client_listener.aclose()
        for registered_task in supervisor.registered:
            registered_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(registered_task, timeout=_TIMEOUT_S)
        if listener is not None:
            with suppress(Exception):
                await listener.aclose()
        if graph is not None:
            with suppress(Exception):
                await graph.aclose()
        set_registry(prior_registry)
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)
        reset_boot_epoch_for_tests()
