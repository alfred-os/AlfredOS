"""Spec A G5 (#237) — the criterion-#7 PROOF: a real ``alfred chat`` turn through the gateway.

This is the FIRST exercise of the full, never-before-connected chain —

    cohost (real ``TuiServer``/socket) --[comms-gateway.sock]-->
        gateway (real ``GatewayCoreLink`` + ``GatewayRelay`` + client listener)
            --[comms-tui.sock]--> daemon (real ``CommsPluginRunner`` HOST,
                real Postgres, real inbound trust-boundary path)
                    --> stubbed ack --> back up the same chain to the cohost.

The #274 e2e used a FAKE core; THIS test boots the REAL daemon socket carrier
(:func:`alfred.cli.daemon._comms_boot._listen_socket_comms_adapter`) so the daemon
binds ``comms-tui.sock`` exactly as ``alfred daemon start`` does, and a REAL
gateway dials it and re-serves it on ``comms-gateway.sock`` for a REAL cohost.

Real-chain discipline (CLAUDE.md hard rules)
--------------------------------------------
* The DAEMON side reuses the production helpers the inbound-turn proof reuses
  (:func:`_build_comms_boot_graph` + the socket-carrier
  :func:`_listen_socket_comms_adapter`) over a REAL ``RealGate`` (the
  ``alfred_tui`` LOAD grant + the quarantined-extract DLP grant — NEVER a
  permissive shim, hard rule #2), a REAL ``AuditWriter`` against a REAL Postgres
  testcontainer, the REAL identity resolver, burst limiter, and inbound path.
* The GATEWAY side is the REAL :class:`GatewayCoreLink` + :class:`GatewayRelay`
  + :class:`GatewayClientListener`. The ONLY non-production seam is the injected
  deterministic ``sleep``/``jitter`` on the core-link's reconnect loop (M3 — so a
  reconnect-banner poll is not gated on real wall-clock backoff + full jitter).
* The COHOST side is the REAL ``CommsSocketTransport`` dialed at
  ``comms-gateway.sock`` driving the REAL ``TuiServer``/``TuiSession`` through the
  REAL :func:`alfred_tui.cohost._serve_wire` loop (with a recording
  ``on_link_state`` banner callback + a recording ``render_outbound`` hook).

The ONLY off-Linux substitution is the quarantined-child spawn (an in-proc echo
double in place of the bwrap child this leg cannot spawn) — the docker-only
``test_daemon_comms_flip_real_spawn`` proves the genuine bwrap spawn. Everything
that matters for the gateway↔daemon composition under proof is production code.

Skip posture mirrors the inbound-turn proof: the ``alfred_tui`` manifest is
``sandbox.kind = "none"``, so under ``ALFRED_ENVIRONMENT=test`` the launcher does
NOT exec a subprocess for the socket carrier (the carrier binds a socket and
awaits a dialer — there is no UID-drop), so this runs locally on macOS + the root
CI integration runner. There is no kind="none" runuser hop on the socket carrier,
but we keep the same root guard as the sibling proof for parity with the
launcher-spawn legs.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import struct
from collections.abc import AsyncIterator, Coroutine, Iterator
from contextlib import asynccontextmanager, suppress
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
from alfred.config.settings import Settings

# The gateway halves the test drives DIRECTLY (so a deterministic clock can be
# injected on the reconnect loop — M3).
from alfred.gateway.client_link import client_handshake as _gateway_client_handshake
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.link_state import GatewayLinkState
from alfred.gateway.process import build_tui_leg, wire_leg_scheduler
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

# The TUI socket-carrier adapter (binds ``comms-tui.sock`` via adapter_kind="tui").
_ADAPTER_ID = "alfred_tui"
_PLUGIN_ID = "alfred_tui"
_PLUGIN_MANIFEST_TIER = "operator"  # plugins/alfred_tui/manifest.toml subscriber_tier

# Discriminating inbound values so a dropped trigger param surfaces as the wrong
# canonical id / a refused empty body rather than passing by luck.
_PLATFORM_USER_ID = "operator-victim-9931"
_INBOUND_CONTENT = "hello from the s4-g5 gateway-chain proof"
_CANONICAL_SLUG = "alice"
_USER_LANGUAGE = "en-GB"

# A >=32-byte pepper for the audit_hash HKDF (matches the harness floor).
_AUDIT_HASH_PEPPER = "integration-test-pepper-0123456789abcdef-padding"

# Generous bounds so a wedged leg fails loud rather than hanging the suite.
_TIMEOUT_S = 20.0

_LAUNCHER_TEST_UID = getpass.getuser()
_LAUNCHER_REQUIRES_ROOT = os.uname().sysname == "Linux" and os.geteuid() != 0

# The ack content the daemon's stubbed dispatch emits (``daemon_runtime._ACK_CONTENT``).
# The ack is routed through the outbound DLP chokepoint + wrapped in a valid
# OutboundMessageRequest (G5 #237 / hard rule #4); the cohost renders ``body[0]``.
_ACK_CONTENT = "ack"


class _EchoingChildDouble:
    """In-proc length-prefixed quarantined-child double echoing the ingested body.

    The daemon's comms boot graph spawns a REAL bwrap quarantined child; this leg
    runs off-Linux (no bwrap), so the spawn seam is monkeypatched to this double.
    The daemon's real ``QuarantineStdioTransport`` drives it exactly as it would the
    live child. Mirrors ``test_daemon_comms_inbound_turn._EchoingChildDouble``.
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

    Stands in for the real ``Supervisor`` at the one seam this proof does not
    exercise — the supervised TaskGroup. ``_listen_socket_comms_adapter`` calls
    ``register_plugin_task(_accept_and_pump())``; we capture it so the TEST owns
    driving the carrier (and reaps it on teardown). Mirrors the inbound-turn proof's
    double; carries the ``shutdown_event`` the carrier races ``accept()`` against.
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

    CLAUDE.md hard rule #2 — a real :class:`RealGate` over scoped fixture grants,
    NEVER a permissive shim. Two grants, both evaluated by the SAME production
    ``GatePolicy.check`` the hot path uses:

    * the system-tier ``security.quarantined.extract`` grant so the
      ``QuarantinedExtractor``'s post-stage DLP subscriber registers; and
    * an ``(alfred_tui, operator, "*")`` grant authorizing the TUI socket
      carrier's plugin load at handshake (``check_plugin_load`` delegates to
      ``check(..., hookpoint="*", requested_tier=manifest_tier)``).
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


def _seed_bound_user(sync_url: str) -> None:
    """Seed a Discord-bound ``alice`` so the resolver maps the inbound to her.

    The TUI inbound path resolves the binding via the resolver bridge, which maps
    the wire ``adapter_kind`` -> a :class:`Platform` member. The TUI adapter kind is
    ``"tui"`` -> :attr:`Platform.TUI`, so seed a ``Platform.TUI`` binding (NOT
    Discord) for the operator's platform user id so the canonical id lands once the
    bridge mapping is present — see the FINDINGS note: the bridge's
    ``_ADAPTER_KIND_TO_PLATFORM`` table currently OMITS ``"tui"``, so this resolve
    raises ``UnknownAdapterKindError`` today (the second of the two real chain gaps
    this proof surfaces).
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
                    platform=Platform.TUI.value,
                    platform_id=_PLATFORM_USER_ID,
                )
            )
    finally:
        sync_engine.dispose()


@asynccontextmanager
async def _boot_audit_writer(postgres_url: str) -> AsyncIterator[AuditWriter]:
    """Create the schema, seed the user, and yield a real Postgres AuditWriter."""
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        _seed_bound_user(sync_url)

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
    # The platform_user_id the TUI session stamps comes from $USER; pin it to the
    # seeded binding so the resolver maps the inbound to alice deterministically.
    monkeypatch.setenv("USER", _PLATFORM_USER_ID)
    yield


async def _wait_for(predicate: Any, timeout: float) -> None:
    """Poll ``predicate`` (a 0-arg bool callable) until true or the deadline."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise TimeoutError("gateway-chain condition never became true")


def _fetch_t3_promotion_rows(sync_url: str) -> list[dict[str, Any]]:
    """Return every ``comms.inbound.t3_promoted`` audit row's subject + trace_id."""
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


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="parity with the launcher-spawn legs; runs locally + on the root CI runner",
)
@pytest.mark.usefixtures("_boot_env")
async def test_chat_turn_and_reconnect_banner_round_trip_through_gateway(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REAL chain: cohost -> gateway -> daemon -> stubbed ack -> cohost, + reconnect banner.

    This proof is the FIRST exercise of the full cohost->gateway->daemon chain. It
    surfaced THREE real composition bugs no prior layer's tests could catch (the
    launcher-spawn legs skip on non-root CI; the #274 e2e used a FAKE core; the reference
    plugin tolerates loose wire shapes the production TUI rejects), all now FIXED:

    * BUG 1 — the handshake seq-framing asymmetry on the core leg;
    * BUG 2 — the missing tui->Platform resolver mapping;
    * BUG 3 (G5 #237) — the daemon's stubbed outbound ack BYPASSED the outbound DLP
      chokepoint (hard rule #4) AND failed the ``OutboundMessageRequest`` wire contract
      (raw ``{"content": "ack"}`` dict body, missing ``idempotency_key`` /
      ``attachments_refs`` / ``addressing_mode``). The fix routes the ack through
      ``OutboundDlp.scan_for_outbound`` + constructs a valid ``OutboundMessageRequest``,
      so the production ``TuiServer`` accepts it and the ack renders.

    With all three fixed, this is the criterion-#7 PROOF: a real ``alfred chat`` turn
    round-trips end to end + the reconnect banner fires. Do NOT weaken the assertions.
    """
    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")

    # Mint the per-boot epoch the daemon carrier's lifecycle.start handshake carries
    # (the gateway captures + reconciles it). Reset on teardown so a sibling starts clean.
    mint_boot_epoch()

    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
    gate = _boot_gate_with_tui_load_grant()
    supervisor = _RecordingSupervisor()
    broadcaster = LifecycleBroadcaster()

    graph: _CommsBootGraph | None = None
    listener: CommsSocketListener | None = None
    # Gateway halves + cohost — reaped in the finally regardless of how far we got.
    gateway_client_listener: GatewayClientListener | None = None
    relay_task: asyncio.Task[None] | None = None
    gateway_shutdown = asyncio.Event()
    cohost_transport: Any = None
    cohost_wire_task: asyncio.Task[None] | None = None

    # Deterministic reconnect clock (M3): no wall-clock backoff/jitter on the
    # gateway core-link's reconnect loop so the reconnect-banner poll is fast.
    async def _instant_sleep(_delay: float) -> None:
        await asyncio.sleep(0)

    def _no_jitter(hi: float) -> float:
        return hi

    # The recorder for the cohost's reconnect banner states (link.reconnecting / restored).
    link_states: list[str] = []

    async def _record_link_state(method: str) -> None:
        link_states.append(method)

    # The recorder for outbound bodies the cohost renders (the ack lands here).
    rendered: list[str] = []

    def _record_render(body: str) -> None:
        rendered.append(body)

    try:
        async with _boot_audit_writer(postgres_url) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            # ---- Build the daemon comms graph (real Postgres, real path) ----
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

            # ---- Boot the REAL daemon socket carrier (binds comms-tui.sock) ----
            listener = await _listen_socket_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="s4-g5-gateway-chain-proof",
                environment_source="env_var",
                broadcaster=broadcaster,
            )
            # The carrier registered its accept-and-pump task; it now awaits a dialer
            # on comms-tui.sock (the gateway's core leg connects below).
            assert len(supervisor.registered) == 1

            # ---- Start the REAL gateway: dial comms-tui.sock, bind comms-gateway.sock ----
            gateway_client_listener = GatewayClientListener()
            await gateway_client_listener.bind()

            # Spec B G6-4 Task 7 / K1 (#288): the client->core path now routes through the
            # leg scheduler (``submit_tui_unit`` -> enqueue -> scheduler drain ->
            # ``write_leg_unit``), NOT a direct write. Build the TUI leg + pass it to the
            # core link, then wire the scheduler/router over the link — EXACTLY as the
            # production ``GatewayProcess`` does (via the shared ``build_tui_leg`` /
            # ``wire_leg_scheduler`` helpers). Without this the inbound enqueues but never
            # drains (the regression this proof now guards).
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

            # ---- Dial the gateway from the cohost (over comms-gateway.sock) ----
            # The cohost dials BEFORE the gateway accepts so the gateway's single
            # accept resolves; the gateway then HOST-handshakes the cohost.
            async def _accept_and_handshake_client() -> Any:
                await gateway_client_listener.accept()
                client_transport = gateway_client_listener.transport
                assert client_transport is not None
                # The gateway is HOST toward the cohost: SEND lifecycle.start, await ack.
                client_seq_enabled = await _gateway_client_handshake(client_transport)
                return client_transport, client_seq_enabled

            accept_task = asyncio.ensure_future(_accept_and_handshake_client())
            cohost_transport = await dial_comms_socket("gateway")

            # Build the REAL cohost session ONCE with the inbound sink wired to the
            # cohost transport (mirrors cohost._make_socket_inbound_sink) + the render
            # recorder. The serve loop ANSWERS the gateway's lifecycle.start + the later
            # outbound.message ack; the session EMITS the inbound on flush.
            session = TuiSession(
                notify=_make_socket_inbound_sink(cohost_transport),
                render_outbound=_record_render,
            )
            tui_server = TuiServer(session=session)
            cohost_wire_task = asyncio.ensure_future(
                _serve_wire(cohost_transport, tui_server, on_link_state=_record_link_state)
            )

            client_transport, client_seq_enabled = await asyncio.wait_for(
                accept_task, timeout=_TIMEOUT_S
            )

            # C1 — the gateway<->cohost handshake completed BEFORE the turn. The
            # cohost answered lifecycle.start and the gateway's client_handshake
            # returned: the relay leg is up, not turn-by-luck.
            assert isinstance(client_seq_enabled, bool)

            # H2 — the client (TUI) leg stays PLAIN: a cohost echoing seq_ack would be
            # the G2 echo-without-deframe bug. The real TUI returns seq_ack=None.
            assert client_seq_enabled is False

            # ---- Build + run the REAL relay (core leg dial + handshake + pump) ----
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
                scheduler=gateway_scheduler,  # K1: the relay co-runs the drain pump
            )
            relay_task = asyncio.ensure_future(relay.run())

            # C1 (CORE leg) — the gateway<->daemon peer handshake completed AND HELD:
            # the gateway dialed comms-tui.sock, READ the daemon's lifecycle.start,
            # captured its per-boot epoch, sent the ack, and the daemon ACCEPTED that
            # ack (the leg stays UP). Assert this EXPLICITLY + FAST (not via the
            # turn-by-luck T3 poll) so a handshake-framing failure on the core leg
            # surfaces LOUD here rather than as an opaque downstream timeout.
            #
            # The leg must reach UP and STAY UP: a daemon that REJECTS the gateway's
            # ack closes the connection, the gateway's pump sees EOF, and the link
            # falls to REDIALING — a one-shot carrier then never re-handshakes, so the
            # leg never recovers. The "stayed up" re-check after a short settle window
            # is what distinguishes a held leg from a captured-then-torn one.
            await _wait_for(lambda: core_link._core_epoch is not None, _TIMEOUT_S)
            await asyncio.sleep(0.2)  # let an ack-rejection tear the leg if it will
            assert core_link._machine.state is GatewayLinkState.UP, (
                "gateway core leg did not HOLD UP after the handshake — the daemon "
                "rejected the gateway's lifecycle.start ack (seq-framing asymmetry: "
                "the gateway flips enable_seq_ack BEFORE sending its ack, so the ack "
                "goes out seq-framed, but the daemon reads it with seq still OFF and "
                f"rejects it as malformed JSON). Link state: {core_link._machine.state}"
            )

            # ---- ACT: the operator's keystroke-batch emits an inbound.message ----
            # The session emits the notification over the gateway client leg; the relay
            # forwards the opaque payload to the core leg -> daemon ->
            # process_inbound_message.
            await session.consume_user_input(_INBOUND_CONTENT)
            await session.flush_keystroke_batch()

            # ASSERT (real Postgres): the T3-promotion row lands — the inbound crossed
            # cohost -> gateway -> daemon and the daemon promoted it to T3.
            await _wait_for(lambda: bool(_fetch_t3_promotion_rows(sync_url)), _TIMEOUT_S)

            # The daemon dispatched the stubbed ack as an outbound.message REQUEST; it
            # relayed back through the gateway to the cohost, which renders the body.
            # The ack content round-trips byte-for-byte.
            #
            # SCOPE of this e2e assertion: it proves the ack TRAVERSES the outbound DLP
            # chokepoint (the daemon's dispatch cannot construct an OutboundMessageRequest
            # without minting a ScannedOutboundBody via OutboundDlp.scan_for_outbound). It
            # does NOT prove redaction itself — ``"ack"`` trips no canary, so a clean
            # round-trip is expected. The redaction PROPERTY (scan IS called; the body on
            # the wire IS the minted ScannedOutboundBody, never a raw dict) is UNIT-covered
            # in tests/unit/comms_mcp/test_daemon_runtime.py — see
            # ``test_dispatch_after_bind_sends_fixed_ack_outbound`` (the ``_SpyingOutboundDlp``
            # records the scan call) and ``test_dispatch_ack_body_is_not_a_raw_dict``. Those
            # plus the type-level ``ScannedOutboundBody`` invariant (the only minter is
            # ``scan_for_outbound``) make the chokepoint unbypassable, so this e2e need not
            # carry a heavy canary variant.
            await _wait_for(lambda: _ACK_CONTENT in rendered, _TIMEOUT_S)
            assert rendered == [_ACK_CONTENT], rendered

            # ---- The reconnect banner: gap the daemon's core link by re-binding the
            # carrier socket, so the gateway's reconnect loop re-dials successfully. ----
            held_cohost = cohost_transport  # the SAME transport must survive the gap
            # The gap mechanism is a daemon-socket RE-BIND (not just a drop): reap the
            # current carrier (closes its accepted core-leg connection -> the gateway's
            # core pump sees EOF -> emits reconnecting), then stand up a FRESH carrier
            # on the SAME comms-tui.sock path so the gateway's re-dial succeeds (->
            # emits restored). A brand-new boot epoch is minted so the fresh carrier's
            # lifecycle.start carries the new epoch the gateway captures on re-handshake.
            for task in supervisor.registered:
                task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await asyncio.wait_for(task, timeout=_TIMEOUT_S)
            supervisor.registered.clear()
            await listener.aclose()
            reset_boot_epoch_for_tests()
            mint_boot_epoch()
            listener = await _listen_socket_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="s4-g5-gateway-chain-proof-rebind",
                environment_source="env_var",
                broadcaster=broadcaster,
            )

            # The cohost observed reconnecting THEN restored (G4 owns link.unavailable;
            # do NOT assert it here).
            await _wait_for(lambda: "link.restored" in link_states, _TIMEOUT_S)
            assert "link.reconnecting" in link_states, link_states
            assert link_states.index("link.reconnecting") < link_states.index("link.restored")

            # The held cohost connection SURVIVED (single-accept-for-life): a
            # post-reconnect turn still relays the ack back over the SAME transport.
            assert held_cohost is cohost_transport
            rendered.clear()
            await session.consume_user_input(_INBOUND_CONTENT)
            await session.flush_keystroke_batch()
            await _wait_for(lambda: _ACK_CONTENT in rendered, _TIMEOUT_S)
            assert rendered == [_ACK_CONTENT], rendered
    finally:
        # Reap EVERY acquired resource on EVERY exit path (mirror the inbound-turn
        # proof's discipline) regardless of how far boot got.
        gateway_shutdown.set()
        supervisor.shutdown_event.set()
        optional_tasks: tuple[asyncio.Task[None] | None, ...] = (relay_task, cohost_wire_task)
        for maybe_task in optional_tasks:
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
