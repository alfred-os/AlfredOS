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
``test_quarantine_real_extract`` proves the genuine bwrap spawn. Everything
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
from typing import Any, Final, cast

import pytest
from alfred_tui.cohost import _make_socket_inbound_sink, _serve_wire
from alfred_tui.render import build_app
from alfred_tui.server import TuiServer
from alfred_tui.session import TuiSession
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from textual.widgets import Input, RichLog

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
from alfred.comms_mcp.protocol import TurnFailureStage
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
from alfred.i18n import t
from alfred.identity import Authorization, Platform
from alfred.identity.models import PlatformIdentity, User
from alfred.memory.hooks_audit_sink import EpisodicAuditSink
from alfred.memory.models import Base
from alfred.plugins.comms_socket_transport import CommsSocketListener, dial_comms_socket
from alfred.providers.router import ProviderRouter
from alfred.security import tiers as _tiers
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import _make_in_memory_backend, _make_no_op_audit_sink
from tests.helpers.routers import FixedAnswerRouter

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

# FOLD-R19 (#338 PR2): this is the TEST-LOCAL expected reply content — NOT
# ``daemon_runtime._ACK_CONTENT`` (that module constant still backs the RETAINED
# echo adapter's own tests, ``tests/unit/comms_mcp/test_daemon_runtime.py``; it is
# NOT edited here). Production now drives a REAL privileged turn
# (RealTurnOrchestratorAdapter); this proof injects a ``router_override`` (a
# ``FixedAnswerRouter``) so the turn completes offline, deterministically, to
# THIS canned answer. The reply is still routed through the outbound DLP
# chokepoint + wrapped in a valid OutboundMessageRequest (G5 #237 / hard rule
# #4); the cohost renders ``body[0]``.
_ACK_CONTENT = "scripted-real-turn-answer"

# Task 16 (#593 proof): a daily cap strictly below Settings.per_call_max_usd's
# 0.10 default (never overridden by ``_boot_env``), so the orchestrator's
# iteration-0 budget PRE-CHECK (``BudgetGuard.would_exceed`` reading THIS row
# via the SAME resolver instance the daemon boot graph installs) trips a REAL
# ``BudgetError`` — no mock, the actual guard math against a real seeded
# Postgres row. Must stay > 0 (the ``users.daily_budget_usd`` DB CHECK).
_NEAR_ZERO_DAILY_BUDGET_USD: Final[float] = 0.01

# The router's canned reply for the budget-block proof below — MUST NEVER be
# rendered: the pre-check's ``BudgetError`` fires BEFORE the turn's first
# ``router.complete()`` call, so this string appearing in the transcript would
# mean the refusal did not actually halt the turn before a real completion.
_UNREACHABLE_ANSWER: Final[str] = "unreachable-router-answer-budget-block-proof"


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

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        # In-proc double: no real fd broker — return the requested destinations so dispatch's
        # connect-defer broker-before-write proceeds to the frames (golive Task 9).
        return [("gw", 8889)] * count

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
            # #338 PR2: the RealTurnOrchestratorAdapter's ingest() gate-checks
            # t3.downgrade_to_orchestrator on every real turn (this proof drives
            # one) — without this grant the downgrade is denied and the turn
            # halts with no reply (_HaltNoReply), which would silently break the
            # ack-content assertions below rather than fail loud at the cause.
            GrantRow(
                plugin_id="t3.downgrade_to_orchestrator",
                subscriber_tier="system",
                hookpoint="t3.downgrade_to_orchestrator",
                content_tier="T3",
                proposal_branch="test-fixture",
            ),
        }
    )
    return RealGate(
        policy=GatePolicy(grants=grants),
        backend=_make_in_memory_backend(grants=grants),
        audit_sink=_make_no_op_audit_sink(),
    )


def _seed_bound_user(sync_url: str, *, alice_daily_budget_usd: float = 5.0) -> None:
    """Seed a Discord-bound ``alice`` so the resolver maps the inbound to her.

    The TUI inbound path resolves the binding via the resolver bridge, which maps
    the wire ``adapter_kind`` -> a :class:`Platform` member. The TUI adapter kind is
    ``"tui"`` -> :attr:`Platform.TUI`, so seed a ``Platform.TUI`` binding (NOT
    Discord) for the operator's platform user id so the canonical id lands once the
    bridge mapping is present — see the FINDINGS note: the bridge's
    ``_ADAPTER_KIND_TO_PLATFORM`` table currently OMITS ``"tui"``, so this resolve
    raises ``UnknownAdapterKindError`` today (the second of the two real chain gaps
    this proof surfaces).

    #338 PR2: also seeds a SEPARATE household-operator row. ``build_orchestrator``
    (inside the real turn now driven by this proof) constructs a real
    ``Orchestrator``, whose constructor synchronously calls
    ``identity_resolver.get_operator()`` — a distinct requirement from ``alice``'s
    platform binding (there must be exactly ONE ``authorization=operator`` row;
    ``alice`` stays STANDARD so this proof does not conflate "the addressed user"
    with "the household operator").

    ``alice_daily_budget_usd`` (Task 16, #593): overridable so the turn-failure
    proof can seed a cap BELOW ``Settings.per_call_max_usd`` and force a REAL
    ``BudgetError`` out of the real ``BudgetGuard`` — every other caller keeps
    the original ``5.0`` (comfortably above the 0.10 per-call cap).
    """
    sync_engine = create_engine(sync_url, future=True)
    try:
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        with sync_factory.begin() as session:
            user = User(
                slug=_CANONICAL_SLUG,
                display_name=_CANONICAL_SLUG,
                authorization=Authorization.STANDARD.value,
                daily_budget_usd=alice_daily_budget_usd,
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
            session.add(
                User(
                    slug="the-operator",
                    display_name="the-operator",
                    authorization=Authorization.OPERATOR.value,
                    daily_budget_usd=5.0,
                    language=_USER_LANGUAGE,
                )
            )
    finally:
        sync_engine.dispose()


@asynccontextmanager
async def _boot_audit_writer(
    postgres_url: str, *, alice_daily_budget_usd: float = 5.0
) -> AsyncIterator[AuditWriter]:
    """Create the schema, seed the user, and yield a real Postgres AuditWriter.

    ``alice_daily_budget_usd`` forwards to :func:`_seed_bound_user` (Task 16,
    #593) — see its docstring.
    """
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        _seed_bound_user(sync_url, alice_daily_budget_usd=alice_daily_budget_usd)

        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        yield AuditWriter(session_factory=session_scope)
    finally:
        await engine.dispose()


@pytest.fixture
def _boot_env(
    monkeypatch: pytest.MonkeyPatch, postgres_url: str, egress_proxy_url_env: str
) -> Iterator[None]:
    """Set the env the production Settings + broker + carrier boot read."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_ENV", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-integration-placeholder")
    # #340 golive Task 7: the comms boot now REFUSES on an unset quarantine provider
    # key (the host pre-spawn §20.2 primary defense — the placeholder path is gone).
    # The 2b echo child still reads + scrubs + discards it, so a placeholder value is
    # enough to clear the refuse and reach the real bwrap spawn under test.
    monkeypatch.setenv(
        "ALFRED_QUARANTINE_PROVIDER_API_KEY", "not-a-real-secret-quarantine-placeholder"
    )
    monkeypatch.setenv("ALFRED_AUDIT.HASH_PEPPER", _AUDIT_HASH_PEPPER)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ADAPTER_ID}"]')
    monkeypatch.setenv("ALFRED_PLUGIN_UID", _LAUNCHER_TEST_UID)
    # #592 (b338841f): the platform_user_id the TUI session stamps comes from
    # alfred.config.operator_env.operator_display_name(), which reads
    # $ALFRED_OPERATOR_NAME (defaulting to "operator" when unset/blank) — NOT
    # $USER, which nothing has read here since that refactor. Pin it to the
    # seeded binding so the resolver maps the inbound to alice deterministically.
    monkeypatch.setenv("ALFRED_OPERATOR_NAME", _PLATFORM_USER_ID)
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

            async def _fake_spawn(
                *, provider_key: str, refusal_recorder: object = None, **_golive: object
            ) -> _EchoingChildDouble:
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
                real_gate=gate,
                # #338 PR2: offline test seam — the real, egress-proxied
                # build_router is never reached; the turn completes to this one
                # canned answer (retargeted _ACK_CONTENT, FOLD-R19).
                router_override=cast(ProviderRouter, FixedAnswerRouter(answer=_ACK_CONTENT)),
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


def _richlog_text(log: RichLog) -> str:
    """The visible plain text of a RichLog, stripped of Rich style metadata.

    Mirrors ``plugins/alfred_tui/tests/test_textual_app.py``'s ``_plain_text``
    helper: ``str(strip)`` renders the Strip *repr* (Segment + Style noise),
    which would let a markup assertion pass on style attributes rather than
    literal glyphs, so this joins each strip's ``Segment.text`` instead.
    """
    return "\n".join("".join(seg.text for seg in strip) for strip in log.lines)


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="parity with the launcher-spawn legs; runs locally + on the root CI runner",
)
@pytest.mark.usefixtures("_boot_env")
async def test_core_turn_failure_reaches_chat_and_releases_the_pending_turn(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 16 (#591/#592/#593) — the composition PROOF: a real refusal reaches a real TUI.

    Drives a real turn through the SAME cohost -> gateway -> daemon chain the
    sibling proof above exercises, but this time the seeded ``alice`` row's
    ``daily_budget_usd`` (:data:`_NEAR_ZERO_DAILY_BUDGET_USD`) sits BELOW
    ``Settings.per_call_max_usd``'s ``0.10`` default, so the orchestrator's
    iteration-0 budget pre-check trips a REAL ``BudgetError``
    (``alfred.budget.guard.BudgetGuard.would_exceed`` reading the REAL seeded
    row via the SAME resolver instance the daemon boot graph installs) — no
    mock, no forced exception, the actual guard math against a real Postgres
    row. This mirrors how ``tests/integration/test_audit_persistence.py``'s
    ``test_budget_block_audit_row_survives_rollback`` forces the SAME
    ``BudgetError`` class (there via a mocked ``BudgetGuard``; here via the
    real one).

    Tasks 9-12 wired the server-side ``turn.failed`` notify off that refusal
    leg; Tasks 13-15 wired the client-side routing + rendering + i18n catalog.
    THIS is the one test proving all of it composes as a working system end to
    end: the REAL :class:`alfred_tui.textual.app.AlfredTuiApp` (driven under
    Textual's ``run_test()`` pilot — never a recording double) submits a real
    keystroke through its OWN ``on_input_submitted`` handler; the inbound
    crosses the real socket chain; the daemon's
    ``RealTurnOrchestratorAdapter.dispatch`` catches the ``BudgetError``,
    audits it, and sends ``turn.failed``; the gateway relays it UNTOUCHED
    (Task 10's own proof); the cohost's ``_serve_wire`` pump routes it to
    ``app.set_turn_failed``; and the app paints the localized
    ``tui.turn_failed.budget_exhausted`` copy AND re-enables ``#user_input`` —
    the two acceptance assertions below.

    Self-review (this test is NOT one that would pass regardless of Task 12's
    notify wiring): if ``_notify_turn_failed`` were never called — e.g. Task
    12's ``except BudgetError`` arm reverted to a bare re-raise — the app's
    ``_turn_pending`` reactive would never flip back to ``False`` (nothing
    else ends the turn: no reply is ever sent, since the pre-check halts
    before the first ``router.complete()``), so the ``_wait_for`` poll below
    raises ``TimeoutError`` after ``_TIMEOUT_S`` (20s) — well inside the app's
    own 90s watchdog window. A reverted Task 12 fails this test LOUD with a
    timeout, not a silent pass.
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

    # Deterministic reconnect clock (M3, unused on the happy handshake path here
    # but kept for parity with the sibling proof's GatewayCoreLink construction).
    async def _instant_sleep(_delay: float) -> None:
        await asyncio.sleep(0)

    def _no_jitter(hi: float) -> float:
        return hi

    try:
        async with _boot_audit_writer(
            postgres_url, alice_daily_budget_usd=_NEAR_ZERO_DAILY_BUDGET_USD
        ) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            # ---- Build the daemon comms graph (real Postgres, real path) ----
            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
            with _NONCE_LOCK:
                nonce = CapabilityGateNonce()
                _tiers._set_authorized_t3_nonce(nonce)

            async def _fake_spawn(
                *, provider_key: str, refusal_recorder: object = None, **_golive: object
            ) -> _EchoingChildDouble:
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
                real_gate=gate,
                # The budget pre-check halts the turn BEFORE its first
                # `router.complete()` call, so this override is never actually
                # invoked — the test seam still requires SOME router so boot
                # never reaches the real, egress-proxied build_router. Its
                # answer is the sentinel this test asserts never renders.
                router_override=cast(ProviderRouter, FixedAnswerRouter(answer=_UNREACHABLE_ANSWER)),
            )

            # ---- Boot the REAL daemon socket carrier (binds comms-tui.sock) ----
            listener = await _listen_socket_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="s593-turn-failed-chain-proof",
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
                dial_adapter_id="tui",
                sleep=_instant_sleep,
                jitter=_no_jitter,
                shutdown_event=gateway_shutdown,
                tui_leg=tui_leg,
            )
            gateway_scheduler = wire_leg_scheduler(core_link, tui_leg)

            # ---- Dial the gateway from the cohost (over comms-gateway.sock) ----
            async def _accept_and_handshake_client() -> Any:
                await gateway_client_listener.accept()
                client_transport = gateway_client_listener.transport
                assert client_transport is not None
                client_seq_enabled = await _gateway_client_handshake(client_transport)
                return client_transport, client_seq_enabled

            accept_task = asyncio.ensure_future(_accept_and_handshake_client())
            cohost_transport = await dial_comms_socket("gateway")

            # ---- Build the REAL TuiSession + AlfredTuiApp (Task 16's brief: a
            # real AlfredTuiApp under run_test(), NOT a recording double) and
            # cross-wire it into the wire pump exactly as alfred_tui.cohost.
            # run_cohosted does in production (build_app + _serve_wire's
            # on_turn_failed callback routed to app.set_turn_failed). ----
            session = TuiSession(notify=_make_socket_inbound_sink(cohost_transport))
            app = build_app(session)  # cross-wires session.render_outbound -> app.write_outbound
            tui_server = TuiServer(session=session)

            async def _route_turn_failed(stage: TurnFailureStage) -> None:
                app.set_turn_failed(stage)

            cohost_wire_task = asyncio.ensure_future(
                _serve_wire(cohost_transport, tui_server, on_turn_failed=_route_turn_failed)
            )

            client_transport, client_seq_enabled = await asyncio.wait_for(
                accept_task, timeout=_TIMEOUT_S
            )
            assert isinstance(client_seq_enabled, bool)
            assert client_seq_enabled is False

            # ---- Build + run the REAL relay (core leg dial + handshake + pump) ----
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
                scheduler=gateway_scheduler,
            )
            relay_task = asyncio.ensure_future(relay.run())

            # The core leg must reach UP and HOLD (same discipline as the sibling
            # proof — see its comment for why the "stayed up" re-check matters).
            await _wait_for(lambda: core_link._core_epoch is not None, _TIMEOUT_S)
            await asyncio.sleep(0.2)
            assert core_link._machine.state is GatewayLinkState.UP, (
                "gateway core leg did not HOLD UP after the handshake — "
                f"link state: {core_link._machine.state}"
            )

            # ---- ACT: submit a REAL keystroke through the REAL AlfredTuiApp
            # under Textual's run_test() pilot — not a raw session call. ----
            async with app.run_test() as pilot:
                input_widget = app.query_one("#user_input", Input)
                input_widget.value = _INBOUND_CONTENT
                await pilot.press("enter")
                await pilot.pause()

                # Everything downstream is real local sockets + a real (fast)
                # Postgres testcontainer with NO network latency, so the whole
                # refusal round trip can complete WITHIN this single
                # `pilot.pause()` — `on_input_submitted`'s own
                # `await self._session.flush_keystroke_batch()` yields the loop
                # mid-send, and the concurrently-running wire pump can drive the
                # daemon's reply all the way back to `app.set_turn_failed` before
                # that await even returns. So `_turn_pending` may ALREADY be
                # `False` here — asserting `True` at this exact instant would be
                # racy, not a real precondition. The pending indicator is instead
                # proven below via TRANSCRIPT ORDER (deterministic regardless of
                # timing): the echoed "You: ..." + "thinking..." lines must
                # precede the turn-failure line, or the turn was never actually
                # marked pending before being released.

                # ASSERT (real Postgres): the inbound crossed cohost -> gateway
                # -> daemon and the daemon promoted it to T3 — the extract +
                # downgrade path ran before the budget pre-check that refuses it.
                await _wait_for(lambda: bool(_fetch_t3_promotion_rows(sync_url)), _TIMEOUT_S)

                # The daemon's real BudgetGuard refused the turn; its
                # turn.failed notification crossed daemon -> gateway (relayed
                # untouched) -> cohost's wire pump -> app.set_turn_failed,
                # which ends the pending turn.
                await _wait_for(lambda: app._turn_pending is False, _TIMEOUT_S)
                await pilot.pause()

                log_text = _richlog_text(app.query_one("#conversation_log", RichLog))
                # The pending indicator DID engage, in the right order, before
                # being released — the "pending" half of #593's proof. Check
                # each localized marker's presence explicitly (log_text in the
                # message) BEFORE calling .index() on it — a missing marker
                # should fail with the actual transcript content, not a bare
                # ValueError("substring not found") that hides it.
                #
                # Whitespace-collapsed on BOTH sides (matching the #594 S3
                # fix in plugins/alfred_tui/tests/test_textual_app.py): the
                # budget_exhausted copy is 160 chars, longer than RichLog's
                # ~78-col wrap width in this run_test() terminal, so a
                # word-wrap can land a literal "\n" where the msgstr has a
                # plain space. Collapsing runs of whitespace to one space is
                # order-preserving, so the three markers' relative .index()
                # positions below still correctly prove transcript order.
                normalized_log_text = " ".join(log_text.split())
                you_marker = " ".join(t("tui.label_you").split())
                thinking_marker = " ".join(t("tui.thinking").split())
                failed_marker = " ".join(t("tui.turn_failed.budget_exhausted").split())
                assert you_marker in normalized_log_text, log_text
                assert thinking_marker in normalized_log_text, log_text
                assert failed_marker in normalized_log_text, log_text
                you_index = normalized_log_text.index(you_marker)
                thinking_index = normalized_log_text.index(thinking_marker)
                failed_index = normalized_log_text.index(failed_marker)
                assert you_index < thinking_index < failed_index, log_text
                # Non-vacuity: the turn never reached a real completion — the
                # router's canned reply must be ABSENT (the pre-check halted
                # before router.complete() could ever be called).
                assert _UNREACHABLE_ANSWER not in log_text

                # (1) the localized budget_exhausted copy reached the transcript
                # (already proven present above by the ``.index()`` lookup) and
                # (2) #user_input is re-enabled, not left disabled forever.
                assert app.query_one("#user_input", Input).disabled is False
    finally:
        # Reap EVERY acquired resource on EVERY exit path (mirror the sibling
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
