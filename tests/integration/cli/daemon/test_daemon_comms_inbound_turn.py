"""PR-S4-11b end-to-end proof — the daemon comms-spawn machinery, turn-complete.

The keystone the whole PR-S4-11b daemon comms-spawn build stands on: the daemon's
PRODUCTION boot helpers (:func:`_build_comms_boot_graph` +
:func:`_spawn_comms_adapter`) spawn a REAL launcher-launched ``alfred_comms_test``
plugin, the plugin emits a real ``inbound.message`` notification, and that frame
travels the FULL inbound trust-boundary path —

    pump -> session._on_post_handshake_method -> InboundMessageHandler.process
         -> process_inbound_message (resolve -> burst -> quarantined_extract[fixture]
            -> ingest -> dispatch) -> CommsInboundOrchestratorAdapter.dispatch
         -> runner.send_request("outbound.message", ...) -> plugin

— landing a real ``comms.inbound.t3_promoted`` audit row in a REAL Postgres
testcontainer, with the resolved canonical user id and a peppered
``platform_user_id_hash``, and emitting the ack outbound frame back to the plugin.

This is the proof PR-S4-11b's unit cut (``test_daemon_comms_spawn.py``) cannot
give: that suite monkeypatches ``CommsStdioTransport`` / ``CommsPluginRunner`` to
fakes, so it proves the construction order but NOT that the wired graph actually
processes a turn through a launcher-spawned subprocess against real Postgres.

Production-helper reuse (NOT reimplementation)
----------------------------------------------
The boot graph is assembled by the SAME production helpers ``_start_async`` calls
— :func:`_build_comms_boot_graph` and :func:`_spawn_comms_adapter` — so the test
exercises the production wiring, not a copy of it. ``_spawn_comms_adapter`` was
given an additive return of the live :class:`CommsPluginRunner` (it previously
returned ``None``) precisely so this test can drive the host -> plugin request
seam through the real runner; the daemon boot loop ignores that return (the
runner's lifetime is the supervised pump it just registered).

The ONLY substitutions are at seams that are not the property under proof:

* a recording **fake supervisor** captures the pump coroutine
  (``register_plugin_task``) so the test owns driving it, and satisfies the
  breaker-trip / restart seams (no breaker trip is expected on the happy path);
* the hook registry is installed via the production
  :func:`install_boot_hook_registry` over a grant-seeded REAL :class:`RealGate`
  (:func:`_boot_gate_with_comms_load_grant` — scoped grants for the DLP chain +
  the comms plugin load), NEVER a permissive shim (CLAUDE.md hard rule #2) — so
  the post-stage DLP subscriber genuinely registers AND the adapter's load is
  authorized the way an approved operator grant would (see the "real-source
  deviation" note: the production boot gate does not yet supply that load grant).

Everything else — the launcher spawn, the stdio transport, the session handler
fan-out, the inbound trust-boundary path, the real ``QuarantinedExtractor`` (over
the real ``QuarantineStdioTransport`` driving an in-proc echoing child double in
place of the bwrap spawn this off-Linux leg cannot do — the docker-only flip test
proves the genuine bwrap child), the real identity resolver, the real burst
limiter, the real ``AuditWriter`` against real Postgres — is production code.

Why it runs locally (macOS) + on root CI
-----------------------------------------
The reference manifest declares ``sandbox.kind = "none"``; under
``ALFRED_ENVIRONMENT=test`` the launcher execs the plugin unsandboxed on
non-Linux dev hosts, while a Linux runner UID-drops via ``runuser`` (root-only).
The skipif mirrors ``tests/integration/test_comms_runner_substrate.py``: skip on
non-root Linux, run on macOS + the root CI integration runner.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import struct
from collections.abc import AsyncIterator, Coroutine, Iterator
from contextlib import asynccontextmanager, suppress
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from alfred.audit.log import AuditWriter
from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.cli.daemon._commands import (
    _build_boot_outbound_dlp,
    _build_comms_boot_graph,
    _CommsBootGraph,
    _spawn_comms_adapter,
)
from alfred.config.settings import Settings
from alfred.hooks.boot import install_boot_hook_registry
from alfred.hooks.capability import CapabilityGate
from alfred.hooks.registry import get_registry, set_registry
from alfred.identity import (
    Authorization,
    Platform,
)
from alfred.identity.models import PlatformIdentity, User
from alfred.memory.hooks_audit_sink import EpisodicAuditSink
from alfred.memory.models import Base
from alfred.plugins.comms_stdio_transport import CommsStdioTransport
from alfred.providers.router import ProviderRouter
from alfred.security import tiers as _tiers
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import _make_in_memory_backend, _make_no_op_audit_sink
from tests.helpers.routers import FixedAnswerRouter


class _EchoingChildDouble:
    """In-proc length-prefixed child double echoing the ingested body.

    PR-S4-11c-2b: the daemon's comms boot graph now spawns a REAL bwrap quarantined
    child. This end-to-end proof runs on macOS / non-root Linux (no bwrap), so it
    monkeypatches ``spawn_quarantine_child_io`` to return this double — the daemon's
    real ``QuarantineStdioTransport`` drives it exactly as it would the live child.
    The docker-only ``test_daemon_comms_flip_real_spawn`` proves the genuine bwrap
    spawn; this proof keeps the full inbound-turn path runnable off-Linux.
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
            # Fail loud on an unknown handle rather than echoing "" — a broken
            # ingest→extract handle flow (e.g. a split staging map) must surface as
            # a crash here, not a synthetic "extracted" reply the audit assertions
            # would false-pass on (CR #255).
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


pytestmark = pytest.mark.integration

# The reference plugin's stable identifiers (see plugins/alfred_comms_test/main.py
# + plugins/alfred_comms_test/manifest.toml).
_ADAPTER_ID = "alfred_comms_test"  # [comms_mcp] adapter_kind the host tables key on

# Discriminating inbound values — NOT the reference plugin's defaults
# ("discord:reference" / "") so a round-trip that silently dropped the trigger
# params would surface as the wrong canonical id / a refused empty body.
_PLATFORM_USER_ID = "discord:victim-9931"
_INBOUND_CONTENT = "hello from the s4-11b end-to-end proof"

# The synthetic Discord-bound user the resolver must map the inbound to.
_CANONICAL_SLUG = "alice"
_USER_LANGUAGE = "en-GB"

# A >=32-byte pepper for the audit_hash HKDF (matches the harness floor). The
# daemon's production broker reads this from the env (``ALFRED_AUDIT.HASH_PEPPER``
# — the broker maps the ``audit.hash_pepper`` secret name onto that env var).
_AUDIT_HASH_PEPPER = "integration-test-pepper-0123456789abcdef-padding"

# Generous bound so a wedged subprocess fails loud rather than hanging the pump.
_TIMEOUT_S = 15.0

# The reference plugin's kind="none" launcher UID-drops via ``runuser`` on Linux
# (root-only). Point ``ALFRED_PLUGIN_UID`` at the current user so
# ``runuser -u <self>`` succeeds when run as root; the skipif covers the non-root
# Linux runner that cannot UID-drop. On macOS the launcher execs unsandboxed in
# dev/test, so this runs locally without root. Mirrors the substrate test's
# proven posture (required-checks.md: launcher-spawn legs are local/root-only).
_LAUNCHER_TEST_UID = getpass.getuser()
_LAUNCHER_REQUIRES_ROOT = os.uname().sysname == "Linux" and os.geteuid() != 0

# The reference plugin's manifest plugin id + declared subscriber tier (see
# plugins/alfred_comms_test/manifest.toml). The session's post-handshake
# ``check_plugin_load`` is gated on ``(plugin_id, manifest_tier)``.
_PLUGIN_ID = "alfred.comms-test"
_PLUGIN_MANIFEST_TIER = "user-plugin"


def _boot_gate_with_comms_load_grant() -> CapabilityGate:
    """Return a REAL RealGate seeded for BOTH chains this turn exercises.

    CLAUDE.md hard rule #2 — a real :class:`RealGate` over scoped fixture grants,
    NEVER a permissive shim. Two grants, both evaluated by the SAME production
    :meth:`GatePolicy.check` the hot path uses:

    * the system-tier ``security.quarantined.extract`` grant
      (``make_quarantined_extract_chain_gate``'s grant) so the
      :class:`QuarantinedExtractor`'s post-stage DLP subscriber registers; and
    * a ``(alfred.comms-test, user-plugin, "*")`` grant authorizing the comms
      adapter's plugin load at handshake (``check_plugin_load`` delegates to
      ``check(..., hookpoint="*", requested_tier=manifest_tier)``).

    This second grant MATCHES what production now seeds: the daemon boot path
    derives one config-sourced ``check_plugin_load`` grant per enabled comms
    adapter via ``comms_adapter_load_grants`` (ADR-0027 Decision 6), threaded
    into the seed-gate as ``extra_grants``, and passes the RAW ``real_gate``
    (not the ``_SupervisorBootGate`` wrapper) to ``_spawn_comms_adapter`` so the
    handshake's ``check_plugin_load`` resolves. This test installs the gate +
    registry DIRECTLY (bypassing the probe sequence + real-Postgres seed for a
    hermetic turn), seeding the SAME ``(alfred.comms-test, user-plugin, "*")``
    grant the production builder produces — so the inbound-turn proof exercises
    the real grant policy, not a permissive shim.
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
            # t3.downgrade_to_orchestrator on every real turn this proof drives.
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


class _OutboundFrameRecorder:
    """Records every host -> plugin frame as the raw bytes the transport writes.

    Wraps the REAL :meth:`CommsStdioTransport.send` (installed via monkeypatch on
    the class) so the #152 identity invariant can be asserted on the ACTUAL bytes
    production sends to the plugin — not on a hand-built frame. The serialization
    mirrors the transport's own (``json.dumps(frame) + "\\n"``).
    """

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        # The live transport instance, captured on first send so the test can
        # drive the fire-and-forget inject TRIGGER (a notification, not a
        # request/response — so ``runner.send_request`` would hang on it).
        self.transport: CommsStdioTransport | None = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        original = CommsStdioTransport.send
        recorder = self

        async def _recording_send(self: CommsStdioTransport, frame: Any) -> None:
            recorder.transport = self
            recorder.frames.append((json.dumps(dict(frame)) + "\n").encode())
            await original(self, frame)

        monkeypatch.setattr(CommsStdioTransport, "send", _recording_send)


class _RecordingSupervisor:
    """Captures the pump coroutine + records breaker/restart hand-offs.

    Stands in for the real :class:`alfred.supervisor.core.Supervisor` at the ONE
    seam this proof does not exercise — the supervised TaskGroup. The production
    ``_spawn_comms_adapter`` calls ``register_plugin_task(runner.pump())``; here
    we capture that coroutine so the TEST owns driving the pump (and can race it
    against the inbound injection + await the routed turn). It satisfies the
    session's ``_SupervisorLike`` seam (``trip_breaker`` / ``request_plugin_restart``)
    and the breaker-tripper bridge; no trip is expected on the happy path.
    """

    def __init__(self) -> None:
        self.registered: list[asyncio.Task[None]] = []
        self.trip_calls: list[dict[str, str]] = []
        self.restart_calls: list[dict[str, str]] = []
        # DEFECT 1 wired ``_spawn_comms_adapter`` to read the supervisor's
        # graceful-drain signal; the real Supervisor exposes a per-instance
        # ``shutdown_event``. Mirror it here so this double satisfies the spawn
        # seam (the unit ``FakeSupervisor`` carries the same attribute).
        self.shutdown_event = asyncio.Event()

    def register_plugin_task(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self.registered.append(task)
        return task

    async def trip_breaker(self, *, component_id: str, reason: str) -> None:
        self.trip_calls.append({"component_id": component_id, "reason": reason})

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None:
        self.restart_calls.append({"adapter_id": adapter_id, "reason": reason})


def _seed_discord_bound_user(sync_url: str) -> None:
    """Seed a Discord-bound ``alice`` so the resolver maps the inbound to her.

    #338 PR2: also seeds a SEPARATE household-operator row — ``build_orchestrator``
    (inside the real turn now driven by ``_build_comms_boot_graph``) constructs a real
    ``Orchestrator``, whose constructor synchronously calls
    ``identity_resolver.get_operator()``. ``alice`` stays STANDARD.
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
async def _boot_audit_writer(postgres_url: str) -> AsyncIterator[AuditWriter]:
    """Create the schema, seed the user, and yield a real Postgres AuditWriter."""
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
    """Set the env the production Settings + broker + launcher boot read.

    ``ALFRED_ENVIRONMENT=test`` opens the reference plugin's inject_inbound gate
    AND makes the launcher exec kind="none" unsandboxed on dev hosts;
    ``ALFRED_AUDIT.HASH_PEPPER`` is the broker secret the inbound audit_hash recipe
    fetches (the broker maps the ``audit.hash_pepper`` secret name onto this env
    var). ``ALFRED_PLUGIN_UID`` is the runuser target on a root Linux runner.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # The reference plugin gates inject_inbound on ALFRED_ENV (not _ENVIRONMENT).
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
    yield


async def _wait_for(predicate: Any, timeout: float) -> None:
    """Poll ``predicate`` (a 0-arg bool callable) until true or the deadline."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError("inbound-turn condition never became true")


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


def _fetch_quarantine_extract_rows(sync_url: str) -> list[dict[str, Any]]:
    """Return every ``quarantine.extract`` audit row's result (the extractor lift)."""
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT result FROM audit_log WHERE event = :event"),
                {"event": "quarantine.extract"},
            )
            return [dict(row._mapping) for row in result]
    finally:
        engine.dispose()


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="kind=none launcher UID-drops via runuser (root-only on Linux); "
    "runs locally + on the root CI integration runner",
)
@pytest.mark.usefixtures("_boot_env")
async def test_daemon_comms_inbound_turn_lands_t3_promotion_row(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: spawned plugin inbound -> full path -> real T3-promotion row + ack."""
    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")

    # Capture the REAL host -> plugin frames the transport writes so the #152
    # identity invariant is asserted on production bytes (not a hand-built frame).
    recorder = _OutboundFrameRecorder()
    recorder.install(monkeypatch)

    # Install the production boot hook registry over a grant-seeded REAL RealGate
    # so the QuarantinedExtractor's post-stage DLP subscriber genuinely registers
    # (CLAUDE.md hard rule #2 — never a permissive shim). The sink is the durable
    # EpisodicAuditSink the daemon wires in production. Restore the singleton in
    # teardown so this test does not leak its registry into sibling tests.
    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
    gate = _boot_gate_with_comms_load_grant()
    runner = None
    graph: _CommsBootGraph | None = None
    supervisor = _RecordingSupervisor()
    try:
        async with _boot_audit_writer(postgres_url) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            # Build the comms graph + spawn the adapter the SAME way the daemon
            # does (production helpers — reuse, not reimplementation).
            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
            # PR-S4-11c-2b: ``_build_comms_boot_graph`` is now ASYNC and CONSUMES the
            # ``t3_nonce`` — it builds a real ``T3BodyRecorder`` that tags the inbound
            # body ``TaggedContent[T3]`` with the AUTHORISED nonce, so the nonce must
            # be the registered process slot (not a bare inert one). Register it for
            # the turn + restore on teardown. The graph also SPAWNS the quarantined
            # child; this off-Linux proof monkeypatches the spawn seam to the in-proc
            # echoing double (the docker-only flip test proves the real bwrap spawn).
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
                # PR-S4-235-1: the graph now builds the daemon-owned ContentStore the
                # per-adapter promoter shares. ``alfred_comms_test`` is empty-set (None
                # promoter), so the store is never written to here; pass ``None`` for
                # the policies ref since this turn exercises no per-session quota deref.
                policies_ref=None,
                real_gate=gate,
                # #338 PR2: offline test seam — this proof asserts the T3-promotion
                # audit row, not reply content, so the real, egress-proxied
                # build_router is never reached.
                router_override=cast(ProviderRouter, FixedAnswerRouter()),
            )
            runner = await _spawn_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="s4-11b-e2e-proof",
                environment_source="env_var",
            )

            # The pump was registered on the (fake) supervisor's TaskGroup stand-in;
            # it is now reading, so the injected inbound notification will be routed.
            assert len(supervisor.registered) == 1

            # ACT: drive the inbound turn through the REAL transport's host ->
            # plugin write seam. The inject_inbound trigger is a NOTIFICATION (the
            # plugin emits an inbound.message frame back, with no correlated
            # response id), so it is fired via the transport's fire-and-forget
            # ``send`` — NOT ``runner.send_request`` (which would hang awaiting a
            # response that never comes). The runner's pump is the sole reader; this
            # is only a WRITE, so there is no reader conflict. Mirrors the substrate
            # test's ``transport.send`` trigger pattern.
            assert recorder.transport is not None  # set during the handshake send
            await recorder.transport.send(
                {
                    "jsonrpc": "2.0",
                    "method": "alfred_comms_test/inject_inbound",
                    "params": {
                        "platform_user_id": _PLATFORM_USER_ID,
                        "content": _INBOUND_CONTENT,
                    },
                }
            )

            # ASSERT (against real Postgres): the T3-promotion row lands. Poll
            # rather than sleep — the inbound path is async across the pump.
            await _wait_for(lambda: bool(_fetch_t3_promotion_rows(sync_url)), _TIMEOUT_S)

            # The ack outbound frame reached the plugin (dispatch -> send_outbound
            # -> outbound.message request). The plugin's handle_outbound_message
            # buffered it; adapter.health reports the buffer depth, and the runner
            # correlates that REQUEST/response (adapter.health IS a request).
            #
            # #338 PR2: poll rather than a single immediate check — the REAL turn
            # (working-memory pool acquire/release + a completion call through
            # the injected router) adds async work between the T3-promotion
            # commit (just awaited above) and the outbound ack actually reaching
            # the plugin's buffer, unlike the old echo path's near-synchronous ack.
            deadline = asyncio.get_running_loop().time() + _TIMEOUT_S
            delivered: dict[str, Any] = {}
            while asyncio.get_running_loop().time() < deadline:
                delivered = await runner.send_request("adapter.health", {})
                if int(str(delivered["queue_depth"])) >= 1:
                    break
                await asyncio.sleep(0.02)
            assert int(str(delivered["queue_depth"])) >= 1, delivered
        # End the audit-writer context only after the assertions that need it.
    finally:
        # Tear down EVERY acquired resource regardless of how far boot got — do NOT
        # gate on `runner` (resources are acquired BEFORE it is assigned, so a
        # `_spawn_comms_adapter` failure mid-way would otherwise leak them). CR #255.
        for task in supervisor.registered:
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=_TIMEOUT_S)
        # Close the live adapter CommsStdioTransport (captured on first send) so the
        # launcher-spawned adapter subprocess never leaks past the test.
        if recorder.transport is not None:
            with suppress(Exception):
                await recorder.transport.close()
        # Reap the quarantine child the comms graph owns whenever the graph built
        # (graph built => quarantine_transport => spawned child).
        if graph is not None:
            with suppress(Exception):
                await graph.aclose()
        set_registry(prior_registry)
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)

    # The quarantine.extract row lands result="extracted" — the LOAD-BEARING
    # extractor-lift assertion (the docker-only flip test asserts it against a real
    # bwrap child; here it runs on every integration leg). Because the recorder
    # stages the T3 body and the transport drains it from the SAME single-use
    # QuarantineStagingMap, an "extracted" row also proves _build_comms_boot_graph
    # shares ONE staging map between recorder + transport — a split map would make
    # the drain raise (StagingHandleNotConfiguredError) and never land this row.
    extract_rows = _fetch_quarantine_extract_rows(sync_url)
    assert len(extract_rows) == 1, extract_rows
    assert extract_rows[0]["result"] == "extracted", extract_rows[0]

    rows = _fetch_t3_promotion_rows(sync_url)
    assert len(rows) == 1, rows
    row = rows[0]
    subject = row["subject"]

    # The resolved canonical id (alice) lands on the row — proving the real
    # identity resolver mapped discord:victim-9931 -> the seeded Discord binding.
    assert subject["canonical_user_id"] == _CANONICAL_SLUG
    assert row["actor_user_id"] == _CANONICAL_SLUG
    assert subject["adapter_id"] == _ADAPTER_ID
    assert subject["language"] == _USER_LANGUAGE
    # T3 provenance is hard-coded on the inbound path (no silent promotion).
    assert row["trust_tier_of_trigger"] == "T3"
    assert row["result"] == "promoted"

    # The platform user id crosses the audit boundary ONLY as a peppered hash —
    # never the raw value (sec-010). The trace_id is the inbound message id, not
    # the raw platform id.
    pid_hash = subject["platform_user_id_hash"]
    assert isinstance(pid_hash, str) and pid_hash
    assert _PLATFORM_USER_ID not in pid_hash
    assert pid_hash != _PLATFORM_USER_ID

    # #152 identity invariant: the canonical user id NEVER crosses outward in any
    # host -> plugin frame. The platform user id IS allowed outward (it is the
    # addressing channel — the ack's target_platform_id), but the canonical id is
    # resolved host-side and stays host-side. Assert on the REAL captured bytes
    # (every host -> plugin frame: handshake, inject trigger, the outbound ack,
    # the health probe). At least the ack frame must be present.
    assert recorder.frames, "expected captured host -> plugin frames (incl. the ack)"
    ack_frames = [f for f in recorder.frames if b"outbound.message" in f]
    assert ack_frames, "expected the dispatch ack (outbound.message) frame"
    for frame_bytes in recorder.frames:
        decoded = frame_bytes.decode()
        assert _CANONICAL_SLUG not in decoded, decoded
