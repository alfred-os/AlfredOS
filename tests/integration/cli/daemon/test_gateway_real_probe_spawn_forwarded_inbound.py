"""DOCKER-ONLY: a REAL bwrap gateway adapter child's inbound reaches core dispatch.

Spec B G6-7-7 Task 4 (#309) — the keystone privileged proof of the whole G6-7
inbound-forward bridge. It is the docker-only sibling of the off-Linux A1 scaffold
(``test_forwarded_inbound_gateway_to_core_turn.py``): A1 injects the forwarded frame
DIRECTLY via ``core_link.forward_adapter_inbound(...)``; Task 4 REPLACES that direct
injection with the production path end to end —

    GatewayAdapterSupervisor.supervise_one("discord")
      -> GatewayAdapterChildFactory.spawn_and_handshake (override -> alfred.gateway.discord_probe)
        -> REAL bin/alfred-plugin-launcher.sh -> bwrap (sandbox.kind="full") -> the probe child
      -> GatewayAdapterCredentialClient.acquire_and_deliver
        -> core_link.request_spawn_grant (over the UP core leg)
          -> the daemon socket carrier's CoreAdapterCredentialResolver
            (discord -> secret-id discord_bot_token -> the broker's env-fallback marker)
        -> deliver_provider_key_via_fd3 (atomic writev onto the child's fd-3 WRITE end)
      -> the probe reads fd 3, acks ``fd3-received``, emits ONE ``inbound.message``
      -> _GatewayAdapterChild.wait_until_exit drives GatewayInboundForwardRunner.pump
        -> GatewayForwardDisposition -> core_link.forward_adapter_inbound("discord", body)
          -> the discord GatewayLeg -> the leg scheduler drain -> write_leg_unit
            -> the seq codec -> comms-tui.sock -> the daemon pump
              -> the disposition's gateway.adapter.inbound method-peek
                -> GatewayForwardedInboundReceiver.receive -> process_inbound_message
                  (commit_at_dispatch_edge=True, against a REAL Postgres testcontainer)

landing (a) a discord ``comms.inbound.t3_promoted`` audit row resolved to the
seeded probe-bound user and (b) a committed G0 ``inbound_idempotency`` row on the
composite ``(discord, _PROBE_INBOUND_ID)`` key, with NO ``comms.inbound.poisoned``
dead-letter row.

How it differs from the two mirrors
------------------------------------
* vs A1 (``test_forwarded_inbound_gateway_to_core_turn``): A1 keeps the WHOLE
  forwarded-path scaffold (real daemon comms graph, real socket carrier, real
  gateway core leg + relay + cohost handshake, the discord-leg registration) but
  injects the frame by calling ``forward_adapter_inbound`` directly — the gateway
  ADAPTER supervisor never spawns. Task 4 reuses that scaffold UNCHANGED and adds
  the REAL ``GatewayAdapterSupervisor`` + the REAL ``GatewayInboundForwardRunner``
  forward factory (reused from production via
  :meth:`GatewayProcess._build_adapter_runner_factory`) + a REAL bwrap probe spawn,
  so the credential round-trip (never exercised by A1 — its spawn never ran) is
  proven for real and the inbound is PRODUCED by a live child, not injected.
* vs the flip mirror (``test_daemon_comms_flip_real_spawn``): that test makes the
  QUARANTINE child a real bwrap spawn; here the quarantine child stays the in-proc
  ``_EchoingChildDouble`` (monkeypatched, exactly as A1) and ONLY the gateway
  ADAPTER child (the probe) is a real bwrap spawn — a DIFFERENT sandbox host
  (``alfred.gateway.adapter_child_factory`` / ``bin/alfred-plugin-launcher.sh``).

The fd-3 credential-absence proof (the crux — test-101 / test-002 / sec-005)
----------------------------------------------------------------------------
The marker delivered as the discord ``discord_bot_token`` is a UNIQUE high-entropy
blob GENERATED AT RUNTIME (``"g67probe." + secrets.token_hex(24)`` — never a
token-shaped source literal, so GitHub push-protection GH013 cannot trip). It is
seeded ONLY in ``ALFRED_DISCORD_BOT_TOKEN`` (the broker's file-first / env-fallback
source for ``discord_bot_token``; no secrets file exists in the test, so the env
wins). The probe child's env is SCRUBBED — ``_scrubbed_base``'s allowlist EXCLUDES
``ALFRED_DISCORD_BOT_TOKEN`` — so the marker reaches the probe ONLY over fd 3. That
is the G6-3 invariant. With the probe blocked reading stdin AFTER its emit (so the
child is ALIVE), we read ``/proc/<child.pid>/environ`` and assert the marker bytes
are ABSENT, with three controls so the assertion can never pass vacuously:
NON-EMPTY (``len(environ_bytes) > 0``), a MUTATION control (a known-present var —
``PATH=`` — IS in the SAME read, proving the assertion CAN fire), and a POSITIVE
fd-3 control (the forwarded ``t3_promoted`` row landed AT ALL — the probe emits the
inbound only AFTER reading fd 3, so the inbound's arrival proves the fd-3 delivery
happened).

WHY DOCKER-ONLY
---------------
The gateway adapter child resolves ``sandbox.kind="full"`` -> bwrap on Linux; the
spawn needs ``bwrap`` present, a Linux kernel, AND root, PLUS the ADR-0030 bound-
interpreter provisioning (``ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON`` set to a real
interpreter binary with ``alfred`` installed into it). It SKIPS on macOS / non-root
/ unprovisioned CI and RUNS + gates merge on the privileged-Linux CI legs
(``integration-privileged``; aarch64 twin ``integration-privileged-arm64``, #269).
The quarantine-child provisioning
(``ALFRED_QUARANTINE_CHILD_PYTHON``) is deliberately OUT of the gate — the
quarantine child stays the in-proc echo double, so it is never spawned here.
Reproduce locally via the docker-privileged reproduction recipe in
``docs/subsystems/comms.md`` (proto py3.14 + ``uv pip install --python "$PROTO_PY" .``
+ ``uv sync --dev`` + the bound ``sudo env`` / ``uv run pytest`` invocation). See
``tests/integration/cli/daemon/test_daemon_comms_flip_real_spawn.py`` (the daemon-
layer real-spawn proof this mirrors) and procedural_local_docker_for_ci_only_failures
in project memory.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import secrets
import shutil
import struct
import subprocess
from collections.abc import AsyncIterator, Coroutine, Iterator
from contextlib import asynccontextmanager, suppress
from typing import Any, cast

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
from alfred.cli.daemon._boot_audit import LifecycleBroadcaster
from alfred.cli.daemon._commands import _build_boot_outbound_dlp
from alfred.cli.daemon._comms_boot import (
    _build_comms_boot_graph,
    _CommsBootGraph,
    _listen_socket_comms_adapter,
)
from alfred.config.settings import Settings
from alfred.egress.adapter_egress_addr import DISCORD_EGRESS_SOCKET_PATH
from alfred.gateway.adapter_child_factory import GatewayAdapterChildFactory
from alfred.gateway.adapter_credential_client import GatewayAdapterCredentialClient
from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import GatewayAdapterSupervisor
from alfred.gateway.client_link import client_handshake as _gateway_client_handshake
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.discord_probe import (
    _PROBE_CONTENT,
    _PROBE_INBOUND_ID,
    _PROBE_PLATFORM_USER_ID,
)
from alfred.gateway.link_state import GatewayLinkState
from alfred.gateway.process import (
    GatewayProcess,
    _CoreEpochCredSeam,
    build_adapter_leg,
    build_tui_leg,
    wire_leg_scheduler,
)
from alfred.gateway.relay import GatewayRelay
from alfred.gateway.status_leg import GatewayCoreLinkStatusSink
from alfred.hooks.boot import install_boot_hook_registry
from alfred.hooks.registry import get_registry, set_registry
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

# The TUI socket-carrier adapter (binds ``comms-tui.sock`` via adapter_kind="tui") — the
# carrier the gateway's core leg dials. The FORWARDED inbound's adapter id is "discord".
_ADAPTER_ID = "alfred_tui"
_PLUGIN_ID = "alfred_tui"
_PLUGIN_MANIFEST_TIER = "operator"  # plugins/alfred_tui/manifest.toml subscriber_tier

# The forwarded inbound is a DISCORD frame (the probe announces adapter_id="discord");
# its envelope + body adapter_id is "discord".
_FORWARDED_ADAPTER_ID = "discord"

# The seeded discord-bound user the probe's _PROBE_PLATFORM_USER_ID maps to. The probe
# owns the inbound id / platform id / content sentinels (imported above) because the
# scrubbed child env cannot carry per-test values.
_CANONICAL_SLUG = "alice"
_USER_LANGUAGE = "en-GB"

# A >=32-byte pepper for the audit_hash HKDF (matches the harness floor).
_AUDIT_HASH_PEPPER = "integration-test-pepper-0123456789abcdef-padding"

# Generous bounds so a wedged leg / unspawned child fails loud rather than hanging.
_TIMEOUT_S = 30.0

_LAUNCHER_TEST_UID = getpass.getuser()


# DOCKER-ONLY guard (gate on the GATEWAY-adapter var, NOT the quarantine var; the
# quarantine child stays the in-proc echo double). The gateway adapter child needs
# bwrap + Linux + root + the ADR-0030 bound-interpreter provisioning
# (``ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON`` set to a real interpreter with ``alfred``
# installed). The standard uv-venv CI leg lacks the bound interpreter, so this SKIPS
# there rather than failing.
_HAS_BWRAP = shutil.which("bwrap") is not None
_PROVISIONED = bool(os.environ.get("ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON"))
# os.uname / os.geteuid do NOT exist on Windows; since @skipif is evaluated at import,
# probe them behind hasattr so test COLLECTION stays import-safe on non-Unix (a Windows
# box would otherwise AttributeError before the skip; CR #255).
_IS_LINUX_ROOT = (
    hasattr(os, "uname")
    and os.uname().sysname == "Linux"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
)
_DOCKER_ONLY = pytest.mark.skipif(
    not _HAS_BWRAP or not _IS_LINUX_ROOT or not _PROVISIONED,
    reason=(
        "gateway real-spawn: needs bwrap + Linux + root + the ADR-0030 bound-interpreter "
        "provisioning (ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON set, alfred installed into that "
        "interpreter). RUNS + gates merge on the privileged-Linux CI legs "
        "(`integration-privileged` on amd64, `integration-privileged-arm64` on "
        "aarch64 — #269); skipped on macOS / non-root / unprovisioned local "
        "boxes — reproduce via `docker run --rm --privileged --platform "
        "linux/<arch>`: use `linux/arm64` on an Apple-Silicon host (amd64 emulation "
        "fails there with `exec format error` without qemu binfmt), `linux/amd64` on "
        "x86-64."
    ),
)


class _EchoingChildDouble:
    """In-proc length-prefixed quarantined-child double echoing the ingested body.

    The daemon's comms boot graph spawns a REAL bwrap QUARANTINED child; Task 4 makes
    ONLY the gateway ADAPTER child (the probe) a real bwrap spawn, so the quarantine
    spawn seam is monkeypatched to this double (exactly as A1). The daemon's real
    ``QuarantineStdioTransport`` drives it as it would the live child. Mirrors
    ``test_forwarded_inbound_gateway_to_core_turn._EchoingChildDouble``.
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

    Stands in for the real ``Supervisor`` at the one seam this proof does not exercise —
    the supervised TaskGroup. ``_listen_socket_comms_adapter`` calls
    ``register_plugin_task(_accept_and_pump())``; we capture it so the TEST owns driving
    the carrier (and reaps it on teardown). Mirrors A1's double; carries the
    ``shutdown_event`` the carrier races ``accept()`` against.
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
    permissive shim. Two grants, both evaluated by the SAME production ``GatePolicy.check``
    the hot path uses: the system-tier ``security.quarantined.extract`` grant so the
    ``QuarantinedExtractor``'s post-stage DLP subscriber registers; and an
    ``(alfred_tui, operator, "*")`` grant authorizing the TUI socket carrier's plugin load
    at handshake (``check_plugin_load`` delegates to ``check(..., hookpoint="*", ...)``).
    Mirrors A1's ``_boot_gate_with_tui_load_grant``.
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


def _seed_discord_bound_user(sync_url: str) -> None:
    """Seed a Discord-bound ``alice`` keyed on the probe's platform id.

    The forwarded receiver dispatches with the per-``discord`` collaborator set, whose
    resolver bridge maps the wire ``adapter_kind`` -> :attr:`Platform.DISCORD`. So seed a
    ``Platform.DISCORD`` binding (NOT TUI) for the PROBE's fixed platform user id
    (``_PROBE_PLATFORM_USER_ID``, imported from the probe module) so the forwarded
    inbound the live probe emits resolves to ``alice``. Mirrors A1's seed helper, keyed on
    the probe's sentinel instead of A1's local constant.

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
                    platform_id=_PROBE_PLATFORM_USER_ID,
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
    """Create the schema, seed the probe-bound discord user, and yield a Postgres AuditWriter."""
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
    """Set the env the production Settings + broker + carrier boot read.

    ``ALFRED_ENVIRONMENT=test`` (per-test, devops-006 — NOT job-wide) is BOTH the launcher's
    kind="full" bwrap-policy resolver AND the gateway launch-target override allowlist gate
    (``_OVERRIDE_ALLOWED_ENVIRONMENTS`` = {"development", "test"}), so the
    ``override_map={"discord": (probe...)}`` is honored and the probe spawns. The marker is
    seeded as the broker's ``discord_bot_token`` via ``ALFRED_DISCORD_BOT_TOKEN`` (file-first
    then env; no secrets file exists in the test, so the env wins) and set per-test in the
    test body so its lifetime is the test's.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_ENV", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-integration-placeholder")
    monkeypatch.setenv("ALFRED_AUDIT.HASH_PEPPER", _AUDIT_HASH_PEPPER)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ADAPTER_ID}"]')
    monkeypatch.setenv("ALFRED_PLUGIN_UID", _LAUNCHER_TEST_UID)
    # G7-4 / ADR-0043: the shared discord-adapter bwrap policy rw-binds the gateway
    # egress-socket dir (``DISCORD_EGRESS_SOCKET_PATH.parent``). The REAL launcher binds
    # it unconditionally — fail-closed: a missing egress plane MUST fail the real adapter
    # spawn — so the real-spawn probe needs the source dir to exist exactly as the gateway
    # container provides it (the alfred-core image's mkdir + the egress volume). The probe
    # performs no egress; an empty dir satisfies the bwrap bind. (Skipped tests never reach
    # this fixture, so the mkdir only runs in the root+bwrap privileged lane.)
    egress_dir = DISCORD_EGRESS_SOCKET_PATH.parent
    egress_dir_created = not egress_dir.exists()
    egress_dir.mkdir(parents=True, exist_ok=True)
    try:
        yield
    finally:
        if egress_dir_created:
            shutil.rmtree(egress_dir, ignore_errors=True)


async def _wait_for(
    predicate: Any,
    timeout: float,
    *,
    watch: tuple[asyncio.Task[Any], ...] = (),
) -> None:
    """Poll ``predicate`` (a 0-arg bool callable) until true or the deadline.

    If any ``watch`` background task (the relay / accept-pump / cohost-wire / spawn loops)
    crashes mid-wait, re-raise its exception IMMEDIATELY so the ACT phase surfaces the REAL
    fault (a wire / dispatch / spawn break) loudly, instead of masking it as an opaque
    "condition never became true" timeout — the teardown ``suppress`` would otherwise
    swallow it entirely (err-002).
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
    raise TimeoutError("gateway real-spawn forwarded-inbound condition never became true")


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


@_DOCKER_ONLY
@pytest.mark.usefixtures("_boot_env")
async def test_real_bwrap_probe_spawn_forwarded_inbound_reaches_core_dispatch(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A REAL bwrap gateway probe's inbound reaches core dispatch; the credential is fd-3-only.

    Boots the A1 forwarded-path scaffold (real daemon comms graph with the in-proc
    quarantine echo double, real socket carrier, real gateway core leg + relay + cohost
    handshake, the discord-leg registration) UNCHANGED, then — instead of A1's direct
    ``forward_adapter_inbound`` injection — stands up the REAL ``GatewayAdapterSupervisor``
    over the REAL ``GatewayAdapterChildFactory`` (with the probe override + a recording
    Popen) and the production forward-runner factory, and SPAWNS a REAL bwrap probe. The
    probe acquires its credential over the leg (G6-3 round-trip), reads it off fd 3, and
    emits ONE ``inbound.message`` the real forward-runner pumps to core dispatch. Asserts
    the discord ``comms.inbound.t3_promoted`` row resolved to ``alice`` + the committed G0
    ``inbound_idempotency`` row on ``(discord, _PROBE_INBOUND_ID)`` + NO poisoned row, AND
    that the credential marker is ABSENT from the live child's ``/proc/<pid>/environ``
    (with NON-EMPTY + MUTATION + POSITIVE-fd-3 controls). Do NOT weaken the assertions.
    """
    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")

    # The fd-3 credential marker: UNIQUE + high-entropy + GENERATED AT RUNTIME (never a
    # token-shaped source literal -> GitHub push-protection GH013). Seeded ONLY as the
    # broker's ``discord_bot_token`` env-fallback; the scrubbed child env excludes
    # ``ALFRED_DISCORD_BOT_TOKEN``, so it can reach the probe ONLY over fd 3.
    bot_token_marker = "g67probe." + secrets.token_hex(24)
    monkeypatch.setenv("ALFRED_DISCORD_BOT_TOKEN", bot_token_marker)

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
    spawn_task: asyncio.Task[None] | None = None
    gateway_shutdown = asyncio.Event()
    cohost_transport: Any = None
    # The recording Popen captures the live probe child so we can read its /proc/<pid>/environ.
    spawned_procs: list[subprocess.Popen[bytes]] = []
    adapter_supervisor: GatewayAdapterSupervisor | None = None

    async def _instant_sleep(_delay: float) -> None:
        await asyncio.sleep(0)

    def _no_jitter(hi: float) -> float:
        return hi

    def _recording_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        # The factory builds the argv (the launcher path + the closed override target);
        # this wrapper only records the live child so we can read its /proc/<pid>/environ.
        # The argv is the factory's, never untrusted input — S603 is a false positive here.
        # The factory always spawns in BINARY mode (no text=/encoding=), so the child is a
        # ``Popen[bytes]`` at runtime; pyright cannot prove that through ``*args/**kwargs``
        # (it resolves the text overload), so cast to the seam's declared type.
        proc = cast("subprocess.Popen[bytes]", subprocess.Popen(*args, **kwargs))  # noqa: S603
        spawned_procs.append(proc)
        return proc

    try:
        async with _boot_audit_writer(postgres_url) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            # ---- Build daemon comms graph (real Postgres, real path, real discord receiver,
            # in-proc quarantine echo double — ONLY the gateway adapter child is real) ----
            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
            with _NONCE_LOCK:
                nonce = CapabilityGateNonce()
                _tiers._set_authorized_t3_nonce(nonce)

            async def _fake_spawn(
                *, provider_key: str, refusal_recorder: object = None
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
                # #338 PR2: offline test seam — this proof asserts the real-spawn
                # credential/forwarded-inbound wiring, not reply content, so the
                # real, egress-proxied build_router is never reached.
                router_override=cast(ProviderRouter, FixedAnswerRouter()),
            )

            # ---- Boot the REAL daemon socket carrier (binds comms-tui.sock + AUTO-wires
            # BOTH the credential resolver AND the forwarded-inbound receiver — the
            # ``_accept_and_pump`` carrier hard-codes with_credential_resolver=True +
            # with_forwarded_inbound_receiver=True, so the probe's G6-3 credential
            # round-trip is served by the daemon's CoreAdapterCredentialResolver) ----
            listener = await _listen_socket_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="g6-7-7-real-spawn-proof",
                environment_source="env_var",
                broadcaster=broadcaster,
            )
            assert len(supervisor.registered) == 1

            # ---- Start the REAL gateway core link: dial comms-tui.sock, bind the client sock ----
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
            # Register the BINDING discord leg so the production
            # ``core_link.forward_adapter_inbound(adapter_id="discord", ...)`` the
            # forward-runner calls finds a registered leg to route the probe's inbound onto
            # (the same per-adapter leg ``GatewayProcess._register_adapter_legs`` builds).
            gateway_scheduler.register_leg(build_adapter_leg(_FORWARDED_ADAPTER_ID))

            # ---- Build the REAL gateway adapter supervisor for "discord" with the probe
            # override + a recording Popen. The forward-runner factory is REUSED from
            # production via ``GatewayProcess._build_adapter_runner_factory`` (do NOT
            # hand-duplicate the GatewayInboundForwardRunner wiring — that would draw a
            # duplication finding; the helper also registers the per-adapter back-pressure
            # gate with the scheduler, FORK-C). The supervisor mirrors
            # ``GatewayProcess._build_adapter_supervisor`` collaborator-for-collaborator,
            # injecting ONLY the override_map + recording_popen (the test seam). ----
            gp = GatewayProcess(
                shutdown_event=gateway_shutdown, adapter_ids=[_FORWARDED_ADAPTER_ID]
            )
            runner_factory = gp._build_adapter_runner_factory(core_link, gateway_scheduler)
            child_factory = GatewayAdapterChildFactory(
                runner_factory=runner_factory,
                popen_factory=_recording_popen,
                override_map={
                    _FORWARDED_ADAPTER_ID: ("alfred.discord_probe", "alfred.gateway.discord_probe")
                },
            )
            adapter_supervisor = GatewayAdapterSupervisor(
                child_factory=child_factory,
                cred_seam=_CoreEpochCredSeam(core_link=core_link),
                credential_client=GatewayAdapterCredentialClient(core_link=core_link),
                emitter=AdapterStatusEmitter(sink=GatewayCoreLinkStatusSink(core_link=core_link)),
                epoch_source=core_link.current_core_epoch,
                sleep=_instant_sleep,
            )

            # ---- Dial the gateway from a minimal cohost (over comms-gateway.sock) so the
            # gateway's client-leg lifecycle.start is answered + the relay comes up. This
            # proof drives the FORWARDED path produced by the real probe, not a
            # cohost-originated turn, so no TuiServer turn is needed (reusing the production
            # serve loop just guarantees a conformant handshake reply). ----
            async def _accept_and_handshake_client() -> Any:
                await gateway_client_listener.accept()
                client_transport = gateway_client_listener.transport
                assert client_transport is not None
                client_seq_enabled = await _gateway_client_handshake(client_transport)
                return client_transport, client_seq_enabled

            accept_task = asyncio.ensure_future(_accept_and_handshake_client())
            cohost_transport = await dial_comms_socket("gateway")

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
            # The captured epoch is ALSO the supervisor's cred-seam liveness signal
            # (``_CoreEpochCredSeam.is_available`` reads ``current_core_epoch() is not None``),
            # so the spawn proceeds only once the credential leg is genuinely up.
            await _wait_for(lambda: core_link._core_epoch is not None, _TIMEOUT_S)
            await asyncio.sleep(0.2)  # let an ack-rejection tear the leg if it will
            assert core_link._machine.state is GatewayLinkState.UP, (
                "gateway core leg did not HOLD UP after the handshake — the daemon rejected "
                f"the gateway's lifecycle.start ack. Link state: {core_link._machine.state}"
            )

            # ---- PRE-SPAWN baseline (err-002): NO idempotency row + NO t3_promoted row
            # exists yet for the probe's key, so the post-spawn rows cannot be pre-existing. ----
            assert (
                _fetch_inbound_idempotency(
                    sync_url, adapter_id=_FORWARDED_ADAPTER_ID, inbound_id=_PROBE_INBOUND_ID
                )
                == []
            ), "pre-spawn: an inbound_idempotency row already exists for the probe key"
            assert _fetch_t3_promotion_rows(sync_url) == [], (
                "pre-spawn: a comms.inbound.t3_promoted row already exists"
            )

            # ---- ACT: spawn the REAL bwrap probe in the background. ``supervise_one``
            # checks the cred-seam liveness (epoch set -> available), spawns the child via
            # the launcher under bwrap, runs the G6-3 credential round-trip over the leg
            # (request_spawn_grant -> the daemon's CoreAdapterCredentialResolver -> the
            # marker delivered over fd 3), runs the handshake, reaches UP, then awaits the
            # child exit — driving the forward-runner pump which forwards the probe's ONE
            # inbound.message via core_link.forward_adapter_inbound to core dispatch. ----
            spawn_task = asyncio.ensure_future(
                adapter_supervisor.supervise_one(_FORWARDED_ADAPTER_ID)
            )

            act_watch = tuple(
                t
                for t in (
                    relay_task,
                    cohost_wire_task,
                    accept_task,
                    spawn_task,
                    *supervisor.registered,
                )
                if t is not None
            )

            # The probe's child is captured by the recording Popen the moment it spawns. Wait
            # for it so the credential-absence read targets the live child (it blocks reading
            # stdin after its emit, so it stays ALIVE for the /proc read).
            await _wait_for(lambda: bool(spawned_procs), _TIMEOUT_S, watch=act_watch)
            assert len(spawned_procs) == 1, spawned_procs
            child_proc = spawned_procs[0]

            # ASSERT (real Postgres): the discord T3-promotion row lands — the live probe's
            # inbound crossed the gateway adapter leg + the core socket, re-parsed, resolved
            # to alice, and promoted to T3. Watch the live loops so a mid-ACT crash (or a
            # fail-closed spawn) surfaces loud, not as a timeout (err-002). This row's arrival
            # is ALSO the POSITIVE fd-3 control: the probe reads fd 3 (step 2) BEFORE emitting
            # the inbound (step 4), so the inbound reaching core proves the fd-3 delivery
            # happened (a credential that never arrived would wedge the probe on os.read(3)
            # and no inbound would ever be emitted).
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
            # The platform user id crosses the audit boundary ONLY as a peppered hash, and
            # NEITHER the platform id NOR the credential marker is in that hash.
            pid_hash = subject["platform_user_id_hash"]
            assert isinstance(pid_hash, str) and pid_hash
            assert _PROBE_PLATFORM_USER_ID not in pid_hash
            assert bot_token_marker not in pid_hash

            # ---- CREDENTIAL-ABSENCE proof (the crux). The child is ALIVE (it blocks reading
            # stdin after its emit), so read its /proc/<pid>/environ and prove the marker is
            # absent, with three controls so the assertion can never pass vacuously. ----
            environ_bytes = _read_proc_environ(child_proc.pid)
            # NON-EMPTY guard: a zero-byte read would make every ``not in`` assertion vacuous.
            assert len(environ_bytes) > 0, "child /proc/<pid>/environ read was empty"
            # MUTATION control: a known-present scrubbed-allowlist var (PATH) IS in the SAME
            # read — proving the absence assertion CAN fire (the read is the real child env).
            assert b"PATH=" in environ_bytes, (
                "expected PATH= in the child env (the scrubbed allowlist forwards it); "
                "its absence means the /proc read did not capture the child's real environ"
            )
            # THE invariant (test-101 / test-002 / sec-005): the fd-3-delivered credential
            # marker is NOT in the adversary-facing child's environment — it crossed ONLY
            # over fd 3 (the scrubbed allowlist excludes ALFRED_DISCORD_BOT_TOKEN).
            assert bot_token_marker.encode() not in environ_bytes, (
                "the fd-3 credential marker leaked into the gateway adapter child's "
                "environment — it must cross ONLY over fd 3 (CLAUDE.md hard rule #6)"
            )

            # ASSERT (real Postgres): the G0 inbound_idempotency row is COMMITTED on the
            # composite (discord, _PROBE_INBOUND_ID) key — the dispatched-edge commit_once
            # fired AFTER a successful dispatch, so a present row proves the forwarded inbound
            # completed core dispatch, not merely passed admission.
            await _wait_for(
                lambda: bool(
                    _fetch_inbound_idempotency(
                        sync_url, adapter_id=_FORWARDED_ADAPTER_ID, inbound_id=_PROBE_INBOUND_ID
                    )
                ),
                _TIMEOUT_S,
                watch=act_watch,
            )
            idem_rows = _fetch_inbound_idempotency(
                sync_url, adapter_id=_FORWARDED_ADAPTER_ID, inbound_id=_PROBE_INBOUND_ID
            )
            assert len(idem_rows) == 1, idem_rows
            assert idem_rows[0]["adapter_id"] == _FORWARDED_ADAPTER_ID, idem_rows[0]
            assert idem_rows[0]["inbound_id"] == _PROBE_INBOUND_ID, idem_rows[0]
            # The sentinel content is fixed by the probe (imported); assert it is non-empty so
            # a future drift in the probe's contract surfaces as a referenced-but-unused import.
            assert _PROBE_CONTENT, "the probe content sentinel must be non-empty"

            # The forwarded frame took the CLEAN dispatch edge and ONLY that edge: assert no
            # poisoned dead-letter row exists for it, so a spurious refusal that ALSO happened
            # to promote + commit can't slip past this happy-path proof undetected (test-102).
            assert _fetch_audit_rows_by_event(sync_url, event="comms.inbound.poisoned") == [], (
                "unexpected poisoned dead-letter row on the happy path"
            )
    finally:
        # Reap EVERY acquired resource on EVERY exit path (mirror A1's discipline) regardless
        # of how far boot got, PLUS the gateway adapter supervisor + the real probe child.
        gateway_shutdown.set()
        supervisor.shutdown_event.set()
        # Cancel + await the spawn task FIRST: cancelling ``supervise_one`` unwinds through
        # ``_await_exit_or_stop``'s CancelledError arm, which terminate-and-reaps the live
        # bwrap probe child via ``_GatewayAdapterChild.aclose`` (SIGTERM + reap + close the
        # transport pipes -> the probe sees stdin EOF and exits). H1 — no leaked sandbox child.
        if spawn_task is not None:
            spawn_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(spawn_task, timeout=_TIMEOUT_S)
        # Defence-in-depth: if the supervisor's reap somehow did not terminate the child
        # (e.g. the spawn task never reached the steady-state UP wait), terminate + reap any
        # captured Popen directly so no bwrap process leaks (never raises).
        for proc in spawned_procs:
            if proc.returncode is None and proc.poll() is None:
                with suppress(ProcessLookupError, OSError):
                    proc.terminate()
            loop = asyncio.get_running_loop()
            with suppress(Exception):
                try:
                    await asyncio.wait_for(
                        loop.run_in_executor(None, proc.wait), timeout=_TIMEOUT_S
                    )
                except TimeoutError:
                    with suppress(ProcessLookupError, OSError):
                        proc.kill()
                    with suppress(Exception):
                        await asyncio.wait_for(
                            loop.run_in_executor(None, proc.wait), timeout=_TIMEOUT_S
                        )
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


def _read_proc_environ(pid: int) -> bytes:
    """Read the live child's ``/proc/<pid>/environ`` (NUL-separated env bytes).

    Runs ONLY under the docker-only gate (Linux + root), where ``/proc`` exists and the
    test process can read the child it spawned. The bytes are NUL-separated ``KEY=VALUE``
    pairs; the credential-absence proof asserts the marker bytes are not present AND a
    known-present ``PATH=`` IS present in the SAME read (the mutation control).
    """
    with open(f"/proc/{pid}/environ", "rb") as fh:  # noqa: PTH123 - /proc is not a Path target
        return fh.read()
