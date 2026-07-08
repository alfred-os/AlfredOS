"""DOCKER-ONLY: the daemon go-live flip drives a REAL bwrap quarantined child.

PR-S4-11c-2b (#237) — the production daemon flip proven end to end. This is the
proof the off-Linux ``test_daemon_comms_inbound_turn`` cannot give: that the
daemon's PRODUCTION boot helpers (``_build_comms_boot_graph`` +
``_spawn_comms_adapter``) — NOT a monkeypatched spawn seam — stand up a REAL
``alfred.security.quarantine_child`` subprocess via
``bin/alfred-plugin-launcher.sh`` (``sandbox.kind="full"`` -> bwrap), deliver its
provider key over fd 3, and run a full inbound turn through it:

    spawned alfred_comms_test plugin -> inbound.message notification
      -> inbound trust-boundary path -> CommsExtractorBridge.extract
      -> T3BodyRecorder (tag T3 + stage) -> QuarantineStdioTransport
      -> quarantine.ingest{handle_id, body} -> bwrapped child caches it
      -> quarantine.extract{handle_id, schema} -> child pops + echoes
      -> ControlResult -> QuarantinedExtractor lift -> post-stage DLP scan
      -> quarantine.extract audit row (result="extracted")
      -> ingest -> dispatch ack -> outbound.message

versus ``test_daemon_comms_inbound_turn`` (which monkeypatches
``spawn_quarantine_child_io`` to an in-proc echoing double), the ONLY thing that
changes here is the child-IO seam: a REAL bwrapped subprocess driven through the
SAME production ``_build_comms_boot_graph``. NO ``_RecordedExtractTransport`` (it
was deleted by the 2b flip) is anywhere in the path — the ``quarantine.extract``
``result="extracted"`` row only lands AFTER the live child replies, so a child
that never spawned / never replied would time out at ``read_frame``
(``QuarantineChildSpawnError``) and refuse the boot.

WHY DOCKER-ONLY: ``sandbox.kind="full"`` resolves to bwrap on Linux; the spawn
needs ``bwrap`` present, a Linux kernel, AND root, PLUS the ADR-0030 bound-
interpreter provisioning (``ALFRED_QUARANTINE_CHILD_PYTHON`` set to a real
interpreter binary with ``alfred`` installed into it). It SKIPS on macOS / non-root
/ unprovisioned CI. #248 wired it into the ``integration-privileged`` CI leg (a
hermetic ``~/.proto`` python whose prefix the launcher binds into the sandbox), so
it RUNS + gates merge there. Reproduce locally via ``docker run --rm --privileged
--platform linux/amd64 debian:bookworm`` with ``ALFRED_QUARANTINE_CHILD_PYTHON=
/usr/bin/python3`` + ``alfred`` pip-installed into that interpreter — see
``tests/integration/test_quarantine_child_real_spawn.py`` (the precursor 2b0 proof
this mirrors at the daemon layer) and procedural_local_docker_for_ci_only_failures
in project memory.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import shutil
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
from alfred.hooks.registry import get_registry, set_registry
from alfred.identity import Authorization, Platform
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

pytestmark = pytest.mark.integration

# Reference plugin identifiers (plugins/alfred_comms_test/{main,manifest}.py).
_ADAPTER_ID = "alfred_comms_test"
_PLUGIN_ID = "alfred.comms-test"
_PLUGIN_MANIFEST_TIER = "user-plugin"

# Discriminating inbound values so a dropped trigger surfaces as a wrong id / body.
_PLATFORM_USER_ID = "discord:victim-flip-7741"
_INBOUND_CONTENT = "hello from the s4-11c-2b daemon flip"
_CANONICAL_SLUG = "alice"
_USER_LANGUAGE = "en-GB"

_AUDIT_HASH_PEPPER = "integration-test-pepper-0123456789abcdef-padding"
_TIMEOUT_S = 20.0
_LAUNCHER_TEST_UID = getpass.getuser()

# DOCKER-ONLY guard (mirrors tests/integration/test_quarantine_child_real_spawn.py):
# bwrap + Linux + root + the ADR-0030 bound-interpreter provisioning. The kind="full"
# quarantine child needs all four; the standard uv-venv CI leg lacks the bound
# interpreter, so this SKIPS there rather than failing.
_HAS_BWRAP = shutil.which("bwrap") is not None
_PROVISIONED = bool(os.environ.get("ALFRED_QUARANTINE_CHILD_PYTHON"))
# os.uname / os.geteuid do NOT exist on Windows; since @skipif is evaluated at
# import, probe them behind hasattr so test COLLECTION stays import-safe on
# non-Unix (a Windows box would otherwise AttributeError before the skip; CR #255).
_IS_LINUX_ROOT = (
    hasattr(os, "uname")
    and os.uname().sysname == "Linux"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
)
_DOCKER_ONLY = pytest.mark.skipif(
    not _HAS_BWRAP or not _IS_LINUX_ROOT or not _PROVISIONED,
    reason=(
        "daemon go-live flip real bwrap spawn: needs bwrap + Linux + root + the "
        "ADR-0030 bound-interpreter provisioning (ALFRED_QUARANTINE_CHILD_PYTHON set, "
        "alfred installed into that interpreter). RUNS + gates merge in the "
        "privileged-Linux CI leg (`integration-privileged`); skipped on macOS / "
        "non-root / unprovisioned local boxes — reproduce via `docker run --rm "
        "--privileged --platform linux/amd64`."
    ),
)


def _boot_gate_with_comms_load_grant() -> RealGate:
    """A REAL RealGate seeded for BOTH chains the turn exercises (no permissive shim).

    The SAME two-grant fixture ``test_daemon_comms_inbound_turn`` uses (CLAUDE.md
    hard rule #2): the system-tier ``security.quarantined.extract`` grant so the
    QuarantinedExtractor's post-stage DLP subscriber registers, plus the
    ``(alfred.comms-test, user-plugin, "*")`` plugin-load grant the production boot
    path seeds per enabled adapter.
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


class _TransportCapture:
    """Captures the live ``CommsStdioTransport`` on its first send.

    The runner holds the transport privately; the inbound-turn proof captures it by
    wrapping ``CommsStdioTransport.send`` (the handshake's first send sets it). The
    test then drives the fire-and-forget inject_inbound TRIGGER through that captured
    transport — a notification, so ``runner.send_request`` would hang on it.
    """

    def __init__(self) -> None:
        self.transport: CommsStdioTransport | None = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original = CommsStdioTransport.send
        capture = self

        async def _capturing_send(self: CommsStdioTransport, frame: Any) -> None:
            capture.transport = self
            await original(self, frame)

        monkeypatch.setattr(CommsStdioTransport, "send", _capturing_send)


class _RecordingSupervisor:
    """Captures the pump coroutine + records breaker/restart hand-offs.

    The ONE seam this proof does not exercise — the supervised TaskGroup. The
    production ``_spawn_comms_adapter`` calls ``register_plugin_task(runner.pump())``;
    the test captures that coroutine so it owns driving the pump.
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


def _seed_discord_bound_user(sync_url: str) -> None:
    """Seed the Discord-bound canonical user PLUS the household operator.

    #338 PR2: ``build_orchestrator`` (inside the real turn now driven by
    ``_build_comms_boot_graph``) constructs a real ``Orchestrator``, whose
    constructor synchronously calls ``identity_resolver.get_operator()`` — a
    distinct requirement from the Discord-bound user's platform identity
    (there must be exactly ONE ``authorization=operator`` row). The bound user
    stays STANDARD so this proof does not conflate "the addressed user" with
    "the household operator".
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

    ``ALFRED_ENVIRONMENT=test`` opens the reference plugin's inject_inbound gate AND
    drives the launcher to resolve the kind="full" bwrap policy (the env only gates
    the kind="none" / non-Linux paths — "test" still bwraps the kind="full" Linux
    child). ``ALFRED_QUARANTINE_CHILD_PYTHON`` is preserved from the harness (the
    bound interpreter); the broker provider key stays UNSET so the documented
    placeholder path is exercised (the 2b echo child scrubs + discards it).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_ENV", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-integration-placeholder")
    monkeypatch.setenv("ALFRED_AUDIT.HASH_PEPPER", _AUDIT_HASH_PEPPER)
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ADAPTER_ID}"]')
    monkeypatch.setenv("ALFRED_PLUGIN_UID", _LAUNCHER_TEST_UID)
    yield


async def _wait_for(predicate: Any, timeout: float) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError("inbound-turn condition never became true")


def _fetch_rows(sync_url: str, event: str) -> list[dict[str, Any]]:
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT subject, result FROM audit_log WHERE event = :event"),
                {"event": event},
            )
            return [dict(row._mapping) for row in result]
    finally:
        engine.dispose()


@_DOCKER_ONLY
@pytest.mark.usefixtures("_boot_env")
async def test_daemon_flip_drives_real_bwrap_child_and_lands_extracted_row(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production daemon flip drives a REAL bwrap child + lands an extracted row.

    No ``spawn_quarantine_child_io`` monkeypatch: ``_build_comms_boot_graph`` spawns
    the genuine bwrap quarantined child. Asserts the inbound turn drove the live
    child (it echoed the T3 body), the ``quarantine.extract`` audit row landed with
    ``result="extracted"``, and the ``comms.inbound.t3_promoted`` row landed — all
    through production wiring with NO ``_RecordedExtractTransport`` in the path.
    """
    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")

    capture = _TransportCapture()
    capture.install(monkeypatch)

    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    gate = _boot_gate_with_comms_load_grant()
    graph: _CommsBootGraph | None = None
    supervisor = _RecordingSupervisor()
    try:
        async with _boot_audit_writer(postgres_url) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
            # PRODUCTION helper — REAL spawn (no monkeypatch). On this provisioned
            # Linux+root+bwrap host the spawn succeeds; on an unprovisioned host the
            # whole test is skipped by _DOCKER_ONLY.
            graph = await _build_comms_boot_graph(
                settings=settings,
                audit=audit,
                outbound_dlp=outbound_dlp,
                t3_nonce=nonce,
                # PR-S4-235-1: the graph builds the daemon-owned ContentStore the
                # per-adapter promoter shares. ``alfred_comms_test`` is empty-set
                # (None promoter), so the store is never written to here.
                policies_ref=None,
                real_gate=gate,
                # #338 PR2: offline test seam — this proof doesn't assert reply
                # content, only that the extracted/T3-promoted rows land, so the
                # real, egress-proxied build_router is never reached.
                router_override=cast(ProviderRouter, FixedAnswerRouter()),
            )
            await _spawn_comms_adapter(
                adapter_id=_ADAPTER_ID,
                settings=settings,
                audit=audit,
                gate=gate,
                supervisor=supervisor,  # type: ignore[arg-type]
                graph=graph,
                boot_id="s4-11c-2b-flip-proof",
                environment_source="env_var",
            )
            assert len(supervisor.registered) == 1

            # Drive the inbound turn through the captured transport's host -> plugin
            # write seam (the inject_inbound trigger is a NOTIFICATION — fire-and-
            # forget ``send``, NOT ``runner.send_request`` which would hang).
            assert capture.transport is not None  # set during the handshake send
            await capture.transport.send(
                {
                    "jsonrpc": "2.0",
                    "method": "alfred_comms_test/inject_inbound",
                    "params": {
                        "platform_user_id": _PLATFORM_USER_ID,
                        "content": _INBOUND_CONTENT,
                    },
                }
            )

            # The live bwrap child echoed the T3 body, the extractor lifted it, the
            # post-stage DLP subscriber ran, and the quarantine.extract row landed.
            await _wait_for(lambda: bool(_fetch_rows(sync_url, "quarantine.extract")), _TIMEOUT_S)
            extract_rows = _fetch_rows(sync_url, "quarantine.extract")
            assert len(extract_rows) == 1, extract_rows
            assert extract_rows[0]["result"] == "extracted"

            # The full inbound trust-boundary path also landed the T3-promotion row.
            await _wait_for(
                lambda: bool(_fetch_rows(sync_url, "comms.inbound.t3_promoted")), _TIMEOUT_S
            )
            promo_rows = _fetch_rows(sync_url, "comms.inbound.t3_promoted")
            assert len(promo_rows) == 1, promo_rows
            assert promo_rows[0]["subject"]["canonical_user_id"] == _CANONICAL_SLUG
            assert promo_rows[0]["result"] == "promoted"
    finally:
        # Tear down EVERY acquired resource regardless of how far boot got — do NOT
        # gate on `runner` (resources are acquired BEFORE it is assigned, so a
        # `_spawn_comms_adapter` failure mid-way would otherwise leak them). CR #255.
        for task in supervisor.registered:
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=_TIMEOUT_S)
        # Close the captured adapter transport so the adapter subprocess is reaped.
        if capture.transport is not None:
            with suppress(Exception):
                await capture.transport.close()
        # Reap the REAL bwrapped quarantine child the comms graph owns whenever the
        # graph built (graph built => quarantine_transport => spawned child).
        if graph is not None:
            with suppress(Exception):
                await graph.aclose()
        set_registry(prior_registry)
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)
