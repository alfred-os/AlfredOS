"""Daemon command bodies — boot / stop / status (#174 PR-S4-1).

The boot sequence (core-007 closure — probes at the CLI layer, NOT inside
``Supervisor.start()``):

1. ``load_settings_or_die()`` — build the boot AuditWriter FIRST (sec-001),
   then resolve the mandatory dual-sourced ``environment``. On a
   missing/invalid environment, emit ``DAEMON_BOOT_FAILED_FIELDS`` and exit
   2 — never a silent failure (CLAUDE.md hard rule 7).
2. Emit the ``daemon.boot.environment_source_conflict`` audit row if the
   env-var and ``/etc/alfred/environment`` disagree (the env-var wins).
3. Unsandboxed-in-production refusal (sec-002 — truthy-env parsing).
4. Probe (a) launcher policy-resolving, (b) snapshot-ref init, (c)
   capability-gate handshake. Any refusal runs ``_refuse_boot`` (arch-001 —
   invoke the ``daemon.boot.failed`` hookpoint, then audit, then exit).
5. Construct the ``Supervisor`` with ``state_git_path`` + the two stub
   kwargs, emit ``DAEMON_BOOT_FIELDS``, invoke ``daemon.boot.completed``,
   write the PID file, then run the supervised TaskGroup until shutdown.

Every ``append_schema`` on a refusal/completion path is wrapped so an
audit-write failure quarantines with exit 3 (sec-003).
"""

from __future__ import annotations

import asyncio
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, Protocol

import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
    DAEMON_BOOT_FAILED_FIELDS,
    DAEMON_BOOT_FIELDS,
)

# PR-S4-11c-2a0 (#237): mint + register the per-process authorised T3 nonce at
# boot. Imported at module scope (not lazily) so the boot-wiring unit tests can
# monkeypatch the ``alfred.cli.daemon._commands.create_and_register_t3_nonce``
# seam to count / fault the call without a real subprocess.
from alfred.bootstrap.nonce_factory import (
    T3NonceAlreadyRegisteredError,
    create_and_register_t3_nonce,
)
from alfred.cli.daemon._audit_fallback import build_boot_audit_writer
from alfred.cli.daemon._daemon_pidfile import (
    DaemonPidFileError,
    default_pidfile_path,
    delete_pidfile,
    is_pid_alive,
    load_pidfile,
    write_pidfile,
)
from alfred.cli.daemon._daemon_probes import (
    _truthy_env,
    probe_capability_gate_handshake,
    probe_launcher_policy_resolving,
    probe_snapshot_ref_init,
)
from alfred.cli.daemon._failures import (
    BootInfraInstallFailedFailure,
    CommsAdapterSpawnFailedFailure,
    CommsMultiAdapterUnsupportedFailure,
    DaemonBootFailure,
    EnvironmentNotSetFailure,
    QuarantineGrantMissingFailure,
    T3NonceRegistrationFailedFailure,
    UnsandboxedEnvInProductionFailure,
)
from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
    load_environment,
)
from alfred.hooks.errors import HookError
from alfred.i18n import t

# PR-S4-11b (#237): module-level so the boot-wiring unit tests monkeypatch these
# two seams (``alfred.cli.daemon._commands.CommsStdioTransport`` /
# ``...CommsPluginRunner``) to fakes — no real subprocess spawns in unit tests.
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_stdio_transport import CommsStdioTransport
from alfred.plugins.errors import ManifestError
from alfred.plugins.manifest import parse_manifest
from alfred.supervisor.core import Supervisor

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.comms_mcp.daemon_runtime import (
        CommsInboundOrchestratorAdapter,
        OutboundSenderLike,
    )
    from alfred.config.settings import Settings
    from alfred.hooks.capability import CapabilityGate
    from alfred.security.capability_gate._gate import RealGate
    from alfred.security.dlp import OutboundDlpProtocol
    from alfred.security.tiers import CapabilityGateNonce
    from alfred.supervisor.core import Supervisor as _SupervisorType

# Exit codes (operator-facing contract; documented in the runbook PR-S4-11).
_EXIT_REFUSED: Final[int] = 2
_EXIT_AUDIT_UNWRITABLE: Final[int] = 3

# Sentinel for the SHA of an empty / absent state.git repo.
_STATE_GIT_HEAD_UNKNOWN: Final[str] = "unknown"

# A no-op operator id for the PR-S4-1 stub resolver. PR-S4-5 ships the real
# session-file + Postgres binding.
_STUB_OPERATOR_ID: Final[str] = "_daemon_boot"


class _StubOperatorResolver:
    """No-op operator resolver for PR-S4-1 (real one lands in PR-S4-5)."""

    async def resolve(self) -> str:
        return _STUB_OPERATOR_ID


class _BootRefusedError(Exception):
    """Internal control-flow signal: a refusal already emitted + must exit.

    Carries the exit code so the synchronous Typer command can translate it
    into ``typer.Exit`` after ``asyncio.run`` unwinds.
    """

    def __init__(self, code: int) -> None:
        super().__init__(f"boot_refused:{code}")
        self.code = code


# ---------------------------------------------------------------------------
# Overridable builders (monkeypatched by the unit tests).
# ---------------------------------------------------------------------------


def build_boot_session_scope(  # pragma: no cover - real-infra glue; unit tests monkeypatch
    settings: Settings,
) -> Callable[[], AbstractAsyncContextManager[AsyncSession]]:
    """Build the async session scope the Supervisor + audit writer share."""
    from alfred.memory.db import build_session_scope

    # build_session_scope is an untyped Slice-1 helper (returns a no-arg
    # callable shaped exactly like our annotation); the cast pins the type.
    return build_session_scope(settings)  # type: ignore[no-any-return]


def _build_boot_outbound_dlp(  # pragma: no cover - real-infra glue; unit tests monkeypatch
    *,
    settings: Settings,
    audit: AuditWriter,
) -> OutboundDlpProtocol:
    """Construct the outbound DLP scanner threaded into the dispatch loop.

    arch-001 (#173 / PR-S4-2). Broker + audit sink mirror the
    orchestrator's outbound-DLP wiring (``alfred.cli.main``): the broker
    redacts AlfredOS-owned secrets, the generic-API-key regex catches
    leaked third-party keys, and modification events land an audit row.
    Attributed to the system actor — the dispatch loop is a T0/T1
    supervisor surface, not an end-user turn.
    """
    from alfred.cli._bootstrap import build_adapter_dlp_audit_sink, build_broker
    from alfred.security.dlp import OutboundDlp

    broker = build_broker(settings)
    sink = build_adapter_dlp_audit_sink(
        audit_writer=audit,
        operator_user_id="supervisor",
        language=settings.operator_language,
    )
    return OutboundDlp(broker=broker, audit=sink)


# ---------------------------------------------------------------------------
# PR-S4-11b (#237): comms-adapter boot wiring.
#
# All of this is built ONLY when ``settings.comms_enabled_adapters`` is non-empty
# — a default-empty boot constructs none of it and is byte-for-byte unchanged.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _CommsAdapterWireSpec:
    """The manifest-derived identifiers one comms adapter is spawned with.

    Mind the id triplet (spec §8.3): the launcher ``plugin_id`` (the manifest
    ``[plugin] id`` + sandbox-policy key, e.g. ``alfred.comms-test``) differs from
    the wire ``adapter_kind`` (``[comms_mcp] adapter_kind``, e.g.
    ``alfred_comms_test``) the host's body/classifier tables are keyed on. The
    runner/transport/session use ``adapter_kind``; the launcher spec's
    ``plugin_id`` uses the manifest plugin id.
    """

    plugin_id: str
    adapter_kind: str
    module: str
    sandbox_kind: str
    manifest_path: Path
    manifest_raw: str


class _RunnerOutboundSender:
    """The narrow host -> plugin outbound seam the dispatch ack flows through.

    Satisfies :class:`alfred.comms_mcp.daemon_runtime.OutboundSenderLike` by
    mapping ``send_outbound`` onto a ``outbound.message`` JSON-RPC request on the
    runner. Kept a tiny adapter here (not in ``daemon_runtime``) so that module
    never imports the runner — the one-directional import graph (daemon_runtime
    is imported BY the runner's consumers, never the reverse) stays intact.
    """

    def __init__(self, *, runner: CommsPluginRunner) -> None:
        self._runner = runner

    async def send_outbound(
        self,
        *,
        adapter_id: str,
        target_platform_id: str,
        body: Mapping[str, object],
    ) -> Mapping[str, object]:
        return await self._runner.send_request(
            "outbound.message",
            {
                "adapter_id": adapter_id,
                "target_platform_id": target_platform_id,
                "body": dict(body),
            },
        )


def _resolve_comms_adapter_wire_spec(adapter_id: str) -> _CommsAdapterWireSpec:
    """Resolve + parse one enabled adapter's manifest into its wire identifiers.

    A missing manifest, a parse failure, or a missing ``[comms_mcp]`` block /
    ``adapter_kind`` for an ENABLED adapter raises (caller maps the raise onto
    :func:`_refuse_boot` — fail-closed, CLAUDE.md hard rule #7). The
    ``comms_enabled_adapters`` Settings validator already proved the manifest
    file exists + the id charset is safe, but this re-parses it for the wire
    fields and re-raises loudly if the block is malformed.
    """
    import tomllib

    from alfred.cli._launcher_spawn import repo_root

    plugin_dir = repo_root() / "plugins" / adapter_id
    manifest_path = plugin_dir / "manifest.toml"
    manifest_raw = manifest_path.read_text(encoding="utf-8")
    manifest = parse_manifest(manifest_raw)
    if manifest.comms_mcp_module is None:
        raise _CommsAdapterManifestError(adapter_id, "comms_mcp_module")

    data = tomllib.loads(manifest_raw)
    comms_section = data.get("comms_mcp")
    adapter_kind = comms_section.get("adapter_kind") if isinstance(comms_section, dict) else None
    if not isinstance(adapter_kind, str) or not adapter_kind:
        raise _CommsAdapterManifestError(adapter_id, "adapter_kind")

    return _CommsAdapterWireSpec(
        plugin_id=manifest.plugin_id,
        adapter_kind=adapter_kind,
        module=manifest.comms_mcp_module,
        sandbox_kind=manifest.sandbox.kind,
        manifest_path=manifest_path,
        manifest_raw=manifest_raw,
    )


class _CommsAdapterManifestError(Exception):
    """An enabled comms adapter's manifest is missing a required wire field."""

    def __init__(self, adapter_id: str, field: str) -> None:
        super().__init__(f"comms adapter {adapter_id!r} manifest missing {field!r}")
        self.adapter_id = adapter_id
        self.field = field


@dataclass(frozen=True, slots=True)
class _CommsBootGraph:
    """The pre-Supervisor comms components shared across every enabled adapter.

    Built once (guarded behind ``if settings.comms_enabled_adapters``) and threaded
    into the per-adapter handler construction + spawn loop. ``inbound_orchestrator``
    has its outbound sender bound LATER, per adapter, once the runner exists.

    ``t3_nonce`` is the per-process authorised :class:`CapabilityGateNonce` minted
    at boot (PR-S4-11c-2a0). It is threaded onto the graph so PR-S4-11c-2a's
    ``record_body`` seam can tag the inbound body ``TaggedContent[T3]`` via
    :func:`alfred.security.tiers.tag_t3_with_nonce`. In THIS precursor it is
    carried-but-not-yet-consumed (record_body lands in 2a) — the same
    threaded-but-inert pattern as 11c-1's orchestrator and 11b0's grant seed. It is
    held here (passed by DI, never re-fetched from the module slot) so the gate's
    ``is``-identity check holds — the factory docstring forbids stashing it in any
    module global outside ``alfred.security.tiers``.
    """

    secret_broker: object
    resolver_bridge: object
    extractor_bridge: object
    burst_limiter: object
    inbound_orchestrator: CommsInboundOrchestratorAdapter
    t3_nonce: CapabilityGateNonce


def _build_comms_boot_graph(
    *,
    settings: Settings,
    audit: AuditWriter,
    outbound_dlp: OutboundDlpProtocol,
    t3_nonce: CapabilityGateNonce,
) -> _CommsBootGraph:
    """Construct the pre-Supervisor comms graph (PR-S4-11b construction step 1-5).

    Built ONLY when at least one adapter is enabled. Assembles the secret broker,
    the sync identity-resolver bridge, the real (recorded-transport) quarantined
    extractor + its body-shaped bridge, the burst limiter, and the inbound
    orchestrator adapter whose outbound sender is bound per-adapter after the
    runner exists.

    ``t3_nonce`` is the per-process authorised :class:`CapabilityGateNonce` the
    daemon minted at boot. It is stored on the returned graph (PR-S4-11c-2a0
    precursor infra) for PR-S4-11c-2a's ``record_body`` seam — it is NOT consumed
    here yet (the ``CommsExtractorBridge`` still constructs without a
    ``record_body``), mirroring the threaded-but-inert DI precedent of 11c-1's
    orchestrator and 11b0's grant seed.
    """
    from typing import cast

    from alfred.cli._bootstrap import build_broker, install_identity_factories_for_settings
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge, SyncIdentityResolverBridge
    from alfred.comms_mcp.daemon_runtime import (
        CommsInboundOrchestratorAdapter,
        _build_comms_inbound_extractor,
    )
    from alfred.orchestrator.burst_limiter import BurstLimiter
    from alfred.security.dlp import OutboundDlp

    secret_broker = build_broker(settings)
    resolver = install_identity_factories_for_settings(settings)
    resolver_bridge = SyncIdentityResolverBridge(resolver=resolver)
    # ``_build_boot_outbound_dlp`` always constructs a concrete ``OutboundDlp``
    # (it is annotated to the Protocol for the Supervisor's narrower consumer);
    # the extractor's post-stage scan needs the concrete class, so the cast pins
    # what the runtime already guarantees rather than widening the Wave-2 helper.
    extractor = _build_comms_inbound_extractor(
        audit_writer=audit, outbound_dlp=cast("OutboundDlp", outbound_dlp)
    )
    extractor_bridge = CommsExtractorBridge(extractor=extractor)
    # AuditWriter satisfies the BurstLimiter's ``_AuditWriterLike`` seam at
    # runtime (its append/append_schema are the keyword forms the limiter calls);
    # mypy flags the more-specific override against the ``**kwargs`` Protocol, the
    # same structural mismatch the per-adapter handlers below carry an ignore for.
    burst_limiter = BurstLimiter(audit_writer=audit)  # type: ignore[arg-type]
    inbound_orchestrator = CommsInboundOrchestratorAdapter(extractor_bridge=extractor_bridge)
    return _CommsBootGraph(
        secret_broker=secret_broker,
        resolver_bridge=resolver_bridge,
        extractor_bridge=extractor_bridge,
        burst_limiter=burst_limiter,
        inbound_orchestrator=inbound_orchestrator,
        t3_nonce=t3_nonce,
    )


async def _spawn_comms_adapter(
    *,
    adapter_id: str,
    settings: Settings,
    audit: AuditWriter,
    gate: object,
    supervisor: _SupervisorType,
    graph: _CommsBootGraph,
    boot_id: str,
    environment_source: str,
) -> CommsPluginRunner:
    """Spawn + readiness-probe one enabled comms adapter, then register its pump.

    The fail-closed boot primitive (architect's required shape): the daemon
    ``await runner.start_and_handshake()`` BEFORE committing to the long-lived
    pump, so a broken adapter (missing/parse-broken manifest, spawn failure,
    not-ok handshake) REFUSES the boot via :func:`_refuse_boot` rather than
    parking with a dead plugin. On success the pump is scheduled as a supervised
    TaskGroup task.

    Returns the live :class:`CommsPluginRunner` (post-handshake, pump scheduled)
    so a caller that needs the host -> plugin request seam can drive it — the
    daemon boot loop ignores the return (the runner's lifetime is the supervised
    pump it just registered), while the end-to-end integration proof
    (``test_daemon_comms_inbound_turn``) grabs it to drive the inbound-injection
    trigger through the real runner rather than reimplementing the wiring.
    """
    from alfred.cli._launcher_spawn import PluginLaunchSpec, repo_root
    from alfred.comms_mcp.bootstrap import build_supervisor_breaker_tripper
    from alfred.comms_mcp.daemon_runtime import CommsAdapterCrashedHookInvoker
    from alfred.comms_mcp.handlers import (
        AdapterCrashHandler,
        BindingRequestHandler,
        InboundMessageHandler,
        PlatformRateLimitHandler,
    )
    from alfred.plugins.errors import ManifestError, PluginError
    from alfred.plugins.session import AlfredPluginSession

    try:
        wire = _resolve_comms_adapter_wire_spec(adapter_id)
    except (OSError, ManifestError, _CommsAdapterManifestError) as exc:
        await _refuse_boot(
            audit,
            _comms_adapter_failure(adapter_id),
            t("daemon.boot.comms_adapter_spawn_failed", adapter_id=adapter_id),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is annotated NoReturn (it raises _BootRefusedError); this
        # line is unreachable defence-in-depth for the type checker's flow.
        raise AssertionError("unreachable") from exc  # pragma: no cover

    # The ``python -m`` target the launcher execs is the manifest module
    # ``alfred_comms_test.main`` — a top-level package under ``plugins/``. So the
    # child PYTHONPATH must carry the ``plugins/`` PARENT (not the per-adapter dir,
    # which would put the module's siblings on the path but not the package
    # itself), plus ``src/`` so the core ``alfred.comms_mcp`` protocol resolves in
    # the scrubbed child env. Mirrors the proven substrate-test spawn roots
    # (``tests/integration/test_comms_runner_substrate.py``).
    plugins_root = repo_root() / "plugins"
    src_root = repo_root() / "src"
    breaker_tripper = build_supervisor_breaker_tripper(supervisor=supervisor)
    hook_invoker = CommsAdapterCrashedHookInvoker()
    inbound_handler = InboundMessageHandler(
        identity_resolver=graph.resolver_bridge,  # type: ignore[arg-type]
        orchestrator=graph.inbound_orchestrator,
        burst_limiter=graph.burst_limiter,  # type: ignore[arg-type]
        audit_writer=audit,  # type: ignore[arg-type]
        secret_broker=graph.secret_broker,  # type: ignore[arg-type]
        sub_payload_promoter=None,
    )
    binding_handler = BindingRequestHandler(
        audit_writer=audit,  # type: ignore[arg-type]
        secret_broker=graph.secret_broker,  # type: ignore[arg-type]
    )
    rate_limit_handler = PlatformRateLimitHandler(
        breaker_tripper=breaker_tripper,
        audit_writer=audit,  # type: ignore[arg-type]
    )
    crash_handler = AdapterCrashHandler(audit_writer=audit, hook_invoker=hook_invoker)  # type: ignore[arg-type]

    spec = PluginLaunchSpec(
        plugin_id=wire.plugin_id,
        manifest_path=wire.manifest_path,
        module=wire.module,
        adapter_id=wire.adapter_kind,
        import_roots=(plugins_root, src_root),
        inherit_stdio=False,
        sandbox_kind=wire.sandbox_kind,
    )
    transport = CommsStdioTransport(adapter_id=wire.adapter_kind, spec=spec)
    session = await AlfredPluginSession.for_comms_adapter(
        adapter_id=wire.adapter_kind,
        manifest_raw=wire.manifest_raw,
        audit_writer=audit,
        gate=gate,  # type: ignore[arg-type]
        supervisor=supervisor,  # type: ignore[arg-type]
        inbound_handler=inbound_handler,
        binding_handler=binding_handler,
        rate_limit_handler=rate_limit_handler,
        crash_handler=crash_handler,
        transport=None,
        max_in_flight_notifications=settings.comms_max_in_flight_notifications,
    )
    # PR-S4-11b DEFECT 1: wire the supervisor's graceful-drain signal into the
    # runner so its pump exits PROMPTLY on ``alfred daemon stop`` instead of
    # blocking on the idle plugin stream until the 10s drain budget force-cancels
    # it (which recorded ``cancelled_with_errors`` + crashed the audit insert).
    # Read AFTER ``supervisor.start()`` (this spawn runs post-start), so it is
    # the live per-cycle event the heartbeat/dispatch loops also observe.
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=wire.adapter_kind,
        shutdown_event=supervisor.shutdown_event,
        # Match the runner's in-flight dispatch-task cap to the session's per-
        # adapter dispatch semaphore so the reader's task-tracking backpressure and
        # the handler-execution backpressure share one bound (PR-S4-11b deadlock
        # fix: notifications dispatch as bounded background tasks so the single
        # reader stays free to resolve a reentrant handler's outbound ack).
        max_in_flight_notifications=settings.comms_max_in_flight_notifications,
    )
    sender: OutboundSenderLike = _RunnerOutboundSender(runner=runner)
    graph.inbound_orchestrator.bind_outbound_sender(sender)

    try:
        await runner.start_and_handshake()
    except PluginError as exc:
        await _refuse_boot(
            audit,
            _comms_adapter_failure(adapter_id),
            t("daemon.boot.comms_adapter_handshake_failed", adapter_id=adapter_id),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is annotated NoReturn (it raises _BootRefusedError); this
        # line is unreachable defence-in-depth for the type checker's flow.
        raise AssertionError("unreachable") from exc  # pragma: no cover

    supervisor.register_plugin_task(runner.pump())
    # O1 (PR-S4-11b): make the headline feature observable in `alfred daemon
    # start` output — without this the only signal a comms adapter actually
    # spawned was a `plugin.lifecycle.loaded` audit-log SQL query. Echoed AFTER
    # the handshake + pump registration so the line means "this adapter is live",
    # not merely "spawn attempted".
    typer.echo(t("daemon.comms.adapter_spawned", adapter_id=adapter_id))
    return runner


def _comms_adapter_failure(adapter_id: str) -> CommsAdapterSpawnFailedFailure:
    """A loud boot-failure carrier for a comms-adapter spawn/handshake refusal."""
    return CommsAdapterSpawnFailedFailure(adapter_id=adapter_id)


class _BackingStoreAvailabilityGate(Protocol):
    """The PUBLIC contract the supervisor boot gate depends on.

    arch-222-1 / err-001 / core-eng-pr222-1: the boot gate consumes
    :meth:`RealGate.is_backing_store_available` through this Protocol rather
    than reaching into the private ``_fail_closed`` attribute. A ``getattr``
    default would fail-OPEN (report "available") if the attribute were ever
    renamed; depending on a typed contract makes the bridge survive a
    refactor and keeps the fail-closed direction safe.
    """

    def is_backing_store_available(self) -> bool: ...


class _SupervisorBootGate:
    """Gate adapter the Supervisor consumes.

    Wraps a :class:`RealGate` (for the hot-path ``check*`` calls the plugin
    lifecycle will make) and re-exports the SYNC
    ``is_backing_store_available()`` the supervisor's
    ``CapabilityGateMonitor`` heartbeat polls. The wrapped gate's PUBLIC
    :meth:`is_backing_store_available` is the source of truth — it returns
    ``not _fail_closed`` (driven by RealGate's own heartbeat), so the
    monitor's transition logic stays correct. We delegate to that public
    method (no ``getattr`` default, no private reach) so a missing method is
    a loud ``AttributeError`` at construction-adjacent call time rather than
    a silent fail-OPEN.
    """

    def __init__(self, gate: _BackingStoreAvailabilityGate) -> None:
        self._gate = gate

    def is_backing_store_available(self) -> bool:
        return self._gate.is_backing_store_available()


class _BootHandshake:
    """Async Postgres-connectivity handshake the capability-gate probe uses.

    core-eng-002: this is where Postgres reachability is checked (probe c),
    via a real ``SELECT 1`` over the boot session scope. Distinct from the
    snapshot-ref probe (b), which is file-only.
    """

    def __init__(
        self,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def is_backing_store_available(self) -> bool:
        from alfred.memory.db import healthcheck

        await healthcheck(self._session_scope)
        return True


async def build_boot_real_gate_for_daemon(
    settings: Settings,
) -> RealGate:  # pragma: no cover - real-infra glue; unit tests monkeypatch
    """Construct the RAW seeded :class:`RealGate` (ADR-0026 seed-then-load).

    Builds the Postgres backend, then delegates to
    :func:`alfred.bootstrap.gate_factory.build_boot_real_gate` which seeds
    the first-party system grants BEFORE loading the in-memory policy. The
    gate is returned RAW (not wrapped in :class:`_SupervisorBootGate`) so
    :func:`_start_async` can (a) install it into the boot
    :class:`HookRegistry` and (b) run the post-install grant assertion
    against ``check`` before wrapping it for the Supervisor.

    ``start_heartbeat=True`` is load-bearing for runtime-outage detection:
    the supervisor's :class:`CapabilityGateMonitor` polls the wrapped
    gate's ``is_backing_store_available``, which reads the RealGate
    ``_fail_closed`` flag driven ONLY by the heartbeat loop. With the
    heartbeat OFF, a RUNTIME Postgres outage after boot would go
    undetected and the gate would never fail-closed. The boot-time
    liveness check is the separate async ``SELECT 1`` handshake (probe c);
    the heartbeat is the post-boot continuous check.

    ADR-0027: ``extra_grants`` carries the config-sourced comms-adapter
    plugin-LOAD grants derived from ``settings.comms_enabled_adapters`` by
    the pure :func:`comms_adapter_load_grants` builder (unit-covered in
    isolation). Empty for a default-empty config, so the boot seed is then
    EXACTLY :data:`FIRST_PARTY_SYSTEM_GRANTS`. A broken / ``system``-tier
    manifest for an enabled adapter raises out of the builder here
    (:class:`alfred.plugins.errors.ManifestError`) — as does an unreadable
    manifest file (:class:`OSError`) — fail-closed, rather than seeding
    nothing. The ``except (SQLAlchemyError, HookError, ManifestError, OSError)``
    / grant-assertion arms in :func:`_start_async` surface it as an audited
    ``boot_infra_install_failed`` refusal (exit 2 + a ``daemon.boot.failed``
    row), never a raw traceback.
    """
    from alfred.bootstrap.gate_factory import build_boot_real_gate
    from alfred.security.capability_gate._comms_adapter_grants import (
        comms_adapter_load_grants,
    )
    from alfred.security.capability_gate.backend import PostgresBackend

    backend = PostgresBackend(dsn=settings.database_url.unicode_string())

    async def _noop_audit_sink(**_kw: object) -> None:
        return None

    return await build_boot_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink,
        start_heartbeat=True,
        extra_grants=comms_adapter_load_grants(settings),
    )


def _first_party_grant_live(gate: CapabilityGate) -> bool:
    """Return ``True`` iff every first-party system grant is live on ``gate``.

    ADR-0026: drives the assertion off the SAME
    :data:`FIRST_PARTY_SYSTEM_GRANTS` constant the seed uses, so the seed
    and the liveness check can never drift. A ``False`` from any
    :meth:`RealGate.check` means the seed-then-load did not project the
    grant into the in-memory policy — a structurally-broken trust boundary
    (the :class:`QuarantinedExtractor` could not register its DLP scan).
    """
    from alfred.security.capability_gate._bootstrap_grants import (
        FIRST_PARTY_SYSTEM_GRANTS,
    )

    # Fail closed on an empty grant set: ``all(())`` is vacuously True, which
    # would let the boot assertion pass with NOTHING asserted. A trust boundary
    # with no first-party grant to verify is itself broken — refuse.
    if not FIRST_PARTY_SYSTEM_GRANTS:
        return False
    return all(
        gate.check(
            plugin_id=grant.plugin_id,
            hookpoint=grant.hookpoint,
            requested_tier=grant.subscriber_tier,
        )
        for grant in FIRST_PARTY_SYSTEM_GRANTS
    )


def _install_quarantine_boot_registry(gate: CapabilityGate, *, audit: AuditWriter) -> None:
    """Install the boot :class:`HookRegistry` over ``gate`` + the durable sink.

    The registry sink is the boot :class:`AuditWriter` wrapped in
    :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink` so a
    DLP-subscriber-deny refusal row is DURABLE (CLAUDE.md hard rule #7),
    NOT the gate's no-op sink. ``gate`` is the RAW :class:`RealGate` whose
    ``check`` consults the grant policy — passing the
    :class:`_SupervisorBootGate` wrapper (no ``check``) would be a
    fail-open smell the typed signature rejects.
    """
    from alfred.hooks.boot import install_boot_hook_registry
    from alfred.memory.hooks_audit_sink import EpisodicAuditSink

    install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))


def build_boot_handshake(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> _BootHandshake:
    """Build the async Postgres-connectivity handshake for probe (c)."""
    return _BootHandshake(session_scope)


def read_state_git_head_sha(state_git_path: Path) -> str:
    """Return the state.git HEAD SHA, or a sentinel for an empty/absent repo.

    A list-form ``git rev-parse HEAD`` (no shell). A bare repo with no
    commits, or a missing path, resolves to ``_STATE_GIT_HEAD_UNKNOWN`` so
    the boot row always carries a value rather than crashing the boot.
    """
    try:
        # ``git`` is a trusted binary on the install PATH; the args are
        # repo-path + fixed subcommands, not untrusted input. List-form (no
        # shell). S607: partial path is intentional — resolving to an
        # absolute path would couple the CLI to the install layout.
        completed = subprocess.run(  # noqa: S603
            ["git", "-C", str(state_git_path), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return _STATE_GIT_HEAD_UNKNOWN
    if completed.returncode != 0:
        return _STATE_GIT_HEAD_UNKNOWN
    sha = completed.stdout.strip()
    # An empty bare repo can echo the literal ``HEAD`` (git-version
    # dependent) with returncode 0; only accept a real 40-hex object id so
    # the boot row never records a non-SHA placeholder.
    if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
        return sha
    return _STATE_GIT_HEAD_UNKNOWN


def wait_for_shutdown(  # pragma: no cover - real-loop signal glue; unit tests monkeypatch
    _supervisor: Supervisor,
) -> asyncio.Future[None]:
    """Park until a shutdown signal resolves.

    PR-S4-1 wires SIGTERM (sent by ``alfred daemon stop``) to set a future
    that resolves this await, then the boot path drains the supervisor + the
    PID file. The default implementation registers a SIGTERM handler on the
    running loop.
    """
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[None] = loop.create_future()

    def _on_term() -> None:
        if not fut.done():
            fut.set_result(None)

    import signal

    try:
        loop.add_signal_handler(signal.SIGTERM, _on_term)
        loop.add_signal_handler(signal.SIGINT, _on_term)
    except (NotImplementedError, ValueError):  # pragma: no cover - platform/loop edge
        # Some platforms / non-main-thread loops cannot install signal
        # handlers; the future simply never resolves there and the operator
        # uses the supervisor's own shutdown path. Not exercised in unit
        # tests (which patch this whole function).
        pass
    return fut


# ---------------------------------------------------------------------------
# Boot orchestration
# ---------------------------------------------------------------------------


async def _emit_or_quarantine(
    audit: AuditWriter,
    *,
    fields: frozenset[str],
    schema_name: str,
    event: str,
    subject: dict[str, object],
    result: str,
) -> None:
    """Append an audit row; on failure quarantine with exit 3 (sec-003)."""
    try:
        await audit.append_schema(
            fields=fields,
            schema_name=schema_name,
            event=event,
            actor_user_id=None,
            actor_persona="daemon",
            subject=subject,
            trust_tier_of_trigger="T0",
            result=result,
            cost_estimate_usd=0.0,
            cost_actual_usd=0.0,
            trace_id=str(subject.get("boot_id", uuid.uuid4())),
        )
    except (SQLAlchemyError, OSError) as exc:
        # err-002: narrow to the persistence family. A DB-write failure
        # (SQLAlchemyError) or a DSN-unreachable / socket error (OSError —
        # ConnectionError is an OSError subclass) is a genuine
        # "audit log unwritable" event → quarantine with exit 3 (sec-003,
        # CLAUDE.md hard rule 7: a failed audit write is loud).
        #
        # Any OTHER exception (TypeError/KeyError/serialization bug in
        # append_schema) is a real CODE defect — it must propagate and
        # crash loudly rather than masquerade as "Postgres is down".
        typer.echo(t("daemon.boot.audit_log_unwritable"), err=True)
        raise _BootRefusedError(_EXIT_AUDIT_UNWRITABLE) from exc


async def _refuse_boot(
    audit: AuditWriter,
    failure: DaemonBootFailure,
    message: str,
    *,
    boot_id: str,
    environment_source: str,
) -> NoReturn:
    """Refuse the boot: invoke hookpoint, emit failed row, print, exit 2.

    arch-001 closure: the ``daemon.boot.failed`` hookpoint is invoked BEFORE
    the audit emit so the hookpoint surface is live, not dead.

    Security LOW (sec): the ``NoReturn`` annotation is load-bearing — it lets
    the type checker prove every call site halts, so no refusal can ever
    fall through into ``Supervisor`` construction (a fail-OPEN on a security
    refusal). Callers therefore need no explicit ``return`` afterwards.
    """
    await _invoke_boot_failed(failure)
    await _emit_or_quarantine(
        audit,
        fields=DAEMON_BOOT_FAILED_FIELDS,
        schema_name="DAEMON_BOOT_FAILED_FIELDS",
        event="daemon.boot.failed",
        subject={
            "boot_id": boot_id,
            "attempted_at": datetime.now(UTC).isoformat(),
            "failure_reason": failure.failure_reason,
            "environment_source": environment_source,
        },
        result="refused",
    )
    typer.echo(message, err=True)
    raise _BootRefusedError(_EXIT_REFUSED)


async def _invoke_boot_failed(failure: DaemonBootFailure) -> None:
    """Invoke the ``daemon.boot.failed`` hookpoint (arch-001)."""
    from alfred.hooks import SYSTEM_ONLY_TIERS
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke

    correlation_id = str(uuid.uuid4())
    # Invoked with kind="post" — mirrors the supervisor's
    # _invoke_supervisor_hookpoint shape. The hookpoint is an OBSERVATION of
    # a refusal that already happened (the boot failure is the carrier
    # payload), not an error-stage substitution chain, so the post stage is
    # the correct lifecycle slot — and the error stage's required ``exc``
    # argument would be synthetic here.
    ctx: HookContext[dict[str, object]] = HookContext(
        action_id="daemon.boot.failed",
        hookpoint="daemon.boot.failed",
        input={"failure_reason": failure.failure_reason, "correlation_id": correlation_id},
        correlation_id=correlation_id,
        kind="post",
    )
    await invoke(
        "daemon.boot.failed",
        ctx,
        kind="post",
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
    )


async def _invoke_boot_completed(boot_id: str, state_git_head_sha: str) -> None:
    """Invoke the ``daemon.boot.completed`` hookpoint (no in-tree subscribers)."""
    from alfred.hooks import SYSTEM_ONLY_TIERS
    from alfred.hooks.context import HookContext
    from alfred.hooks.invoke import invoke

    correlation_id = str(uuid.uuid4())
    ctx: HookContext[dict[str, object]] = HookContext(
        action_id="daemon.boot.completed",
        hookpoint="daemon.boot.completed",
        input={
            "boot_id": boot_id,
            "state_git_head_sha": state_git_head_sha,
            "correlation_id": correlation_id,
        },
        correlation_id=correlation_id,
        kind="post",
    )
    await invoke(
        "daemon.boot.completed",
        ctx,
        kind="post",
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
    )


def _load_settings_or_die() -> tuple[Settings, EnvironmentLoadResult | None]:
    """Resolve Settings, signalling refusal when environment is unset.

    arch-002: returns ``(Settings, EnvironmentLoadResult | None)`` — no data
    smuggled into the Pydantic model. sec-001: the caller has already built
    the AuditWriter, so the ``_EnvironmentNotSetError`` this raises is
    converted by the async caller into the audit-then-exit refusal. On
    success it constructs ``Settings`` (which re-runs the loader internally)
    and returns the validated settings plus the load result for the conflict
    audit.
    """
    loaded = load_environment()
    if loaded.value is None:
        # Refusal happens via the async _refuse_boot — but this helper is
        # sync (it precedes Settings construction). Surface a typed signal
        # the async caller converts into the refusal.
        raise _EnvironmentNotSetError(loaded)

    from alfred.config.settings import Settings, SettingsError

    try:
        settings = Settings()  # type: ignore[no-untyped-call]  # reason: Settings.__init__ untyped pending task-17
    except SettingsError as exc:  # pragma: no cover - defensive; env already validated
        raise _EnvironmentNotSetError(loaded) from exc
    return settings, settings.environment_load_result


class _EnvironmentNotSetError(Exception):
    """Internal: the dual-source environment loader produced no value."""

    def __init__(self, load_result: EnvironmentLoadResult) -> None:
        super().__init__("environment_not_set")
        self.load_result = load_result


def _environment_refusal_message(load_result: EnvironmentLoadResult) -> str:
    """Pick the operator-facing refusal copy for an unresolved environment.

    devex-222-01: an UNRECOGNISED value (a typo like ``staging`` / ``dev``)
    is distinct from a fully-unset environment. The unrecognised branch
    echoes what the operator typed so a typo is not indistinguishable from
    "unset" — and names the accepted values so the next attempt succeeds.
    """
    if load_result.source is EnvironmentSource.UNRECOGNISED:
        return t(
            "daemon.boot.environment_unrecognised",
            value=load_result.unrecognised_value or "",
        )
    return t("daemon.boot.environment_not_set")


async def _start_async() -> None:
    boot_id = str(uuid.uuid4())
    # sec-001: build the AuditWriter BEFORE the environment check so the
    # most common misconfiguration still emits an audit row.
    audit = build_boot_audit_writer()

    try:
        settings, load_result = _load_settings_or_die()
    except _EnvironmentNotSetError as exc:
        # devex-222-01: distinguish a TYPO (env var set to an unrecognised
        # value) from a fully-unset environment. The unrecognised path
        # echoes the operator's typo + the accepted values so following the
        # message literally does not re-trigger the same refusal.
        message = _environment_refusal_message(exc.load_result)
        await _refuse_boot(
            audit,
            EnvironmentNotSetFailure(),
            message,
            boot_id=boot_id,
            environment_source=exc.load_result.source.value,
        )

    # The conflict audit (if any) goes out BEFORE the probes so the row is
    # present even if a later probe refuses.
    if load_result is not None and load_result.conflict:
        await _emit_or_quarantine(
            audit,
            fields=DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
            schema_name="DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS",
            event="daemon.boot.environment_source_conflict",
            subject={
                "boot_id": boot_id,
                "env_var_value": load_result.value,
                "etc_file_value": load_result.conflicting_file_value,
                "resolved_value": load_result.value,
            },
            result="success",
        )

    source = (
        load_result.source.value if load_result is not None else EnvironmentSource.ENV_VAR.value
    )

    # Refusal: unsandboxed escape hatch set in production (sec-002).
    if _truthy_env("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED") and settings.environment == "production":
        await _refuse_boot(
            audit,
            UnsandboxedEnvInProductionFailure(),
            t("daemon.boot.unsandboxed_in_production"),
            boot_id=boot_id,
            environment_source=source,
        )

    # Probe (a): launcher policy-resolving.
    failure_a = await probe_launcher_policy_resolving(environment=settings.environment)
    if failure_a is not None:
        await _refuse_boot(
            audit,
            failure_a,
            t("daemon.boot.launcher_not_policy_resolving"),
            boot_id=boot_id,
            environment_source=source,
        )

    # Probe (b): snapshot-ref init (FILE-ONLY; core-eng-002). CR #6: the
    # policies path is resolved from Settings (anchored at /etc/alfred),
    # NOT from the daemon's CWD.
    failure_b, snapshot_ref = await probe_snapshot_ref_init(
        environment=settings.environment,
        config_path=settings.policies_path,
    )
    if failure_b is not None or snapshot_ref is None:
        await _refuse_boot(
            audit,
            failure_b if failure_b is not None else _snapshot_failure(),
            t("daemon.boot.snapshot_ref_init_failed"),
            boot_id=boot_id,
            environment_source=source,
        )

    # Probe (c): capability-gate handshake — Postgres reachability via a
    # real SELECT 1 over the boot session scope (core-eng-002).
    session_scope = build_boot_session_scope(settings)
    handshake = build_boot_handshake(session_scope)
    failure_c = await probe_capability_gate_handshake(gate=handshake)
    if failure_c is not None:
        await _refuse_boot(
            audit,
            failure_c,
            t("daemon.boot.capability_gate_handshake_failed"),
            boot_id=boot_id,
            environment_source=source,
        )

    # All probes passed. Build the RAW seeded RealGate (ADR-0026
    # seed-then-load), install the boot HookRegistry over it so a
    # production QuarantinedExtractor can register its DLP subscriber, and
    # ASSERT the seeded first-party grant is live. Placed AFTER probe (c)
    # so Postgres is known-reachable.
    #
    # FIX 1 (CLAUDE.md hard rule #7): the seed-gate build can raise a
    # SQLAlchemyError (Postgres write failure mid-seed) and the registry
    # install can raise a HookError (hookpoint metadata drift). FIX 2
    # (PR-S4-11b review): the seed-gate build ALSO runs the config-sourced
    # comms-adapter grants-builder (comms_adapter_load_grants, inside
    # build_boot_real_gate_for_daemon), which raises ManifestError (corrupt /
    # system-tier enabled-adapter manifest — see CommsAdapterSystemTierError)
    # or OSError (manifest file unreadable). Any of these would otherwise
    # propagate as an UNCAUGHT crash out of _start_async — fail-closed + safe,
    # but it SKIPS the audited refusal path (no daemon.boot.failed row, not
    # exit 2; a raw traceback + exit 1). The grant-assertion arm below is
    # already audited; wrap the seed + install arms so they match: a failure
    # runs _refuse_boot (exit 2 + a daemon.boot.failed row) under the DISTINCT
    # boot_infra_install_failed reason — telling a broken seed/install/manifest
    # apart from a seed that succeeded but failed to project the grant
    # (quarantine_grant_missing).
    try:
        real_gate = await build_boot_real_gate_for_daemon(settings)
        # The registry sink is the durable boot AuditWriter (wrapped), so a
        # DLP-subscriber-deny refusal row lands in the audit log — NOT the
        # gate's no-op sink (CLAUDE.md hard rule #7).
        _install_quarantine_boot_registry(real_gate, audit=audit)
    except (SQLAlchemyError, HookError, ManifestError, OSError):
        # _refuse_boot is NoReturn (raises _BootRefusedError → exit 2), so
        # control never falls through to the grant-assertion below — the
        # type checker proves the seed/install fault cannot reach Supervisor
        # construction (a fail-OPEN on a security-boot fault).
        await _refuse_boot(
            audit,
            BootInfraInstallFailedFailure(),
            t("daemon.boot.boot_infra_install_failed"),
            boot_id=boot_id,
            environment_source=source,
        )
    # Fail-closed boot grant-assertion: the seeded grant MUST be live
    # after seed-then-load + install. Driven off the same
    # FIRST_PARTY_SYSTEM_GRANTS constant as the seed so the two can never
    # drift. A False result is a structurally-broken trust boundary —
    # refuse boot (exit 2 + audit row), never silently continue.
    if not _first_party_grant_live(real_gate):
        await _refuse_boot(
            audit,
            QuarantineGrantMissingFailure(),
            t("daemon.boot.quarantine_grant_missing"),
            boot_id=boot_id,
            environment_source=source,
        )
    # Wrap the raw gate for the Supervisor's sync backing-store-availability
    # surface (the CapabilityGateMonitor heartbeat polls it).
    gate: object = _SupervisorBootGate(real_gate)

    # PR-S4-11c-2a0 (#237): mint + register the per-process authorised T3 nonce.
    # ALWAYS at boot (not comms-gated): the factory docstring says "once at
    # process start" and names future non-comms consumers (StdioTransport,
    # quarantine_host) that also need it, and a None slot is the production bug
    # being fixed — leaving it None on a default-empty boot would keep every
    # authorised T3-tagging path dead. The slot is the live identity the gate's
    # ``is`` check reads; the returned object is threaded by DI into the comms
    # boot graph (record_body lands in 2a). Placed AFTER the trust-boundary infra
    # (seed-gate + boot registry + grant-assertion) so the nonce is registered
    # only once that boundary is known-good — a daemon that cannot stand up its
    # gate never gets a live T3 slot. Fail-closed: a non-None slot at boot (a
    # re-entrant boot / leaked fixture / duplicate registration) raises
    # T3NonceAlreadyRegisteredError → audited refusal (exit 2), never a silent
    # rotation of a live nonce out from under its holders (CLAUDE.md hard rule #7).
    try:
        t3_nonce = create_and_register_t3_nonce()
    except T3NonceAlreadyRegisteredError:
        await _refuse_boot(
            audit,
            T3NonceRegistrationFailedFailure(),
            t("daemon.boot.t3_nonce_registration_failed"),
            boot_id=boot_id,
            environment_source=source,
        )

    started_at = datetime.now(UTC)
    state_git_head_sha = read_state_git_head_sha(settings.state_git_path)
    policies_snapshot_hash = snapshot_ref.snapshot_hash()

    # arch-001 (#173 / PR-S4-2): construct the outbound DLP singleton at
    # boot and thread it to the Supervisor, which lands it on every
    # ProposalContext. The dispatch loop scans ``failure_detail`` through
    # this scanner before it reaches the ledger (CLAUDE.md #4 — DLP cannot
    # be disabled per-call). Broker + audit sink mirror the orchestrator's
    # outbound-DLP wiring in ``alfred.cli.main``.
    outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)

    # FIX 4 (PR-S4-11b review): this cut builds ONE shared inbound orchestrator
    # whose outbound sender is bound per-adapter (last-writer-wins), so with two
    # enabled adapters adapter-A's inbound turn would dispatch its ack through
    # adapter-B's runner — a cross-route. Until per-adapter inbound routing lands
    # (PR-S4-11c), REFUSE boot fail-closed (audited, exit 2) when more than one
    # adapter is enabled rather than parking a mis-wired multi-adapter graph
    # (CLAUDE.md hard rule #7). Placed BEFORE the comms-graph build / supervisor
    # start so the refusal has no spawn side effects.
    if len(settings.comms_enabled_adapters) > 1:
        await _refuse_boot(
            audit,
            CommsMultiAdapterUnsupportedFailure(enabled_count=len(settings.comms_enabled_adapters)),
            t("daemon.boot.comms_multi_adapter_unsupported"),
            boot_id=boot_id,
            environment_source=source,
        )

    # PR-S4-11b (#237): the pre-Supervisor comms graph (secret broker, identity-
    # resolver bridge, quarantined extractor + bridge, burst limiter, inbound
    # orchestrator). Built ONLY when an operator has opted comms adapters in — a
    # default-empty boot constructs NONE of it, so the boot path is byte-for-byte
    # unchanged (proven by ``test_default_empty_adapters_boot_unchanged``). The
    # inbound orchestrator's outbound sender is bound per-adapter once the runner
    # exists (the late-bind seam in ``CommsInboundOrchestratorAdapter``).
    comms_graph = (
        _build_comms_boot_graph(
            settings=settings,
            audit=audit,
            outbound_dlp=outbound_dlp,
            t3_nonce=t3_nonce,
        )
        if settings.comms_enabled_adapters
        else None
    )

    supervisor = Supervisor(
        session_scope=session_scope,
        gate=gate,
        audit=audit,
        state_git_path=settings.state_git_path,
        proposal_dispatch_interval_s=settings.proposal_dispatch_interval_s,
        policies_ref=snapshot_ref,
        operator_session_resolver=_StubOperatorResolver(),
        outbound_dlp=outbound_dlp,
    )

    # The PID file is written BEFORE start() so a concurrent ``alfred daemon
    # stop`` can find us the instant the supervisor begins coming up.
    pidfile_path = default_pidfile_path()
    write_pidfile(
        pidfile_path,
        pid=_current_pid(),
        boot_id=boot_id,
        started_at=started_at.isoformat(),
    )

    try:
        # CR #2: declare boot COMPLETE only after ``supervisor.start()``
        # succeeds. Emitting the completion row / echoing "started" BEFORE
        # start() would record a ``daemon.boot.completed`` row + tell the
        # operator the daemon is up for a boot that may then fail in start()
        # — a lie to both the audit trail and the operator.
        await supervisor.start()

        # FIX 1 (PR-S4-11b review): spawn + readiness-probe every enabled comms
        # adapter BEFORE emitting the completion signal. The completion row /
        # hookpoint / "started" echo are the daemon's "I am fully up" assertion;
        # an enabled adapter that then fails spawn/handshake (-> ``_refuse_boot``,
        # exit 2) means the daemon is NOT up, so emitting "completed" first would
        # record a ``daemon.boot.completed`` row + tell the operator the daemon is
        # up for a boot that the very next statement refuses — a lie to both the
        # audit trail and the operator (the same class of lie CR #2 fixed for
        # ``supervisor.start()``). Each ``_spawn_comms_adapter`` awaits
        # ``runner.start_and_handshake()`` BEFORE committing the long-lived pump,
        # so a broken adapter refuses fail-closed (CLAUDE.md hard rule #7) rather
        # than parking with a dead plugin. The loop is a no-op when
        # ``comms_graph is None`` (default-empty adapters) — that path emits
        # ``completed`` below exactly as before.
        if comms_graph is not None:
            for adapter_id in settings.comms_enabled_adapters:
                await _spawn_comms_adapter(
                    adapter_id=adapter_id,
                    settings=settings,
                    audit=audit,
                    # The session's post-handshake ``check_plugin_load`` needs the
                    # FULL CapabilityGate surface — pass the RAW ``real_gate``, NOT
                    # the ``_SupervisorBootGate`` wrapper (which exposes only
                    # ``is_backing_store_available`` for the heartbeat and would
                    # ``AttributeError`` on ``check_plugin_load``, crashing the
                    # handshake). The wrapper is the Supervisor's surface; the comms
                    # session's surface is the gate itself.
                    gate=real_gate,
                    supervisor=supervisor,
                    graph=comms_graph,
                    boot_id=boot_id,
                    environment_source=source,
                )

        # All enabled adapters spawned + handshaked (or there were none): NOW the
        # daemon is genuinely up, so emit the completion row, invoke the
        # hookpoint, and echo "started".
        await _emit_or_quarantine(
            audit,
            fields=DAEMON_BOOT_FIELDS,
            schema_name="DAEMON_BOOT_FIELDS",
            event="daemon.boot.completed",
            subject={
                "boot_id": boot_id,
                "started_at": started_at.isoformat(),
                "state_git_head_sha": state_git_head_sha,
                "slice_version": "4",
                "policies_snapshot_hash": policies_snapshot_hash,
                "environment": settings.environment,
            },
            result="success",
        )

        await _invoke_boot_completed(boot_id, state_git_head_sha)

        typer.echo(t("daemon.boot.started", boot_id=boot_id))

        await wait_for_shutdown(supervisor)
    finally:
        # Drain the supervisor (no-op if start() never succeeded) and remove
        # the PID file on EVERY exit path — clean shutdown, a start() crash,
        # or a quarantine (exit 3) on the completion row — so a failed boot
        # never leaves a stale pidfile behind.
        await supervisor.stop()
        delete_pidfile(pidfile_path)


def _current_pid() -> int:
    import os

    return os.getpid()


def _snapshot_failure() -> DaemonBootFailure:
    from alfred.cli.daemon._failures import SnapshotRefInitFailedFailure

    return SnapshotRefInitFailedFailure(detail_redacted="snapshot_ref_none")


# ---------------------------------------------------------------------------
# Typer command entrypoints
# ---------------------------------------------------------------------------


def start_daemon() -> None:
    """Boot the AlfredOS daemon (spec §3, #174)."""
    try:
        asyncio.run(_start_async())
    except _BootRefusedError as refused:
        raise typer.Exit(code=refused.code) from refused


def stop_daemon() -> None:
    """Stop the daemon by signalling SIGTERM to the PID file's owner."""
    import os
    import signal

    path = default_pidfile_path()
    try:
        info = load_pidfile(path)
    except DaemonPidFileError:
        typer.echo(t("daemon.stop.no_daemon"))
        return  # exit 0 — operator-safe
    if not is_pid_alive(info.pid):
        typer.echo(t("daemon.stop.stale_pidfile"))
        return  # exit 0; stop is a no-op
    try:
        os.kill(info.pid, signal.SIGTERM)
    except ProcessLookupError:
        typer.echo(t("daemon.stop.stale_pidfile"))
        return
    typer.echo(t("daemon.stop.confirmed", pid=info.pid))


def status_daemon() -> None:
    """Render the daemon boot subset: PID, boot_id, started_at.

    ``alfred status`` is the general-health overview; ``alfred daemon
    status`` is the boot-process subset (devex-002 — their --help text
    cross-references). Status is read-only: no daemon / stale pidfile is not
    an error.
    """
    path = default_pidfile_path()
    try:
        info = load_pidfile(path)
    except DaemonPidFileError:
        typer.echo(t("daemon.status.not_running"))
        return
    if not is_pid_alive(info.pid):
        typer.echo(t("daemon.status.stale_pidfile", pid=info.pid))
        return
    # devex-222-03: the value is the raw boot timestamp, so the label is
    # "Started:" — not "Uptime:" (which would promise a duration the
    # operator must compute by hand). A humanised uptime duration lands in
    # a follow-up; for now the label honestly describes its value.
    typer.echo(
        t(
            "daemon.status.template",
            pid=info.pid,
            started_at=info.started_at,
            boot_id=info.boot_id,
            last_boot_at=info.started_at,
        )
    )
