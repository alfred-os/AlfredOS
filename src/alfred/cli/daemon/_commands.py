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
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, Protocol

import structlog
import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    COMMS_SOCKET_PEER_REJECTED_FIELDS,
    DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
    DAEMON_BOOT_FAILED_FIELDS,
    DAEMON_BOOT_FIELDS,
    DAEMON_CONTROL_PEER_REJECTED_FIELDS,
    DAEMON_LIFECYCLE_FIELDS,
)

# PR-S4-11c-2a0 (#237): mint + register the per-process authorised T3 nonce at
# boot. Imported at module scope (not lazily) so the boot-wiring unit tests can
# monkeypatch the ``alfred.cli.daemon._commands.create_and_register_t3_nonce``
# seam to count / fault the call without a real subprocess.
from alfred.bootstrap.lifecycle_epoch import current_boot_epoch, mint_boot_epoch
from alfred.bootstrap.nonce_factory import (
    T3NonceAlreadyRegisteredError,
    create_and_register_t3_nonce,
)
from alfred.cli.daemon._audit_fallback import build_boot_audit_writer
from alfred.cli.daemon._daemon_control_server import DaemonControlServer
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
    CommsAdapterBindFailedFailure,
    CommsAdapterSpawnFailedFailure,
    CommsMultiAdapterUnsupportedFailure,
    CommsPromoterMisconfiguredFailure,
    DaemonBootFailure,
    EnvironmentNotSetFailure,
    QuarantineChildSpawnFailedFailure,
    QuarantineGrantMissingFailure,
    T3NonceRegistrationFailedFailure,
    UnsandboxedEnvInProductionFailure,
)

# PR-S4-11b (#237): module-level so the boot-wiring unit tests monkeypatch these
# two seams (``alfred.cli.daemon._commands.CommsStdioTransport`` /
# ``...CommsPluginRunner``) to fakes — no real subprocess spawns in unit tests.
from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LIFECYCLE_REASON_SHUTDOWN,
)
from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
    load_environment,
)
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.hooks.errors import HookError
from alfred.i18n import t
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_socket_transport import CommsSocketListener
from alfred.plugins.comms_stdio_transport import CommsStdioTransport
from alfred.plugins.comms_wire import CommsProtocolError
from alfred.plugins.errors import ManifestError
from alfred.plugins.manifest import parse_manifest

# PR-S4-11c-2b: the comms-graph build spawns the live bwrap quarantined child;
# its loud spawn refusal is caught at the boot call site to refuse boot fail-closed
# (audited) on a non-Linux / unprovisioned host. Imported at module scope so the
# boot-wiring unit tests can monkeypatch the spawn seam (``spawn_quarantine_child_io``)
# without a real subprocess and still raise this through the boot path.
from alfred.security.quarantine_child_io import QuarantineChildSpawnError
from alfred.supervisor.core import Supervisor

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.comms_mcp.adapter_credential_resolver import CoreAdapterCredentialResolver
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
    from alfred.comms_mcp.daemon_runtime import (
        CommsInboundOrchestratorAdapter,
        OutboundSenderLike,
    )
    from alfred.comms_mcp.forwarded_inbound_receiver import (
        GatewayForwardedInboundReceiver,
        _ForwardedCollaborators,
    )
    from alfred.comms_mcp.protocol import OutboundMessageRequest
    from alfred.config.settings import Settings
    from alfred.hooks.capability import CapabilityGate
    from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
    from alfred.security.capability_gate._gate import RealGate
    from alfred.security.dlp import OutboundDlpProtocol
    from alfred.security.quarantine_transport import QuarantineStdioTransport
    from alfred.security.tiers import CapabilityGateNonce
    from alfred.supervisor.core import Supervisor as _SupervisorType

log = structlog.get_logger(__name__)

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

    async def send_outbound(self, request: OutboundMessageRequest) -> Mapping[str, object]:
        # Serialise the fully-validated request onto the wire. ``model_dump(mode=
        # "json")`` produces a JSON-round-trippable dict whose ``body`` is the
        # ``[redacted_text, scan_result]`` pair the consumer re-validates back into
        # the DLP-minted ``ScannedOutboundBody`` (G5 #237) — so the params SATISFY
        # ``OutboundMessageRequest.model_validate`` on the real TUI / Discord plugin.
        return await self._runner.send_request(
            "outbound.message",
            request.model_dump(mode="json"),
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


def _build_sub_payload_promoter(
    *,
    adapter_kind: str,
    content_store: object,
) -> object | None:
    """Build a :class:`SubPayloadPromoter` for ``adapter_kind``, or ``None`` (PR-S4-235-1).

    The deterministic per-adapter promoter factory: an adapter kind whose
    :data:`REQUIRED_CLASSIFIERS_BY_KIND` set is NON-empty (e.g. ``"discord"``) gets a
    configured promoter so the host promotes raw (T3) sub-payloads to single-use
    ``ContentHandle`` references BEFORE the quarantined extract (CLAUDE.md hard rule
    #5). An EMPTY-set kind (the reference plugin / TUI plain-text path) gets ``None``
    — promotion is inert there, so the default-empty path stays byte-for-byte
    unchanged (``frozenset()`` -> ``None`` -> the existing inbound behaviour).

    The ``content_store`` is the daemon-owned, process-lived
    :class:`alfred.plugins.web_fetch.content_store.ContentStore` shared across every
    per-adapter promoter (one Redis connection pool per process, not per request). It
    is typed ``object`` here because the promoter's structural ``_ContentStoreLike``
    Protocol — a single ``write`` method — is what actually binds it; the concrete
    import stays inside the function so the module's import closure does not pull the
    Redis client into every daemon-command import.
    """
    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND
    from alfred.comms_mcp.inbound_scanner import InboundContentScanner
    from alfred.comms_mcp.sub_payload_promotion import SubPayloadPromoter

    if not REQUIRED_CLASSIFIERS_BY_KIND.get(adapter_kind, frozenset()):
        return None
    return SubPayloadPromoter(
        adapter_kind=adapter_kind,
        scanner=InboundContentScanner(),
        content_store=content_store,  # type: ignore[arg-type]
    )


class _CommsAdapterManifestError(Exception):
    """An enabled comms adapter's manifest is missing a required wire field."""

    def __init__(self, adapter_id: str, field: str) -> None:
        super().__init__(f"comms adapter {adapter_id!r} manifest missing {field!r}")
        self.adapter_id = adapter_id
        self.field = field


# The forwarded-inbound kinds the HOST can re-parse + dispatch behind the gateway
# leg (ADR-0039). One registry entry per kind. Initially just ``"discord"`` (the
# first network-facing adapter the gateway spawns + forwards); a new hostable kind
# is added here AND must carry the host-side classifier/promoter machinery the
# registry builder fail-closes on. Keyed on the wire ``adapter_kind`` (the host's
# closed vocabulary), mirroring ``REQUIRED_CLASSIFIERS_BY_KIND`` / the promoter
# factory — NOT the per-instance launcher id.
_FORWARDED_INBOUND_KINDS: Final[tuple[str, ...]] = ("discord",)


class _ForwardedInboundRegistryMisconfiguredError(Exception):
    """A forwarded-inbound kind needs a promoter the deterministic factory withheld.

    Spec B G6-7-4 (#309). The boot-time mirror of the inbound M2 fail-closed guard,
    raised for a forwarded-inbound kind whose
    :data:`alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND` set is
    non-empty (e.g. ``"discord"``) but whose :func:`_build_sub_payload_promoter`
    yielded ``None`` (a structural REQUIRED_CLASSIFIERS_BY_KIND / factory drift). The
    promoter is what promotes raw (T3) sub-payloads to single-use ``ContentHandle``
    refs BEFORE the quarantined extract (CLAUDE.md hard rule #5), so a missing one is
    a fail-closed BOOT refusal — never a deferred per-message ``PromoterRequiredError``
    that would trip mid-traffic on the first forwarded inbound. Raised out of
    :func:`_build_forwarded_inbound_registry` (which has no supervisor / ``_refuse_boot``
    plumbing yet) and caught at the :func:`_build_comms_boot_graph` CALL SITE, where it
    is routed to an audited ``CommsPromoterMisconfiguredFailure`` refusal — exactly the
    catch-at-call-site shape ``QuarantineChildSpawnError`` uses (the graph builder runs
    before the supervisor exists).
    """

    def __init__(self, adapter_kind: str) -> None:
        super().__init__(
            f"forwarded-inbound kind {adapter_kind!r} requires a sub-payload promoter "
            "but the factory yielded None"
        )
        self.adapter_kind = adapter_kind


def _build_forwarded_inbound_registry(
    *,
    graph_content_store: object,
    resolver_bridge: object,
    inbound_orchestrator: object,
    burst_limiter: object,
    secret_broker: object,
) -> Mapping[str, _ForwardedCollaborators]:
    """Build the per-kind forwarded-inbound collaborator registry (Spec B G6-7-4 / #309).

    One :class:`_ForwardedCollaborators` entry per hostable forwarded kind
    (:data:`_FORWARDED_INBOUND_KINDS` — initially just ``"discord"``). For each kind:

    * build the per-kind :class:`SubPayloadPromoter` via the SAME deterministic factory
      the spawned-adapter wiring uses (:func:`_build_sub_payload_promoter`), so the host
      promotes raw (T3) sub-payloads to single-use ``ContentHandle`` refs BEFORE the
      quarantined extract (CLAUDE.md hard rule #5);
    * FAIL CLOSED at boot if a classifier-bearing kind yields a ``None`` promoter —
      raise :class:`_ForwardedInboundRegistryMisconfiguredError` (the call site refuses
      the boot) rather than defer to a per-message ``PromoterRequiredError`` mid-traffic;
    * mint ONE LONG-LIVED :class:`_PreResolutionLimiter` per kind (sec-003): the coarse
      per-``(adapter_id, platform_user_id_hash)`` DoS budget MUST accumulate across the
      flood of inbounds one platform user can send, so the limiter is built ONCE here
      and held for the receiver's whole lifetime — a per-call instance would silently
      reset the window every message and disable the gate.

    The orchestrator / resolver / burst-limiter / secret-broker are the per-boot
    singletons shared with the spawned-adapter inbound handlers (the SAME graph fields),
    so a forwarded inbound is dispatched with the identical collaborator set a
    daemon-spawned one would be. Returns an immutable mapping (the receiver only reads).
    """
    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND
    from alfred.comms_mcp.forwarded_inbound_receiver import _ForwardedCollaborators
    from alfred.comms_mcp.inbound import _PreResolutionLimiter

    registry: dict[str, _ForwardedCollaborators] = {}
    for kind in _FORWARDED_INBOUND_KINDS:
        promoter = _build_sub_payload_promoter(
            adapter_kind=kind,
            content_store=graph_content_store,
        )
        if promoter is None and REQUIRED_CLASSIFIERS_BY_KIND.get(kind, frozenset()):
            raise _ForwardedInboundRegistryMisconfiguredError(kind)
        registry[kind] = _ForwardedCollaborators(
            sub_payload_promoter=promoter,  # type: ignore[arg-type]
            resolver_bridge=resolver_bridge,  # type: ignore[arg-type]
            orchestrator=inbound_orchestrator,  # type: ignore[arg-type]
            burst_limiter=burst_limiter,  # type: ignore[arg-type]
            secret_broker=secret_broker,  # type: ignore[arg-type]
            # ONE long-lived limiter per kind (sec-003) — built ONCE, never per call.
            pre_resolution_limiter=_PreResolutionLimiter(),
        )
    return registry


# The comms ``adapter_kind`` whose host wire is a 0600 unix socket the daemon
# binds + accepts (ADR-0031), NOT a subprocess pipe the daemon spawns. The
# foreground ``alfred chat`` is a separate, operator-owned PTY process the daemon
# cannot spawn-and-own, so the two peers rendezvous over a named local socket.
_SOCKET_BACKED_ADAPTER_KIND: Final[str] = "tui"


def _is_socket_backed_adapter_kind(adapter_kind: str) -> bool:
    """True iff the adapter reaches the host over a unix socket (the TUI), not a pipe.

    Keyed on the wire ``adapter_kind`` (the host-side closed vocabulary), not the
    per-instance launcher id — the carrier choice is a property of the adapter KIND.
    """
    return adapter_kind == _SOCKET_BACKED_ADAPTER_KIND


async def _resolve_adapter_carrier_kind(
    *,
    adapter_id: str,
    audit: AuditWriter,
    boot_id: str,
    environment_source: str,
) -> str:
    """Resolve the wire ``adapter_kind`` so the boot loop can pick the carrier.

    The SAME guarded manifest resolution the per-carrier builders use, hoisted so the
    loop can choose the stdio-pipe vs unix-socket branch BEFORE dispatching. A broken
    manifest REFUSES the boot here (audited, exit 2) — identical fail-closed posture
    to the in-builder resolution, so a manifest failure can never slip past the
    carrier selector into an unguarded raise (CLAUDE.md hard rule #7).
    """
    from alfred.plugins.errors import ManifestError

    try:
        return _resolve_comms_adapter_wire_spec(adapter_id).adapter_kind
    except (OSError, ManifestError, _CommsAdapterManifestError) as exc:
        await _refuse_boot(
            audit,
            _comms_adapter_failure(adapter_id),
            t("daemon.boot.comms_adapter_spawn_failed", adapter_id=adapter_id),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is NoReturn (raises _BootRefusedError); unreachable defence.
        raise AssertionError("unreachable") from exc  # pragma: no cover


# Spec A G3-2 (#237): the narrow transport-error family a per-sender broadcast catch
# tolerates. A wire-send failure to a single peer is best-effort (the audit row at the
# callsite is authoritative), so a dead/torn peer connection is logged-not-fatal — but
# the catch is NARROW (never bare ``Exception``): a programming error must still surface
# loud (CLAUDE.md hard rule #7), and ``asyncio.CancelledError`` (a BaseException, not in
# this tuple) MUST propagate so the ``going_down`` broadcast — which runs in the boot
# drain ``finally`` — never swallows a cancellation and wedges the drain.
_LIFECYCLE_WIRE_SEND_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    BrokenPipeError,
    ConnectionResetError,
    CommsProtocolError,
    OSError,
)

# A wedged-but-connected peer that stops draining must not hang the daemon's
# lifecycle broadcast (especially ``going_down`` in the shutdown ``finally``). The
# frame is best-effort, so bound each per-sender send with a short timeout and move
# on. This is the per-broadcast SEND timeout (closing the sec-264-002 / CR #264
# shutdown-hang) — distinct from the G4 replay back-pressure the fleet deferred. A
# healthy same-uid peer drains instantly; 2s is generous before declaring it wedged.
_LIFECYCLE_BROADCAST_TIMEOUT_SECONDS: Final[float] = 2.0

# The bounded interval (seconds) between durable-intake ack emits (Spec A
# G4b-2a-pre / ADR-0032 Decision 3 coalescing — "piggyback + bounded timer; no
# standalone ack per data frame"). 1s gives a steady, message-rate-INDEPENDENT ack
# that drains the gateway's ReplayBuffer (G4b-2a) on a quiet-but-healthy link too,
# while coalescing a burst of inbound commits into ONE ack frame rather than one per
# message. The timer only emits on a high-water ADVANCE, so a quiet link costs one
# cheap ``cumulative_ack()`` read per interval and no wire traffic.
_DURABLE_INTAKE_ACK_INTERVAL_SECONDS: Final[float] = 1.0

# The last-emitted sentinel for the ack timer. ``-1`` (NOT 0) so the FIRST durable
# commit (``cumulative_ack`` ``-1 -> 0``) is an ADVANCE that DOES emit — a ``0``
# sentinel would suppress the first ack forever and the gateway's first trim would
# never fire (F5). The tracker itself returns ``-1`` before any contiguous run, so
# the emitted value is floored to ``max(ack, 0)`` (mirrors ``core_link.py``'s
# relay-ack floor — the wire's ``a=0`` placeholder maps the "nothing acked yet" -1).
_ACK_NOT_YET_EMITTED: Final[int] = -1


async def _emit_durable_intake_ack_loop(
    *,
    send_notification: Callable[[str, Mapping[str, object]], Awaitable[None]],
    cumulative_ack: Callable[[], int],
    shutdown_event: asyncio.Event,
    interval_seconds: float = _DURABLE_INTAKE_ACK_INTERVAL_SECONDS,
) -> None:
    """Per-connection bounded timer that emits ``daemon.comms.ack`` on a high-water advance.

    Spec A G4b-2a-pre / ADR-0032 (#237 — F2/F4/F5). Reads the host durable-intake
    tracker's ``cumulative_ack`` on each ``interval_seconds`` tick and emits ONE
    id-less ``daemon.comms.ack{cumulative_ack}`` via ``send_notification`` IFF the
    high-water advanced since the last emit. The frame rides IN the seq stream
    (``send_notification`` consumes a send-seq), which is exactly WHY the gateway's
    ``_route_unit`` needs a consume arm for it.

    Lifetime is the ACCEPTED CONNECTION: the caller (``_accept_and_pump``)
    constructs the tracker + schedules this loop per connection and reaps it in its
    teardown ``finally`` (a cancel -> ``await gather(..., return_exceptions=True)``).
    The loop also returns cleanly when ``shutdown_event`` fires so a graceful
    ``alfred daemon stop`` drains promptly without waiting for the cancel.

    FAIL-LOUD send (F5 / hard rule #7): a broken-pipe / transport-closed send
    PROPAGATES — it is NOT swallowed into a quiet retry. The peer is gone; the pump's
    crash arm owns the connection-death routing. The loop never re-tries a dead wire.
    """
    last_emitted = _ACK_NOT_YET_EMITTED
    while not shutdown_event.is_set():
        # Race the interval sleep against the shutdown signal so a clean stop ends the
        # loop within one tick rather than after a full interval (cancellation-safe:
        # the caller's reap cancels this wait too).
        with suppress(TimeoutError):
            async with asyncio.timeout(interval_seconds):
                await shutdown_event.wait()
        if shutdown_event.is_set():
            return
        # Gate on the RAW high-water (``-1`` when NOTHING has durably committed yet)
        # against the ``-1`` sentinel — so a truly quiet link (no commit ever) never
        # emits, while the FIRST commit (raw ``-1 -> 0``) is a genuine advance that
        # does. Only the EMITTED value is floored to ``max(ack, 0)`` (the wire's
        # non-negative counter; the ``-1`` "nothing acked" maps to the ``a=0``
        # placeholder, mirroring ``core_link.py``'s relay-ack floor).
        ack = cumulative_ack()
        if ack <= last_emitted:
            # Quiet link / no advance since the last emit — suppress (no wire traffic).
            continue
        await send_notification(DAEMON_COMMS_ACK, {"cumulative_ack": max(ack, 0)})
        last_emitted = ack


class LifecycleBroadcaster:
    """Boot-local fan-out of the core's lifecycle frames to the socket carrier(s).

    Spec A G3-2 (#237). Held as a BOOT-LOCAL var in :func:`daemon_start` (NOT a field
    on the frozen :class:`_CommsBootGraph` — architect M-1: the graph is an immutable
    DI bundle and a mutable late-binding registry on it would risk broadcasting through
    an already-reaped transport at ``aclose`` time). The socket-carrier runner registers
    its id-less ``send_notification`` here AFTER its handshake; ``_emit_ready`` /
    ``_emit_going_down`` broadcast through it AFTER the (authoritative) audit row.

    ONLY the socket-listener carrier registers — never the daemon-spawned stdio
    adapters, which die with the core and so neither need nor receive the frames
    (G2-lesson). In the normal boot the socket peer connects on-demand later, so the
    boot-time ``ready`` broadcast reaches ZERO senders — a clean DEBUG no-op (the
    headline G3-2 runtime behaviour, architect H-1). The wire frame is best-effort; the
    audit row is authoritative (spec §6).
    """

    def __init__(self) -> None:
        self._senders: list[tuple[str, Callable[[str, Mapping[str, object]], Awaitable[None]]]] = []

    def register(
        self,
        adapter_id: str,
        sender: Callable[[str, Mapping[str, object]], Awaitable[None]],
    ) -> None:
        """Register one socket-carrier runner's id-less notification sender."""
        self._senders.append((adapter_id, sender))

    async def broadcast_ready(self, epoch: str) -> None:
        """Fan ``daemon.lifecycle.ready`` (with the boot epoch) to every sender."""
        await self._broadcast(DAEMON_LIFECYCLE_READY, {"epoch": epoch}, phase="ready")

    async def broadcast_going_down(self, reason: str) -> None:
        """Fan ``daemon.lifecycle.going_down`` (with the reason) to every sender."""
        await self._broadcast(DAEMON_LIFECYCLE_GOING_DOWN, {"reason": reason}, phase="going_down")

    async def _broadcast(self, method: str, params: Mapping[str, object], *, phase: str) -> None:
        if not self._senders:
            # The headline normal-boot no-op (architect H-1): the socket peer
            # connects on-demand, so a boot-time broadcast reaches no sender. Clean
            # DEBUG, never a warning — this is the expected path, not a fault.
            log.debug("comms.lifecycle.no_peer", phase=phase)
            return
        for adapter_id, sender in self._senders:
            try:
                await asyncio.wait_for(
                    sender(method, params),
                    timeout=_LIFECYCLE_BROADCAST_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                # A wedged-but-connected peer that stopped draining: bound the
                # best-effort frame and move on (the audit row at the callsite is
                # authoritative). ``wait_for`` cancels the inner send; abandoning a
                # partial frame to an already-wedged peer is acceptable. Loud, never
                # silent (CR #264 / sec-264-002).
                log.warning(
                    "comms.lifecycle.wire_send_timeout",
                    adapter_id=adapter_id,
                    phase=phase,
                    timeout_s=_LIFECYCLE_BROADCAST_TIMEOUT_SECONDS,
                )
            except _LIFECYCLE_WIRE_SEND_EXCEPTIONS as exc:
                # Best-effort wire frame: a dead/torn peer is logged-not-fatal (the
                # audit row at the callsite is authoritative). NEVER catch bare
                # ``Exception`` (a real bug surfaces loud) and NEVER swallow
                # ``CancelledError`` (it is a BaseException outside this tuple, so it
                # propagates — the ``going_down`` broadcast runs in the shutdown
                # finally and must not wedge the drain).
                log.warning(
                    "comms.lifecycle.wire_send_failed",
                    adapter_id=adapter_id,
                    phase=phase,
                    error=repr(exc),
                )


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
    # The LIVE quarantine transport (owns the bwrap child via its ChildIO). Held so
    # the daemon can reap the child on EVERY exit path (PR-S4-11c-2b / CR #255).
    quarantine_transport: QuarantineStdioTransport
    # The daemon-owned, process-lived ContentStore the per-adapter SubPayloadPromoters
    # write raw (T3) sub-payload bytes through (PR-S4-235-1). Constructed ONCE here so
    # one Redis connection pool is shared across every promoter (perf-006), and reaped
    # on EVERY exit path (a leaked Redis client is the analog of the leaked bwrap child
    # — CR #255). Typed ``object`` so the module import closure stays free of the Redis
    # client; the concrete type is ``alfred.plugins.web_fetch.content_store.ContentStore``.
    content_store: object
    # The daemon-owned durable accept-once store (Spec A G0). Built ONCE in
    # ``_build_comms_boot_graph`` and injected into every per-adapter inbound
    # handler so a replayed comms frame short-circuits before any side effect. It
    # owns its ``session_scope`` over the SHARED DSN-cached engine (the
    # ``audit_writer`` shape), so — unlike ``content_store`` / ``quarantine_transport``
    # — it deliberately has NO reap on ``aclose``: ``dispose_all_engines()`` reaps
    # that one cached engine once at process exit, and disposing it on graph
    # teardown would pull the connection pool out from under every other daemon
    # component that shares it. Typed concretely (NOT ``object``) so ``mypy --strict``
    # checks the inject site; the ``TYPE_CHECKING`` import keeps the module's import
    # closure free of the memory package at runtime.
    idempotency_store: PostgresInboundIdempotencyStore
    # Spec B G6-2b-2a (#288): the core-side observer/auditor for gateway-reported
    # adapter status. Built ONCE here, injected into every per-adapter session so a
    # gateway.adapter.* frame is validated / epoch-reconciled / audited / refused
    # core-side. Holds no resource to reap (pure validator + in-memory snapshot map),
    # so ``aclose`` does not touch it.
    status_observer: AdapterStatusObserver
    # Spec B G6-3 (#288): the core-side credential resolver (the ONLY decryptor). Built
    # ONCE here, injected into the gateway-leg runner so a ``gateway.adapter.spawn_request``
    # resolves to a ``core.adapter.spawn_grant`` over the trusted leg. Holds the secret
    # broker + an in-memory dedup cache (per gateway<->core link lifetime); no resource to
    # reap, so ``aclose`` does not touch it.
    credential_resolver: CoreAdapterCredentialResolver
    # Spec B G6-2b-2b (#288): the SHARED crash-dedup reconciler. Built ONCE here and
    # injected into BOTH the status observer (gateway-crash arm) AND every per-adapter
    # AdapterCrashHandler (in-child arm) so the two coexisting crash signals fold into
    # one incident. In-memory only (per gateway<->core link lifetime); the durable
    # trail is the signed audit log; NOT reachable from the ``alfred status`` CLI today
    # (the CLI does not dial the daemon — see the crash_incident_reconciler module
    # docstring's snapshot-reachability decision; 2b-2c owns the query seam). Holds no
    # resource to reap, so ``aclose`` does not touch it.
    crash_incident_reconciler: CrashIncidentReconciler
    # Spec B G6-7-4 (#309): the per-boot gateway-forwarded inbound receiver — the
    # core-side T3 trust seam that re-parses a ``gateway.adapter.inbound`` envelope and
    # dispatches it on the dispatched edge with the right per-kind collaborator set.
    # Built ONCE here (over the fail-closed per-kind registry) and injected into the
    # gateway-leg runner; the per-CONNECTION ack tracker is bound onto it at accept time
    # (the SAME instance the inbound handler + ack-emit timer use). In-memory only (the
    # registry of per-boot singletons + a per-kind long-lived limiter); holds no resource
    # to reap, so ``aclose`` does not touch it (the same posture as ``credential_resolver``
    # / ``status_observer``).
    forwarded_inbound_receiver: GatewayForwardedInboundReceiver

    async def aclose(self) -> None:
        """Reap the LIVE bwrap quarantined child + the daemon-owned ContentStore.

        Closes the quarantine transport (``-> child_io.aclose()`` SIGTERMs + reaps
        the bwrap subprocess) so the child never leaks past the daemon, and closes the
        process-lived ContentStore (``-> Redis client.aclose()``) so its connection
        pool never leaks (PR-S4-235-1 — the Redis-client analog of the bwrap child;
        CR #255). Called on EVERY exit path after the spawn: a ``Supervisor()`` /
        ``write_pidfile`` / ``supervisor.start()`` failure, an adapter refusal, or a
        normal shutdown. Both closes are idempotent, so a double-close (e.g. shutdown
        after a start() failure) is safe.

        The two closes are isolated so a failing transport close never skips the
        ContentStore reap (and vice versa) — the exact leaks this teardown exists to
        prevent. ``ContentStore.close`` is the idempotent connection-drop API
        (NOT ``aclose`` — that is the child-IO method).
        """
        from alfred.plugins.web_fetch.content_store import ContentStore

        try:
            await self.quarantine_transport.close()
        finally:
            # In production `content_store` is ALWAYS a real `ContentStore` (built in
            # `_build_comms_boot_graph`), so the True arm always runs; the isinstance
            # guard only spares a test double that has no `close()`. If a future
            # structural store seam is introduced, widen this reap to it (else its
            # client would silently leak) — see test_graph_aclose_skips_close_for_non_content_store.
            if isinstance(self.content_store, ContentStore):
                await self.content_store.close()


async def _build_comms_boot_graph(
    *,
    settings: Settings,
    audit: AuditWriter,
    outbound_dlp: OutboundDlpProtocol,
    t3_nonce: CapabilityGateNonce,
    policies_ref: object,
) -> _CommsBootGraph:
    """Construct the pre-Supervisor comms graph (PR-S4-11b construction step 1-5).

    Built ONLY when at least one adapter is enabled. Assembles the secret broker,
    the sync identity-resolver bridge, the REAL quarantined extractor over a LIVE
    bwrap-spawned quarantined child (PR-S4-11c-2b go-live flip) + its body-shaped
    bridge, the burst limiter, and the inbound orchestrator adapter whose outbound
    sender is bound per-adapter after the runner exists.

    ``async`` because the extractor build spawns the quarantined child
    (``spawn_quarantine_child_io``). FAIL-CLOSED: on a non-Linux / unprovisioned
    host the spawn raises ``QuarantineChildSpawnError``, which propagates so the
    daemon refuses to boot (the caller wraps it in an audited refusal) rather than
    silently degrading to a fixture (CLAUDE.md hard rule #7).

    ``t3_nonce`` is the per-process authorised :class:`CapabilityGateNonce` the
    daemon minted + registered at boot. PR-S4-11c-2b CONSUMES it: it is injected
    into the :class:`T3BodyRecorder` (the ``record_body`` seam) that tags the
    inbound body ``TaggedContent[T3]`` and stages it in the SAME single-use
    :class:`QuarantineStagingMap` the ``QuarantineStdioTransport`` drains — closing
    the inline-over-wire content path (ADR-0029) in production.
    """
    from typing import cast

    from alfred.cli._bootstrap import build_broker, install_identity_factories_for_settings
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge, SyncIdentityResolverBridge
    from alfred.comms_mcp.daemon_runtime import (
        CommsInboundOrchestratorAdapter,
        _build_comms_inbound_extractor,
    )
    from alfred.memory.forwarded_dispatch_attempts import (
        PostgresForwardedDispatchAttemptStore,
    )
    from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
    from alfred.orchestrator.burst_limiter import BurstLimiter
    from alfred.plugins.web_fetch.content_store import ContentStore
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder

    secret_broker = build_broker(settings)
    resolver = install_identity_factories_for_settings(settings)
    resolver_bridge = SyncIdentityResolverBridge(resolver=resolver)
    # PR-S4-235-1: the daemon-owned ContentStore the per-adapter SubPayloadPromoters
    # write raw (T3) sub-payload bytes through. Constructed ONCE here (one Redis
    # connection pool per process, not per request — perf-006) and threaded onto the
    # graph so ``aclose`` reaps it on every exit path (a leaked Redis client is the
    # analog of the leaked bwrap child — CR #255). ``policies_ref`` carries the active
    # snapshot so the store's per-session quota deref reads live policy.
    content_store = ContentStore(
        redis_url=settings.redis_url,
        policies_ref=policies_ref,  # type: ignore[arg-type]
    )
    # ONE single-use staging map shared between the recorder (writer) and the
    # transport (drainer) — the host owns the raw T3 body between them (ADR-0029).
    staging = QuarantineStagingMap()
    # ``_build_boot_outbound_dlp`` always constructs a concrete ``OutboundDlp``
    # (it is annotated to the Protocol for the Supervisor's narrower consumer);
    # the extractor's post-stage scan needs the concrete class, so the cast pins
    # what the runtime already guarantees rather than widening the Wave-2 helper.
    extractor, quarantine_transport = await _build_comms_inbound_extractor(
        audit_writer=audit,
        outbound_dlp=cast("OutboundDlp", outbound_dlp),
        secret_broker=secret_broker,
        staging=staging,
    )
    # The child is now LIVE. Reap it if any of the remaining (synchronous) graph
    # assembly raises before we return the graph — otherwise `_start_async` never
    # receives the graph, so its exit-path teardown can't see the transport and the
    # bwrap child leaks (CR #255 round-5).
    try:
        # The ``record_body`` seam: tag the inbound body T3 under the boot nonce +
        # stage it for the transport's ``quarantine.ingest`` drain. A wrong/None
        # nonce is a loud refusal inside T3BodyRecorder (never a stage-untagged
        # fallback).
        recorder = T3BodyRecorder(nonce=t3_nonce, staging=staging)
        extractor_bridge = CommsExtractorBridge(extractor=extractor, record_body=recorder)
        # ── #339 SEAM (G7-2.5 PR2 / §5.3) ───────────────────────────────────
        # The live ``web.fetch`` egress extractor is assembled by
        # ``alfred.plugins.web_fetch.assembly.build_web_fetch_egress_extractor``,
        # REUSING this same ``extractor`` + ``recorder`` (and the boot
        # ``CapabilityGate``) — it must NOT spawn a second quarantined child
        # (§4.3 one production extractor; CORE-4 shared-child HoL). The factory
        # is NOT called here: ``dispatch_web_fetch`` has zero production callers
        # until #339 wires the tool-calling loop (after G7-3), so building it at
        # boot would be dangling, never-exercised construction. #339 calls the
        # factory at the point it first needs a live ``web.fetch``, threading:
        #   build_web_fetch_egress_extractor(
        #       settings=settings, gate=<the boot CapabilityGate>,
        #       extractor=extractor, recorder=recorder, outbound_dlp=<cast>,
        #       audit_writer=audit,
        #       session_scope=build_boot_session_scope(settings))
        # The gateway relay address rides ``settings.egress_relay_url`` (PR2
        # compose). An integration test over a loopback relay proves the wiring
        # (test_web_fetch_assembly.py), per ADR-0041.
        #
        # SINGLETON CONTRACT (#339): the live caller MUST build the extractor ONCE
        # here at composition and reuse that single instance — do NOT call
        # build_web_fetch_egress_extractor per fetch. RelayEgressClient's in-flight
        # concurrency semaphore is PER-INSTANCE, so a per-fetch factory call would
        # give each fire its own semaphore and defeat the global cap (the "a burst
        # cannot head-of-line the comms relay" guarantee).
        # ────────────────────────────────────────────────────────────────────
        # AuditWriter satisfies the BurstLimiter's ``_AuditWriterLike`` seam at
        # runtime (its append/append_schema are the keyword forms the limiter calls);
        # mypy flags the more-specific override against the ``**kwargs`` Protocol, the
        # same structural mismatch the per-adapter handlers below carry an ignore for.
        burst_limiter = BurstLimiter(audit_writer=audit)  # type: ignore[arg-type]
        inbound_orchestrator = CommsInboundOrchestratorAdapter(
            extractor_bridge=extractor_bridge,
            # The stubbed ack dispatch routes the ack through this DLP chokepoint
            # before it crosses the wire (G5 #237; CLAUDE.md hard rule #4). The same
            # concrete ``OutboundDlp`` the extractor's post-stage scan uses.
            outbound_dlp=cast("OutboundDlp", outbound_dlp),
        )
        # Spec A G0: the durable accept-once store. Owns its ``session_scope`` over
        # the SHARED DSN-cached engine (the ``audit_writer`` shape), so it is
        # deliberately NOT reaped on graph teardown — see the ``idempotency_store``
        # field comment + the resolved-open-question (shared-engine, must-not-dispose):
        # ``dispose_all_engines()`` reaps that one cached engine at process exit, and
        # disposing it here would break every other daemon component that shares it.
        # Spec B G6-7-5 (#309): the durable forwarded-dispatch attempt ledger backing
        # the ADR-0039 item-4b poison ceiling. Same shared-engine ``session_scope``
        # shape as ``idempotency_store`` (NOT reaped on graph teardown — see that
        # field's comment); the receiver threads it into every dispatched-edge call.
        forwarded_dispatch_attempt_store = PostgresForwardedDispatchAttemptStore(
            session_scope=build_boot_session_scope(settings),
        )
        idempotency_store = PostgresInboundIdempotencyStore(
            session_scope=build_boot_session_scope(settings),
        )
        # Spec B G6-2b-2a (#288): the core-side adapter-status observer. Its
        # ``expected_epoch`` is a callable so it reads the daemon's per-boot epoch at
        # OBSERVE time (correction #3: wrap ``current_boot_epoch() -> str | None`` into
        # ``Callable[[], str]`` — passing ``current_boot_epoch`` directly fails
        # mypy-strict on the ``str | None`` return). The epoch is the SAME value
        # threaded into the runner's ``lifecycle.start`` handshake, so a genuine live
        # ``up`` matches and a forged/stale epoch is refused (the false-liveness defense).
        from alfred.comms_mcp.adapter_credential_resolver import CoreAdapterCredentialResolver
        from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
        from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

        # Spec B G6-3 (#288): the core-side credential resolver — the ONLY decryptor.
        # Holds the SAME secret broker the rest of the boot graph uses; resolves the
        # platform credential for a gateway adapter (re)spawn over the trusted leg.
        credential_resolver = CoreAdapterCredentialResolver(
            broker=secret_broker,
            audit=audit,
            now=lambda: datetime.now(UTC),
        )

        def _expected_epoch() -> str:
            epoch = current_boot_epoch()
            if epoch is None:  # pragma: no cover - boot epoch is minted before the graph
                raise RuntimeError("boot epoch unset when building the status observer")
            return epoch

        # ONE reconciler shared by the observer (gateway-crash arm) AND every per-adapter
        # crash handler (in-child arm) — the crash-dedup join (G6-2b-2b / #288).
        crash_incident_reconciler = CrashIncidentReconciler()
        status_observer = AdapterStatusObserver(
            audit=audit,
            expected_epoch=_expected_epoch,
            now=lambda: datetime.now(UTC),
            reconciler=crash_incident_reconciler,
        )
        # Spec B G6-7-4 (#309): the per-boot gateway-forwarded inbound receiver, built
        # over the fail-closed per-kind collaborator registry. A classifier-bearing kind
        # with a None promoter raises ``_ForwardedInboundRegistryMisconfiguredError`` HERE
        # (caught at the call site -> audited refuse-boot) — fail-closed at boot, never a
        # deferred per-message ``PromoterRequiredError`` (CLAUDE.md hard rules #5 + #7).
        # The collaborators are the SAME per-boot singletons the spawned-adapter inbound
        # handlers use (so a forwarded inbound dispatches identically); the ack tracker is
        # bound per accepted connection at accept time, not here.
        from alfred.comms_mcp.forwarded_inbound_receiver import GatewayForwardedInboundReceiver

        forwarded_inbound_receiver = GatewayForwardedInboundReceiver(
            registry=_build_forwarded_inbound_registry(
                graph_content_store=content_store,
                resolver_bridge=resolver_bridge,
                inbound_orchestrator=inbound_orchestrator,
                burst_limiter=burst_limiter,
                secret_broker=secret_broker,
            ),
            idempotency_store=idempotency_store,
            attempt_store=forwarded_dispatch_attempt_store,
            audit_writer=audit,  # type: ignore[arg-type]
        )
        return _CommsBootGraph(
            secret_broker=secret_broker,
            resolver_bridge=resolver_bridge,
            extractor_bridge=extractor_bridge,
            burst_limiter=burst_limiter,
            inbound_orchestrator=inbound_orchestrator,
            t3_nonce=t3_nonce,
            quarantine_transport=quarantine_transport,
            content_store=content_store,
            idempotency_store=idempotency_store,
            status_observer=status_observer,
            credential_resolver=credential_resolver,
            crash_incident_reconciler=crash_incident_reconciler,
            forwarded_inbound_receiver=forwarded_inbound_receiver,
        )
    except Exception:
        # Reap BOTH the live bwrap child (via the transport) and the ContentStore's
        # Redis client if any post-spawn assembly raises before the graph returns —
        # otherwise neither reaches the daemon's exit-path teardown and both leak
        # (CR #255). Isolated so a transport-close failure never skips the store reap.
        try:
            await quarantine_transport.close()
        finally:
            await content_store.close()
        raise


@dataclass(frozen=True, slots=True)
class _CommsAdapterWiring:
    """The per-adapter session + wire spec shared by the stdio + socket branches.

    Built once by :func:`_build_comms_adapter_wiring` (manifest resolve, promoter,
    the four handlers, the :class:`AlfredPluginSession`) so the carrier-specific
    branches (:func:`_spawn_comms_adapter` for the stdio pipe,
    :func:`_listen_socket_comms_adapter` for the unix socket) construct only the
    transport + runner and never duplicate the handler fan-out.

    ``inbound_handler`` is exposed so the SOCKET carrier can bind a PER-CONNECTION
    durable-intake ack tracker onto it AFTER the handshake (Spec A G4b-2a-pre — the
    tracker's lifetime is the accepted connection, not the per-boot wiring). The
    stdio carrier never touches it (its inbound carries no wire seq).
    """

    wire: _CommsAdapterWireSpec
    session: object
    inbound_handler: object


async def _build_comms_adapter_wiring(
    *,
    adapter_id: str,
    settings: Settings,
    audit: AuditWriter,
    gate: object,
    supervisor: _SupervisorType,
    graph: _CommsBootGraph,
    boot_id: str,
    environment_source: str,
) -> _CommsAdapterWiring:
    """Resolve the manifest + build the promoter, handlers, and plugin session.

    The carrier-agnostic half of an adapter's boot (shared by the stdio + socket
    branches). Every fail-closed refusal that precedes the wire — a broken manifest,
    a misconfigured sub-payload promoter — happens here, so both carriers inherit the
    same audited-refusal posture (CLAUDE.md hard rule #7). The transport + runner are
    the caller's job (they differ by carrier).
    """
    from alfred.comms_mcp.bootstrap import build_supervisor_breaker_tripper
    from alfred.comms_mcp.daemon_runtime import CommsAdapterCrashedHookInvoker
    from alfred.comms_mcp.handlers import (
        AdapterCrashHandler,
        BindingRequestHandler,
        InboundMessageHandler,
        PlatformRateLimitHandler,
    )
    from alfred.plugins.errors import ManifestError
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

    breaker_tripper = build_supervisor_breaker_tripper(supervisor=supervisor)
    hook_invoker = CommsAdapterCrashedHookInvoker()
    # PR-S4-235-1: build the per-adapter host-side sub-payload promoter. The factory
    # is keyed on the WIRE ``adapter_kind`` (the host's classifier/body tables key,
    # NOT the launcher plugin id) and returns a configured promoter for a
    # classifier-bearing kind (e.g. ``discord``) or ``None`` for an empty-set kind
    # (the reference plugin / TUI plain-text path — byte-for-byte unchanged). It
    # shares the daemon-owned ContentStore so raw (T3) sub-payloads land in one
    # process-lived Redis pool.
    sub_payload_promoter = _build_sub_payload_promoter(
        adapter_kind=wire.adapter_kind,
        content_store=graph.content_store,
    )
    # Boot-time mirror of the inbound M2 fail-closed guard: a classifier-bearing
    # adapter kind whose factory yielded a ``None`` promoter is a structural wiring
    # defect (the factory is deterministic, so this never happens on a correct build
    # — it is defence-in-depth against a future REQUIRED_CLASSIFIERS_BY_KIND /
    # factory drift). REFUSE BOOT fail-closed NOW (audited, exit 2) rather than wait
    # for the first inbound message to trip the runtime M2 guard mid-traffic
    # (CLAUDE.md hard rules #5 + #7). The empty-set path (None promoter for a kind
    # with NO required classifiers) is correct and is NOT refused.
    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND

    if sub_payload_promoter is None and REQUIRED_CLASSIFIERS_BY_KIND.get(
        wire.adapter_kind, frozenset()
    ):
        await _refuse_boot(
            audit,
            CommsPromoterMisconfiguredFailure(adapter_id=adapter_id),
            t("daemon.boot.comms_promoter_misconfigured", adapter_id=adapter_id),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is NoReturn (raises _BootRefusedError); unreachable defence.
        raise AssertionError("unreachable")  # pragma: no cover
    inbound_handler = InboundMessageHandler(
        identity_resolver=graph.resolver_bridge,  # type: ignore[arg-type]
        orchestrator=graph.inbound_orchestrator,
        burst_limiter=graph.burst_limiter,  # type: ignore[arg-type]
        audit_writer=audit,  # type: ignore[arg-type]
        secret_broker=graph.secret_broker,  # type: ignore[arg-type]
        sub_payload_promoter=sub_payload_promoter,  # type: ignore[arg-type]
        # No ``type: ignore`` here (unlike the ``object``-typed graph fields above):
        # ``graph.idempotency_store`` is concretely typed ``PostgresInboundIdempotencyStore``,
        # which structurally satisfies the handler's ``_InboundIdempotencyStoreLike``.
        idempotency_store=graph.idempotency_store,
    )
    binding_handler = BindingRequestHandler(
        audit_writer=audit,  # type: ignore[arg-type]
        secret_broker=graph.secret_broker,  # type: ignore[arg-type]
    )
    rate_limit_handler = PlatformRateLimitHandler(
        breaker_tripper=breaker_tripper,
        audit_writer=audit,  # type: ignore[arg-type]
    )
    crash_handler = AdapterCrashHandler(
        audit_writer=audit,  # type: ignore[arg-type]
        hook_invoker=hook_invoker,
        # The SAME reconciler the boot graph injected into the status observer, so a
        # gateway crash and this in-child crash for one physical crash fold into one
        # incident (G6-2b-2b / #288).
        reconciler=graph.crash_incident_reconciler,
    )

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
        status_observer=graph.status_observer,
        transport=None,
        max_in_flight_notifications=settings.comms_max_in_flight_notifications,
    )
    return _CommsAdapterWiring(wire=wire, session=session, inbound_handler=inbound_handler)


def _build_comms_runner(
    *,
    session: object,
    transport: object,
    adapter_kind: str,
    supervisor: _SupervisorType,
    settings: Settings,
    graph: _CommsBootGraph,
    with_credential_resolver: bool = False,
    with_forwarded_inbound_receiver: bool = False,
) -> CommsPluginRunner:
    """Construct the runner over an established transport + bind the outbound sender.

    Shared by the stdio (pipe) and socket (gateway) branches — only the ``transport``
    differs. Binds the inbound orchestrator's outbound sender to THIS runner so the
    dispatch ack flows back over the same wire.

    ``with_credential_resolver`` (Spec B G6-3 / #288) wires the credential
    request/response routing ONLY on the SOCKET (gateway) leg — the leg the gateway
    dials to request adapter credentials. The stdio (daemon-spawned) legs carry no
    credential request, so they leave it OFF (the resolver is never reached on them).

    ``with_forwarded_inbound_receiver`` (Spec B G6-7-4 / #309) injects the per-boot
    gateway-forwarded inbound receiver ONLY on the gateway leg, so a
    ``gateway.adapter.inbound`` notification is re-parsed + dispatched on the trusted
    T3 seam (instead of the session's unknown_method refusal). The stdio
    (daemon-spawned) legs carry no forwarded inbound, so they leave it OFF (the
    disposition's None-branch falls through to the fail-closed refusal — byte-for-byte
    unchanged).
    """
    runner = CommsPluginRunner(
        session=session,  # type: ignore[arg-type]
        transport=transport,  # type: ignore[arg-type]
        adapter_id=adapter_kind,
        # PR-S4-11b DEFECT 1: the supervisor's graceful-drain signal so the pump
        # exits PROMPTLY on ``alfred daemon stop`` instead of blocking on the idle
        # stream until the drain budget force-cancels it.
        shutdown_event=supervisor.shutdown_event,
        # Match the runner's in-flight dispatch-task cap to the session's per-adapter
        # dispatch semaphore so the two backpressure bounds share one value.
        max_in_flight_notifications=settings.comms_max_in_flight_notifications,
        # Spec A G3-2 (#237) — architect H-2: thread the non-secret per-boot epoch
        # into the ``lifecycle.start`` handshake so the G3-3 gateway reconciles
        # core-liveness from the handshake (the boot-``ready`` broadcast normally
        # reaches zero senders). ``current_boot_epoch()`` is ``None`` only before
        # ``mint_boot_epoch`` runs at boot — by the time a runner is built it is set.
        boot_epoch=current_boot_epoch(),
        # Spec B G6-3 (#288): only the gateway (socket) leg carries the credential
        # round-trip; the resolver routes spawn_request -> spawn_grant on this runner.
        credential_resolver=graph.credential_resolver if with_credential_resolver else None,
        # Spec B G6-7-4 (#309): only the gateway leg carries forwarded inbounds; the
        # receiver re-parses + dispatches a ``gateway.adapter.inbound`` on this runner.
        # The concrete ``GatewayForwardedInboundReceiver.set_ack_tracker`` narrows its
        # param to ``_AckTrackerLike`` against the runner's ``_ForwardedReceiverLike``
        # Protocol (``object``), the same structural-override mismatch the per-adapter
        # handlers / credential resolver carry an ignore for.
        forwarded_inbound_receiver=(
            graph.forwarded_inbound_receiver  # type: ignore[arg-type]
            if with_forwarded_inbound_receiver
            else None
        ),
    )
    sender: OutboundSenderLike = _RunnerOutboundSender(runner=runner)
    graph.inbound_orchestrator.bind_outbound_sender(sender)
    return runner


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
    """Spawn + readiness-probe one stdio-pipe comms adapter, then register its pump.

    The fail-closed boot primitive (architect's required shape): the daemon
    ``await runner.start_and_handshake()`` BEFORE committing to the long-lived
    pump, so a broken adapter (missing/parse-broken manifest, spawn failure,
    not-ok handshake) REFUSES the boot via :func:`_refuse_boot` rather than
    parking with a dead plugin. On success the pump is scheduled as a supervised
    TaskGroup task.

    This is the SUBPROCESS-PIPE carrier (Discord, the reference plugin): the daemon
    owns both ends, so spawn → handshake → register runs inline. The unix-socket
    carrier (the foreground TUI) is :func:`_listen_socket_comms_adapter`, whose peer
    arrives asynchronously and so cannot handshake inline at boot (ADR-0031).

    Returns the live :class:`CommsPluginRunner` (post-handshake, pump scheduled)
    so a caller that needs the host -> plugin request seam can drive it — the
    daemon boot loop ignores the return (the runner's lifetime is the supervised
    pump it just registered), while the end-to-end integration proof
    (``test_daemon_comms_inbound_turn``) grabs it to drive the inbound-injection
    trigger through the real runner rather than reimplementing the wiring.
    """
    from alfred.cli._launcher_spawn import PluginLaunchSpec, repo_root
    from alfred.plugins.errors import PluginError

    wiring = await _build_comms_adapter_wiring(
        adapter_id=adapter_id,
        settings=settings,
        audit=audit,
        gate=gate,
        supervisor=supervisor,
        graph=graph,
        boot_id=boot_id,
        environment_source=environment_source,
    )
    wire = wiring.wire

    # The ``python -m`` target the launcher execs is the manifest module
    # ``alfred_comms_test.main`` — a top-level package under ``plugins/``. So the
    # child PYTHONPATH must carry the ``plugins/`` PARENT (not the per-adapter dir,
    # which would put the module's siblings on the path but not the package
    # itself), plus ``src/`` so the core ``alfred.comms_mcp`` protocol resolves in
    # the scrubbed child env. Mirrors the proven substrate-test spawn roots
    # (``tests/integration/test_comms_runner_substrate.py``).
    plugins_root = repo_root() / "plugins"
    src_root = repo_root() / "src"
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
    runner = _build_comms_runner(
        session=wiring.session,
        transport=transport,
        adapter_kind=wire.adapter_kind,
        supervisor=supervisor,
        settings=settings,
        graph=graph,
    )

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


async def _listen_socket_comms_adapter(
    *,
    adapter_id: str,
    settings: Settings,
    audit: AuditWriter,
    gate: object,
    supervisor: _SupervisorType,
    graph: _CommsBootGraph,
    boot_id: str,
    environment_source: str,
    broadcaster: LifecycleBroadcaster,
) -> CommsSocketListener:
    """Bind the 0600 comms socket + schedule the accept → handshake → pump task.

    The UNIX-SOCKET carrier for the foreground TUI (ADR-0031). Unlike the stdio
    carrier (:func:`_spawn_comms_adapter`), the daemon does NOT own the peer:
    ``alfred chat`` is a separate, operator-owned PTY process that connects LATER
    (and may never connect). So the handshake CANNOT run inline at boot — it would
    block ``alfred daemon start`` forever on an absent peer. Instead:

    * **bind inline (fail-closed)** — binding the 0600 owner-only socket under the
      daemon's 0700 runtime dir IS a daemon-owned, boot-time operation, so a bind
      failure (``OSError``) REFUSES the boot via :func:`_refuse_boot` (audited, exit
      2) exactly like a manifest resolution failure;
    * **accept + handshake + pump as a supervised task** — once bound, a background
      task awaits the peer, builds the runner over the accepted connection, binds the
      outbound sender, handshakes, and pumps. A handshake failure on the peer cannot
      refuse a boot that already completed; it routes through the runner's own crash
      teardown (the transport closes, no leak).

    Returns the :class:`CommsSocketListener` so the daemon reaps the socket + listener
    on EVERY exit path (mirrors :meth:`_CommsBootGraph.aclose`); the socket file is
    unlinked there so no stale inode lingers.
    """
    wiring = await _build_comms_adapter_wiring(
        adapter_id=adapter_id,
        settings=settings,
        audit=audit,
        gate=gate,
        supervisor=supervisor,
        graph=graph,
        boot_id=boot_id,
        environment_source=environment_source,
    )
    wire = wiring.wire

    async def _on_peer_rejected(peer_uid: int | None) -> None:
        """Write the loud ``comms.socket.peer_uid_rejected`` audit row (arch-263-001).

        Fired by the listener at the reject point. A mismatched-uid peer is an
        EXPECTED adversarial event, so the boot is NOT refused (refusing here would
        be a self-inflicted DoS — an attacker racing the socket could kill every
        boot). The row is loud; ``peer_uid``/``expected_uid`` are non-secret ints.
        If the audit WRITE itself fails, ``_emit_or_quarantine`` raises; the
        listener's ``_on_connect`` catches that and ESCALATES it onto the supervised
        ``accept()`` future (``set_exception``), so the broken security audit fails
        LOUD (an audited supervisor crash) rather than being orphaned in the
        detached ``start_unix_server`` callback (hard rule #7).
        """
        import os

        await _emit_or_quarantine(
            audit,
            fields=COMMS_SOCKET_PEER_REJECTED_FIELDS,
            schema_name="COMMS_SOCKET_PEER_REJECTED_FIELDS",
            event="comms.socket.peer_uid_rejected",
            subject={
                "adapter_id": wire.adapter_kind,
                "peer_uid": "" if peer_uid is None else str(peer_uid),
                "expected_uid": str(os.getuid()),
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            result="refused",
        )

    listener = CommsSocketListener(
        adapter_id=wire.adapter_kind,
        on_peer_rejected=_on_peer_rejected,
    )
    try:
        await listener.bind()
    except OSError as exc:
        # Binding the daemon's own socket failed (e.g. a foreign inode at the path
        # this listener refuses to unlink). A daemon-owned, boot-time failure —
        # REFUSE fail-closed (audited, exit 2), never park a half-bound adapter.
        await listener.aclose()
        await _refuse_boot(
            audit,
            _comms_adapter_bind_failure(adapter_id),
            t("daemon.boot.comms_socket_bind_failed", adapter_id=adapter_id),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is NoReturn (raises _BootRefusedError); unreachable defence.
        raise AssertionError("unreachable") from exc  # pragma: no cover

    async def _accept_and_pump() -> None:
        """Await the peer, then run the unchanged runner lifecycle over the socket.

        Runs as a supervised task so boot never blocks on an absent peer. The runner,
        handshake, and dispatch/ack path are reused UNCHANGED — only the transport is
        the accepted socket connection (ADR-0031 Decision 1).

        The ``accept()`` is raced against the supervisor's shutdown signal so a clean
        ``alfred daemon stop`` drains PROMPTLY even when no peer ever connected (the
        common post-merge state — the ``alfred chat`` client ships in a later PR).
        Without the race, a bare ``await listener.accept()`` ignores the shutdown
        event while parked on an absent peer, so the supervisor's graceful-drain
        budget (``_STOP_DRAIN_TIMEOUT_SECONDS``) elapses in full before the force-
        cancel — a 10s latency tax on every clean stop. When shutdown wins the race we
        return; the listener is still reaped by the daemon's ``finally`` (idempotent
        ``aclose``), so the teardown / reaping order is unchanged.
        """
        accept_task = asyncio.ensure_future(listener.accept())
        shutdown_wait = asyncio.ensure_future(supervisor.shutdown_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {accept_task, shutdown_wait}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            # Cancel whichever lost the race + reap it so no "Task was destroyed but it
            # is pending" / unretrieved-exception warning escapes this supervised task.
            for task in (accept_task, shutdown_wait):
                if not task.done():
                    task.cancel()
            await asyncio.gather(accept_task, shutdown_wait, return_exceptions=True)
        if shutdown_wait in done:
            # Shutdown wins the race — never build a runner / start a handshake after
            # the daemon has begun stopping (ADR-0031 accept-vs-shutdown invariant).
            # If BOTH futures resolved on the SAME tick, a peer was accepted moments
            # before shutdown fired: retrieve and CLOSE that transport so the
            # connection is discarded, never used (otherwise it leaks). The losing
            # ``accept_task`` is cancelled by the ``finally`` only when it is still
            # pending; here it is ``done``, so its result is the transport to reap.
            if accept_task in done:
                transport = accept_task.result()
                await transport.close()
            # Else: only shutdown is done; ``accept_task`` is still pending and the
            # ``finally`` already cancelled it. Either way, exit so the supervisor's
            # drain completes promptly — the listener is reaped by the daemon's
            # finally (idempotent aclose); no runner was built.
            return
        # Only accept_task completed. A genuine accept() failure must still raise out
        # of this supervised task — ``.result()`` re-raises any accept error (and is
        # safe: accept_task is in ``done``).
        transport = accept_task.result()
        runner = _build_comms_runner(
            session=wiring.session,
            transport=transport,
            adapter_kind=wire.adapter_kind,
            supervisor=supervisor,
            settings=settings,
            graph=graph,
            # The SOCKET carrier IS the gateway leg — wire the credential round-trip
            # AND the forwarded-inbound receiver (Spec B G6-7-4 / #309).
            with_credential_resolver=True,
            with_forwarded_inbound_receiver=True,
        )
        # devex HIGH-1 (Spec B G6-7-4 / #309): ONE operator-facing preview-status
        # warning at ARM-TIME (the socket listener is one-shot per boot, so this fires
        # once per boot — never per-frame / per-connection). Names the G6-7
        # inbound-bridge as PREVIEW/test-only: forwarded-inbound replay is now BOUNDED
        # by the item-4b poison ceiling (G6-7-5), but the path is NOT yet flag-day'd
        # into production (G6-7-8). Operator-routed via ``t()`` (i18n hard rule #1).
        log.warning(
            "comms.gateway.forwarded_inbound_preview",
            message=t("gateway.adapter.forwarded_inbound.preview"),
            adapter_id=wire.adapter_kind,
        )
        # Spec A G3-2 (#237): split ``run`` into ``start_and_handshake`` + ``pump``
        # so the socket-carrier runner's id-less ``send_notification`` is registered
        # with the lifecycle broadcaster ONLY AFTER its handshake completes — the
        # wire is then negotiated + live, so a lifecycle frame the broadcaster fans
        # to it is framed correctly (architect H-2/H-3). A handshake failure here
        # cannot refuse an already-completed boot, so it raises out of this
        # supervised task (the runner's ``finally`` closes the transport — no leak),
        # and the runner is never registered (no broadcast to a dead peer).
        await runner.start_and_handshake()
        # Register ONLY the socket carrier — never the daemon-spawned stdio adapters,
        # which die with the core and so neither need nor receive lifecycle frames
        # (G2-lesson).
        broadcaster.register(wire.adapter_kind, runner.send_notification)

        # Spec A G4b-2a-pre (#237 — F2/F4): construct the PER-CONNECTION durable-intake
        # ack tracker HERE (not in the per-boot ``_build_comms_adapter_wiring``), bind it
        # onto the inbound handler so each G0 ``commit_once`` advances it, and schedule
        # the per-connection ack-emit timer. The daemon's comms listener is ONE-SHOT per
        # boot (``accept()`` raises on a second call), so a single tracker per accepted
        # connection is correct today; G4b-2b's reconnect-replay MUST reset/reconstruct
        # the tracker per accepted connection (see ``InboundMessageHandler.set_ack_tracker``).
        # Both the tracker and the timer are REAPED in this task's teardown ``finally``
        # (NOT ``_CommsBootGraph.aclose`` — that reaps process-singletons; wrong lifetime).
        ack_tracker = BoundedSeqAckTracker()
        wiring.inbound_handler.set_ack_tracker(ack_tracker)  # type: ignore[attr-defined]
        # Spec B G6-7-4 (#309): bind the SAME per-connection tracker onto the
        # gateway-forwarded inbound receiver (the per-boot singleton on the graph, the
        # SAME instance injected into this runner's disposition). The receiver's
        # dispatched-edge ``observe(wire_seq)`` must advance the SAME contiguous
        # high-water this connection's ack-emit timer reports back to the gateway — a
        # fresh tracker here would split the high-water and the gateway would never see
        # the forwarded inbounds acked.
        graph.forwarded_inbound_receiver.set_ack_tracker(ack_tracker)
        ack_timer = asyncio.ensure_future(
            _emit_durable_intake_ack_loop(
                send_notification=runner.send_notification,
                cumulative_ack=ack_tracker.cumulative_ack,
                shutdown_event=supervisor.shutdown_event,
            )
        )
        try:
            await runner.pump()
        finally:
            # Reap the per-connection ack timer on EVERY pump exit (clean EOF, peer
            # crash, shutdown, or a cancel of this supervised task). Mirrors the
            # accept-race reap above: cancel -> await gather(return_exceptions=True) so
            # no "Task was destroyed but it is pending" / unretrieved-exception warning
            # escapes. A fail-loud ack-send (broken pipe) surfaces as the timer task's
            # exception, retrieved-and-discarded here — the pump's crash arm already
            # owns the connection-death routing.
            ack_timer.cancel()
            await asyncio.gather(ack_timer, return_exceptions=True)

    supervisor.register_plugin_task(_accept_and_pump())
    # O1 mirror: the socket adapter is observable in `alfred daemon start` output the
    # same as a spawned one — the socket is bound + the accept task is live (the peer
    # connects later). "live" here means "listening", not "handshaked".
    typer.echo(t("daemon.comms.adapter_listening", adapter_id=adapter_id))
    return listener


def _make_control_reject_auditor(
    audit: AuditWriter,
) -> Callable[[int | None], Awaitable[None]]:
    """Build the ``DaemonControlServer.on_peer_rejected`` callback (G6-2b-2c / ADR-0038).

    Fired by the control server at the reject point when a mismatched-uid peer dials the
    0600 control socket. The control plane is daemon-GLOBAL, so the row carries NO
    ``adapter_id`` (arch-M1) — it uses the dedicated ``DAEMON_CONTROL_PEER_REJECTED_FIELDS``
    schema. A rejection is an EXPECTED adversarial event (a same-uid race / wider-perm
    misconfig), so it does NOT refuse the boot: a loud audit row + ``result="refused"``,
    then the server keeps serving. If the audit WRITE itself fails, ``_emit_or_quarantine``
    raises; the server's ``_reject_peer`` escalates that LOUD (it does not fold into the
    resilient-connection swallow — hard rule #7).
    """

    async def _on_control_peer_rejected(peer_uid: int | None) -> None:
        import os

        await _emit_or_quarantine(
            audit,
            fields=DAEMON_CONTROL_PEER_REJECTED_FIELDS,
            schema_name="DAEMON_CONTROL_PEER_REJECTED_FIELDS",
            event="daemon.control.peer_uid_rejected",
            subject={
                "peer_uid": "" if peer_uid is None else str(peer_uid),
                "expected_uid": str(os.getuid()),
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            result="refused",
        )

    return _on_control_peer_rejected


def _comms_adapter_failure(adapter_id: str) -> CommsAdapterSpawnFailedFailure:
    """A loud boot-failure carrier for a comms-adapter spawn/handshake refusal."""
    return CommsAdapterSpawnFailedFailure(adapter_id=adapter_id)


def _comms_adapter_bind_failure(adapter_id: str) -> CommsAdapterBindFailedFailure:
    """A loud boot-failure carrier for a comms-adapter socket-bind refusal (ADR-0031)."""
    return CommsAdapterBindFailedFailure(adapter_id=adapter_id)


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


async def _emit_ready(
    audit: AuditWriter,
    *,
    boot_id: str,
    epoch: str,
    broadcaster: LifecycleBroadcaster,
) -> None:
    """Write the ``daemon.lifecycle.ready`` AUDIT row, THEN broadcast the wire frame.

    ``ready`` = HEALTH (the full security boot graph is up), not socket-bind:
    this runs only AFTER ``daemon.boot.completed`` (invariant 1). The
    fail-loud audit row is AUTHORITATIVE; G3-2 additionally broadcasts the
    id-less ``daemon.lifecycle.ready`` notification over the socket carrier
    (best-effort, spec §6) AFTER the row commits. In the normal boot the socket
    peer connects on-demand later, so this broadcast reaches ZERO senders — a
    clean DEBUG no-op (architect H-1); the gateway derives liveness from the
    handshake epoch instead (architect H-2).
    """
    await _emit_or_quarantine(
        audit,
        fields=DAEMON_LIFECYCLE_FIELDS,
        schema_name="DAEMON_LIFECYCLE_FIELDS",
        # Spec A G3-2 (#237) — architect L-1: the audit ``event`` uses the SAME
        # constant the runner frames on the wire, so the audit-event-name and the
        # wire-method-name cannot drift.
        event=DAEMON_LIFECYCLE_READY,
        subject={
            "boot_id": boot_id,
            "epoch": epoch,
            "phase": "ready",
            "reason": "",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        result="success",
    )
    # Broadcast AFTER the authoritative audit row (spec §6 — the frame is
    # best-effort; a wire-send failure is logged-not-fatal inside the broadcaster).
    await broadcaster.broadcast_ready(epoch)
    typer.echo(t("daemon.lifecycle.ready", epoch=epoch))


async def _emit_going_down(
    audit: AuditWriter,
    *,
    boot_id: str,
    epoch: str,
    broadcaster: LifecycleBroadcaster,
) -> None:
    """Write the ``daemon.lifecycle.going_down`` AUDIT row, THEN broadcast the frame.

    Records the start of the PLANNED drain. ``reason`` is the closed
    ``Literal["shutdown"]`` — a bare SIGTERM carries no intent (G3 widens the
    vocabulary with its consumer). The fail-loud audit row (exit 3 on an
    unwritable audit) is AUTHORITATIVE; G3-2 additionally broadcasts the id-less
    ``daemon.lifecycle.going_down`` notification over the socket carrier
    (best-effort, spec §6) AFTER the row. The CALLER (the boot ``finally``) nests
    this emit so that even if it raises, the existing child/socket/pidfile reap
    chain STILL runs. H1 ordering: this broadcast runs BEFORE
    ``supervisor.stop()`` (which sets ``shutdown_event`` → the pump closes the
    transport), so the frame still reaches a connected peer.
    """
    await _emit_or_quarantine(
        audit,
        fields=DAEMON_LIFECYCLE_FIELDS,
        schema_name="DAEMON_LIFECYCLE_FIELDS",
        # Spec A G3-2 (#237) — architect L-1: SAME constant as the wire method.
        event=DAEMON_LIFECYCLE_GOING_DOWN,
        subject={
            "boot_id": boot_id,
            "epoch": epoch,
            "phase": "going_down",
            "reason": LIFECYCLE_REASON_SHUTDOWN,
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        result="success",
    )
    await broadcaster.broadcast_going_down(LIFECYCLE_REASON_SHUTDOWN)
    typer.echo(t("daemon.lifecycle.going_down", reason=LIFECYCLE_REASON_SHUTDOWN))


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

    # Spec A G1 (#237): mint the per-boot, NON-secret lifecycle epoch recorded
    # in the ``daemon.lifecycle.ready`` / ``daemon.lifecycle.going_down`` audit
    # rows (and reserved for the comms handshake the gateway adds in G3).
    # Distinct from the secret CapabilityGateNonce just above — see
    # alfred.bootstrap.lifecycle_epoch. Minted HERE (alongside the T3 nonce,
    # past every early-refusal probe) rather than at the very top of boot: only
    # the ``ready``/``going_down`` rows use it and both fire only after the boot
    # graph is healthy, so an early refusal — which emits no lifecycle row —
    # never needs (and must not leak) an epoch. This mirrors the T3 nonce's
    # placement so a refusal before this point poisons no per-process slot.
    epoch = mint_boot_epoch()

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
    comms_graph: _CommsBootGraph | None = None
    # ADR-0031: socket-backed (TUI) adapters bind a unix-socket listener the daemon
    # must reap on EVERY exit path (the socket file + the asyncio server) — the
    # listener-analog of the bwrap child the comms graph reaps. Collected here so the
    # ``finally`` can ``aclose`` each one regardless of which boot step exits.
    socket_listeners: list[CommsSocketListener] = []
    # G6-2b-2c (#288 / ADR-0038): the daemon control plane — a 0600 request/response
    # socket the CLI dials for the live per-adapter status. Declared HERE, before the
    # supervisor ``try``, so the drain ``finally`` can never ``NameError`` on it and the
    # socket is reaped on EVERY exit path (test-M6 — the architect's hoist note from #299).
    control_server: DaemonControlServer | None = None
    # Spec A G3-2 (#237): the boot-LOCAL lifecycle-frame fan-out (architect M-1 — NOT
    # a field on the frozen ``_CommsBootGraph``). The socket-carrier runner registers
    # its id-less sender here post-handshake; ``_emit_ready`` / ``_emit_going_down``
    # broadcast through it after the (authoritative) audit row. Zero registrations in
    # the normal boot (the peer connects on-demand) → a clean DEBUG no-op.
    lifecycle_broadcaster = LifecycleBroadcaster()
    if settings.comms_enabled_adapters:
        # PR-S4-11c-2b: the comms-graph build now SPAWNS the live bwrap quarantined
        # child (``spawn_quarantine_child_io`` inside ``_build_comms_inbound_extractor``).
        # FAIL-CLOSED (CLAUDE.md hard rule #7): on a non-Linux / unprovisioned host
        # that spawn raises ``QuarantineChildSpawnError`` — REFUSE boot with an
        # audited failure + clear operator message rather than degrade to a fixture.
        # Placed BEFORE ``write_pidfile`` / ``supervisor.start`` so the refusal has
        # no daemon-up side effects.
        try:
            comms_graph = await _build_comms_boot_graph(
                settings=settings,
                audit=audit,
                outbound_dlp=outbound_dlp,
                t3_nonce=t3_nonce,
                policies_ref=snapshot_ref,
            )
        except QuarantineChildSpawnError:
            await _refuse_boot(
                audit,
                QuarantineChildSpawnFailedFailure(),
                t("daemon.boot.quarantine_child_spawn_failed"),
                boot_id=boot_id,
                environment_source=source,
            )
        except _ForwardedInboundRegistryMisconfiguredError as exc:
            # Spec B G6-7-4 (#309): a forwarded-inbound kind in the receiver registry
            # needs a promoter the deterministic factory withheld (a structural
            # REQUIRED_CLASSIFIERS_BY_KIND / factory drift). REFUSE BOOT fail-closed
            # (audited, exit 2) under the SAME ``comms_promoter_misconfigured`` reason the
            # spawned-adapter inbound-handler path uses — rather than defer to a
            # per-message ``PromoterRequiredError`` mid-traffic (CLAUDE.md hard rules #5 +
            # #7). The graph builder's post-spawn ``except`` already reaped the live bwrap
            # child + the ContentStore before this propagated, so nothing leaks. The
            # closed-vocab kind is the failure's ``adapter_id`` (never raw content).
            await _refuse_boot(
                audit,
                CommsPromoterMisconfiguredFailure(adapter_id=exc.adapter_kind),
                t("daemon.boot.comms_promoter_misconfigured", adapter_id=exc.adapter_kind),
                boot_id=boot_id,
                environment_source=source,
            )
            # _refuse_boot is annotated NoReturn (it raises _BootRefusedError); this
            # line is unreachable defence-in-depth for the type checker's flow, matching
            # the sibling _refuse_boot arms.
            raise AssertionError("unreachable") from exc  # pragma: no cover

    # Supervisor construction + pidfile + start live INSIDE the try so the finally
    # reaps the live quarantine child (comms_graph) on a failure of ANY of them, not
    # just start()+ — the comms-graph build already spawned the bwrap child (CR #255).
    supervisor: _SupervisorType | None = None
    pidfile_path: Path | None = None
    # Spec A G1 (#237): tracks whether the boot reached the healthy/ready point,
    # so the drain ``finally`` emits ``going_down`` ONLY for a daemon that
    # actually came up (a refusing boot also runs the finally — invariant 3).
    # Declared HERE, before the try, so the finally can never NameError on it.
    ready_emitted = False
    try:
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
                # The session's post-handshake ``check_plugin_load`` needs the FULL
                # CapabilityGate surface — pass the RAW ``real_gate``, NOT the
                # ``_SupervisorBootGate`` wrapper (which exposes only
                # ``is_backing_store_available`` for the heartbeat and would
                # ``AttributeError`` on ``check_plugin_load``, crashing the
                # handshake). The wrapper is the Supervisor's surface; the comms
                # session's surface is the gate itself.
                #
                # ADR-0031: branch on the adapter's CARRIER. A socket-backed (TUI)
                # adapter is loaded under the SAME first-party comms LOAD grant
                # (ADR-0026 — no widening); the only difference is the wire is a
                # 0600 unix socket the daemon binds + accepts, not a subprocess pipe
                # it spawns. The selector keys on the wire ``adapter_kind``, resolved
                # via the guarded helper so a broken manifest refuses the boot here
                # rather than raising unguarded out of the carrier branch.
                wire_kind = await _resolve_adapter_carrier_kind(
                    adapter_id=adapter_id,
                    audit=audit,
                    boot_id=boot_id,
                    environment_source=source,
                )
                if _is_socket_backed_adapter_kind(wire_kind):
                    socket_listeners.append(
                        await _listen_socket_comms_adapter(
                            adapter_id=adapter_id,
                            settings=settings,
                            audit=audit,
                            gate=real_gate,
                            supervisor=supervisor,
                            graph=comms_graph,
                            boot_id=boot_id,
                            environment_source=source,
                            broadcaster=lifecycle_broadcaster,
                        )
                    )
                else:
                    await _spawn_comms_adapter(
                        adapter_id=adapter_id,
                        settings=settings,
                        audit=audit,
                        gate=real_gate,
                        supervisor=supervisor,
                        graph=comms_graph,
                        boot_id=boot_id,
                        environment_source=source,
                    )

        # G6-2b-2c (#288 / ADR-0038): bind + start the daemon control plane
        # UNCONDITIONALLY — it is a DAEMON control plane, not an adapter-specific one
        # (CR T0). A zero-adapter daemon still binds the socket so ``alfred daemon
        # status`` reports ``adapters_none`` (a healthy empty set), not "unavailable".
        # When the comms graph exists, the control plane reads the LIVE observer +
        # reconciler; otherwise it answers an empty adapter map (the server tolerates
        # None/None). Bound here, after any adapters, so a control dial reaches a
        # fully-wired status surface; reaped in the drain ``finally`` (every exit path).
        # A refused different-uid dial writes a loud audit row via the reject auditor
        # (the control plane is daemon-global — no adapter_id); the auditor uses the
        # audit writer, which is available regardless of the comms graph.
        control_server = DaemonControlServer(
            observer=comms_graph.status_observer if comms_graph is not None else None,
            reconciler=(comms_graph.crash_incident_reconciler if comms_graph is not None else None),
            on_peer_rejected=_make_control_reject_auditor(audit),
        )
        await control_server.start()

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

        # Spec A G1 (#237): the boot graph is healthy — record ``ready`` + the
        # per-boot epoch (AUDIT row; ready = HEALTH, not socket-bind). Set the
        # flag LAST so a failure in ``_emit_ready`` (exit 3 on an unwritable
        # audit) does NOT then emit ``going_down`` for a boot that never
        # announced ready.
        await _emit_ready(audit, boot_id=boot_id, epoch=epoch, broadcaster=lifecycle_broadcaster)
        ready_emitted = True

        await wait_for_shutdown(supervisor)
    finally:
        # Spec A G1 (#237): record the planned drain BEFORE the teardown, but
        # ONLY if the daemon actually came up (``ready_emitted``). The finally
        # also runs on a boot REFUSAL (which already audits ``daemon.boot.failed``
        # and never reached ``ready``); emitting ``going_down`` there would record
        # a departure that never happened (invariant 3). The going_down audit row
        # is FAIL-LOUD — but it must NEVER skip the child/socket/pidfile reap below
        # (the exact #255 leak this finally exists to prevent). So it is nested in
        # its OWN try whose finally IS the existing stop+reap chain: if the
        # going_down emit raises (exit 3), the reap chain STILL runs, THEN the
        # exception propagates.
        try:
            if ready_emitted:
                await _emit_going_down(
                    audit,
                    boot_id=boot_id,
                    epoch=epoch,
                    broadcaster=lifecycle_broadcaster,
                )
        finally:
            # Drain the supervisor (skipped if it never constructed), reap the live
            # quarantine child, and remove the PID file on EVERY exit path — clean
            # shutdown, a Supervisor()/write_pidfile()/start() failure, an adapter
            # refusal, or a quarantine (exit 3) on the completion row — so a failed
            # boot leaves neither a stale pidfile nor a leaked bwrap child behind
            # (CR #255). Isolate the steps: a failing ``supervisor.stop()`` must NOT
            # skip the child reap + pidfile delete (the exact leaks this finally
            # exists to prevent; CR #255). The reap is suppressed so it never masks
            # the real exit either.
            try:
                # Spec A G3-2 (#237) H1 ORDERING INVARIANT: ``_emit_going_down``
                # (above) broadcasts the ``going_down`` wire frame BEFORE this
                # ``supervisor.stop()``. ``stop()`` sets the supervisor's
                # ``shutdown_event``, which the socket-carrier pump observes and
                # closes the transport — so a ``going_down`` broadcast AFTER
                # ``stop()`` would race a closing transport and lose the frame. Keep
                # the broadcast strictly before this call.
                if supervisor is not None:
                    await supervisor.stop()
            finally:
                if comms_graph is not None:
                    with suppress(Exception):
                        await comms_graph.aclose()
                # ADR-0031: reap every socket listener (close the asyncio server +
                # the underlying socket, unlink the socket file) on EVERY exit path
                # so no stale socket inode lingers — the socket-file analog of the
                # bwrap-child reap above. Isolated per-listener so one failing reap
                # never skips the rest or the pidfile delete (the exact leaks this
                # finally prevents).
                for listener in socket_listeners:
                    with suppress(Exception):
                        await listener.aclose()
                # G6-2b-2c (#288 / ADR-0038): reap the control server (close the asyncio
                # server + unlink the socket file) on EVERY exit path — the same
                # leak-discipline as the socket listeners above. Suppressed so a failing
                # reap never masks the real exit or skips the pidfile delete.
                if control_server is not None:
                    with suppress(Exception):
                        await control_server.aclose()
                if pidfile_path is not None:
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
    _render_live_adapter_status()


# G6-2b-2c (#288 / ADR-0038): the render-layer map from a wire ``RenderedAdapterState`` to
# its localized ``daemon.status.state.*`` catalog key (the state token is localized, not
# raw-interpolated — i18n hard rule). A render-layer concern, so it lives here.
_ADAPTER_STATE_KEYS: Mapping[str, str] = {
    "up": "daemon.status.state.up",
    "down": "daemon.status.state.down",
    "crashed": "daemon.status.state.crashed",
    "breaker_open": "daemon.status.state.breaker_open",
    "unknown": "daemon.status.state.unknown",
}


def _render_live_adapter_status() -> None:
    """Dial the daemon control plane + render the live per-adapter status (#288, ADR-0038).

    Read-only, best-effort: a daemon-absent dial is silently the not-running-already-said
    path; a protocol/auth fault degrades to "no adapter section" (the signed audit log is
    authoritative). The response is LIVE (no snapshot/staleness/boot_id).
    """
    from alfred.cli.daemon import _daemon_control_client
    from alfred.cli.daemon._daemon_control_client import (
        DaemonControlError,
        DaemonControlUnavailableError,
    )
    from alfred.cli.daemon._daemon_control_protocol import (
        STATUS_QUERY_METHOD,
        DaemonStatusResult,
    )

    try:
        # Resolve via the module (not the name bound at import) so a test that
        # monkeypatches ``_daemon_control_client.query_daemon_control`` is honoured.
        response = asyncio.run(_daemon_control_client.query_daemon_control(STATUS_QUERY_METHOD))
    except DaemonControlUnavailableError:
        # The daemon is not running / the control socket is not reachable. The pidfile
        # subset already rendered; an "unavailable" breadcrumb here would be noise on the
        # already-said not-running posture, so stay silent (the existing contract).
        return
    except DaemonControlError as exc:
        # An auth / protocol fault (NOT daemon-absent): the control plane answered but the
        # answer was unusable. Degrade LOUDLY-but-best-effort — render the "status
        # unavailable" line (distinguishable from a healthy zero-adapter daemon) + a
        # breadcrumb, never crash the read-only status command (CLAUDE.md hard rule #7:
        # the signed audit log is authoritative; this is the operator-UX surface).
        typer.echo(t("daemon.status.adapters_unavailable"))
        log.warning("daemon.status.control_query_failed", error=type(exc).__name__)
        return
    if response.error is not None or response.result is None:
        # The daemon returned a structured error (or an empty result). DISTINGUISHABLE
        # from a healthy zero-adapter daemon (which renders ``adapters_none``): render the
        # "status unavailable" line + the same breadcrumb rather than silently returning.
        typer.echo(t("daemon.status.adapters_unavailable"))
        log.warning("daemon.status.control_query_failed", error="control_response_error")
        return
    try:
        result = DaemonStatusResult.model_validate(response.result)
    except ValueError as exc:
        # A malformed ``response.result`` (a wire/version skew, a future field the
        # local models don't know) raises pydantic ``ValidationError`` (a ``ValueError``
        # subclass). UNCAUGHT it would crash the read-only ``alfred daemon status`` — so
        # degrade EXACTLY like the other control faults: render the "unavailable" line +
        # a breadcrumb, never a traceback (CR T1; CLAUDE.md hard rule #7).
        typer.echo(t("daemon.status.adapters_unavailable"))
        log.warning("daemon.status.control_query_failed", error=type(exc).__name__)
        return
    if not result.adapters:
        typer.echo(t("daemon.status.adapters_none"))
        return
    typer.echo(t("daemon.status.adapters_header"))
    for adapter_id in sorted(result.adapters):
        line = result.adapters[adapter_id]
        latest = (
            t(
                "daemon.status.adapter_latest_crash",
                seq=line.latest_crash.host_restart_seq,
                source=line.latest_crash.crash_signal_source,
            )
            if line.latest_crash is not None
            else ""
        )
        typer.echo(
            t(
                "daemon.status.adapter_line",
                adapter_id=line.adapter_id,
                state=t(_ADAPTER_STATE_KEYS[line.state]),
                incarnation=line.current_incarnation,
                crashes=line.crash_incident_count,
                latest_crash=latest,
            )
        )
