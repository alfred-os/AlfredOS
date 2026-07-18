"""Daemon comms-adapter boot graph + spawn/listen wiring (#256 PR-3).

Extracted from ``_commands.py``: the pre-Supervisor comms boot graph
(secret broker, identity-resolver bridge, quarantined extractor + bridge,
burst limiter, inbound orchestrator — :class:`_CommsBootGraph` /
:func:`_build_comms_boot_graph`), the per-adapter spawn / socket-listen wiring
(:func:`_spawn_comms_adapter` / :func:`_listen_socket_comms_adapter`), the
carrier-kind resolution, the forwarded-inbound registry, the durable-intake ack
loop, and the comms adapter-failure helpers. Built ONLY when an operator opts
comms adapters in — a default-empty boot constructs none of it.

Depends on ``_boot_audit`` (``_refuse_boot`` / ``_emit_or_quarantine`` /
``LifecycleBroadcaster``) and ``_failures`` at MODULE scope — one-directional.
The only ``_commands`` dependency is a CALL-TIME lazy import of the shared
``build_boot_session_scope`` constructor inside ``_build_comms_boot_graph``
(breaks the module-load cycle; keeps the ``_commands.build_boot_session_scope``
test seam live). ``_start_async`` (in ``_commands``) drives these via the
re-imported names.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import structlog
import typer

from alfred.audit.audit_row_schemas import (
    COMMS_SOCKET_PEER_REJECTED_FIELDS,
    DAEMON_CONTROL_PEER_REJECTED_FIELDS,
)

# The per-boot lifecycle epoch the status observer reads at OBSERVE time (the
# false-liveness defense: a forged/stale epoch is refused). Module-scope so the
# boot-wiring unit tests can monkeypatch it.
from alfred.bootstrap.lifecycle_epoch import current_boot_epoch
from alfred.cli.daemon._boot_audit import (
    LifecycleBroadcaster,
    _emit_or_quarantine,
    _refuse_boot,
)
from alfred.cli.daemon._failures import (
    CommsAdapterBindFailedFailure,
    CommsAdapterSpawnFailedFailure,
    CommsAdapterUnknownKindFailure,
    CommsPromoterMisconfiguredFailure,
)

# PR-S4-11b (#237) / #256 PR-3: module-level so the boot-wiring unit tests
# monkeypatch these two seams (``alfred.cli.daemon._comms_boot.CommsStdioTransport``
# / ``...CommsPluginRunner``) to fakes — no real subprocess spawns in unit tests.
# (The spawn/listen helpers that read these names now live in THIS module, so the
# seam is here, not ``_commands``.)
from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
)
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.i18n import t
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_socket_transport import CommsSocketListener
from alfred.plugins.comms_stdio_transport import CommsStdioTransport
from alfred.plugins.errors import ManifestError
from alfred.plugins.manifest import parse_manifest

# PR-S4-11c-2b: the comms-graph build spawns the live bwrap quarantined child;
# its loud spawn refusal is caught at the boot call site to refuse boot fail-closed
# (audited) on a non-Linux / unprovisioned host. Imported at module scope so the
# boot-wiring unit tests can monkeypatch the spawn seam (``spawn_quarantine_child_io``)
# without a real subprocess and still raise this through the boot path.

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from alfred.audit.log import AuditWriter
    from alfred.comms_mcp.adapter_credential_resolver import CoreAdapterCredentialResolver
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
    from alfred.comms_mcp.daemon_runtime import OutboundSenderLike
    from alfred.comms_mcp.forwarded_inbound_receiver import (
        GatewayForwardedInboundReceiver,
        _ForwardedCollaborators,
    )
    from alfred.comms_mcp.protocol import OutboundMessageRequest
    from alfred.comms_mcp.real_turn_adapter import RealTurnOrchestratorAdapter
    from alfred.config.settings import Settings
    from alfred.hooks.capability import CapabilityGate
    from alfred.identity.resolver import IdentityResolver
    from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
    from alfred.providers.router import ProviderRouter
    from alfred.security.dlp import OutboundDlpProtocol
    from alfred.security.quarantine_transport import QuarantineStdioTransport
    from alfred.security.tiers import CapabilityGateNonce
    from alfred.supervisor.core import Supervisor as _SupervisorType

log = structlog.get_logger(__name__)


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

    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND

    if adapter_kind not in REQUIRED_CLASSIFIERS_BY_KIND:
        raise _UnknownAdapterKindError(adapter_id, adapter_kind)

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
    — promotion is inert there, so the registered-empty path stays byte-for-byte
    unchanged (an empty required set -> ``None`` -> the existing inbound behaviour). An
    UNREGISTERED kind never reaches here — it is refused at manifest resolution (#374).

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

    if not REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]:
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


class _UnknownAdapterKindError(_CommsAdapterManifestError):
    """An enabled comms adapter declares an ``adapter_kind`` absent from the host registry.

    The manifest's ``adapter_kind`` is a non-empty string but NOT a member of the
    host's closed vocabulary
    (:data:`alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND`) — a
    typo'd or unregistered kind (#374). Refusing boot here (fail-closed, CLAUDE.md hard
    rules #5 + #7) stops the adapter being spawned with a ``None`` promoter and no host
    classifiers, which would let raw (T3) sub-payloads reach the orchestrator
    unpromoted. A subtype of :class:`_CommsAdapterManifestError` so it still unwinds
    through the manifest-error refusal path, but a dedicated narrow
    ``except _UnknownAdapterKindError`` arm (BEFORE the generic
    ``except (OSError, ManifestError, _CommsAdapterManifestError)``) at each refusal
    site routes it to an audited ``comms_adapter_unknown_kind`` refusal (exit 2) whose
    operator message names the offending kind — not the generic
    ``comms_adapter_spawn_failed`` "missing/malformed manifest" text.
    """

    def __init__(self, adapter_id: str, adapter_kind: str) -> None:
        super().__init__(adapter_id, "adapter_kind")
        self.adapter_kind = adapter_kind
        # The parent ctor built a "manifest missing 'adapter_kind'" message, but here
        # the field is PRESENT and names an unregistered kind — restate accurately.
        self.args = (
            f"comms adapter {adapter_id!r} manifest declares unknown adapter_kind "
            f"{adapter_kind!r} (not in REQUIRED_CLASSIFIERS_BY_KIND)",
        )


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
        if promoter is None and REQUIRED_CLASSIFIERS_BY_KIND[kind]:
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

    try:
        return _resolve_comms_adapter_wire_spec(adapter_id).adapter_kind
    except _UnknownAdapterKindError as exc:
        # #374: name the offending field + value so the operator sees a typo, not the
        # misleading generic "missing or malformed manifest" spawn-failed text. MUST
        # precede the generic arm below — this IS a _CommsAdapterManifestError subtype.
        await _refuse_boot(
            audit,
            _comms_adapter_unknown_kind_failure(adapter_id, exc.adapter_kind),
            t(
                "daemon.boot.comms_adapter_unknown_kind",
                adapter_id=adapter_id,
                adapter_kind=exc.adapter_kind,
            ),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is NoReturn (raises _BootRefusedError); unreachable defence.
        raise AssertionError("unreachable") from exc  # pragma: no cover
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

    ``resolver`` (#338 PR2 cutover): the RAW :class:`IdentityResolver` (arch-001)
    — NOT just ``resolver_bridge``, the sync wrapper. Exposed alongside the
    bridge because ``build_orchestrator`` (below) REUSES this exact instance so
    the process-global ``install_identity_factories_for_settings`` is not
    re-fired and the promoted ``version_counter`` stays the single coherent
    instance across the resolver + the orchestrator's budget guard.
    """

    secret_broker: object
    resolver_bridge: object
    resolver: IdentityResolver
    extractor_bridge: object
    burst_limiter: object
    # #338 PR2 cutover: the REAL privileged-turn adapter (was the deterministic-
    # echo CommsInboundOrchestratorAdapter). Satisfies the SAME _OrchestratorLike
    # Protocol, so every Spec A/B idempotency/replay caller below (the forwarded-
    # inbound registry, the per-adapter InboundMessageHandler) is untouched.
    inbound_orchestrator: RealTurnOrchestratorAdapter
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
    real_gate: CapabilityGate,
    router_override: ProviderRouter | None = None,
) -> _CommsBootGraph:
    """Construct the pre-Supervisor comms graph (PR-S4-11b construction step 1-5).

    Built ONLY when at least one adapter is enabled. Assembles the secret broker,
    the sync identity-resolver bridge, the REAL quarantined extractor over a LIVE
    bwrap-spawned quarantined child (PR-S4-11c-2b go-live flip) + its body-shaped
    bridge, the burst limiter, and the REAL-TURN inbound orchestrator adapter
    (#338 PR2 cutover) whose outbound sender is bound per-adapter after the
    runner exists.

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

    ``real_gate`` (#338 PR2, REQUIRED): the RAW seeded :class:`CapabilityGate` the
    :class:`RealTurnOrchestratorAdapter` uses for its per-turn
    ``t3.downgrade_to_orchestrator`` clearance check — the SAME instance the
    daemon boot path builds + asserts live BEFORE this graph is constructed
    (never the ``_SupervisorBootGate`` wrapper, which exposes only the
    backing-store-availability surface).

    ``router_override`` (#338 PR2, test seam, default ``None``): production
    ALWAYS builds the real, egress-proxied ``ProviderRouter`` (never leave this
    non-``None`` outside a test) — the param exists so a boot-graph unit test can
    inject an offline double instead of requiring a live gateway proxy + a real
    provider secret.
    """
    from typing import cast

    # Lazy import (breaks the _commands <-> _comms_boot module-load cycle; #256 PR-3):
    # build_boot_session_scope is a shared real-infra constructor that STAYS in
    # _commands. Imported at CALL time so a conftest patch of
    # ``_commands.build_boot_session_scope`` is still honoured (the test seam).
    from alfred.cli._bootstrap import (
        _episodic_factory,
        build_broker,
        build_orchestrator,
        build_router,
        build_working_memory_pool,
        install_identity_factories_for_settings,
    )
    from alfred.cli.daemon._commands import build_boot_session_scope
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge, SyncIdentityResolverBridge
    from alfred.comms_mcp.daemon_runtime import _build_comms_inbound_extractor
    from alfred.comms_mcp.real_turn_adapter import RealTurnOrchestratorAdapter
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
    # The ContentStore's Redis client is live BEFORE the quarantined child spawns;
    # if that spawn refuses (``QuarantineChildSpawnError`` on a non-Linux /
    # unprovisioned host) the graph never returns, so ``_start_async``'s exit-path
    # teardown never sees the store and the Redis client leaks. Reap it here on a
    # pre-child-live failure (the post-spawn assembly is reaped by the ``except``
    # below, which ALSO reaps the now-live transport). Suppressed so the store-close
    # never masks the original spawn refusal (CLAUDE.md #7).
    try:
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
            environment=settings.environment,
        )
    except Exception:
        with suppress(Exception):
            await content_store.close()
        raise
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
        # #338 PR2 cutover: the REAL privileged-turn adapter. Assemble the
        # Orchestrator by REUSING the graph's already-built broker + resolver
        # (FOLD-1 — never build_orchestrator(settings) bare, which double-builds
        # the broker + re-fires the process-global install_identity_factories) plus
        # a freshly-built PROXIED router. Egress tools are DEFERRED (#338 scope):
        # no tool_registry is passed, so the Act loop runs one completion and the
        # (registry, gate, outbound_dlp) trio guard at core.py:973 is never reached.
        # router_override is the OFFLINE test seam; production builds the real
        # proxied router (build_router -> EgressClient.from_settings raises
        # IOPlaneUnavailableError when ALFRED_EGRESS_PROXY_URL is unset; the
        # deepseek key raises UnknownSecretError — both routed to an audited
        # refuse-boot arm in _commands.py, FOLD-2).
        router = (
            router_override
            if router_override is not None
            else build_router(secret_broker, settings)
        )
        orchestrator = build_orchestrator(
            settings,
            # FOLD-R7: broker passed per build_orchestrator's docstring to avoid a
            # throwaway build_broker; it is UNUSED here because `router` is injected
            # (broker only feeds build_router, which is skipped). No redaction risk:
            # the log redactor is process-global (configure_logging). The ADR-0048
            # one-broker-instance invariant binds the FUTURE build_tool_registry
            # broker (tools-on), not this call.
            broker=secret_broker,
            router=router,
            resolver=resolver,
            session_scope=build_boot_session_scope(settings),
            # extraction runs at the adapter->bridge boundary, not the orchestrator funnel
            quarantined_extractor=None,
        )
        working_memory_pool = build_working_memory_pool(
            settings,
            episodic_factory=_episodic_factory,
            session_scope=build_boot_session_scope(settings),
        )
        inbound_orchestrator = RealTurnOrchestratorAdapter(
            orchestrator=orchestrator,
            working_memory_pool=working_memory_pool,
            # RAW RealGate for the t3.downgrade_to_orchestrator check (seeded grant reused)
            gate=real_gate,
            audit_writer=audit,
            outbound_dlp=cast("OutboundDlp", outbound_dlp),
            extractor_bridge=extractor_bridge,
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
            resolver=resolver,
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
        # (CR #255). Each reap is ``suppress``-ed so a close failure never REPLACES
        # the original assembly exception (e.g. _ForwardedInboundRegistryMisconfigured
        # -> the audited comms_promoter_misconfigured refusal) — a masked refusal
        # cause would be a fail-loud violation (CLAUDE.md #7). The original ``raise``
        # below always wins.
        with suppress(Exception):
            await quarantine_transport.close()
        with suppress(Exception):
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
    from alfred.plugins.session import AlfredPluginSession

    try:
        wire = _resolve_comms_adapter_wire_spec(adapter_id)
    except _UnknownAdapterKindError as exc:
        # #374: name the offending field + value (defence-in-depth mirror of the carrier
        # refusal — the boot loop resolves the carrier kind first, so a real boot refuses
        # THERE; this copy fires only when the wiring is driven directly). MUST precede
        # the generic arm — this IS a _CommsAdapterManifestError subtype.
        await _refuse_boot(
            audit,
            _comms_adapter_unknown_kind_failure(adapter_id, exc.adapter_kind),
            t(
                "daemon.boot.comms_adapter_unknown_kind",
                adapter_id=adapter_id,
                adapter_kind=exc.adapter_kind,
            ),
            boot_id=boot_id,
            environment_source=environment_source,
        )
        # _refuse_boot is NoReturn (raises _BootRefusedError); unreachable defence.
        raise AssertionError("unreachable") from exc  # pragma: no cover
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
    # with NO required classifiers) is correct and is NOT refused. Post-#374
    # ``wire.adapter_kind`` is chokepoint-validated (``_resolve_comms_adapter_wire_spec``
    # already refused an unregistered kind), so this reads the table by subscript, not
    # ``.get(..., frozenset())`` — an unknown kind can never silently pass here.
    from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND

    if sub_payload_promoter is None and REQUIRED_CLASSIFIERS_BY_KIND[wire.adapter_kind]:
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
        # ``suppress`` the listener reap so an aclose failure never REPLACES the
        # audited bind refusal below (CLAUDE.md #7 — the refusal must surface).
        with suppress(Exception):
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


def _comms_adapter_unknown_kind_failure(
    adapter_id: str, adapter_kind: str
) -> CommsAdapterUnknownKindFailure:
    """A loud boot-failure carrier for a typo'd/unregistered ``adapter_kind`` (#374).

    The durable ``daemon.boot.failed`` audit row carries the DISTINCT
    ``failure_reason`` (``comms_adapter_unknown_kind``) — ``_refuse_boot`` projects a
    fixed subject shape (``failure_reason`` only, not per-failure fields), the same as
    every other boot failure. The exact offending ``adapter_kind`` this carrier holds
    is surfaced to the operator via the refusal message and to the
    ``daemon.boot.failed`` hookpoint payload (``_invoke_boot_failed(failure)``); it is
    not persisted in the audit-row subject.
    """
    return CommsAdapterUnknownKindFailure(adapter_id=adapter_id, adapter_kind=adapter_kind)
