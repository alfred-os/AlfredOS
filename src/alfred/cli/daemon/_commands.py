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

The audited-refusal + lifecycle-emit MECHANISM this sequence invokes
(``_refuse_boot`` / ``_emit_or_quarantine`` / ``_emit_ready`` /
``_emit_going_down`` / ``LifecycleBroadcaster``) lives in
:mod:`alfred.cli.daemon._boot_audit` (#256 PR-1); this module orchestrates it.
"""

from __future__ import annotations

import asyncio
import subprocess
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import structlog
import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
    DAEMON_BOOT_FIELDS,
)

# PR-S4-11c-2a0 (#237): mint + register the per-process authorised T3 nonce at
# boot. Imported at module scope (not lazily) so the boot-wiring unit tests can
# monkeypatch the ``alfred.cli.daemon._commands.create_and_register_t3_nonce``
# seam to count / fault the call without a real subprocess.
from alfred.bootstrap.lifecycle_epoch import mint_boot_epoch
from alfred.bootstrap.nonce_factory import (
    T3NonceAlreadyRegisteredError,
    create_and_register_t3_nonce,
)
from alfred.cli.daemon._audit_fallback import build_boot_audit_writer
from alfred.cli.daemon._boot_audit import (
    LifecycleBroadcaster,
    _BootRefusedError,
    _emit_going_down,
    _emit_or_quarantine,
    _emit_ready,
    _invoke_boot_completed,
    _refuse_boot,
)
from alfred.cli.daemon._comms_boot import (
    _build_comms_boot_graph,
    _CommsBootGraph,
    _ForwardedInboundRegistryMisconfiguredError,
    _is_socket_backed_adapter_kind,
    _listen_socket_comms_adapter,
    _make_control_reject_auditor,
    _resolve_adapter_carrier_kind,
    _spawn_comms_adapter,
)
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
    CommsMultiAdapterUnsupportedFailure,
    CommsPromoterMisconfiguredFailure,
    DaemonBootFailure,
    EgressPlaneUnavailableFailure,
    EnvironmentNotSetFailure,
    OperatorNotSeededFailure,
    QuarantineChildSpawnFailedFailure,
    QuarantineGrantMissingFailure,
    RouterSecretMissingFailure,
    SecretsConfigFailedFailure,
    T3NonceRegistrationFailedFailure,
    UnsandboxedEnvInProductionFailure,
)
from alfred.cli.daemon._gate_boot import (
    _first_missing_first_party_grant,
    _first_party_grant_live,
    _install_quarantine_boot_registry,
    _SupervisorBootGate,
    build_boot_handshake,
    build_boot_real_gate_for_daemon,
)
from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
    load_environment,
)

# #338 PR2 (FOLD-2): ``_build_comms_boot_graph`` is the first boot caller of
# ``build_router``, which builds the egress-proxied ``ProviderRouter`` the
# ``RealTurnOrchestratorAdapter`` needs. ``EgressClient.from_settings`` raises this
# fail-closed when ``ALFRED_EGRESS_PROXY_URL`` is unset/blank (the connectivity-free
# core has no direct-egress fallback) — caught at the call site below so the daemon
# refuses boot audited (exit 2) rather than crash uncaught (#368 anti-pattern).
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.hooks.errors import HookError
from alfred.i18n import t

# #338 PR2 (Task-3-review must-carry, NOT one of the plan's originally-enumerated
# FOLD-2 pair): ``_build_comms_boot_graph`` now assembles a REAL ``Orchestrator``,
# whose constructor synchronously calls ``identity_resolver.get_operator()``
# (``core.py:308``) and raises this when zero or more than one operator user
# exists (``identity/resolver.py:191/197``). Caught at the call site below so a
# comms-enabled boot with no (or a corrupt multi-operator) seeded identity refuses
# audited (exit 2) instead of crashing uncaught (#368 anti-pattern).
from alfred.identity.errors import IdentityResolutionError
from alfred.plugins.errors import ManifestError

# PR-S4-11c-2b: the comms-graph build spawns the live bwrap quarantined child;
# its loud spawn refusal is caught at the boot call site to refuse boot fail-closed
# (audited) on a non-Linux / unprovisioned host. Imported at module scope so the
# boot-wiring unit tests can monkeypatch the spawn seam (``spawn_quarantine_child_io``)
# without a real subprocess and still raise this through the boot path.
from alfred.security.quarantine_child_io import QuarantineChildSpawnError

# #338 PR2 (FOLD-2, defense-in-depth): ``UnknownSecretError`` is a ``KeyError``
# subclass raised by ``build_router``'s ``secret_broker.get("deepseek_api_key")``.
# Unreachable via a real boot today (the required-field ``SettingsError`` guard
# trips first — FOLD-R15), kept for the same reason ``SecretBrokerConfigError``'s
# sibling arm below is kept. No broad ``KeyError``/``AlfredError`` catch precedes
# either arm in this try, so ordering among these three new arms is unconstrained.
from alfred.security.secrets import SecretBrokerConfigError, UnknownSecretError
from alfred.supervisor.core import Supervisor

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.config.settings import Settings

    # sec-001 (#256 PR-3): annotation-only here (``socket_listeners:
    # list[CommsSocketListener]`` in _start_async). Kept under TYPE_CHECKING so the
    # runtime name lives ONLY in _comms_boot — a stray ``_commands.CommsSocketListener``
    # monkeypatch then AttributeErrors LOUD (like the other repointed seams) instead
    # of silently no-op'ing.
    from alfred.plugins.comms_socket_transport import CommsSocketListener
    from alfred.security.dlp import OutboundDlpProtocol
    from alfred.supervisor.core import Supervisor as _SupervisorType

log = structlog.get_logger(__name__)


# Sentinel for the SHA of an empty / absent state.git repo.
_STATE_GIT_HEAD_UNKNOWN: Final[str] = "unknown"

# A no-op operator id for the PR-S4-1 stub resolver. PR-S4-5 ships the real
# session-file + Postgres binding.
_STUB_OPERATOR_ID: Final[str] = "_daemon_boot"


class _StubOperatorResolver:
    """No-op operator resolver for PR-S4-1 (real one lands in PR-S4-5)."""

    async def resolve(self) -> str:
        return _STUB_OPERATOR_ID


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
    except SettingsError as exc:
        # Defensive: the env was already validated, but a Settings() failure here
        # must still surface as the audited environment_not_set refusal, never a raw
        # traceback (covered by test_settings_error_after_valid_env_refuses).
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
        # devex follow-up (#339 PR3 review): name the ACTUAL failing grant in
        # the log line so an operator debugging (say) a missing
        # `tool.dispatch` grant isn't misled by a DLP-subscriber-only framed
        # message. This is purely diagnostic — it does not touch the audited
        # `failure_reason` token (stays `quarantine_grant_missing`, an
        # existing test-pinned contract) or the closed
        # `DAEMON_BOOT_FAILED_FIELDS` audit schema.
        missing_grant = _first_missing_first_party_grant(real_gate)
        log.error(
            "daemon.boot.quarantine_grant_missing",
            missing_grant_plugin_id=missing_grant.plugin_id if missing_grant else None,
            missing_grant_hookpoint=missing_grant.hookpoint if missing_grant else None,
        )
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
    #
    # #368: SecretBroker.from_settings (inside _build_boot_outbound_dlp) is
    # fail-closed at the trust boundary — a bad secrets file (insecure perms,
    # a directory where a file is expected, a missing required file, or a file
    # inside a git worktree) raises SecretBrokerConfigError. Unguarded, that
    # crashes uncaught out of _start_async as a raw traceback + exit 1, SKIPPING
    # the audited refusal every other boot-infra failure uses. Route it through
    # the SAME audited path (exit 2 + a daemon.boot.failed row) under a DEDICATED
    # secrets_config_failed reason (#370 item 2) so the durable audit row + the
    # daemon.boot.failed hookpoint tell a secrets misconfig apart from a
    # capability-gate seed/install fault, and so a misconfigured secrets file
    # surfaces like a broken seed/install, not a stack trace. The OPERATOR-facing
    # refusal message is the exception's own str(exc) — already t()-rendered and
    # carrying
    # the concrete remedy (chmod 600 / move out of the git repo / create the
    # file) — so the operator is told it is a SECRETS problem, not sent hunting
    # the capability-gate/hook-registry rows the generic boot_infra message names
    # (devex dx-001). The subtype messages carry only path/mode/parent, never a
    # secret value (they raise before the file is read — verified in secrets.py).
    # Fail-closed is preserved — only the surfacing changes. _refuse_boot is
    # NoReturn (raises _BootRefusedError → exit 2), so control never falls through
    # to a use of an unbound outbound_dlp.
    try:
        outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
    except SecretBrokerConfigError as exc:
        await _refuse_boot(
            audit,
            SecretsConfigFailedFailure(),
            str(exc),
            boot_id=boot_id,
            environment_source=source,
        )

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
                # #338 PR2: the RAW real_gate (NOT the _SupervisorBootGate wrapper) —
                # the RealTurnOrchestratorAdapter needs the full CapabilityGate surface
                # for its per-turn t3.downgrade_to_orchestrator clearance check.
                real_gate=real_gate,
            )
        except SecretBrokerConfigError as exc:
            # #368 defense-in-depth: _build_comms_boot_graph builds its own
            # SecretBroker (via build_broker, BEFORE the bwrap spawn in
            # _build_comms_inbound_extractor, so nothing is live to reap). The
            # _build_boot_outbound_dlp guard above already refuses boot on a bad
            # secrets file (identical construction, runs first), so this arm is
            # unreachable TODAY — but guarding here makes the refusal LOCAL rather
            # than dependent on that positional ordering (CLAUDE.md hard rule #7).
            # Same dedicated secrets_config_failed reason as the outbound-dlp guard
            # (a misconfigured secrets file is a secrets problem whichever build
            # catches it) and the same str(exc) operator message (#370 item 2).
            await _refuse_boot(
                audit,
                SecretsConfigFailedFailure(),
                str(exc),
                boot_id=boot_id,
                environment_source=source,
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
        except IOPlaneUnavailableError:
            # FOLD-2 (#338 PR2): _build_comms_boot_graph's Orchestrator assembly calls
            # build_router, which calls EgressClient.from_settings FIRST — raising this
            # fail-closed when ALFRED_EGRESS_PROXY_URL is unset/blank. Unlike the secrets
            # arms above, this IS reachable via a real boot: egress_proxy_url is an
            # OPTIONAL Settings field, so no earlier required-field guard trips first.
            # The connectivity-free core (Spec C / ADR-0042) has no direct-egress
            # fallback, so REFUSE boot fail-closed (audited, exit 2) rather than crash
            # uncaught (CLAUDE.md hard rule #7 — the #368 anti-pattern).
            await _refuse_boot(
                audit,
                EgressPlaneUnavailableFailure(),
                t("daemon.boot.egress_plane_unavailable"),
                boot_id=boot_id,
                environment_source=source,
            )
        except UnknownSecretError:
            # FOLD-2 (#338 PR2, defense-in-depth): the same build_router call resolves
            # the DeepSeek provider key via secret_broker.get("deepseek_api_key"), which
            # raises this (a KeyError subclass) when the key is unprovisioned.
            # UNREACHABLE via a real _start_async boot TODAY (FOLD-R15): deepseek_api_key
            # is a REQUIRED Settings field, so a missing/placeholder key already trips
            # the earlier required-field SettingsError guard (audited as
            # EnvironmentNotSetFailure) before _build_comms_boot_graph ever runs. Kept
            # for the same reason the (also unreachable-today) SecretBrokerConfigError
            # arm above is kept — a future decoupling of the Settings field from the
            # broker lookup must still refuse fail-closed rather than crash uncaught
            # (CLAUDE.md hard rule #7). The operator message names only the missing KEY
            # CLASS, never a secret value.
            await _refuse_boot(
                audit,
                RouterSecretMissingFailure(),
                t("daemon.boot.router_secret_missing"),
                boot_id=boot_id,
                environment_source=source,
            )
        except IdentityResolutionError:
            # #338 PR2 (Task-3-review must-carry): _build_comms_boot_graph now
            # assembles a REAL Orchestrator, whose constructor synchronously calls
            # identity_resolver.get_operator() (core.py:308) — raising this when zero
            # or more than one operator user exists (identity/resolver.py:191/197).
            # REACHABLE via a real boot (a fresh install with no seeded operator, or a
            # corrupt multi-operator state). Before this arm it propagated as an
            # UNCAUGHT crash out of _start_async (exit 1, no audit row) — the #368
            # anti-pattern. REFUSE boot fail-closed (audited, exit 2) instead (CLAUDE.md
            # hard rule #7). The SAME reason covers both the zero- and
            # multiple-operator cases — the resolver's own message differs, but this
            # arm does not (and the audit row stays content-free either way).
            await _refuse_boot(
                audit,
                OperatorNotSeededFailure(),
                t("daemon.boot.operator_not_seeded"),
                boot_id=boot_id,
                environment_source=source,
            )

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
                # ``# pragma: no branch``: the ``pidfile_path is None`` arm is a
                # #255 leak-guard reached ONLY while an exception unwinds through this
                # finally (Supervisor construction raised BEFORE ``write_pidfile`` — see
                # test_daemon_boot_reap_finally). coverage.py can't record a branch
                # whose not-taken side leaves the block via a propagating exception
                # rather than clean fall-through, so the arc is unrecordable. The taken
                # (delete) side is covered by every clean-shutdown test. This is a
                # cleanup guard, never a fail-closed refuse-decision arm (sec-003).
                if pidfile_path is not None:  # pragma: no branch
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
