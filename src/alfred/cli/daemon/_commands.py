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
    DaemonBootFailure,
    EnvironmentNotSetFailure,
    UnsandboxedEnvInProductionFailure,
)
from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
    load_environment,
)
from alfred.i18n import t
from alfred.supervisor.core import Supervisor

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.config.settings import Settings

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


async def build_boot_gate(
    settings: Settings,
) -> object:  # pragma: no cover - real-infra glue; unit tests monkeypatch
    """Construct the RealGate-wrapping supervisor gate.

    Production wires a real Postgres-backed :class:`RealGate` via the
    bootstrap factory; this PR is the first to construct the Supervisor in
    production, so the gate is wrapped in :class:`_SupervisorBootGate` to
    add the sync backing-store-availability surface the heartbeat polls.
    """
    from alfred.bootstrap.gate_factory import build_real_gate
    from alfred.security.capability_gate.backend import PostgresBackend

    backend = PostgresBackend(dsn=settings.database_url.unicode_string())

    async def _noop_audit_sink(**_kw: object) -> None:
        return None

    real_gate = await build_real_gate(
        backend=backend,
        audit_sink=_noop_audit_sink,
        start_heartbeat=False,
    )
    return _SupervisorBootGate(real_gate)


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

    # Probe (b): snapshot-ref init (FILE-ONLY; core-eng-002).
    failure_b, snapshot_ref = await probe_snapshot_ref_init(environment=settings.environment)
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

    # All probes passed. Construct the Supervisor + emit completion.
    gate = await build_boot_gate(settings)
    started_at = datetime.now(UTC)
    state_git_head_sha = read_state_git_head_sha(settings.state_git_path)
    policies_snapshot_hash = snapshot_ref.snapshot_hash()

    supervisor = Supervisor(
        session_scope=session_scope,
        gate=gate,
        audit=audit,
        state_git_path=settings.state_git_path,
        proposal_dispatch_interval_s=settings.proposal_dispatch_interval_s,
        policies_ref=snapshot_ref,
        operator_session_resolver=_StubOperatorResolver(),
    )

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

    pidfile_path = default_pidfile_path()
    write_pidfile(
        pidfile_path,
        pid=_current_pid(),
        boot_id=boot_id,
        started_at=started_at.isoformat(),
    )
    typer.echo(t("daemon.boot.started", boot_id=boot_id))

    await supervisor.start()
    try:
        await wait_for_shutdown(supervisor)
    finally:
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
