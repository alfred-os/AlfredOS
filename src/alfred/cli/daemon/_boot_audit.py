"""Daemon boot audit + lifecycle-emit — the audited refusal mechanism (#256 PR-1).

Extracted from ``_commands.py`` (the dependency leaf of the boot module split):
the ``daemon.boot.failed`` refusal path (``_refuse_boot`` — invoke hookpoint,
emit the failed row, exit 2), the audit-append-or-quarantine primitive
(``_emit_or_quarantine`` — a failed audit write is loud, exit 3; sec-003), the
``daemon.lifecycle.ready`` / ``going_down`` emits, and the boot-local
``LifecycleBroadcaster`` fan-out of lifecycle wire frames to the socket carrier.

Fail-closed: every ``append_schema`` on a refusal/completion path quarantines
with exit 3 on an audit-write failure; ``_refuse_boot`` is ``NoReturn`` so no
refusal can fall through into ``Supervisor`` construction.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NoReturn

import structlog
import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.audit_row_schemas import (
    DAEMON_BOOT_FAILED_FIELDS,
    DAEMON_LIFECYCLE_FIELDS,
)
from alfred.cli.daemon._failures import DaemonBootFailure
from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LIFECYCLE_REASON_SHUTDOWN,
)
from alfred.i18n import t
from alfred.plugins.comms_wire import CommsProtocolError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from alfred.audit.log import AuditWriter

log = structlog.get_logger(__name__)


# Exit codes (operator-facing contract; documented in the runbook PR-S4-11).
_EXIT_REFUSED: Final[int] = 2
_EXIT_AUDIT_UNWRITABLE: Final[int] = 3


class _BootRefusedError(Exception):
    """Internal control-flow signal: a refusal already emitted + must exit.

    Carries the exit code so the synchronous Typer command can translate it
    into ``typer.Exit`` after ``asyncio.run`` unwinds.
    """

    def __init__(self, code: int) -> None:
        super().__init__(f"boot_refused:{code}")
        self.code = code


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
