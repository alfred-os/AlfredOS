"""alfred supervisor CLI — status + circuit-breaker reset.

T1-tier commands per spec §3.6 and §10.8:

* ``alfred supervisor status`` — read-only; lists all supervised components
  and their circuit-breaker states.
* ``alfred supervisor reset <component> --confirm`` — calls
  :meth:`Supervisor.reset_breaker`; requires ``--confirm`` gate.

All operator-facing output routes through :func:`alfred.i18n.t` per CLAUDE.md
i18n rule #1. The audit row for ``reset`` carries ``operator_user_id`` per
``SUPERVISOR_BREAKER_RESET_FIELDS`` (see
:mod:`alfred.audit.audit_row_schemas` shipped in PR-S3-0a).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Annotated

import structlog
import typer

from alfred.i18n import t

supervisor_app = typer.Typer(help=t("cli.supervisor.help"), no_args_is_help=True)
_log = structlog.get_logger(__name__)


def _emit_breaker_reset_attempt_audit(*, component_id: str) -> None:
    """Emit a fail-loud audit-row stand-in BEFORE calling ``reset_breaker``.

    sec-pr-s3-6-04: a crash inside :meth:`Supervisor.reset_breaker` (e.g.
    Postgres connection lost mid-transaction) previously left no
    forensic trail at all -- the only audit row the path emitted lived
    inside the supervisor itself, post-write. By logging the attempt
    BEFORE we cross into the supervisor we guarantee an audit-graph
    breadcrumb pointing at the operator intent regardless of whether
    the reset actually lands.

    Fields mirror :data:`SUPERVISOR_BREAKER_RESET_FIELDS` so the eventual
    PR-S3-7 wiring (an ``AuditWriter`` instance reachable from the sync
    CLI bootstrap) can simply replace the structlog call with
    ``await audit_writer.append_schema(...)`` without restructuring the
    emit site. ``operator_user_id`` is intentionally ``None`` for now --
    devex-007 / spec §10.8 defer the attribution wiring to PR-S3-7; a
    follow-up issue tracks the gap, but this row going out unsigned is
    strictly better than no row at all (CLAUDE.md hard rule #7).

    The structlog redactor in :mod:`alfred.cli._bootstrap` runs in front
    of every output processor so any accidental secret-shaped string in
    ``component_id`` is masked before render.

    perf-001: :mod:`alfred.audit.audit_row_schemas` is imported lazily
    inside the function body because the parent package's ``__init__``
    eagerly loads :class:`alfred.memory.models.AuditEntry`, pulling the
    SQLAlchemy ORM (~140 ms) into every ``alfred --help`` invocation
    that imports this sub-app. Deferring the constant lookup to the
    actual emit path keeps the typer surface light.
    """
    from alfred.audit.audit_row_schemas import SUPERVISOR_BREAKER_RESET_FIELDS

    # ``correlation_id`` ties the attempt row to the eventual
    # supervisor-side reset row (when PR-S3-7 wires the live emit) so
    # the audit-graph forensic traversal can join the two halves.
    correlation_id = str(uuid.uuid4())
    # CR-149 sec-pr-s3-6-cr-149: the attempt row is emitted BEFORE
    # ``reset_breaker`` runs, so we do not yet know the breaker's
    # actual state. The previous shape unconditionally wrote
    # ``old_state="OPEN"`` and ``new_state="CLOSED"`` into the
    # forensic trail, which is a false transition the moment the
    # component does not exist or the reset later fails. Spec §10.8
    # requires auditable operator actions, not invented state.
    # ``None`` (rendered as JSON ``null`` by the structlog renderer)
    # is the explicit "not yet known" sentinel; PR-S3-7 will read the
    # live breaker via ``Supervisor.get_breaker_state`` and emit a
    # second, terminal row carrying the real transition after the
    # reset succeeds. Until then the attempt row stays honest: we
    # observed an operator-initiated reset attempt against
    # ``component_id``; the transition is unknown.
    _log.info(
        "supervisor.breaker.reset.attempted",
        schema_name="SUPERVISOR_BREAKER_RESET_FIELDS",
        component_id=component_id,
        old_state=None,
        new_state=None,
        trip_count=None,
        operator_user_id=None,
        correlation_id=correlation_id,
        # ``schema_fields`` round-trips the declared field set so a
        # log-grepping audit collector can validate the row at parse
        # time and surface schema drift if ``SUPERVISOR_BREAKER_RESET_FIELDS``
        # gains a key without this emitter being updated.
        schema_fields=sorted(SUPERVISOR_BREAKER_RESET_FIELDS),
    )


def _get_supervisor() -> object:
    """Return the live :class:`Supervisor` instance.

    Imported lazily so the CLI bootstrap does not construct a supervisor
    for read-only commands like ``alfred status``. Tests patch this
    function with an :class:`unittest.mock.AsyncMock`.

    Depends on PR-S3-3b: ``alfred.supervisor.core.Supervisor.get_instance``.
    Until that singleton accessor ships, this raises :class:`RuntimeError`
    so :func:`supervisor_status` can surface the friendly "supervisor not
    running" hint instead of a raw traceback.
    """
    # Deferred import — Supervisor depends on Postgres + async bootstrap.
    # The CLI is synchronous (Typer); we run the async call via asyncio.run.
    from alfred.supervisor.core import Supervisor

    get_instance = getattr(Supervisor, "get_instance", None)
    if get_instance is None:
        # PR-S3-3b ships the singleton accessor; until then surface the
        # not-running path rather than constructing a half-wired supervisor.
        msg = "Supervisor.get_instance not yet available; wired in PR-S3-3b."
        raise RuntimeError(msg)
    return get_instance()


def _list_breaker_states() -> list[dict[str, object]]:
    """Query the ``circuit_breakers`` Postgres table for all component states.

    Depends on PR-S3-3b migration 0010 + the SQLAlchemy model wiring (the
    Postgres projection lands in a follow-up PR). Until then this MUST
    fail closed: returning ``[]`` collapsed "the read-path is not yet
    implemented" with "the supervisor has zero registered components",
    so an operator running ``alfred supervisor status`` saw the empty
    hint and could not tell which condition held. CR-149 round-4 +
    CLAUDE.md hard rule #7 forbid the silent-failure shape on T1
    operator surfaces.

    Tests patch this with fixture rows OR with a return value to exercise
    the populated table path; production callers see the typed
    ``NotImplementedError`` and the supervisor_status handler converts it
    into a localised "status unavailable" message.
    """
    msg = "breaker status unavailable: read path not implemented"
    raise NotImplementedError(msg)


@supervisor_app.command("status")
def supervisor_status() -> None:
    """List all supervised components and their circuit-breaker states.

    Spec §11.3: ``alfred supervisor status`` is a read-only Postgres read.
    Discovery path: ``quarantine_unavailable`` error →
    ``alfred supervisor status`` →
    ``alfred supervisor reset <component> --confirm``.
    """
    # devex-013: disambiguate empty state -- supervisor not running vs
    # genuinely empty. The probe is the supervisor lookup itself; failing
    # there means the bootstrap could not reach a live supervisor.
    #
    # err-001 / cross-cutting R4: narrow the except clause to the three
    # shapes a "supervisor not reachable" failure actually produces:
    #
    # * ``RuntimeError`` -- :func:`_get_supervisor` raises this until
    #   PR-S3-3b ships ``Supervisor.get_instance``; the test
    #   ``test_status_no_supervisor_running_exits_nonzero`` pins it.
    # * ``ConnectionError`` -- Postgres / supervisor IPC unreachable.
    # * ``asyncio.TimeoutError`` -- supervisor lookup hung past its
    #   deadline.
    #
    # Anything else (``AttributeError``, ``TypeError``, ``KeyError``,
    # ...) is a programmer bug and MUST propagate so the operator sees a
    # full traceback in the structlog stream and the bug surfaces loud.
    # CR-149 round-5 (sec-pr-s3-6-cr-149-r5): split the supervisor probe
    # and the read-path call into separate try blocks so the
    # ``NotImplementedError`` handler scopes ONLY to
    # :func:`_list_breaker_states`. A ``NotImplementedError`` escaping
    # from :func:`_get_supervisor` -- or from any module it lazily
    # imports (e.g. an abstract method left unwired during a refactor of
    # :class:`alfred.supervisor.core.Supervisor`) -- is a genuine
    # bootstrap bug and MUST surface a full traceback, not the friendly
    # "read path unavailable" hint. Mapping a probe-side
    # ``NotImplementedError`` to the localised read-path message
    # silently lied about the failure shape and regressed CLAUDE.md
    # hard rule #7 on a T1 operator surface.
    #
    # ``NotImplementedError`` is a subclass of ``RuntimeError`` in
    # CPython, so the probe-side ``except (RuntimeError, ...)`` arm
    # would otherwise swallow it and route to the localised
    # "supervisor not running" hint -- equally a silent lie about the
    # actual failure shape. The explicit ``except NotImplementedError:
    # raise`` before the RuntimeError arm pins the propagation contract
    # in code rather than relying on a future reader spotting the MRO
    # quirk.
    try:
        _get_supervisor()
    except NotImplementedError:
        # Probe-side NotImplementedError is a bootstrap bug; let it
        # propagate so the operator sees the typed traceback rather
        # than the friendly "supervisor not running" hint that the
        # RuntimeError handler below would otherwise emit (per
        # Python's NotImplementedError-is-a-RuntimeError MRO).
        raise
    except (RuntimeError, ConnectionError, TimeoutError) as exc:
        typer.echo(t("cli.supervisor.status.no_supervisor_running"), err=True)
        raise typer.Exit(code=1) from exc
    try:
        rows = _list_breaker_states()
    except NotImplementedError as exc:
        # CR-149 round-4: the read-path is not yet wired (Postgres
        # projection for circuit_breakers lands in a follow-up PR).
        # Surface that explicitly to the operator rather than mapping
        # to the "no components yet" hint — silently returning the
        # empty-state message would lie about the system's actual
        # state and break the discovery path (CLAUDE.md hard rule #7,
        # PRD §10.8 forensic contract).
        typer.echo(t("cli.supervisor.status.read_path_unavailable"), err=True)
        raise typer.Exit(code=1) from exc
    except (ConnectionError, TimeoutError) as exc:
        # Once the Postgres projection lands the read-path can also fail
        # for bootstrap / IPC reasons; treat those as "supervisor not
        # running" the same way the probe does, so the operator sees
        # one shape of fail-loud message regardless of which side of
        # the bootstrap actually broke.
        typer.echo(t("cli.supervisor.status.no_supervisor_running"), err=True)
        raise typer.Exit(code=1) from exc
    if not rows:
        typer.echo(t("cli.supervisor.status.empty_hint"))
        return
    header = "  ".join(
        [
            t("cli.supervisor.status.column.component").ljust(25),
            t("cli.supervisor.status.column.state").ljust(10),
            t("cli.supervisor.status.column.trip_count").ljust(12),
            t("cli.supervisor.status.column.last_trip_at").ljust(25),
        ]
    )
    typer.echo(header)
    for row in rows:
        state_raw = str(row.get("state", ""))
        # Map the breaker-state enum to a localised label so the table is
        # readable in every operator language.
        #
        # CR-149: an unknown enum value now renders an explicit
        # ``unknown`` label rather than silently mapping to ``closed``.
        # The prior shape lied about breaker health on a T1 operator
        # surface: a new or corrupt enum value would surface as the
        # localised CLOSED string, hiding a tripped / unsupported
        # state from the operator. Spec §11.3 is operator-facing
        # status; CLAUDE.md hard rule #7 requires failing loud.
        state_key_map = {
            "OPEN": "cli.supervisor.status.breaker_state.open",
            "CLOSED": "cli.supervisor.status.breaker_state.closed",
            "HALF_OPEN": "cli.supervisor.status.breaker_state.half_open",
        }
        state_label = t(state_key_map.get(state_raw, "cli.supervisor.status.breaker_state.unknown"))
        last_trip = str(row.get("last_trip_at") or "-")
        # rvw-010: hardcoded column widths mis-render in CJK locales (code-point
        # width vs display width). Deferred to a follow-up that swaps in
        # rich.table.Table in Slice 4.
        typer.echo(
            f"{row.get('component', '')!s:<25}  "
            f"{state_label:<10}  "
            f"{row.get('trip_count', 0)!s:<12}  "
            f"{last_trip:<25}"
        )


@supervisor_app.command("reset")
def supervisor_reset(
    component_id: Annotated[str, typer.Argument(help=t("cli.supervisor.reset.usage"))],
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm",
            help=t("cli.supervisor.reset.confirm_prompt"),
        ),
    ] = False,
) -> None:
    """Reset a circuit breaker from OPEN to CLOSED.

    Spec §10.8: operator-tier T1 command; requires ``--confirm``; emits a
    ``supervisor.breaker.reset`` audit row with ``operator_user_id``
    attribution. The ``--confirm`` gate prevents accidental resets in
    scripts — a supervisor reset clears a tripped circuit breaker,
    potentially re-enabling a quarantined-LLM plugin that failed 3+ times
    in 5 minutes.
    """
    if not confirm:
        # devex-004 + i18n-004: the catalog entry for confirm_prompt requires
        # {component}, {trip_count}, {last_trip_at}. We pass safe placeholders
        # for trip_count / last_trip_at until PR-S3-7 wires
        # Supervisor.get_breaker_state.
        typer.echo(
            t(
                "cli.supervisor.reset.confirm_prompt",
                component=component_id,
                trip_count="-",
                last_trip_at="-",
            ),
            err=True,
        )
        # i18n-004 fix: previously a hardcoded English f-string. Now routed
        # through t() so the rerun hint translates with the operator language.
        typer.echo(
            t("cli.supervisor.reset.rerun_hint", component=component_id),
            err=True,
        )
        raise typer.Exit(code=1)

    # CR-149: probe the supervisor BEFORE emitting the attempt-row.
    # The previous shape called ``_get_supervisor()`` outside any
    # exception handler, so a missing / unreachable supervisor raised
    # a raw traceback instead of the localised "supervisor not
    # running" hint the ``status`` command already uses. Spec §11.3
    # makes ``reset`` an operator surface, not a debug surface — the
    # error path here mirrors :func:`supervisor_status` exactly. The
    # attempt-row is emitted only AFTER the probe succeeds so a
    # supervisor that was never reachable does not generate a misleading
    # forensic breadcrumb (the operator never actually crossed the
    # boundary; rolling a fake row would invent state per CR-149
    # finding #14's pattern).
    try:
        supervisor = _get_supervisor()
    except (RuntimeError, ConnectionError, TimeoutError) as exc:
        typer.echo(t("cli.supervisor.status.no_supervisor_running"), err=True)
        raise typer.Exit(code=1) from exc

    # sec-pr-s3-6-04: emit the forensic-attempt audit row BEFORE crossing
    # into the supervisor. A crash inside ``reset_breaker`` (Postgres
    # connection lost mid-transaction, breaker-state lock contention,
    # ...) previously left no trail at all. The order here is
    # load-bearing: attempt-row first, reset call second; if the audit
    # emission itself fails, the reset is aborted (the structlog stream
    # is the operator's last forensic backstop and silently skipping
    # the row would violate CLAUDE.md hard rule #7).
    _emit_breaker_reset_attempt_audit(component_id=component_id)

    # devex-007: operator_user_id=None is a known placeholder. Full T1
    # attribution requires wiring IdentityResolver.resolve() from the CLI
    # session in PR-S3-7. Human judgment required: surface an unmistakable
    # error if attribution cannot be resolved, or emit None and let the
    # audit row carry NULL (weaker audit story). Decision deferred to
    # PR-S3-7; see devex-007 + spec §10.8. A follow-up issue tracks the
    # operator_user_id wiring; the attempt-row above going out unsigned
    # is strictly better than no row at all.
    #
    # err-001 / cross-cutting R4: narrow the except shape to
    # ``SupervisorError`` (every supervisor-domain failure mode the
    # spec models) plus ``ConnectionError`` / ``asyncio.TimeoutError``
    # (the two connection-shape failures that surface inside
    # ``asyncio.run`` when the supervisor IPC drops mid-call). A bare
    # ``except Exception`` would mask programmer bugs
    # (typed-method-signature drift, ``KeyError`` from a refactored
    # payload) -- those MUST propagate so the bug is loud.
    #
    # The lazy import lives at the top of the try-block so the
    # except-clause narrowing has the type bound; an ImportError here
    # surfaces as a non-zero exit through the same localised path.
    try:
        from alfred.supervisor.errors import (
            NoSuchComponentError,
            SupervisorError,
        )
    except ImportError as exc:
        # Defensive: a broken supervisor namespace must not deny the
        # operator the localised error -- fall back to the generic key.
        typer.echo(
            t(
                "cli.supervisor.reset.unexpected_error",
                component=component_id,
                error_type="ImportError",
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc

    try:
        asyncio.run(
            supervisor.reset_breaker(  # type: ignore[attr-defined]  # PR-S3-3b ships the singleton
                component_id=component_id,
                operator_user_id=None,
            )
        )
    except NoSuchComponentError as exc:
        # CR-149 round-7: typed-exception dispatch. The previous shape
        # branched on English substrings in ``str(exc).lower()`` to
        # decide whether to render the operator-targeted
        # ``component_not_found`` hint, which silently broke under
        # non-English operator languages and catalog copy-edits — the
        # exact CLAUDE.md hard rule #7 silent-skip shape on a T1
        # surface. :class:`NoSuchComponentError` is a typed
        # :class:`SupervisorError` subclass raised by
        # :meth:`Supervisor.reset_breaker` when the operator-supplied
        # ``component_id`` is not registered, so the dispatch now
        # routes off the class — locale-immune by construction.
        typer.echo(
            t(
                "cli.supervisor.reset.component_not_found",
                component=component_id,
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    except SupervisorError as exc:
        # Every other supervisor-domain failure surfaces through the
        # generic ``unexpected_error`` key. The ``NoSuchComponentError``
        # arm above runs first because MRO lookup tries the most
        # specific class match before falling through to the parent
        # ``SupervisorError`` branch.
        typer.echo(
            t(
                "cli.supervisor.reset.unexpected_error",
                component=component_id,
                error_type=type(exc).__name__,
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc
    except (ConnectionError, TimeoutError) as exc:
        # Connection-shape failures route through the generic
        # unexpected_error key -- the operator's next step is to check
        # whether the supervisor process is alive, not to retry with a
        # different component id.
        typer.echo(
            t(
                "cli.supervisor.reset.unexpected_error",
                component=component_id,
                error_type=type(exc).__name__,
            ),
            err=True,
        )
        raise typer.Exit(code=1) from exc

    typer.echo(t("cli.supervisor.reset.success", component=component_id))
