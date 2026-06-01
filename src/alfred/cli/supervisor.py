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
from typing import Annotated

import typer

from alfred.i18n import t

supervisor_app = typer.Typer(help=t("cli.supervisor.help"), no_args_is_help=True)


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

    Depends on PR-S3-3b migration 0010 + the SQLAlchemy model. Returns an
    empty list until PR-S3-3b merges; tests patch this with fixture rows.
    """
    return []


@supervisor_app.command("status")
def supervisor_status() -> None:
    """List all supervised components and their circuit-breaker states.

    Spec §11.3: ``alfred supervisor status`` is a read-only Postgres read.
    Discovery path: ``quarantine_unavailable`` error →
    ``alfred supervisor status`` →
    ``alfred supervisor reset <component> --confirm``.
    """
    # devex-013: disambiguate empty state — supervisor not running vs
    # genuinely empty. The probe is the supervisor lookup itself; failing
    # there means the bootstrap could not reach a live supervisor.
    try:
        _get_supervisor()
        rows = _list_breaker_states()
    except Exception as exc:
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
        # readable in every operator language. Unknown values fall back to
        # the CLOSED label so we never leak an untranslated enum string.
        state_key_map = {
            "OPEN": "cli.supervisor.status.breaker_state.open",
            "CLOSED": "cli.supervisor.status.breaker_state.closed",
            "HALF_OPEN": "cli.supervisor.status.breaker_state.half_open",
        }
        state_label = t(state_key_map.get(state_raw, "cli.supervisor.status.breaker_state.closed"))
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

    supervisor = _get_supervisor()

    # devex-007: operator_user_id=None is a known placeholder. Full T1
    # attribution requires wiring IdentityResolver.resolve() from the CLI
    # session in PR-S3-7. Human judgment required: surface an unmistakable
    # error if attribution cannot be resolved, or emit None and let the
    # audit row carry NULL (weaker audit story). Decision deferred to
    # PR-S3-7; see devex-007 + spec §10.8.
    try:
        asyncio.run(
            supervisor.reset_breaker(  # type: ignore[attr-defined]  # PR-S3-3b ships the singleton
                component_id=component_id,
                operator_user_id=None,
            )
        )
    except Exception as exc:
        # devex-005: map specific error types to distinct messages so
        # operators can distinguish "wrong component ID" from "supervisor
        # unavailable". Import lazily to avoid bootstrap cost on the
        # happy path of other CLI commands.
        try:
            from alfred.supervisor.errors import (
                SupervisorError,
            )

            # ``ComponentNotFoundError`` is a future-PR-S3-7 refinement.
            # Until then any :class:`SupervisorError` carrying "not found"
            # in its message is treated as the component-missing branch.
            component_not_found = (
                isinstance(exc, SupervisorError) and "not found" in str(exc).lower()
            )
            if component_not_found:
                typer.echo(
                    t(
                        "cli.supervisor.reset.component_not_found",
                        component=component_id,
                    ),
                    err=True,
                )
            else:
                typer.echo(
                    t(
                        "cli.supervisor.reset.unexpected_error",
                        component=component_id,
                        error_type=type(exc).__name__,
                    ),
                    err=True,
                )
        except ImportError:
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
