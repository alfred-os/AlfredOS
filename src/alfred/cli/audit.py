"""alfred audit CLI — audit ``graph`` with tier swimlane filter + ``log`` view.

Extends the audit surface with ``--tier T1|T2|T3`` filtering. Each tier
produces a swimlane view of audit rows attributed to that tier. The CLI
is read-only per spec §11.3; the SQL is queued for the production
session scope once PR-S3-0b's Alembic migration 0007 lands the extended
``audit_log`` CHECK constraint.

All operator-facing output routes through :func:`alfred.i18n.t` per
CLAUDE.md i18n rule #1. Depends on PR-S3-0a (``audit_row_schemas``).
"""

from __future__ import annotations

from typing import Annotated

import typer

from alfred.i18n import t

audit_app = typer.Typer(help=t("cli.audit.help"), no_args_is_help=True)


def _query_audit_log(
    *,
    tier: str | None = None,
    since_hours: int = 24,
) -> list[dict[str, object]]:
    """Query the ``audit_log`` table with an optional tier filter.

    PR-S3-0b extends the CHECK constraint; the production query is wired
    once the async Postgres session scope is reachable from the CLI
    bootstrap. Returns an empty list as a stub until then — tests patch
    this with fixture rows so the rendering layer is exercised
    independently of the storage layer.

    Parameters are keyword-only on purpose: the call sites all pass
    ``tier=`` + ``since_hours=`` so the mocked assertions can read both
    off ``call_args.kwargs`` without worrying about positional drift.
    """
    # PR-S3-7 wires: build_session_scope(settings) → AsyncSession →
    # SELECT * FROM audit_log WHERE (:tier IS NULL OR trust_tier_of_trigger = :tier)
    #                          AND timestamp >= now() - INTERVAL ':hours hours'
    # Until then the empty list keeps the CLI deterministic.
    del tier, since_hours
    return []


def _parse_since(since: str) -> int:
    """Parse a ``--since`` value like ``24h``, ``7d``, or ``30m`` into hours.

    devex-016: invalid input raises :class:`typer.BadParameter` rather
    than silently defaulting to 24h. Bare integers are rejected — a unit
    suffix is required so the operator's intent is unambiguous.
    """
    raw = since.strip().lower()
    try:
        if raw.endswith("h"):
            return int(raw[:-1])
        if raw.endswith("d"):
            return int(raw[:-1]) * 24
        if raw.endswith("m"):
            minutes = int(raw[:-1])
            # Round to the nearest hour, clamping to 1 so a 5-minute window
            # still surfaces *something* rather than collapsing to zero.
            return max(1, minutes // 60) if minutes >= 60 else 1
    except ValueError:
        # Fall through to the BadParameter below — explicit beats silent.
        pass
    raise typer.BadParameter(
        t("cli.audit.graph.since_invalid", value=since, example="24h, 7d, or 30m"),
        param_hint="'--since'",
    )


@audit_app.command("log")
def audit_log(
    event: Annotated[
        str | None,
        typer.Option("--event", help=t("cli.audit.log.event_help")),
    ] = None,
    since: Annotated[
        str,
        typer.Option("--since", help=t("cli.audit.graph.since_help")),
    ] = "24h",
) -> None:
    """List audit log entries, optionally filtered by event name and time window.

    devex-008: runbook fix-suggestion 3 uses
    ``alfred audit log --event plugin.lifecycle.crashed --since 5m``.
    Spec §11.3 lists this as part of the audit CLI surface. The actual
    rendering uses the same column layout as ``graph`` minus the tier
    swimlane.
    """
    since_hours = _parse_since(since)
    rows = _query_audit_log(tier=None, since_hours=since_hours)
    if event:
        rows = [r for r in rows if r.get("event") == event]
    if not rows:
        typer.echo(t("cli.audit.graph.empty", tier="", since=since))
        return
    for row in rows:
        typer.echo(
            f"{row.get('timestamp', '')!s:<25}  "
            f"{row.get('event', '')!s:<40}  "
            f"{row.get('result', '')!s:<12}  "
            f"{row.get('actor_user_id', '')!s}"
        )


@audit_app.command("graph")
def audit_graph(
    tier: Annotated[
        str | None,
        typer.Option("--tier", help=t("cli.audit.graph.tier_help")),
    ] = None,
    since: Annotated[
        str,
        typer.Option("--since", help=t("cli.audit.graph.since_help")),
    ] = "24h",
) -> None:
    """Show the audit graph, optionally filtered to a trust-tier swimlane.

    Spec §11.3: ``alfred audit graph --tier T1|T2|T3 --since 24h``. Each
    tier's rows form a swimlane; ``--tier T3`` surfaces all web.fetch,
    quarantine.extract, and security.t3_boundary events so an operator
    can audit the privileged/quarantined boundary in one view.
    """
    since_hours = _parse_since(since)

    rows = _query_audit_log(tier=tier, since_hours=since_hours)

    if not rows:
        tier_label = f" ({tier})" if tier else ""
        typer.echo(t("cli.audit.graph.empty", tier=tier_label, since=since))
        return

    # Render header. The tiered header carries the tier value so the
    # operator can tell at a glance which swimlane they're viewing.
    label = t("cli.audit.graph.tier_header", tier=tier) if tier else t("cli.audit.graph.header")
    typer.echo(label)
    typer.echo("-" * 60)

    for row in rows:
        typer.echo(
            f"{row.get('timestamp', '')!s:<25}  "
            f"{row.get('trust_tier_of_trigger', '')!s:<4}  "
            f"{row.get('event', '')!s:<40}  "
            f"{row.get('result', '')!s:<12}  "
            f"{row.get('actor_user_id', '')!s}"
        )
