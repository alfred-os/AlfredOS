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

from enum import StrEnum
from typing import Annotated

import typer

from alfred.i18n import t

audit_app = typer.Typer(help=t("cli.audit.help"), no_args_is_help=True)


class _TierChoice(StrEnum):
    """Closed set of valid ``--tier`` values for ``alfred audit graph``.

    Spec §4.2 enumerates the four trust tiers (T0..T3). Accepting an
    arbitrary string would silently render an empty graph for a typo
    (e.g. ``--tier T5``) -- exactly the silent-failure pattern
    CLAUDE.md hard rule #7 forbids. Typer maps the enum's values to a
    closed CLI choice + raises :class:`typer.BadParameter` on miss.

    sec-pr-s3-6-07 / devex-002 / cross-cutting R3: corroborated across
    three reviewer passes. :class:`enum.StrEnum` keeps each member's
    ``str`` identity, so ``_query_audit_log(tier=...)`` keeps its
    string contract -- callers do not need to know whether a
    ``--tier`` arg surfaced.
    """

    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class AuditBackendUnavailable(RuntimeError):  # noqa: N818
    """The audit-log backend is not yet wired into the CLI.

    CR-149: the previous shape collapsed "backend not implemented yet"
    into "no matching rows", so ``alfred audit log`` / ``alfred audit
    graph`` rendered the localised "no audit rows" message for every
    real invocation. That is the silent-failure pattern CLAUDE.md
    hard rule #7 forbids on operator surfaces — the operator could
    not tell the difference between "the system has no audit rows"
    and "the audit subsystem is not yet plumbed". The stub now raises
    this loud sentinel; the command handlers catch it and surface a
    dedicated localised message that names PR-S3-7 as the unblock
    point.
    """


def _query_audit_log(
    *,
    tier: str | None = None,
    since_hours: int = 24,
) -> list[dict[str, object]]:
    """Query the ``audit_log`` table with an optional tier filter.

    PR-S3-0b extends the CHECK constraint; the production query is wired
    once the async Postgres session scope is reachable from the CLI
    bootstrap. Tests patch this with fixture rows so the rendering
    layer is exercised independently of the storage layer.

    CR-149: until the storage layer lands, the stub raises
    :class:`AuditBackendUnavailable` rather than silently returning
    ``[]``. The command handlers catch the exception and emit a
    dedicated "backend not wired" message, so an operator running
    ``alfred audit log`` against a Slice-3 build sees the truth
    instead of a misleading empty-results render.

    Parameters are keyword-only on purpose: the call sites all pass
    ``tier=`` + ``since_hours=`` so the mocked assertions can read both
    off ``call_args.kwargs`` without worrying about positional drift.
    """
    # PR-S3-7 wires: build_session_scope(settings) → AsyncSession →
    # SELECT * FROM audit_log WHERE (:tier IS NULL OR trust_tier_of_trigger = :tier)
    #                          AND timestamp >= now() - INTERVAL ':hours hours'
    # Until then the stub raises so the CLI never reports false-empty.
    msg = (
        f"audit backend not wired (tier={tier!r}, since_hours={since_hours}); "
        "the SQL query is plumbed in PR-S3-7"
    )
    raise AuditBackendUnavailable(msg)


def _parse_since(since: str) -> int:
    """Parse a ``--since`` value like ``24h``, ``7d``, or ``30m`` into hours.

    devex-016: invalid input raises :class:`typer.BadParameter` rather
    than silently defaulting to 24h. Bare integers are rejected — a unit
    suffix is required so the operator's intent is unambiguous.

    CR-149: non-positive values (``0h``, ``-1d``, ``0m``) are
    rejected for every supported unit. The prior shape silently
    accepted ``0h`` / ``0d`` as zero-hour windows and ``-5m`` as one
    hour, handing the query layer impossible windows. A non-positive
    lookback can never select rows; surfacing :class:`typer.BadParameter`
    at parse time keeps the failure loud (CLAUDE.md hard rule #7).
    """
    raw = since.strip().lower()
    try:
        if raw.endswith("h"):
            hours = int(raw[:-1])
            if hours <= 0:
                raise ValueError
            return hours
        if raw.endswith("d"):
            days = int(raw[:-1])
            if days <= 0:
                raise ValueError
            return days * 24
        if raw.endswith("m"):
            minutes = int(raw[:-1])
            if minutes <= 0:
                raise ValueError
            # CR-149 round-10 (3339423474): the query layer is
            # hour-granular, so ceil the minute window to the next
            # whole hour. The previous shape floored ``90m`` to
            # ``1h``, dropping the oldest 30 minutes from the
            # selection and hiding audit rows during incident review.
            # Ceiling guarantees the requested window is never
            # narrowed; the smallest selectable lookback stays at
            # one hour (``1m`` → ``1h``).
            return (minutes + 59) // 60
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
    try:
        rows = _query_audit_log(tier=None, since_hours=since_hours)
    except AuditBackendUnavailable as exc:
        typer.echo(t("cli.audit.backend_unavailable"), err=True)
        raise typer.Exit(code=1) from exc
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
        _TierChoice | None,
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

    sec-pr-s3-6-07: ``--tier`` is a closed :class:`_TierChoice` enum so
    a typo (``--tier T5``) raises :class:`typer.BadParameter` at parse
    time rather than silently rendering an empty graph.
    """
    since_hours = _parse_since(since)

    # The downstream query stub speaks raw strings; collapse the enum
    # back to its value at the boundary so the storage-layer integration
    # in PR-S3-7 does not need to know the enum exists.
    tier_value = tier.value if tier is not None else None
    try:
        rows = _query_audit_log(tier=tier_value, since_hours=since_hours)
    except AuditBackendUnavailable as exc:
        # CR-149: the stub raises this until PR-S3-7 wires the SQL
        # query; emit the dedicated "backend not yet wired" message
        # so the operator does not confuse "no rows" with "the audit
        # subsystem is not plumbed".
        typer.echo(t("cli.audit.backend_unavailable"), err=True)
        raise typer.Exit(code=1) from exc

    if not rows:
        tier_label = f" ({tier_value})" if tier_value else ""
        typer.echo(t("cli.audit.graph.empty", tier=tier_label, since=since))
        return

    # Render header. The tiered header carries the tier value so the
    # operator can tell at a glance which swimlane they're viewing.
    label = (
        t("cli.audit.graph.tier_header", tier=tier_value)
        if tier_value
        else t("cli.audit.graph.header")
    )
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
