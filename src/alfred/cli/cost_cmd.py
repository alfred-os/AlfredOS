"""``alfred cost report`` — grouped spend report from the audit log.

Closes the CLAUDE.md "Commands you should know" gap for
``alfred cost report --since 7d --by persona``. Reads exclusively from
the ``audit_log`` table — ``cost_actual_usd`` is the canonical
post-call charge per turn (with ``cost_estimate_usd`` as the budget-
gate pre-check); we filter to rows where the actual charge landed so
zero-cost audit noise (adapter startup, CLI mutations) doesn't dilute
the report.

Why no orchestrator dependency
------------------------------

The report is a pure SQL aggregation; it never needs the provider
router, the budget guard, or any persona machinery. Keeping it free
of those imports means the cost subcommand can run on a stack with
zero provider keys configured (operator just wants to inspect the
spend ledger), which is a real first-week-deployment use case.

CLAUDE.md rules honoured
------------------------

* **#1 — every operator-facing string routes through ``t()``.** Column
  headers, the empty-state hint, error messages — all catalog-routed.
* **i18n rule #4 — pybabel extract picks up every literal here.** Each
  ``t(...)`` call uses a literal first arg so the extractor sees it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, cast

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import ColumnElement, create_engine, func, select
from sqlalchemy.orm import sessionmaker

from alfred.cli._bootstrap import load_settings_or_die, sync_db_url
from alfred.cli.audit_cmd import _parse_duration_or_exit
from alfred.i18n import set_language, t
from alfred.memory.models import AuditEntry


class _GroupBy(StrEnum):
    """Closed domain for ``--by``.

    Two values — ``persona`` and ``user`` — match the documented surface
    in CLAUDE.md ("--by persona"). New groupings (model, day) land via
    additive enum values + the matching column projection below.
    """

    PERSONA = "persona"
    USER = "user"


cost_app = typer.Typer(
    help=t("cli.cost.help.group"),
    no_args_is_help=True,
)


@cost_app.callback()
def _cost_callback() -> None:
    """No-op group callback — see ``audit_cmd._audit_callback`` for rationale."""


@cost_app.command("report", help=t("cli.cost.help.report.short"))
def report(
    since: Annotated[
        str,
        typer.Option("--since", help=t("cli.cost.flag.since.short")),
    ] = "7d",
    by: Annotated[
        _GroupBy,
        typer.Option("--by", help=t("cli.cost.flag.by.short")),
    ] = _GroupBy.PERSONA,
) -> None:
    """Render total + average cost per group over the given window.

    Sorted by ``total_cost_usd`` descending so the highest-spend group
    is at the top — that's the question an operator is almost always
    answering ("who's burning my budget?").
    """
    settings = load_settings_or_die()
    set_language(settings.operator_language)

    delta = _parse_duration_or_exit(since)
    cutoff = datetime.now(UTC) - delta

    # The grouping column is chosen up front so the SELECT/GROUP BY pair
    # cannot diverge. Both columns are NOT NULL in the audit schema
    # except ``actor_user_id`` (nullable for system events); when
    # grouping by user we coerce the NULL bucket to a sentinel via
    # ``coalesce`` so it shows up as one row instead of being silently
    # dropped by the GROUP BY.
    unknown_marker = t("cli.cost.report.value.unknown")
    # ``InstrumentedAttribute`` (the persona branch) and ``coalesce`` (the
    # user branch) are both ``ColumnElement[str]`` at runtime but neither
    # checker auto-widens the InstrumentedAttribute. Re-wrap the persona
    # branch through ``cast`` so both branches assign to the declared
    # union — clearer than two ``# type: ignore`` comments and keeps the
    # SELECT/GROUP BY pair single-sourced.
    group_col: ColumnElement[str]
    if by is _GroupBy.PERSONA:
        group_col = cast("ColumnElement[str]", AuditEntry.actor_persona)
    else:
        group_col = func.coalesce(AuditEntry.actor_user_id, unknown_marker)

    engine = create_engine(sync_db_url(settings))
    try:
        factory = sessionmaker(engine, expire_on_commit=False)
        stmt = (
            select(
                group_col.label("group_key"),
                func.count().label("turns"),
                func.sum(AuditEntry.cost_actual_usd).label("total_cost_usd"),
                func.avg(AuditEntry.cost_actual_usd).label("avg_cost_usd"),
            )
            # ``cost_actual_usd > 0`` doubles as the "non-null and non-zero"
            # filter — a NULL never satisfies a numeric comparison. This
            # excludes both adapter-startup rows (estimate-only, actual
            # never reconciled) and zero-cost CLI mutations.
            .where(AuditEntry.cost_actual_usd > 0)
            .where(AuditEntry.created_at > cutoff)
            .group_by(group_col)
            .order_by(func.sum(AuditEntry.cost_actual_usd).desc())
        )
        with factory() as session:
            rows = session.execute(stmt).all()
    finally:
        engine.dispose()

    if not rows:
        typer.echo(t("cli.cost.report.empty_hint"))
        return

    console = Console()
    table = Table(show_header=True)
    # The first column's heading is the grouping name itself — translators
    # supply one of two strings depending on ``--by``. Branch outside the
    # ``t()`` call so each literal appears as its own extractable msgid
    # (pybabel concatenates the ternary inside ``t(...)`` into a phantom
    # msgid otherwise — see the ``status`` command for the canonical
    # discussion).
    if by is _GroupBy.PERSONA:
        first_column_label = t("cli.cost.report.column.persona")
    else:
        first_column_label = t("cli.cost.report.column.user")
    table.add_column(first_column_label)
    table.add_column(t("cli.cost.report.column.turns"))
    table.add_column(t("cli.cost.report.column.total_cost_usd"))
    table.add_column(t("cli.cost.report.column.avg_cost_usd_per_turn"))

    for row in rows:
        table.add_row(
            str(row.group_key),
            str(row.turns),
            f"{float(row.total_cost_usd):.6f}",
            f"{float(row.avg_cost_usd):.6f}",
        )

    console.print(table)


__all__ = ["cost_app"]
