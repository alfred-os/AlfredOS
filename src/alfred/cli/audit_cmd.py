"""``alfred audit log`` — read-only inspection of the audit trail.

Closes the CLAUDE.md "Commands you should know" gap that documented
``alfred audit log`` long before it existed in the Typer surface; until
this PR landed, operators wanting to verify the audit trail had to drop
to raw ``psql``.

The command is **read-only**: every code path here issues a single
``SELECT`` against the ``audit_log`` table, renders a Rich table to
stdout, and exits. No writes, no provider calls, no capability-gate
interaction. The filters (``--since``, ``--user``, ``--persona``,
``--limit``) translate one-to-one into a parameterised SQLAlchemy
``select`` so a buggy filter cannot inject SQL.

Why a sync session
------------------

The :class:`IdentityResolver` already runs against a sync sessionmaker
(see :func:`alfred.cli.\\_bootstrap.install_identity_factories_for_settings`).
For a one-shot read like this, opening a second async engine for a
single ``SELECT`` would add ~200ms of cold-start latency and a redundant
connection-pool. We reuse the resolver's sync engine via the slug-derived
URL (``\\_bootstrap.sync_db_url``) so the operator pays one engine cost
per ``alfred audit log`` invocation.

CLAUDE.md rules honoured
------------------------

* **#1 — every operator-facing string routes through ``t()``.** Column
  headers, error messages, the empty-state hint — all catalog-routed.
* **#3 — every stored user-content row carries a language field.** The
  ``language`` column is rendered verbatim from the row.
* **i18n rule #4 — pybabel extract picks up every literal here.** Each
  ``t(...)`` call uses a literal first arg so the extractor sees it.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from alfred.cli._bootstrap import load_settings_or_die, sync_db_url
from alfred.i18n import set_language, t
from alfred.memory.models import AuditEntry

# Hard upper bound on ``--limit``. The default is small (50); the cap
# stops an operator from typing ``--limit 999999`` and accidentally
# OOM'ing their terminal on a deployment with a busy audit table.
_LIMIT_MAX = 1000
_LIMIT_DEFAULT = 50

# ``--since`` accepts ``<int><suffix>`` with suffix in {m,h,d}. Anything
# else is rejected loudly via ``t()``. The regex is intentionally strict:
# no leading sign, no fractional values, no whitespace. Matches the
# documented surface in CLAUDE.md ("--since 24h", "--since 7d").
_DURATION_RE = re.compile(r"^(\d+)([mhd])$")
_SUFFIX_TO_TIMEDELTA: dict[str, timedelta] = {
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
}


audit_app = typer.Typer(
    help=t("cli.audit.help.group"),
    no_args_is_help=True,
)


@audit_app.callback()
def _audit_callback() -> None:
    """No-op group callback.

    Typer collapses a single-subcommand app into its only command at the
    parent's registration point — so without this callback, ``alfred
    audit log`` would surface as ``alfred audit`` (a hidden trap for the
    documented CLI shape). The callback's presence keeps Typer in
    multi-command mode, preserving the ``alfred audit log`` surface
    that CLAUDE.md documents and that operators are typing today.
    """


def _parse_duration_or_exit(raw: str) -> timedelta:
    """Parse ``5m``/``1h``/``7d`` into a timedelta or exit non-zero.

    Reject malformed input loudly with a ``t()``-routed error so the
    operator sees a localised message instead of an opaque Python
    exception. The valid suffixes are pinned in the module-level dict
    so any future addition (``w`` for weeks) is a one-line change.
    """
    match = _DURATION_RE.match(raw)
    if match is None:
        typer.echo(t("cli.audit.error.invalid_since", value=raw), err=True)
        raise typer.Exit(code=2)
    qty = int(match.group(1))
    if qty <= 0:
        # ``\\d+`` matches "0"; an interval of zero (or negative, though
        # the regex won't match a sign) would silently return every row
        # ever written — almost certainly not what the operator meant.
        typer.echo(t("cli.audit.error.invalid_since", value=raw), err=True)
        raise typer.Exit(code=2)
    return _SUFFIX_TO_TIMEDELTA[match.group(2)] * qty


def _extract_model(subject: dict[str, object] | None) -> str:
    """Pull ``subject->>'model'`` out as a display string.

    Returns an empty string when the row has no subject or no model key —
    callers render that as the empty cell, which is the same convention
    Rich uses for nulls. The audit subject is a free-form JSON dict so
    we do a soft lookup rather than a typed projection.
    """
    if not subject:
        return ""
    value = subject.get("model")
    return "" if value is None else str(value)


@audit_app.command("log", help=t("cli.audit.help.log.short"))
def log(
    since: Annotated[
        str,
        typer.Option("--since", help=t("cli.audit.flag.since.short")),
    ] = "24h",
    user: Annotated[
        str | None,
        typer.Option("--user", help=t("cli.audit.flag.user.short")),
    ] = None,
    persona: Annotated[
        str | None,
        typer.Option("--persona", help=t("cli.audit.flag.persona.short")),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", help=t("cli.audit.flag.limit.short")),
    ] = _LIMIT_DEFAULT,
) -> None:
    """Render the audit log for the given filter window.

    Sorted ``created_at DESC`` so the most recent action is at the top
    of the operator's terminal — that's the question they're almost
    always answering ("what just happened?").
    """
    settings = load_settings_or_die()
    set_language(settings.operator_language)

    if limit < 1 or limit > _LIMIT_MAX:
        typer.echo(t("cli.audit.error.invalid_limit", value=limit, max=_LIMIT_MAX), err=True)
        raise typer.Exit(code=2)

    delta = _parse_duration_or_exit(since)
    cutoff = datetime.now(UTC) - delta

    engine = create_engine(sync_db_url(settings))
    try:
        factory = sessionmaker(engine, expire_on_commit=False)
        stmt = (
            select(AuditEntry)
            .where(AuditEntry.created_at > cutoff)
            .order_by(AuditEntry.created_at.desc())
            .limit(limit)
        )
        if user is not None:
            stmt = stmt.where(AuditEntry.actor_user_id == user)
        if persona is not None:
            stmt = stmt.where(AuditEntry.actor_persona == persona)
        with factory() as session:
            rows = session.scalars(stmt).all()
    finally:
        engine.dispose()

    if not rows:
        typer.echo(t("cli.audit.log.empty_hint"))
        return

    console = Console()
    table = Table(show_header=True)
    table.add_column(t("cli.audit.log.column.time"))
    table.add_column(t("cli.audit.log.column.event"))
    table.add_column(t("cli.audit.log.column.actor_user_id"))
    table.add_column(t("cli.audit.log.column.actor_persona"))
    table.add_column(t("cli.audit.log.column.tier"))
    table.add_column(t("cli.audit.log.column.result"))
    table.add_column(t("cli.audit.log.column.cost_usd"))
    table.add_column(t("cli.audit.log.column.language"))
    table.add_column(t("cli.audit.log.column.model"))

    unknown_marker = t("cli.audit.log.value.unknown")
    for row in rows:
        # ``cost_actual_usd`` is nullable (NULL until reconciled); fall
        # back to the estimate so the operator never sees a literal
        # ``None`` in the cell. Six decimals matches the precision the
        # provider router records under.
        cost = row.cost_actual_usd if row.cost_actual_usd is not None else row.cost_estimate_usd
        table.add_row(
            row.created_at.isoformat(timespec="seconds"),
            row.event,
            row.actor_user_id if row.actor_user_id is not None else unknown_marker,
            row.actor_persona,
            row.trust_tier_of_trigger,
            row.result,
            f"{cost:.6f}",
            row.language,
            _extract_model(row.subject),
        )

    console.print(table)


__all__ = ["audit_app"]
