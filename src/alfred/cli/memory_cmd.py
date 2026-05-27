"""``alfred memory show <user-slug>`` — operator-inspection view.

Closes the CLAUDE.md "Commands you should know" gap for
``alfred memory show <user>``. Surfaces the user row plus the most
recent 20 episodes for that user, so an operator can sanity-check
attribution, language tagging, and trust-tier labelling without
dropping to ``psql``.

WHY the working-memory pool is not displayed
--------------------------------------------

:class:`alfred.memory.working_pool.WorkingMemoryPool` is **per-process,
in-memory state** — the running TUI process owns the buffers; a
short-lived CLI invocation cannot query them. Showing a stubbed
"working memory: <pool unreachable>" line would mislead. We surface a
localised hint instead so the operator knows the pool is intentionally
not in this command's surface, and which command would expose it once
a cross-process interrogation channel exists (Slice 3+ work).

Display vs underlying data
--------------------------

Per spec: the content cell is truncated to ~100 chars **for display
only**. The episode row in Postgres carries the full content;
truncation is presentation logic. Operators who need the full text
read it from the DB (``alfred audit log`` won't help — episodes are a
separate table — but the truncation visibly ends with ``…`` so the
operator knows there's more).

CLAUDE.md rules honoured
------------------------

* **#1 — every operator-facing string routes through ``t()``.**
* **#3 — episode rows display their stored ``language`` tag verbatim.**
* **#7 — no silent failures.** Missing user → ``t()``-routed error +
  exit code 2; no DB-error swallowing.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from alfred.cli._bootstrap import load_settings_or_die, sync_db_url
from alfred.i18n import set_language, t
from alfred.identity.models import User
from alfred.memory.models import Episode

# Display-only truncation length for the content cell. Anything beyond
# this gets the ellipsis treatment. The underlying ``Episode.content``
# is untouched — see module docstring.
_CONTENT_DISPLAY_MAX = 100

# How many recent episodes to render. Matches the WorkingMemoryPool's
# rehydrate limit (``EpisodicMemory.recent`` defaults to 20) so the
# operator-facing view mirrors what the orchestrator would load on a
# fresh acquire.
_EPISODES_LIMIT = 20


memory_app = typer.Typer(
    help=t("cli.memory.help.group"),
    no_args_is_help=True,
)


@memory_app.callback()
def _memory_callback() -> None:
    """No-op group callback — see ``audit_cmd._audit_callback`` for rationale."""


def _truncate_for_display(content: str) -> str:
    """Return ``content`` clipped to the display width with a trailing ellipsis.

    Single-character ellipsis (…) rather than three dots because
    Rich treats it as one cell in fixed-width rendering, which keeps
    column alignment stable across rows of varied lengths. Underlying
    data is not modified — see module docstring.
    """
    if len(content) <= _CONTENT_DISPLAY_MAX:
        return content
    return content[:_CONTENT_DISPLAY_MAX] + "…"


@memory_app.command("show", help=t("cli.memory.help.show.short"))
def show(slug: str) -> None:
    """Render the user summary + recent-episode table for ``slug``."""
    settings = load_settings_or_die()
    set_language(settings.operator_language)

    engine = create_engine(sync_db_url(settings))
    try:
        factory = sessionmaker(engine, expire_on_commit=False)
        with factory() as session:
            user = session.scalar(select(User).where(User.slug == slug))
            if user is None:
                typer.echo(t("cli.memory.error.user_not_found", slug=slug), err=True)
                raise typer.Exit(code=2)
            # Snapshot the fields we need NOW so the user is detached
            # before the session closes. Eager-reading every column we
            # render keeps SQLAlchemy from raising ``DetachedInstance``
            # below when the session exits.
            user_summary: dict[str, object] = {
                "slug": user.slug,
                "display_name": user.display_name,
                "authorization": user.authorization,
                "daily_budget_usd": user.daily_budget_usd,
                "language": user.language,
            }
            episode_rows = session.scalars(
                select(Episode)
                .where(Episode.user_id == slug)
                .order_by(Episode.created_at.desc())
                .limit(_EPISODES_LIMIT)
            ).all()
            # Same detach-safety pattern as ``user_summary``: snapshot
            # the columns we render into plain tuples so a subsequent
            # access doesn't trip on the closed session.
            episode_snapshots: list[tuple[str, str, str, str, str]] = [
                (
                    ep.created_at.isoformat(timespec="seconds"),
                    ep.role,
                    _truncate_for_display(ep.content),
                    ep.trust_tier,
                    ep.language,
                )
                for ep in episode_rows
            ]
    finally:
        engine.dispose()

    # The user-summary block uses the same labels ``alfred user show``
    # uses so a translator only has to localise each field name once.
    # The labels themselves live under ``cli.user.list.column.*`` and
    # were populated in PR-A.
    typer.echo(f"{t('cli.user.list.column.slug')}: {user_summary['slug']}")
    typer.echo(f"{t('cli.user.list.column.display_name')}: {user_summary['display_name']}")
    typer.echo(f"{t('cli.user.list.column.authorization')}: {user_summary['authorization']}")
    typer.echo(
        f"{t('cli.user.list.column.daily_budget_usd')}: "
        f"{float(user_summary['daily_budget_usd']):.2f}"  # type: ignore[arg-type]  # reason: snapshot dict holds the Float column verbatim; format(float) on it is well-defined
    )
    typer.echo(f"{t('cli.user.list.column.language')}: {user_summary['language']}")
    typer.echo("")

    if not episode_snapshots:
        typer.echo(t("cli.memory.show.episodes.empty_hint"))
    else:
        console = Console()
        table = Table(
            show_header=True,
            title=t("cli.memory.show.episodes.title", limit=_EPISODES_LIMIT),
        )
        table.add_column(t("cli.memory.show.column.time"))
        table.add_column(t("cli.memory.show.column.role"))
        table.add_column(t("cli.memory.show.column.content"))
        table.add_column(t("cli.memory.show.column.trust_tier"))
        table.add_column(t("cli.memory.show.column.language"))
        for created, role, content, tier, language in episode_snapshots:
            table.add_row(created, role, content, tier, language)
        console.print(table)

    # WorkingMemoryPool is per-process state — see module docstring for
    # the rationale on not stubbing a fake reading.
    typer.echo("")
    typer.echo(t("cli.memory.show.working.unavailable_hint"))


__all__ = ["memory_app"]
