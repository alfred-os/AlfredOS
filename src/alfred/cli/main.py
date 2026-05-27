"""AlfredOS CLI entry point.

This is the single bootstrap that constructs the full slice-1/2 graph:
``Settings`` → ``SecretBroker`` → ``ProviderRouter`` → ``IdentityResolver``
→ ``BudgetGuard`` → ``WorkingMemoryPool`` → ``Orchestrator`` →
``AlfredTuiApp``. The CLI is the imperative shell; every subsystem below
is a pure-ish core that gets its dependencies passed in.

The ``status`` command exits zero after printing a short health summary so
operators can sanity-check their `.env` before launching the TUI. The
``chat`` command opens the Textual UI. Friendly, ``t()``-routed error
messages are printed (and a non-zero exit code returned) when ``Settings``
fail to load or Postgres is unreachable — never a raw traceback.

CLAUDE.md hard rules honoured at this layer:

  #1  every operator-facing string is routed through ``t()``.
  #6  secrets are read via ``SecretBroker`` (env-backed in slice 1) — never
      ``os.environ`` at this layer.

The structlog redactor (``_redact``) is installed in front of every log
processor chain so any secret value caught by ``SecretBroker.redact()`` is
masked before it leaves the process.
"""

from __future__ import annotations

import asyncio
import subprocess

import typer
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.cli._bootstrap import (
    build_adapter_dlp_audit_sink,
    build_broker,
    build_router,
    configure_logging,
    install_identity_factories_for_settings,
    load_settings_or_die,
)
from alfred.cli.audit_cmd import audit_app
from alfred.cli.discord_cmd import discord_app
from alfred.comms.adapter import build_tui_adapter
from alfred.i18n import set_language, t
from alfred.identity import (
    InProcessTokenBucketRateLimiter,
    Platform,
)
from alfred.identity.cli import user_app
from alfred.memory.db import build_session_scope, healthcheck
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working_pool import WorkingMemoryPool
from alfred.orchestrator.core import Orchestrator
from alfred.security.dlp import OutboundDlp

# Underscore-prefixed re-exports keep the public test surface stable
# (e.g. ``tests/unit/cli/test_main.py`` imports
# ``_build_adapter_dlp_audit_sink``). Pre-D2 these lived inline here;
# they were extracted into :mod:`alfred.cli._bootstrap` to break the
# ``main`` <-> ``discord_cmd`` import cycle.
#
# Only the aliases this module actually references at runtime — or that
# tests import by underscore name — are kept. ``structlog_audit_sink``
# and ``sync_db_url`` previously had stubs here too; they were dead
# (only consumed inside ``_bootstrap``) and CodeQL flagged them as
# unused globals. Callers that want them import from ``_bootstrap``
# directly.
_load_settings_or_die = load_settings_or_die
_build_broker = build_broker
_build_router = build_router
_configure_logging = configure_logging
_install_identity_factories = install_identity_factories_for_settings
_build_adapter_dlp_audit_sink = build_adapter_dlp_audit_sink

app = typer.Typer(help=t("cli.help.root"), no_args_is_help=True)


def _user_bootstrap() -> None:
    """Wire identity factories before any ``alfred user *`` subcommand runs.

    Typer invokes a sub-app's callback before dispatching the chosen
    subcommand. Registering this via ``add_typer(callback=...)`` rather than
    ``@user_app.callback()`` keeps the callback attached to the **root-app's
    registration** of ``user_app`` — direct ``user_app`` invocations (e.g.
    ``tests/unit/identity/test_cli.py``) skip the bootstrap and use the
    monkeypatched factories they install themselves. Settings load through
    ``_load_settings_or_die`` so an unconfigured operator hits the same
    friendly ``.env`` error path as ``alfred chat`` / ``alfred status``.
    """
    settings = _load_settings_or_die()
    set_language(settings.operator_language)
    _install_identity_factories(settings)


app.add_typer(user_app, name="user", callback=_user_bootstrap)
# PR D2: register the ``alfred discord`` Typer group. The group's
# default callback (no subcommand) boots the long-running adapter;
# ``alfred discord verify`` runs the 30s probe. Both subcommands
# construct their own dependency graph inside the callback so the
# import cost only lands when an operator actually uses the surface.
app.add_typer(discord_app, name="discord")
# Read-only operator-inspection surfaces. Each subgroup loads
# ``Settings`` lazily inside its handler (rather than via a
# ``callback=...``) so an operator on an unconfigured stack still gets
# the friendly ``.env`` error from ``_load_settings_or_die`` and never
# a pre-callback traceback. Each subgroup opens its own short-lived
# sync engine — see the module docstrings for the cold-start rationale.
app.add_typer(audit_app, name="audit")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def status() -> None:
    """Print a short config summary: provider, budget, optional fallback.

    Used by operators to confirm their `.env` is loaded and the slice-1
    providers are wired correctly before they invoke ``alfred chat``. Exits
    zero on success; non-zero on Settings load failure (via
    ``_load_settings_or_die``).
    """
    settings = _load_settings_or_die()
    broker = _build_broker(settings)
    set_language(settings.operator_language)
    # The runtime fallback exists iff the broker can mint an Anthropic key
    # (see ``_build_router``). Surfacing the configured name as-is would
    # claim a fallback the operator hasn't actually wired up — and using a
    # hardcoded "yes"/"no" leaks English regardless of operator_language.
    # Derive both from a single boolean and pull the yes/no from the
    # catalog.
    anthropic_configured = broker.has("anthropic_api_key")
    # Pybabel extracts ``t()`` argument as a literal string — a conditional
    # expression inside the call would concatenate the branches into a
    # phantom msgid (e.g. ``"status.yes" if x else "status.no"`` extracts
    # as ``status.yesstatus.no``). Branch outside the call so each literal
    # appears as its own extractable msgid.
    if anthropic_configured:
        yes_no = t("status.yes")
        fallback_label = settings.fallback_provider
    else:
        yes_no = t("status.no")
        fallback_label = t("status.fallback_none")
    typer.echo(t("status.primary_provider", provider=settings.primary_provider))
    typer.echo(t("status.fallback_provider", provider=fallback_label))
    typer.echo(t("status.anthropic_configured", yes_or_no=yes_no))
    typer.echo(t("status.daily_budget", amount=f"{settings.daily_budget_usd:.2f}"))
    typer.echo(t("status.per_call_max", amount=f"{settings.per_call_max_usd:.2f}"))


@app.command()
def chat() -> None:
    """Launch the Textual TUI for an interactive Alfred conversation.

    Synchronous Typer entry point; the async wiring lives in
    ``_chat_main`` and is dispatched via ``asyncio.run``. Catch-and-translate
    happens inside ``_chat_main`` so the user never sees a raw traceback.
    """
    asyncio.run(_chat_main())


@app.command()
def migrate() -> None:
    """Run alembic migrations up to head.

    Invoked from the setup script as ``docker compose run --rm alfred-core
    migrate``. Keeping the surface here (rather than relying on a `sh -c`
    bypass of the ``alfred`` entrypoint) means operators only ever interact
    with one blessed command surface, and the container can keep
    ``ENTRYPOINT ["alfred"]`` without per-call ``--entrypoint`` overrides.
    """
    # List-form is the secure invocation (no shell, no injection). Alembic
    # ships in our own venv and `alfred` runs with that venv's bin/ on PATH
    # (set by the Dockerfile + uv-managed dev shell), so the partial-path
    # lookup S607 flags resolves to a trusted binary in every supported
    # environment. Resolving to an absolute path here would couple the CLI
    # to the install layout and break `uv run alfred migrate` locally.
    subprocess.run(["alembic", "upgrade", "head"], check=True)  # noqa: S607


async def _chat_main() -> None:
    """Async bootstrap: Settings → broker → DB healthcheck → orchestrator → TUI.

    Each step is fallible at the operator's first encounter — bad `.env`,
    Postgres down, etc. — so each is mapped to a ``t()``-routed error
    message before exiting non-zero. The TUI itself never sees these
    failures because they happen before it launches.
    """
    settings = _load_settings_or_die()
    broker = _build_broker(settings)
    _configure_logging(broker)
    set_language(settings.operator_language)

    session_scope = build_session_scope(settings)

    # Up-front healthcheck so a missing/down Postgres surfaces as a friendly
    # one-liner rather than an asyncpg traceback inside the TUI on first
    # keystroke. See ``alfred.memory.db.healthcheck`` for the rationale.
    try:
        await healthcheck(session_scope)
    except SQLAlchemyError as exc:
        typer.echo(t("error.postgres_unreachable", detail=str(exc)))
        typer.echo(t("hint.is_compose_up"))
        raise typer.Exit(code=3) from exc

    # Identity: resolve the operator's canonical slug + language BEFORE
    # constructing the orchestrator so every episode + audit row carries
    # the canonical slug (CLAUDE.md i18n rule #3 + spec §2 identity
    # invariants). Migration 0004 backfilled the operator row from
    # ALFRED_OPERATOR_NAME, so the TUI binding ``(tui, operator_name)``
    # always resolves on a freshly-set-up stack. If it doesn't, the
    # operator skipped ``alembic upgrade head`` or removed the operator
    # row — surface the friendly hint that points at
    # ``alfred user add --authorization operator``.
    #
    # ``_install_identity_factories`` doubles as both the resolver
    # construction and the wiring for the ``alfred user *`` subcommands
    # in the same process, so a Slice-2 operator who launches the TUI
    # then opens another shell to add a second user gets coherent
    # version-counter behaviour without two engines.
    resolver = _install_identity_factories(settings)
    operator = await asyncio.to_thread(resolver.resolve, Platform.TUI, settings.operator_name)
    if operator is None:
        typer.echo(t("cli.user.error.no_operator"), err=True)
        raise typer.Exit(code=2)

    router = _build_router(broker, settings)
    # PR-B Phase 1: per-user BudgetGuard. The loader resolves a canonical
    # ``user_id`` (the resolver's slug) to the live ``User`` row; the
    # guard reads ``daily_budget_usd`` off the row on first-touch and on
    # every version-counter bump. Wrapping ``resolver.show`` keeps the
    # guard ignorant of the SQLAlchemy session lifecycle — the resolver
    # is the one that owns sessions.
    #
    # The operator's ``settings.daily_budget_usd`` (slice-1 single-guard
    # cap) is no longer read here: migration 0004 backfilled it into
    # ``users.daily_budget_usd`` for the operator row, and the loader
    # below is what surfaces it. The per-call cap stays global.
    budget = BudgetGuard(
        user_loader=lambda user_id: resolver.show(slug=user_id),
        per_call_max_usd=settings.per_call_max_usd,
        version_counter=resolver.version_counter,  # type: ignore[attr-defined]  # reason: PR-B Phase 1 — counter promoted via ``_install_identity_factories``; Phase 5 makes it a typed property on IdentityResolver
    )

    # PR-B Phase 5: pool replaces the slice-1 single ``WorkingMemory()`` +
    # rehydrate-on-startup block. The pool is lazy: the very first
    # ``acquire(("alfred", user.slug))`` from the TUI rehydrates the
    # operator's buffer from episodic; subsequent acquires hit the cache.
    # Slice-2 single-operator deployments only ever populate one entry so
    # the LRU cap is effectively unused — ``active_user_count=lambda: 1``
    # makes the floor-of-50 default visible (rather than scaling with a
    # number that doesn't change). Operators can override via
    # ``ALFRED_WORKING_MEMORY_POOL_MAX``; Slice 4+ replaces the lambda
    # with a live count from the identity resolver.
    working_pool = WorkingMemoryPool(
        episodic_factory=lambda session: EpisodicMemory(session=session),
        pool_session_scope=session_scope,
        max_entries=settings.working_memory_pool_max,
        active_user_count=lambda: 1,
    )

    orchestrator = Orchestrator(
        identity_resolver=resolver,
        session_scope=session_scope,
        router=router,
        budget=budget,
    )
    # PR D1: construct the TuiAdapter Protocol seam rather than the
    # AlfredTuiApp directly so the CLI consumes only the public
    # ``alfred.comms.adapter.CommsAdapter`` surface. The adapter holds
    # the canonical Slice-2 inject set; PR D2's Discord adapter takes
    # the same set so the CLI bootstrap shape is unchanged when D2
    # ships. The ``InProcessTokenBucketRateLimiter`` here is a separate
    # instance from the one the resolver holds — both are operator-
    # unlimited in Slice-2 single-operator mode, so the divergence is
    # functionally invisible; Slice-3+ unifies under the supervisor.
    # Adapter outbound DLP wires a PERSISTENT audit sink — not the
    # structlog-bridge no-op. The DLP layer's whole point is audit-on-
    # modification (CLAUDE.md hard rule #7); routing it to the no-op
    # would lose every outbound-redaction event. The sink schedules an
    # async ``AuditWriter.append`` on the running event loop so the
    # synchronous ``_AuditSink`` contract stays satisfied without
    # blocking the scan path. The audit writer is constructed against
    # the same async session_scope ``_install_identity_factories`` uses
    # so audit + identity writes share lifecycle.
    adapter_audit_writer = AuditWriter(session_factory=session_scope)
    adapter_dlp_audit_sink = _build_adapter_dlp_audit_sink(
        audit_writer=adapter_audit_writer,
        operator_user_id=operator.slug,
        language=settings.operator_language,
    )
    outbound_dlp = OutboundDlp(broker=broker, audit=adapter_dlp_audit_sink)
    rate_limiter = InProcessTokenBucketRateLimiter()
    adapter = build_tui_adapter(
        orchestrator=orchestrator,
        identity_resolver=resolver,
        outbound_dlp=outbound_dlp,
        rate_limiter=rate_limiter,
        broker=broker,
        working_pool=working_pool,
    )
    await adapter.start()
    try:
        await adapter.run()
    finally:
        await adapter.stop()


if __name__ == "__main__":  # pragma: no cover - manual entry
    app()
