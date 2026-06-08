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

Module-load discipline (PR-S3-6 perf-001)
-----------------------------------------

The chat-graph dependency chain — :class:`Orchestrator`,
:class:`BudgetGuard`, :class:`WorkingMemoryPool`, :class:`EpisodicMemory`,
:class:`AuditWriter`, :class:`OutboundDlp`, the SQLAlchemy engine +
provider adapters — costs hundreds of milliseconds at import time. Every
``alfred --help`` invocation previously pulled the entire graph just to
render the typer surface. The heavy imports are now scoped inside the
functions that need them (``_chat_main`` for the chat path,
``status`` / ``_user_bootstrap`` for the lighter Settings-only surfaces)
so module load only pays for the typer registration + i18n catalog.

Tests assert the discipline:
``tests/unit/cli/test_main_lazy_imports.py`` introspects ``sys.modules``
after a fresh ``import alfred.cli.main`` and fails if
``alfred.providers`` or ``alfred.memory`` were eagerly pulled in.
"""

from __future__ import annotations

import typer

from alfred.cli.audit import audit_app
from alfred.cli.config import config_app
from alfred.cli.daemon import daemon_app
from alfred.cli.discord_cmd import discord_app
from alfred.cli.plugin import plugin_app
from alfred.cli.supervisor import supervisor_app
from alfred.cli.web import web_app
from alfred.i18n import set_language, t
from alfred.identity.cli import user_app

app = typer.Typer(help=t("cli.help.root"), no_args_is_help=True)


def _user_bootstrap() -> None:
    """Wire identity factories before any ``alfred user *`` subcommand runs.

    Typer invokes a sub-app's callback before dispatching the chosen
    subcommand. Registering this via ``add_typer(callback=...)`` rather than
    ``@user_app.callback()`` keeps the callback attached to the **root-app's
    registration** of ``user_app`` — direct ``user_app`` invocations (e.g.
    ``tests/unit/identity/test_cli.py``) skip the bootstrap and use the
    monkeypatched factories they install themselves. Settings load through
    ``load_settings_or_die`` so an unconfigured operator hits the same
    friendly ``.env`` error path as ``alfred chat`` / ``alfred status``.

    perf-001: ``_bootstrap`` is imported lazily inside the callback rather
    than at module top so ``alfred --help`` (which never invokes this
    callback) does not pay the broker + SQLAlchemy + provider import cost.
    """
    from alfred.cli._bootstrap import (
        install_identity_factories_for_settings,
        load_settings_or_die,
    )

    settings = load_settings_or_die()
    set_language(settings.operator_language)
    install_identity_factories_for_settings(settings)


app.add_typer(user_app, name="user", callback=_user_bootstrap)
# PR D2: register the ``alfred discord`` Typer group. The group's
# default callback (no subcommand) boots the long-running adapter;
# ``alfred discord verify`` runs the 30s probe. Both subcommands
# construct their own dependency graph inside the callback so the
# import cost only lands when an operator actually uses the surface.
app.add_typer(discord_app, name="discord")

# PR-S3-6 Component G: register the Slice-3 Typer groups. Each sub-app
# already carries its own ``help=t(...)`` on its ``typer.Typer(...)``
# constructor so the catalog routes the operator-facing strings once
# at definition time (CLAUDE.md i18n rule #1). The CLI is the single
# discovery surface — registration here is what makes
# ``alfred plugin|web|config|supervisor|audit`` reachable for an
# operator who has only the entry-point on their PATH.
#
# Order matches the plan section ordering (Components A→E in PR-S3-6
# §1633-1671); test_subapp_appears_in_root_help asserts each one is
# present in ``alfred --help`` so any silent drop here surfaces as a
# unit-test red.
app.add_typer(plugin_app, name="plugin")
app.add_typer(web_app, name="web")
app.add_typer(config_app, name="config")
app.add_typer(supervisor_app, name="supervisor")
app.add_typer(audit_app, name="audit")
# PR-S4-1 (#174): the production daemon entrypoint. ``alfred daemon
# start | stop | status`` wires the Supervisor + proposal-dispatch loop.
app.add_typer(daemon_app, name="daemon")


# ---------------------------------------------------------------------------
# Lazy re-export: ``_build_adapter_dlp_audit_sink``
# ---------------------------------------------------------------------------
#
# ``tests/unit/cli/test_main.py`` imports
# ``_build_adapter_dlp_audit_sink`` directly from this module to exercise
# the adapter-DLP audit-sink contract without booting the TUI. Pre-perf-001
# the symbol lived as an eager module-level alias of
# ``alfred.cli._bootstrap.build_adapter_dlp_audit_sink``. That alias forced
# ``_bootstrap`` (and its provider + SQLAlchemy chain) into the import
# graph of every ``alfred --help`` invocation.
#
# ``__getattr__`` (PEP 562) preserves the public test surface — the import
# ``from alfred.cli.main import _build_adapter_dlp_audit_sink`` still
# resolves — while deferring the ``_bootstrap`` import until the symbol is
# actually read. ``alfred --help`` never touches the attribute, so the
# heavy chain is not pulled in on the help path.
def __getattr__(name: str) -> object:
    """Lazy module-attribute lookup for the ``_bootstrap`` re-export.

    Only resolves ``_build_adapter_dlp_audit_sink`` — every other
    attribute access falls through to the standard ``AttributeError`` so a
    typo in a test import surfaces loudly rather than silently importing
    something unintended.
    """
    if name == "_build_adapter_dlp_audit_sink":
        from alfred.cli._bootstrap import build_adapter_dlp_audit_sink

        return build_adapter_dlp_audit_sink
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command(help=t("status.help"))
def status() -> None:
    """Print a short config summary: provider, budget, optional fallback.

    Used by operators to confirm their `.env` is loaded and the slice-1
    providers are wired correctly before they invoke ``alfred chat``. Exits
    zero on success; non-zero on Settings load failure (via
    ``load_settings_or_die``).

    perf-001: ``_bootstrap`` imports lazily — ``alfred --help`` never
    invokes ``status`` and so should not pay the provider chain's cost.
    """
    from alfred.cli._bootstrap import build_broker, load_settings_or_die

    settings = load_settings_or_die()
    broker = build_broker(settings)
    set_language(settings.operator_language)
    # The runtime fallback exists iff the broker can mint an Anthropic key
    # (see ``build_router``). Surfacing the configured name as-is would
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

    perf-001: ``asyncio`` imports lazily so the ``alfred --help`` path —
    which never invokes ``chat`` — does not pay even the stdlib asyncio
    cost.
    """
    import asyncio

    asyncio.run(_chat_main())


@app.command()
def migrate() -> None:
    """Run alembic migrations up to head.

    Invoked from the setup script as ``docker compose run --rm alfred-core
    migrate``. Keeping the surface here (rather than relying on a `sh -c`
    bypass of the ``alfred`` entrypoint) means operators only ever interact
    with one blessed command surface, and the container can keep
    ``ENTRYPOINT ["alfred"]`` without per-call ``--entrypoint`` overrides.

    perf-001: ``subprocess`` imports lazily — ``alfred --help`` does not
    need the subprocess machinery just to render the migrate surface.
    """
    import subprocess

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

    perf-001: every heavy import (orchestrator graph, broker, providers,
    SQLAlchemy session scope, DLP, audit writer, comms adapter factory)
    is scoped to this function body so ``alfred --help`` and the
    lightweight subcommands (``status``, ``migrate``, sub-app ``--help``)
    do not pay the chat-graph load cost at module import time.
    """
    import asyncio

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
    from alfred.comms.adapter import build_tui_adapter
    from alfred.identity import (
        InProcessTokenBucketRateLimiter,
        Platform,
    )
    from alfred.memory.db import build_session_scope, healthcheck
    from alfred.memory.episodic import EpisodicMemory
    from alfred.memory.working_pool import WorkingMemoryPool
    from alfred.orchestrator.core import Orchestrator
    from alfred.security.dlp import OutboundDlp

    settings = load_settings_or_die()
    broker = build_broker(settings)
    configure_logging(broker)
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
    # ``install_identity_factories_for_settings`` doubles as both the
    # resolver construction and the wiring for the ``alfred user *``
    # subcommands in the same process, so a Slice-2 operator who
    # launches the TUI then opens another shell to add a second user
    # gets coherent version-counter behaviour without two engines.
    resolver = install_identity_factories_for_settings(settings)
    operator = await asyncio.to_thread(resolver.resolve, Platform.TUI, settings.operator_name)
    if operator is None:
        typer.echo(t("cli.user.error.no_operator"), err=True)
        raise typer.Exit(code=2)

    router = build_router(broker, settings)
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
        version_counter=resolver.version_counter,  # type: ignore[attr-defined]  # reason: PR-B Phase 1 — counter promoted via ``install_identity_factories_for_settings``; Phase 5 makes it a typed property on IdentityResolver
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
    # the same async session_scope ``install_identity_factories_for_settings``
    # uses so audit + identity writes share lifecycle.
    adapter_audit_writer = AuditWriter(session_factory=session_scope)
    adapter_dlp_audit_sink = build_adapter_dlp_audit_sink(
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
