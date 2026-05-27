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
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

import structlog
import typer
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from structlog.types import EventDict

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.comms.adapter import build_tui_adapter
from alfred.config.settings import Settings, SettingsError
from alfred.i18n import set_language, t
from alfred.identity import (
    IdentityResolver,
    IdentityVersionCounter,
    InProcessTokenBucketRateLimiter,
    Platform,
)
from alfred.memory.db import build_session_scope, healthcheck
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working_pool import WorkingMemoryPool
from alfred.orchestrator.core import Orchestrator
from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter
from alfred.security.dlp import OutboundDlp
from alfred.security.secrets import SecretBroker

if TYPE_CHECKING:
    from alfred.providers.base import Provider

app = typer.Typer(help=t("cli.help.root"), no_args_is_help=True)

# Identity sub-app — ``alfred user add|list|show|remove|bind|unbind|set``.
# The sub-app's commands pull their resolver and audit writer from injected
# factories (see ``alfred.identity.cli.install_factories``). Production
# bootstrap calls ``_install_identity_factories(settings)`` from both
# ``_chat_main`` (TUI) and the ``user`` subcommand callback below, so the
# resolver and writer share one engine + lifecycle across surfaces.
from alfred.identity.cli import install_factories as install_identity_factories  # noqa: E402
from alfred.identity.cli import user_app  # noqa: E402  # registered after app construction


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


# ---------------------------------------------------------------------------
# Bootstrap helpers
# ---------------------------------------------------------------------------


def _load_settings_or_die() -> Settings:
    """Load ``Settings`` from the environment or exit with a friendly hint.

    Two distinct first-time-user errors get distinct messages:

    * ``placeholder_api_key`` — the operator copied .env.example but never
      replaced the literal ``sk-...``. We surface a dedicated translatable
      message because "configuration is invalid" alongside a wall of pydantic
      detail buries the actual fix (edit one line in .env).
    * Anything else — generic ``t("error.config_invalid")`` with the raw
      pydantic detail so the operator can fix the offending field without
      grepping a stack trace.
    """
    try:
        # Settings.__init__ is annotated `# type: ignore[no-untyped-def]` in
        # settings.py (pre-existing tech debt; task-17 cleanup). Until that
        # lands, mypy --strict treats the call as untyped — surface the
        # justification at the call site rather than swallow it silently.
        return Settings()  # type: ignore[no-untyped-call]  # reason: Settings.__init__ is untyped pending task-17.
    except SettingsError as exc:
        # `placeholder_api_key` is a sentinel raised by the deepseek_api_key
        # validator. Match on substring rather than exact equality because
        # pydantic decorates the message with loc/path context.
        if "placeholder_api_key" in str(exc):
            typer.echo(t("error.placeholder_api_key"))
            raise typer.Exit(code=2) from exc
        typer.echo(t("error.config_invalid", detail=str(exc)))
        typer.echo(t("hint.copy_env_example"))
        raise typer.Exit(code=2) from exc


def _build_broker(settings: Settings) -> SecretBroker:
    return SecretBroker.from_settings(settings)


def _build_router(broker: SecretBroker, settings: Settings) -> ProviderRouter:
    """Build the slice-1 ``ProviderRouter`` from the broker's secrets.

    DeepSeek is the primary; Anthropic is wired in as the fallback only if
    the Anthropic key is configured. Slice 2 replaces this with tiered
    capability-aware routing across more providers.
    """
    primary: Provider = DeepSeekProvider.from_settings(
        api_key=broker.get("deepseek_api_key"),
        base_url=settings.deepseek_base_url,
        model=settings.deepseek_model,
    )
    fallback: Provider | None = None
    if broker.has("anthropic_api_key"):
        fallback = AnthropicProvider.from_settings(
            api_key=broker.get("anthropic_api_key"),
            model=settings.anthropic_model,
        )
    return ProviderRouter(primary=primary, fallback=fallback)


# ---------------------------------------------------------------------------
# Identity bootstrap
# ---------------------------------------------------------------------------


def _sync_db_url(settings: Settings) -> str:
    """Return a SYNC SQLAlchemy URL for the identity resolver.

    Slice-1's ``Settings.database_url`` is a ``PostgresDsn`` shaped for the
    async driver (``postgresql+asyncpg``). :class:`IdentityResolver` consumes
    a sync ``sessionmaker[Session]`` deliberately — its callers from async
    paths wrap calls in :func:`asyncio.to_thread` (see resolver docstring).
    Translate to ``postgresql+psycopg`` for the sync engine so the operator
    never has to configure two URLs.

    Handled scheme shapes:

    * ``postgresql+asyncpg://...`` — default Slice-1 settings shape; rewrite
      the driver token in place.
    * ``postgresql://...`` — no driver token; explicitly insert ``+psycopg``
      so SQLAlchemy doesn't fall back to its default driver (psycopg2),
      which is only a dev-tooling dependency on this project.
    * Anything else (``postgresql+psycopg://``, ``postgresql+pg8000://``,
      ...) — pass through. If the operator chose a sync-incompatible driver,
      SQLAlchemy itself will surface a clear engine-construction error.
    """
    url = settings.database_url.unicode_string()
    if "+asyncpg" in url:
        return url.replace("+asyncpg", "+psycopg")
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _install_identity_factories(settings: Settings) -> IdentityResolver:
    """Wire the identity-resolver + audit-writer factories used by ``alfred user *``
    and the TUI startup. Returns the resolver so the caller can read the operator.

    A single shared engine per process keeps the LRU + version counter
    coherent: the TUI's resolve at startup and a subsequent ``alfred user
    set`` invocation in the same process would otherwise see different
    counter values across two engines.

    The audit-writer factory uses the async session_scope (matching slice-1
    :class:`AuditWriter`'s contract); the resolver uses the sync sessionmaker
    described in ``_sync_db_url``.

    The version counter is attached to the returned resolver as
    ``resolver.version_counter`` so PR-B's :class:`BudgetGuard` can subscribe
    to the same instance the resolver bumps on every identity mutation —
    keeping the in-process cache-invalidation contract single-sourced.
    Phase 5 lifts this attribute promotion into the resolver's public API.
    """
    sync_engine = create_engine(_sync_db_url(settings), future=True)
    sync_factory: sessionmaker = sessionmaker(  # type: ignore[type-arg]  # reason: SA 2.0 sessionmaker has runtime-generic shape; the Session-bound form is what IdentityResolver expects and what we pass here
        sync_engine, expire_on_commit=False, future=True
    )
    version_counter = IdentityVersionCounter()
    resolver = IdentityResolver(
        session_factory=sync_factory,
        version_counter=version_counter,
        # PR D1: the in-process token-bucket limiter is the production
        # implementation. Operators have unlimited per-tier defaults, so
        # for Slice-2 single-operator deployments this is functionally
        # equivalent to the null double — but the READ_ONLY refusal path
        # is now wired and the path-shape parity matches PR D2's Discord
        # adapter.
        rate_limiter=InProcessTokenBucketRateLimiter(),
    )
    # PR-B Phase 1: pin the shared counter onto the resolver so call sites
    # that need both (e.g. the BudgetGuard wiring in ``_chat_main``) can
    # reach the same instance without crossing the resolver's
    # encapsulation. Phase 5 promotes this to a typed property.
    resolver.version_counter = version_counter  # type: ignore[attr-defined]  # reason: PR-B Phase 1 dynamic attribute; Phase 5 promotes to a typed property on IdentityResolver
    audit_session_scope = build_session_scope(settings)
    install_identity_factories(
        resolver=lambda: resolver,
        audit_writer=lambda: AuditWriter(session_factory=audit_session_scope),
    )
    return resolver


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _redact_value(v: object) -> object:
    """Mask any registered secret value inside ``v``.

    Bounded recursion: only walks through ``str``, ``Mapping``-ish ``dict``,
    ``list`` and ``tuple``. Other types pass through untouched. This keeps
    the redactor a leaf processor — we never descend into an arbitrary
    object's ``__dict__`` and accidentally trigger ``__repr__`` side effects.

    PR D1 (sec-003) routes the leaf string through
    :meth:`alfred.security.dlp.OutboundDlp.scan` instead of
    ``broker.redact`` so the operator console gains stage-2 generic-API-
    key coverage that ``broker.redact`` alone misses. The DLP instance is
    set by :func:`_configure_logging` once at bootstrap.
    """
    if _outbound_dlp_for_redact is None:
        return v
    if isinstance(v, str):
        return _outbound_dlp_for_redact.scan(v)
    if isinstance(v, dict):
        return {k: _redact_value(item) for k, item in v.items()}
    if isinstance(v, list):
        return [_redact_value(item) for item in v]
    if isinstance(v, tuple):
        return tuple(_redact_value(item) for item in v)
    return v


# Module-level handle the processor closes over. Set by ``_configure_logging``.
# A module-level handle is preferred over passing the DLP scanner through
# structlog because structlog's processor signature is fixed.
_outbound_dlp_for_redact: OutboundDlp | None = None


def _redact(_logger: object, _name: str, event_dict: EventDict) -> EventDict:
    # ``EventDict`` is a Mapping-shaped alias whose values are typed ``Any``;
    # a ``dict[str, object]`` is assignable to it under both checkers because
    # ``Any`` absorbs ``object``. No ignore needed.
    return {k: _redact_value(v) for k, v in event_dict.items()}


def _structlog_audit_sink(
    *,
    event: str,
    subject: Mapping[str, object],
) -> None:
    """No-op audit sink for the structlog-bridge DLP path.

    The DLP scanner needs an audit sink at construction time. For the
    structlog leaf-redactor we deliberately drop the audit row: emitting
    one would re-enter structlog (recursion) and the redacted value has
    already been masked from the operator's view. Slice 3 graduates this
    to a queued async write through :class:`AuditWriter`; the queue is
    drained on a supervisor tick so the audit DB stays consistent
    without re-entrancy. The signature matches
    :class:`alfred.security.dlp._AuditSink` so the same DLP construction
    pattern works for both the structlog path (no-op sink, here) and the
    Discord outbound path (real audit sink, PR D2).
    """
    # Intentional no-op. See module docstring for the recursion-avoidance
    # rationale.


def _build_adapter_dlp_audit_sink(
    *,
    audit_writer: AuditWriter,
    operator_user_id: str,
    language: str,
) -> Callable[..., None]:
    """Return a sync audit sink that persists DLP modification events.

    PR D1 wired the adapter ``OutboundDlp`` against the structlog no-op
    sink — a real gap, because DLP audit-on-modification is the security
    objective of the layer (CLAUDE.md hard rule #7 — no silent failures
    in security paths). This bridge schedules the async
    :meth:`AuditWriter.append` on the running event loop so the sync
    :class:`alfred.security.dlp._AuditSink` Protocol stays satisfied
    without blocking the scan path.

    The created task is logged on failure rather than swallowed: an
    audit-write failure must surface to the operator. We attach a
    structured ``done_callback`` that re-raises the exception via
    structlog at error level — the caller's structlog config has the
    DLP redactor in front so a re-raise here cannot leak the redacted
    value back into the log line.

    ``trust_tier_of_trigger="T2"`` because the scan ran over outbound
    content composed by an authenticated operator. ``result="modified"``
    is the literal because the sink is ONLY called on modification.
    """
    log = structlog.get_logger("alfred.cli.dlp_audit")

    def _on_done(task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("dlp.audit_write_failed", error=str(exc))

    def _sink(*, event: str, subject: Mapping[str, object]) -> None:
        loop = asyncio.get_running_loop()
        task = loop.create_task(
            audit_writer.append(
                event=event,
                actor_user_id=operator_user_id,
                # ``append`` types ``subject`` as ``dict[str, Any]``;
                # widen the read-only ``Mapping`` we receive from DLP
                # back to a fresh dict to satisfy the contract.
                subject=dict(subject),
                trust_tier_of_trigger="T2",
                result="modified",
                cost_estimate_usd=0.0,
                trace_id="dlp-outbound",
                language=language,
            )
        )
        task.add_done_callback(_on_done)

    return _sink


def _configure_logging(broker: SecretBroker) -> None:
    """Wire structlog with the DLP scanner in front of every other processor.

    Called once at bootstrap. The redactor is leaf-bounded (see
    ``_redact_value``) so any secret value caught by either
    :meth:`SecretBroker.redact` (stage 1) OR the generic-API-key regex
    (stage 2) is masked before reaching the renderer — CLAUDE.md hard
    rule #1 on logs + sec-003.
    """
    global _outbound_dlp_for_redact
    _outbound_dlp_for_redact = OutboundDlp(broker=broker, audit=_structlog_audit_sink)
    structlog.configure(
        processors=[
            _redact,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
        cache_logger_on_first_use=True,
    )


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
