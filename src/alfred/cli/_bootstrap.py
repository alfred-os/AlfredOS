"""Shared CLI bootstrap helpers.

This module exists to break the import cycle between
:mod:`alfred.cli.main` and :mod:`alfred.cli.discord_cmd`:

* ``main.py`` registers the ``alfred discord`` sub-app at top-level so
  Typer surfaces the subcommand in ``--help`` output.
* ``discord_cmd.py`` needs the same dependency-graph helpers
  (``_load_settings_or_die``, ``_build_broker``, ``_configure_logging``,
  ``_install_identity_factories``, ``_build_router``,
  ``_structlog_audit_sink``) that ``main._chat_main`` uses, so the
  Discord boot path and the TUI boot path stay in lockstep.

Pre-D2 the helpers lived in ``main.py`` and ``discord_cmd.py`` imported
them inside its function bodies — that's a deferred import on one edge
but the other edge (``main`` → ``discord_cmd``) is eager, which CodeQL
flags as ``py/cyclic-import`` regardless of laziness on the other
side. Extracting the helpers here is the structural fix.

All names are underscore-prefixed because they're internal-to-the-CLI:
external consumers go through the public Typer surface
(``alfred status``, ``alfred chat``, ``alfred discord ...``).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

import structlog
import typer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from structlog.types import EventDict

from alfred.audit.log import AuditWriter
from alfred.config.settings import Settings, SettingsError
from alfred.i18n import t
from alfred.identity import (
    IdentityResolver,
    IdentityVersionCounter,
    InProcessTokenBucketRateLimiter,
)
from alfred.identity.cli import install_factories as install_identity_factories
from alfred.memory.db import build_session_scope
from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter
from alfred.security.dlp import OutboundDlp
from alfred.security.secrets import SecretBroker

if TYPE_CHECKING:
    from alfred.providers.base import Provider


__all__ = [
    "build_adapter_dlp_audit_sink",
    "build_broker",
    "build_router",
    "configure_logging",
    "install_identity_factories_for_settings",
    "load_settings_or_die",
    "structlog_audit_sink",
    "sync_db_url",
]


# Module-level handle the structlog redactor closes over. Set by
# :func:`configure_logging`.
_outbound_dlp_for_redact: OutboundDlp | None = None


def load_settings_or_die() -> Settings:
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


def build_broker(settings: Settings) -> SecretBroker:
    """Construct the slice-1 :class:`SecretBroker` from operator settings."""
    return SecretBroker.from_settings(settings)


def build_router(broker: SecretBroker, settings: Settings) -> ProviderRouter:
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


def sync_db_url(settings: Settings) -> str:
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


def install_identity_factories_for_settings(settings: Settings) -> IdentityResolver:
    """Wire identity-resolver + audit-writer factories used across surfaces.

    A single shared engine per process keeps the LRU + version counter
    coherent: the TUI's resolve at startup and a subsequent ``alfred user
    set`` invocation in the same process would otherwise see different
    counter values across two engines.

    The audit-writer factory uses the async session_scope (matching slice-1
    :class:`AuditWriter`'s contract); the resolver uses the sync sessionmaker
    described in :func:`sync_db_url`.

    The version counter is attached to the returned resolver as
    ``resolver.version_counter`` so PR-B's :class:`BudgetGuard` can subscribe
    to the same instance the resolver bumps on every identity mutation —
    keeping the in-process cache-invalidation contract single-sourced.
    Phase 5 lifts this attribute promotion into the resolver's public API.
    """
    sync_engine = create_engine(sync_db_url(settings), future=True)
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
    set by :func:`configure_logging` once at bootstrap.
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


def _redact(_logger: object, _name: str, event_dict: EventDict) -> EventDict:
    # ``EventDict`` is a Mapping-shaped alias whose values are typed ``Any``;
    # a ``dict[str, object]`` is assignable to it under both checkers because
    # ``Any`` absorbs ``object``. No ignore needed.
    return {k: _redact_value(v) for k, v in event_dict.items()}


def structlog_audit_sink(
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
    del event, subject


def build_adapter_dlp_audit_sink(
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


def configure_logging(broker: SecretBroker) -> None:
    """Wire structlog with the DLP scanner in front of every other processor.

    Called once at bootstrap. The redactor is leaf-bounded (see
    :func:`_redact_value`) so any secret value caught by either
    :meth:`SecretBroker.redact` (stage 1) OR the generic-API-key regex
    (stage 2) is masked before reaching the renderer — CLAUDE.md hard
    rule #1 on logs + sec-003.
    """
    global _outbound_dlp_for_redact
    _outbound_dlp_for_redact = OutboundDlp(broker=broker, audit=structlog_audit_sink)
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
