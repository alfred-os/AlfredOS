"""AlfredOS CLI entry point.

This is the single bootstrap that constructs the full slice-1 graph:
``Settings`` → ``SecretBroker`` → ``ProviderRouter`` → ``BudgetGuard``
→ ``WorkingMemory`` → ``Orchestrator`` → ``AlfredTuiApp``. The CLI is the
imperative shell; every subsystem below is a pure-ish core that gets its
dependencies passed in.

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
from typing import TYPE_CHECKING, cast

import structlog
import typer
from sqlalchemy.exc import SQLAlchemyError
from structlog.types import EventDict

from alfred.budget.guard import BudgetGuard
from alfred.comms.tui import AlfredTuiApp
from alfred.config.settings import Settings, SettingsError
from alfred.i18n import set_language, t
from alfred.memory.db import build_session_scope, healthcheck
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import Role
from alfred.providers.deepseek import DeepSeekProvider
from alfred.providers.router import ProviderRouter
from alfred.security.secrets import SecretBroker

if TYPE_CHECKING:
    from alfred.providers.base import Provider

app = typer.Typer(help=t("cli.help.root"), no_args_is_help=True)

# Identity sub-app — ``alfred user add|list|show|remove|bind|unbind|set``.
# The sub-app's commands pull their resolver and audit writer from injected
# factories (see ``alfred.identity.cli.install_factories``). Production
# bootstrap wiring lands in T15 alongside the TUI startup change; for now
# importing the sub-app at module scope keeps the registration declarative
# and lets ``alfred user --help`` work without dragging in a Settings load.
from alfred.identity.cli import user_app  # noqa: E402  # registered after app construction

app.add_typer(user_app, name="user")


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
# Logging
# ---------------------------------------------------------------------------


def _redact_value(v: object) -> object:
    """Mask any registered secret value inside ``v``.

    Bounded recursion: only walks through ``str``, ``Mapping``-ish ``dict``,
    ``list`` and ``tuple``. Other types pass through untouched. This keeps
    the redactor a leaf processor — we never descend into an arbitrary
    object's ``__dict__`` and accidentally trigger ``__repr__`` side effects.

    Closes over the module-level ``_broker_for_redact`` set by
    ``_configure_logging`` so the processor function itself stays
    structlog-shaped (``(_logger, _name, event_dict) -> EventDict``).
    """
    if _broker_for_redact is None:
        return v
    if isinstance(v, str):
        return _broker_for_redact.redact(v)
    if isinstance(v, dict):
        return {k: _redact_value(item) for k, item in v.items()}
    if isinstance(v, list):
        return [_redact_value(item) for item in v]
    if isinstance(v, tuple):
        return tuple(_redact_value(item) for item in v)
    return v


# Module-level handle the processor closes over. Set by ``_configure_logging``.
# A module-level handle is preferred over passing the broker through structlog
# because structlog's processor signature is fixed.
_broker_for_redact: SecretBroker | None = None


def _redact(_logger: object, _name: str, event_dict: EventDict) -> EventDict:
    # ``EventDict`` is a Mapping-shaped alias whose values are typed ``Any``;
    # a ``dict[str, object]`` is assignable to it under both checkers because
    # ``Any`` absorbs ``object``. No ignore needed.
    return {k: _redact_value(v) for k, v in event_dict.items()}


def _configure_logging(broker: SecretBroker) -> None:
    """Wire structlog with the redactor in front of every other processor.

    Called once at bootstrap. The redactor is leaf-bounded (see
    ``_redact_value``) so any secret value caught by ``SecretBroker.redact``
    is masked before reaching the renderer — CLAUDE.md hard rule #1 on
    logs.
    """
    global _broker_for_redact
    _broker_for_redact = broker
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

    router = _build_router(broker, settings)
    budget = BudgetGuard(
        daily_usd=settings.daily_budget_usd,
        per_call_max_usd=settings.per_call_max_usd,
    )
    working = WorkingMemory()

    # Rehydrate working memory from the most recent episodes so a restart
    # doesn't lose conversational context. ``EpisodicMemory.recent`` returns
    # oldest-first so iteration order matches prompt-assembly order. Episode
    # rows store ``role`` as ``str`` while ``WorkingMemory.append`` wants the
    # ``Role`` literal — only the orchestrator writes episodes, and it
    # constrains the input to ``Role`` at write time, so the cast is honest
    # at this boundary.
    async with session_scope() as session:
        episodic = EpisodicMemory(session=session)
        recent = await episodic.recent(user_id=settings.operator_name, limit=20)
        for ep in recent:
            await working.append(role=cast(Role, ep.role), content=ep.content)

    orchestrator = Orchestrator(
        operator_name=settings.operator_name,
        operator_language=settings.operator_language,
        session_scope=session_scope,
        working=working,
        router=router,
        budget=budget,
    )
    await AlfredTuiApp(orchestrator=orchestrator).run_async()


if __name__ == "__main__":  # pragma: no cover - manual entry
    app()
