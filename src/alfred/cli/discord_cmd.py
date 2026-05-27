"""``alfred discord`` — Typer subcommands for the Discord adapter.

Two subcommands:

* ``alfred discord`` (default callback) — boot the long-running
  :class:`DiscordAdapter`. Constructs the full Slice-2 dependency
  graph and awaits the gateway connection.
* ``alfred discord verify`` — short-lived 30s probe that confirms the
  bot token + intents + secrets file are valid before the operator
  daemonises the long-running service. Exit-code table per spec §2
  lines 130-138 — every code is pinned by a dedicated unit test in
  ``tests/unit/comms/test_discord.py``.

Exit codes (verify):

    0   on_ready fired within 30s — bot is healthy
    1   unrecoverable upstream — gateway 5xx, repeated reconnect
    2   config — bad token, intents off, missing perms, secrets file unreadable
    3   LoginFailure (typed) — token rejected at handshake
    4   timeout — 30s elapsed without on_ready
    130 SIGINT — operator pressed ^C

Boundary discipline: this module imports the adapter ONLY through the
allowlisted :func:`alfred.comms.adapter.build_discord_adapter` and
:func:`alfred.comms.adapter.run_discord_verify_probe` factories. Direct
imports of ``alfred.comms.discord`` would fail the import-isolation
test in ``tests/unit/comms/test_no_direct_adapter_imports.py``.
"""

from __future__ import annotations

import asyncio
import enum

import structlog
import typer

from alfred.i18n import t
from alfred.security.secrets import SecretBrokerConfigError, UnknownSecretError

_log = structlog.get_logger(__name__)

# Verify subcommand's wall-clock timeout. Spec §2 line 134.
_VERIFY_TIMEOUT_S = 30.0


class _VerifyExitCode(enum.IntEnum):
    """Exit codes the verify subcommand returns.

    Mirrors spec §2 lines 130-138 — keep in lockstep. Tests pin one
    branch per value via the ``client_factory`` mock seam in
    ``tests/unit/comms/test_discord.py``.
    """

    OK = 0
    UPSTREAM_UNRECOVERABLE = 1
    CONFIG_FAILED = 2
    LOGIN_FAILED = 3
    TIMEOUT = 4
    INTERRUPTED = 130


discord_app = typer.Typer(
    help=t("cli.discord.help.group"),
    no_args_is_help=False,
    invoke_without_command=True,
)


@discord_app.callback()
def _default(ctx: typer.Context) -> None:
    """Boot the long-running Discord adapter when no subcommand is given.

    Typer's invoke_without_command + callback shape lets us treat the
    bare ``alfred discord`` as the boot path while still exposing
    ``alfred discord verify`` as a sibling subcommand. The subcommand
    handler swap is what makes the documented surface
    ``alfred discord`` / ``alfred discord verify`` work.
    """
    if ctx.invoked_subcommand is not None:
        # A subcommand will run; nothing to do here.
        return
    asyncio.run(_boot_main())


@discord_app.command("verify", help=t("cli.discord.help.verify.short"))
def verify(
    ctx: typer.Context,
    timeout: float = typer.Option(
        _VERIFY_TIMEOUT_S,
        "--timeout",
        help=t("cli.discord.help.verify.timeout"),
        min=1.0,
    ),
) -> None:
    """Run a 30s gateway-readiness probe and exit with the code table."""
    del ctx
    code = asyncio.run(_verify_main(timeout_s=timeout))
    raise typer.Exit(code=int(code))


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------


async def _boot_main() -> None:
    """Construct the full Slice-2 dependency graph + run the adapter.

    Mirrors :func:`alfred.cli.main._chat_main` for the Discord path —
    both paths share the dependency-graph helpers in
    :mod:`alfred.cli._bootstrap` so the Discord boot path stays in
    lockstep with the TUI boot path:

    * ``Settings`` → ``SecretBroker`` (file backend required for the
      Discord token) → DB healthcheck → IdentityResolver → ProviderRouter
      → BudgetGuard → WorkingMemoryPool → OutboundDlp → RateLimiter →
      Orchestrator → DiscordAdapter.

    Any failure before ``adapter.run()`` exits with a friendly t()-routed
    message + non-zero code. Imports are deferred so the autocomplete
    path stays light.
    """
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
    from alfred.comms.adapter import build_discord_adapter
    from alfred.i18n import set_language
    from alfred.identity import InProcessTokenBucketRateLimiter, Platform
    from alfred.memory.db import build_session_scope, healthcheck
    from alfred.memory.episodic import EpisodicMemory
    from alfred.memory.working_pool import WorkingMemoryPool
    from alfred.orchestrator.core import Orchestrator
    from alfred.security.dlp import OutboundDlp

    settings = load_settings_or_die()
    try:
        broker = build_broker(settings)
        broker.get("discord_bot_token")
    except SecretBrokerConfigError as exc:
        typer.echo(
            t("cli.discord.verify.config_failed.secrets_unreadable", detail=str(exc)),
            err=True,
        )
        raise typer.Exit(code=int(_VerifyExitCode.CONFIG_FAILED)) from exc
    except UnknownSecretError as exc:
        typer.echo(
            t("cli.discord.verify.config_failed.bad_token", detail=str(exc)),
            err=True,
        )
        raise typer.Exit(code=int(_VerifyExitCode.CONFIG_FAILED)) from exc

    configure_logging(broker)
    set_language(settings.operator_language)
    session_scope = build_session_scope(settings)

    try:
        await healthcheck(session_scope)
    except SQLAlchemyError as exc:
        # Route to stderr for consistency with the secrets-error branches
        # above (CR comment on PR #106 — minor). Other surfaces also send
        # error chatter to stderr (typer.echo(..., err=True) is the
        # convention; bare typer.echo writes to stdout).
        typer.echo(t("error.postgres_unreachable", detail=str(exc)), err=True)
        typer.echo(t("hint.is_compose_up"), err=True)
        raise typer.Exit(code=3) from exc

    resolver = install_identity_factories_for_settings(settings)
    # Resolve the canonical operator row so the adapter-DLP audit sink can
    # attribute outbound-redaction events to a real user_id. Migration
    # 0004 backfills the operator under ``Platform.TUI`` regardless of
    # which adapter the operator launches first — mirrors the TUI boot
    # in ``cli/main.py``.
    operator = await asyncio.to_thread(resolver.resolve, Platform.TUI, settings.operator_name)
    if operator is None:
        typer.echo(t("cli.user.error.no_operator"), err=True)
        raise typer.Exit(code=2)
    router = build_router(broker, settings)
    budget = BudgetGuard(
        user_loader=lambda user_id: resolver.show(slug=user_id),
        per_call_max_usd=settings.per_call_max_usd,
        version_counter=resolver.version_counter,  # type: ignore[attr-defined]  # reason: counter promoted via _install_identity_factories
    )
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
    # Adapter outbound DLP wires a PERSISTENT audit sink — not the
    # structlog-bridge no-op. DLP audit-on-modification is the security
    # objective of the layer (CLAUDE.md hard rule #7). The persistent
    # sink schedules an async ``AuditWriter.append`` on the running
    # event loop so the synchronous ``_AuditSink`` Protocol stays
    # satisfied without blocking the scan path. Mirrors the TUI boot's
    # wiring in ``cli/main.py`` so both adapters share lifecycle.
    audit = AuditWriter(session_factory=session_scope)
    adapter_dlp_audit_sink = build_adapter_dlp_audit_sink(
        audit_writer=audit,
        operator_user_id=operator.slug,
        language=settings.operator_language,
    )
    outbound_dlp = OutboundDlp(broker=broker, audit=adapter_dlp_audit_sink)
    rate_limiter = InProcessTokenBucketRateLimiter()
    adapter = build_discord_adapter(
        orchestrator=orchestrator,
        identity_resolver=resolver,
        broker=broker,
        outbound_dlp=outbound_dlp,
        rate_limiter=rate_limiter,
        working_pool=working_pool,
        audit=audit,
    )
    await adapter.start()
    try:
        await adapter.run()
    finally:
        await adapter.stop()


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


async def _verify_main(*, timeout_s: float = _VERIFY_TIMEOUT_S) -> _VerifyExitCode:
    """Run the 30s probe; return a typed exit code.

    Implementation lives in :func:`alfred.comms.adapter.run_discord_verify_probe`
    — the allowlisted facade that defers the ``discord.py`` import to
    runtime use. The CLI maps the returned plain-int code onto its own
    typed enum and emits the structlog event with the returned key +
    kwargs.
    """
    from alfred.cli._bootstrap import build_broker, load_settings_or_die
    from alfred.comms.adapter import run_discord_verify_probe
    from alfred.security.dlp import OutboundDlp

    try:
        settings = load_settings_or_die()
        broker = build_broker(settings)
    except (SystemExit, typer.Exit):
        _log.error("discord.verify.config_failed")
        return _VerifyExitCode.CONFIG_FAILED
    except SecretBrokerConfigError:
        _log.exception("discord.verify.config_failed.secrets_unreadable")
        return _VerifyExitCode.CONFIG_FAILED

    outbound_dlp = OutboundDlp(broker=broker, audit=lambda **_kw: None)
    code, event_key, event_kwargs = await run_discord_verify_probe(
        broker=broker,
        outbound_dlp=outbound_dlp,
        timeout_s=timeout_s,
    )
    if code == 0:
        _log.info(event_key, **event_kwargs)
    else:
        _log.error(event_key, **event_kwargs)
    try:
        return _VerifyExitCode(code)
    except ValueError:
        # Defensive: any unrecognised code from the probe collapses to
        # UPSTREAM_UNRECOVERABLE so the CLI still exits non-zero.
        return _VerifyExitCode.UPSTREAM_UNRECOVERABLE
