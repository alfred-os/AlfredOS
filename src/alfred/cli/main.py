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

from typing import Annotated

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
def login(
    user: Annotated[
        str | None, typer.Option("--as", "--user", help=t("cli.login.help.user"))
    ] = None,
    expires_in: Annotated[
        str | None, typer.Option("--expires-in", help=t("cli.login.help.expires_in"))
    ] = None,
    refresh: Annotated[bool, typer.Option("--refresh", help=t("cli.login.help.refresh"))] = False,
) -> None:
    """Create or refresh the operator session (#153).

    Top-level verb (mirrors ``alfred status`` / ``alfred chat``). The heavy
    broker + SQLAlchemy chain is imported lazily inside the impl so
    ``alfred --help`` does not pay it (PR-S3-6 §8.5 perf lesson).
    """
    import asyncio

    from alfred.cli.operator_session import _build_deps, login_impl

    asyncio.run(login_impl(_build_deps(), as_user=user, expires_in=expires_in, refresh=refresh))


@app.command()
def logout() -> None:
    """Revoke and delete the current operator session (#153)."""
    import asyncio

    from alfred.cli.operator_session import _build_deps, logout_impl

    asyncio.run(logout_impl(_build_deps()))


@app.command()
def whoami() -> None:
    """Print the currently-bound operator (#153)."""
    import asyncio

    from alfred.cli.operator_session import _build_deps, whoami_impl

    asyncio.run(whoami_impl(_build_deps()))


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


# The launcher's handshake-probe window (spec §8.7 / core-005). If the
# launcher exits non-zero within this window the daemon is absent or
# mid-restart; if it is still running after the window the TUI is live and
# owns the operator's terminal. devex-003: the operator retries from the
# shell rather than the plugin silently waiting in the foreground.
_LAUNCHER_PROBE_TIMEOUT_S = 2.5


async def _chat_main() -> None:
    """Spawn ``plugins/alfred_tui`` via the launcher and hand it the terminal.

    Slice 4 (PR-S4-10, #206) inverts the Slice-2/3 model: the in-process
    Textual launch (Settings → broker → orchestrator → in-process adapter)
    is replaced by a thin spawn of the TUI MCP plugin through
    ``bin/alfred-plugin-launcher.sh``. The daemon owns the orchestrator
    graph now (spec §3.1); the CLI is just a launcher caller, so none of
    the Slice-2 heavy imports (orchestrator, broker, providers, SQLAlchemy
    session scope, DLP, audit writer, in-process comms adapter) are pulled
    in here any longer.

    The launcher is invoked with the real PR-S4-6 contract — positional
    ``<plugin_id> <executable> [args...]`` with the manifest path on
    ``ALFRED_PLUGIN_MANIFEST_PATH`` — NOT the ``--manifest``/``--adapter-id``
    flags an earlier plan draft assumed (the launcher has no such flags).
    The TUI plugin's manifest declares ``sandbox.kind = "none"`` so the
    launcher ``exec``s the plugin with the CLI's inherited PTY fds, which
    the Textual app needs to render.

    Daemon-missing / daemon-mid-restart path (spec §8.7): the launcher
    fails (non-zero exit within the probe window, a missing launcher
    binary, or an OS spawn error) → the CLI emits the parameterless
    ``comms.tui.daemon_required_to_chat`` t() string on stderr and exits
    code 3 (the same startup-failure code the Postgres-unreachable branch
    used in Slice 2). The plugin never silently waits in its own process.

    perf-001: ``asyncio``/``os``/``shlex``/``uuid`` import lazily so the
    ``alfred --help`` path — which never invokes ``chat`` — pays nothing.
    """
    import asyncio
    import os
    import shlex
    import sys
    import uuid
    from pathlib import Path

    set_language(_operator_language())

    # Repo-root-relative defaults. The launcher + manifest + plugin source
    # ship in-tree; an operator running ``alfred chat`` from the repo root
    # (or with the package installed alongside ``bin/``/``plugins/``) gets
    # the right paths. ``ALFRED_PLUGIN_LAUNCHER`` overrides the launcher
    # for tests + bespoke deployments.
    repo_root = Path(__file__).resolve().parents[3]
    launcher = os.environ.get(
        "ALFRED_PLUGIN_LAUNCHER",
        str(repo_root / "bin" / "alfred-plugin-launcher.sh"),
    )
    manifest_path = repo_root / "plugins" / "alfred_tui" / "manifest.toml"
    plugin_src = repo_root / "plugins" / "alfred_tui" / "src"

    # Per-instance comms-MCP adapter id. The ``tui`` KIND prefix is the
    # contract the host's ``_ingest_tier`` keys on (T1 for the operator);
    # the suffix makes the id unique per launch. The daemon delivers it to
    # the plugin over the ``lifecycle.start`` wire request — the CLI only
    # mints it so the launch is traceable.
    adapter_id = f"tui-{uuid.uuid4()}"

    # ``alfred_tui`` lives under the plugin's own ``src/`` (not the core
    # package), and the server imports both ``alfred.comms_mcp`` (repo
    # root) and ``alfred_tui`` (plugin src). Hand the child a PYTHONPATH
    # spanning both. The kind="none" launcher ``exec``s the executable
    # directly, inheriting this env (unlike the daemon's scrubbed
    # subprocess path), so the child resolves both import roots.
    child_env = dict(os.environ)
    child_env["ALFRED_PLUGIN_MANIFEST_PATH"] = str(manifest_path)
    child_env["ALFRED_PLUGIN_ADAPTER_ID"] = adapter_id
    existing_pythonpath = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(plugin_src), str(repo_root), existing_pythonpath) if p
    )

    cmd = [
        *shlex.split(launcher),
        "alfred_tui",
        sys.executable,
        "-m",
        "alfred_tui.server",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=None,
            stdout=None,
            stderr=None,
            env=child_env,
        )
    except (FileNotFoundError, OSError):
        # Missing launcher binary / OS-level spawn failure. The daemon
        # contract is unmet — surface the friendly t() string, not a
        # traceback.
        typer.echo(t("comms.tui.daemon_required_to_chat"), err=True)
        raise typer.Exit(code=3) from None

    # Probe window: a launcher that exits non-zero within the window means
    # the daemon is absent or mid-restart. A launcher still alive after the
    # window has handed the live TUI the terminal — re-await it without a
    # deadline so the operator's session runs to completion.
    try:
        returncode = await asyncio.wait_for(proc.wait(), timeout=_LAUNCHER_PROBE_TIMEOUT_S)
    except TimeoutError:
        returncode = await proc.wait()

    if returncode != 0:
        typer.echo(t("comms.tui.daemon_required_to_chat"), err=True)
        raise typer.Exit(code=3)


def _operator_language() -> str:
    """Resolve the operator language for the chat surface without the heavy graph.

    The Slice-2 chat path loaded ``Settings`` purely to read
    ``operator_language`` (and to build the now-daemon-owned orchestrator
    graph). The launcher-spawn path needs only the language for the one
    ``t()`` string it may emit, so read it from the environment with the
    same default the settings model uses. Falling back to ``"en"`` keeps
    the daemon-required message legible even on an unconfigured host.
    """
    import os

    return os.environ.get("ALFRED_OPERATOR_LANGUAGE", "en")


if __name__ == "__main__":  # pragma: no cover - manual entry
    app()
