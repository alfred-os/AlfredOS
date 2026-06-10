"""``alfred discord`` — Typer subcommands for the Discord comms-MCP plugin.

Two subcommands:

* ``alfred discord`` (default callback) — spawn the long-running Discord
  adapter plugin (``plugins/alfred_discord``) through the launcher and run it.
* ``alfred discord verify`` — short-lived readiness probe that spawns the
  same plugin and reports whether it launched cleanly within the probe window.

Slice-4 migration (PR-S4-10, #206)
----------------------------------

Slice-2 built the in-process :class:`alfred.comms.adapter.DiscordAdapter`
graph here and ran a 30s ``discord.py`` gateway probe with a rich exit-code
table. PR-S4-9 shipped the launcher-spawned ``plugins/alfred_discord`` plugin;
this module now repoints the CLI at it so the ``src/alfred/comms/`` deletion
(a later flag-day wave) breaks nothing. The in-process
``alfred.comms.adapter`` imports are gone.

The full Slice-4 equivalent of the rich ``alfred discord verify`` exit-code
table (login/intents/timeout) — which was a property of the now-removed
in-process probe — is tracked as a Slice-5 follow-up
(``alfred plugin verify alfred_discord``; see the PR-S4-9 plan). Until then,
``verify`` is a thin launcher-spawn readiness check: a clean launch within the
probe window exits ``0``; a launcher failure (absent/mid-restart daemon,
sandbox refusal, missing launcher binary) surfaces the
``cli.discord.daemon_required`` t() string and exits ``2``.

Boundary discipline: the launch shape is shared with ``alfred chat`` via
:mod:`alfred.cli._launcher_spawn`. The Discord plugin's manifest declares
``sandbox.kind = "full"`` so the launcher resolves the per-OS sandbox policy
before executing it.
"""

from __future__ import annotations

import asyncio
import enum
from typing import TYPE_CHECKING

import structlog
import typer

from alfred.i18n import t

if TYPE_CHECKING:
    from alfred.cli._launcher_spawn import PluginLaunchSpec

_log = structlog.get_logger(__name__)

# Readiness-probe window for ``alfred discord verify``. The Discord plugin is a
# long-running relay, not a foreground app — a launcher still alive after this
# window means it reached a live handshake (healthy); a launcher that exits
# within it failed to hand off. Operator-overridable via ``--timeout``.
_VERIFY_TIMEOUT_S = 30.0

# The Discord plugin id (launcher first positional + sandbox-policy key) and
# the ``python -m`` module the launcher executes. The plugin imports
# ``plugins.alfred_discord.*`` + the core ``alfred.comms_mcp`` protocol, both
# of which resolve from the repo root on PYTHONPATH.
_DISCORD_PLUGIN_ID = "alfred.discord"
_DISCORD_MODULE = "plugins.alfred_discord.server"


class _VerifyExitCode(enum.IntEnum):
    """Exit codes the verify subcommand returns after the comms-MCP migration.

    The Slice-2 table (UPSTREAM/LOGIN/TIMEOUT) belonged to the deleted
    in-process ``discord.py`` probe; the Slice-5 ``alfred plugin verify``
    rebuild restores per-failure granularity. Until then the launcher-spawn
    probe distinguishes only healthy vs. config/launch failure.
    """

    OK = 0
    CONFIG_FAILED = 2


discord_app = typer.Typer(
    help=t("cli.discord.help.group"),
    no_args_is_help=False,
    invoke_without_command=True,
)


@discord_app.callback()
def _default(ctx: typer.Context) -> None:
    """Spawn the long-running Discord adapter plugin when no subcommand is given.

    Typer's invoke_without_command + callback shape lets us treat the bare
    ``alfred discord`` as the boot path while still exposing
    ``alfred discord verify`` as a sibling subcommand.
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
    """Spawn the Discord plugin via the launcher as a readiness probe."""
    del ctx, timeout  # the shared probe window governs the readiness wait
    code = asyncio.run(_verify_main())
    raise typer.Exit(code=int(code))


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------


async def _boot_main() -> None:
    """Spawn ``plugins/alfred_discord`` via the launcher and run it.

    The daemon owns the orchestrator graph in Slice 4; this command is a thin
    launcher caller. A launcher failure (absent/mid-restart daemon, sandbox
    refusal, missing launcher binary) surfaces the ``cli.discord.daemon_required``
    t() string on stderr and exits non-zero — never a raw traceback.
    """
    from alfred.cli._launcher_spawn import LaunchResult, spawn_plugin_via_launcher

    outcome = await spawn_plugin_via_launcher(_build_launch_spec())
    if outcome.result is LaunchResult.FAILED:
        typer.echo(t("cli.discord.daemon_required"), err=True)
        raise typer.Exit(code=int(_VerifyExitCode.CONFIG_FAILED))


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


async def _verify_main() -> _VerifyExitCode:
    """Spawn the plugin via the launcher; return a typed readiness code.

    The Discord plugin is a long-running relay, so the HEALTHY outcome is a
    hand-off (still alive past the probe window), not a clean exit. ``verify``
    spawns with ``block_on_handoff=False`` so the seam terminates the relay and
    reports :data:`~alfred.cli._launcher_spawn.LaunchResult.HANDED_OFF` instead
    of blocking on an exit that never comes (review F3). A clean exit within the
    window is also healthy (a short-lived plugin that completed). Any launcher
    failure is ``CONFIG_FAILED``. Emits the structlog event matching the
    outcome.
    """
    from alfred.cli._launcher_spawn import LaunchResult, spawn_plugin_via_launcher

    outcome = await spawn_plugin_via_launcher(_build_launch_spec(), block_on_handoff=False)
    if outcome.result in (LaunchResult.HANDED_OFF, LaunchResult.COMPLETED):
        _log.info("discord.verify.ok", outcome=outcome.result.name)
        return _VerifyExitCode.OK
    _log.error("discord.verify.config_failed", returncode=outcome.returncode)
    typer.echo(t("cli.discord.daemon_required"), err=True)
    return _VerifyExitCode.CONFIG_FAILED


def _build_launch_spec() -> PluginLaunchSpec:
    """Build the :class:`PluginLaunchSpec` for the Discord plugin.

    Imported lazily (inside the function rather than at module top) so the
    ``alfred --help`` / autocomplete path does not pay the ``asyncio``-chain
    import cost the helper pulls in.
    """
    import uuid

    from alfred.cli._launcher_spawn import PluginLaunchSpec, repo_root

    root = repo_root()
    return PluginLaunchSpec(
        plugin_id=_DISCORD_PLUGIN_ID,
        manifest_path=root / "plugins" / "alfred_discord" / "manifest.toml",
        module=_DISCORD_MODULE,
        # The ``discord`` KIND prefix classifies T2 host-side (broadcast-shaped,
        # never T1); the suffix makes the launch traceable.
        adapter_id=f"discord-{uuid.uuid4()}",
        # The plugin imports ``plugins.alfred_discord.*`` + ``alfred.comms_mcp``;
        # both resolve from the repo root.
        import_roots=(root,),
        # A long-running relay, not a foreground app — pipe its stdio.
        inherit_stdio=False,
        # ``kind="full"`` (manifest sandbox.kind): the Discord relay is
        # adversary-facing with open egress (#230). The launcher-spawn seam
        # hands it a SCRUBBED, allowlisted env so an operator's exported
        # ANTHROPIC_API_KEY / DISCORD_BOT_TOKEN never crosses into it (F2).
        sandbox_kind="full",
    )
