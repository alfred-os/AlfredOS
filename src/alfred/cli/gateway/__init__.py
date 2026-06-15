"""``alfred gateway`` CLI — run / inspect the AlfredOS gateway process (Spec A G3-3b-2b / #237).

The gateway is the resumable front door (ADR-0031): the process that stands in for the
daemon toward an unmodified TUI, surviving a core restart so an ``alfred chat`` session is
not torn down by a daemon bounce. This Typer group exposes it the way ``alfred daemon``
exposes the daemon:

* ``alfred gateway start`` runs the long-running :class:`alfred.gateway.process.GatewayProcess`
  under ``asyncio.run`` with SIGTERM / SIGINT wired to a shutdown event;
* ``alfred gateway status`` is a Settings-only, NON-DIALING health line (security L3 — it
  reports the gateway socket's presence + the runtime-dir posture without opening it).

perf-001: each command LAZY-imports its heavy graph inside the callback body (the relay
chain lives behind :func:`alfred.cli.gateway._commands.start_gateway`), so a plain
``import alfred.cli.gateway`` — and ``alfred --help`` rendered through it — never pulls the
gateway-process / relay import cost. Pinned by ``tests/unit/cli/test_main_lazy_imports.py``.
"""

from __future__ import annotations

import typer

from alfred.i18n import t

gateway_app = typer.Typer(help=t("gateway.help.root"), no_args_is_help=True)


@gateway_app.command("start", help=t("gateway.help.start"))
def start() -> None:
    from alfred.cli.gateway._commands import start_gateway

    start_gateway()


@gateway_app.command("status", help=t("gateway.help.status"))
def status() -> None:
    from alfred.cli.gateway._commands import status_gateway

    status_gateway()


__all__ = ["gateway_app"]
