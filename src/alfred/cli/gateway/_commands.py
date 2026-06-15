"""``alfred gateway`` command bodies — run / inspect the gateway process (Spec A G3-3b-2b / #237).

Two operator commands, mirroring ``alfred daemon``:

* :func:`start_gateway` runs the long-running :class:`alfred.gateway.process.GatewayProcess`
  under :func:`asyncio.run`. It installs SIGTERM + SIGINT handlers that SET the shutdown
  event (so a clean stop unwinds the relay + reaps the listener); on a platform / loop that
  cannot install them (a non-main-thread loop raises ``NotImplementedError`` / ``ValueError``)
  it logs the LOUD ``gateway.cli.signal_handler_unavailable`` key and CONTINUES — falling
  back to ``asyncio.run`` translating ``KeyboardInterrupt`` into a cancel, which
  :meth:`GatewayProcess.run`'s ``finally`` reaps regardless (security M2). A core / socket
  setup failure surfaces as a FRIENDLY message + non-zero exit, never a raw traceback.
* :func:`status_gateway` is a Settings-only health line: it checks the gateway socket's
  presence with :meth:`Path.exists` + a stat of the runtime-dir posture and echoes one of
  two ``t()`` lines, exit 0. **It MUST NOT dial or read the socket** (security L3 — no
  un-authenticated wire read from a status probe).

perf-001: the heavy gateway graph (``alfred.gateway.process`` / ``relay``) is imported
LAZILY inside :func:`start_gateway`, so ``alfred --help`` never pulls the relay chain
(pinned by ``tests/unit/cli/test_main_lazy_imports.py``).
"""

from __future__ import annotations

import asyncio
import os
import stat

import structlog
import typer

from alfred.i18n import t
from alfred.plugins.comms_socket_transport import default_comms_socket_path

log = structlog.get_logger(__name__)

# The gateway's own stable client-facing socket id (spec §10) — the
# ``GatewayClientListener`` binds ``comms-gateway.sock`` keyed on this id, so the
# status probe resolves the same path. Single source of truth with
# :data:`alfred.gateway.client_listener._GATEWAY_ADAPTER_ID`.
_GATEWAY_ADAPTER_ID = "gateway"

# The exit code a friendly "core / socket setup unavailable" refusal returns. Mirrors
# the daemon's non-zero refuse codes — a distinct non-zero so scripts can branch on it.
_EXIT_UNAVAILABLE = 3


def start_gateway() -> None:
    """Run the long-running gateway process until SIGTERM / SIGINT (Spec A G3-3b-2b).

    Builds the shutdown :class:`asyncio.Event`, installs the signal handlers that set it
    (loud-and-continue if the loop cannot), then awaits :meth:`GatewayProcess.run` under
    :func:`asyncio.run`. A core / socket setup failure (e.g. a daemon-unreachable dial)
    is mapped to a FRIENDLY operator message + a non-zero exit — never a raw traceback.
    """
    # perf-001: the relay graph imports lazily here, not at module-top, so
    # ``alfred --help`` never pays the gateway-process import cost.
    from alfred.comms_mcp.errors import DaemonUnavailableError
    from alfred.gateway.process import GatewayProcess

    typer.echo(t("gateway.start.starting"))

    async def _main() -> None:
        shutdown_event = asyncio.Event()
        loop = asyncio.get_running_loop()

        import signal

        def _request_shutdown() -> None:
            shutdown_event.set()

        try:
            loop.add_signal_handler(signal.SIGTERM, _request_shutdown)
            loop.add_signal_handler(signal.SIGINT, _request_shutdown)
        except (NotImplementedError, ValueError):
            # Loud-and-continue (NEVER silent): a non-main-thread loop / a platform
            # without ``add_signal_handler`` cannot install the handlers. The process
            # still runs — ``asyncio.run`` translates a ``KeyboardInterrupt`` into a
            # cancel, and ``GatewayProcess.run``'s ``finally`` reaps regardless
            # (security M2). The operator just loses the SIGTERM-driven clean stop.
            log.warning("gateway.cli.signal_handler_unavailable")

        await GatewayProcess(shutdown_event=shutdown_event).run()

    try:
        asyncio.run(_main())
    except DaemonUnavailableError as exc:
        # Friendly refusal — the core daemon socket was unreachable. Surface a
        # next-step message + a non-zero exit rather than a bare traceback.
        log.warning("gateway.cli.core_unavailable", error=repr(exc))
        typer.echo(t("gateway.start.unavailable"))
        raise typer.Exit(code=_EXIT_UNAVAILABLE) from exc
    typer.echo(t("gateway.start.stopped"))


def status_gateway() -> None:
    """Render the gateway socket presence — a Settings-only, NON-DIALING health line.

    Security L3: this probe MUST NOT open or read the socket. It resolves the gateway
    socket path and reports presence via :meth:`Path.exists` (a lstat-free existence
    check) plus the owner-only ``0700`` posture of the runtime dir when the socket is
    present. Read-only: a missing socket (no gateway running) is NOT an error — exit 0.
    """
    socket_path = default_comms_socket_path(_GATEWAY_ADAPTER_ID)
    if not socket_path.exists():
        typer.echo(t("gateway.status.socket_absent", path=str(socket_path)))
        return
    # The socket is present — report it alongside the runtime-dir posture. The mode is a
    # stat of the PARENT dir (the owner-only 0700 guarantee), NOT a connect: presence +
    # perms is all a non-dialing probe is permitted to read (security L3).
    runtime_mode = stat.S_IMODE(socket_path.parent.stat().st_mode)
    typer.echo(
        t(
            "gateway.status.socket_present",
            path=str(socket_path),
            runtime_mode=f"{runtime_mode:#o}",
            uid=os.getuid(),
        )
    )


__all__ = ["start_gateway", "status_gateway"]
