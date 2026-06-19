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
import http.client
import os
import stat
from typing import Final

import structlog
import typer

from alfred.i18n import t
from alfred.plugins.comms_socket_transport import default_comms_socket_path

log = structlog.get_logger(__name__)

# The exit code a friendly "core / socket setup unavailable" refusal returns. Mirrors
# the daemon's non-zero refuse codes — a distinct non-zero so scripts can branch on it.
_EXIT_UNAVAILABLE = 3

# A friendly "the client socket could not be bound" refusal (e.g. ``EADDRINUSE`` —
# another gateway already holds the socket). A distinct non-zero so an operator script
# can tell "address in use" apart from "core unreachable".
_EXIT_BIND_FAILED = 4

# A friendly "the client handshake with the TUI failed" refusal. A distinct non-zero so
# a torn / malformed client leg is scriptable apart from the bind / core-dial refusals.
_EXIT_HANDSHAKE_FAILED = 5

# The adapter id the gateway dials on the core (the core binds ``comms-{adapter_kind}.sock``;
# the socket-backed ``alfred_tui`` adapter has manifest ``adapter_kind="tui"``). Operator-
# overridable via the env so the dial target is not a hidden constant (Spec B G6-0b / #288).
# The default mirrors ``alfred.gateway.core_link._DEFAULT_DIAL_ADAPTER_ID``.
_DIAL_ADAPTER_ID_ENV: Final[str] = "ALFRED_GATEWAY_DIAL_ADAPTER_ID"
_DEFAULT_DIAL_ADAPTER_ID: Final[str] = "tui"


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
    from alfred.gateway.client_link import GatewayHandshakeError
    from alfred.gateway.process import GatewayProcess

    typer.echo(t("gateway.start.starting"))

    # G6-0: stand up the Prometheus exposition before the relay so a scrape can read
    # gateway_* series. Loud-and-continue on a bind failure; the healthcheck surfaces
    # a degraded endpoint.
    from alfred.gateway.metrics_server import resolve_metrics_port, start_metrics_server

    start_metrics_server(resolve_metrics_port())

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

        dial_adapter_id = os.environ.get(_DIAL_ADAPTER_ID_ENV) or _DEFAULT_DIAL_ADAPTER_ID
        await GatewayProcess(
            shutdown_event=shutdown_event,
            dial_adapter_id=dial_adapter_id,
        ).run()

    try:
        asyncio.run(_main())
    except DaemonUnavailableError as exc:
        # Friendly refusal — the core daemon socket was unreachable. Surface a
        # next-step message + a non-zero exit rather than a bare traceback.
        log.warning("gateway.cli.core_unavailable", error=repr(exc))
        typer.echo(t("gateway.start.unavailable"))
        raise typer.Exit(code=_EXIT_UNAVAILABLE) from exc
    except GatewayHandshakeError as exc:
        # Friendly refusal — the client (TUI) handshake failed (a torn / not-ok /
        # malformed client leg). An EXPECTED operator condition, NOT a programming bug,
        # so surface a next-step message + a distinct non-zero exit, never a traceback.
        log.warning("gateway.cli.handshake_failed", error=repr(exc))
        typer.echo(t("gateway.start.handshake_failed"))
        raise typer.Exit(code=_EXIT_HANDSHAKE_FAILED) from exc
    except OSError as exc:
        # Friendly refusal — the client socket could not be bound (e.g. ``EADDRINUSE``:
        # another gateway already holds it). An EXPECTED operator condition, so surface a
        # next-step message + a distinct non-zero exit rather than a bare traceback.
        # NOTE: scoped to ``OSError`` (bind/socket faults) ONLY — a programming bug
        # (``TypeError``, ``ValueError``, …) still surfaces LOUD (CLAUDE.md hard rule #7).
        log.warning("gateway.cli.bind_failed", error=repr(exc))
        typer.echo(t("gateway.start.bind_failed"))
        raise typer.Exit(code=_EXIT_BIND_FAILED) from exc
    typer.echo(t("gateway.start.stopped"))


def status_gateway() -> None:
    """Render the gateway socket presence — a Settings-only, NON-DIALING health line.

    Security L3: this probe MUST NOT open or read the socket. It resolves the gateway
    socket path and reports presence via :meth:`Path.exists` (a lstat-free existence
    check) plus the owner-only ``0700`` posture of the runtime dir when the socket is
    present. Read-only: a missing socket (no gateway running) is NOT an error — exit 0.
    """
    # perf-001: import the gateway adapter id LAZILY from its single source of truth
    # (the listener that binds the socket), NOT a module-top re-declaration — so the
    # status probe resolves the EXACT path the listener binds and a future rename
    # cannot drift them apart. The import is local because ``alfred.gateway`` eagerly
    # pulls the relay graph (``alfred.gateway.process`` / ``relay``), which the
    # ``alfred --help`` path must never pay (pinned by ``test_main_lazy_imports.py``).
    from alfred.gateway.client_listener import _GATEWAY_ADAPTER_ID

    socket_path = default_comms_socket_path(_GATEWAY_ADAPTER_ID)
    if not socket_path.exists():
        typer.echo(t("gateway.status.socket_absent", path=str(socket_path)))
        return
    # The socket is present — report it alongside the runtime-dir posture. The mode is a
    # stat of the PARENT dir (the owner-only 0700 guarantee), NOT a connect: presence +
    # perms is all a non-dialing probe is permitted to read (security L3).
    #
    # TOCTOU: the runtime dir can vanish between the ``exists()`` check above and this
    # stat (a concurrent reaper / a ``rm -rf ~/.run``). A raw ``OSError`` here would
    # surface as a traceback, breaking this command's "never a raw traceback" contract,
    # so a vanished dir falls back to the friendly socket-absent line + exit 0 — the
    # socket is, by then, genuinely gone.
    try:
        runtime_mode = stat.S_IMODE(socket_path.parent.stat().st_mode)
    except OSError:
        typer.echo(t("gateway.status.socket_absent", path=str(socket_path)))
        return
    typer.echo(
        t(
            "gateway.status.socket_present",
            path=str(socket_path),
            runtime_mode=f"{runtime_mode:#o}",
            uid=os.getuid(),
        )
    )


_HEALTHCHECK_HOST: Final[str] = "127.0.0.1"
_HEALTHCHECK_TIMEOUT_S: Final[float] = 2.0
_BREAKER_METRIC: Final[str] = "gateway_circuit_breaker_open"
_EXIT_UNHEALTHY: Final[int] = 1


def _fetch_metrics_text(port: int) -> str:
    """GET the gateway /metrics exposition text over loopback.

    Uses ``http.client`` against a FIXED loopback host (no dynamic-URL / SSRF surface).
    Raises ``OSError`` (e.g. ConnectionRefusedError / TimeoutError) when the endpoint is
    unreachable — i.e. the gateway is not serving.
    """
    conn = http.client.HTTPConnection(_HEALTHCHECK_HOST, port, timeout=_HEALTHCHECK_TIMEOUT_S)
    try:
        conn.request("GET", "/metrics")
        body: bytes = conn.getresponse().read()
    finally:
        conn.close()
    # Lossless-safe decode: a non-UTF-8 body must not raise UnicodeDecodeError (a
    # ValueError, not OSError) and escape the healthcheck's "never a traceback" contract.
    return body.decode("utf-8", errors="replace")


def _breaker_latched(metrics_text: str) -> bool:
    """True iff a gateway_circuit_breaker_open SAMPLE reports >= 1.

    Skips ``# HELP`` / ``# TYPE`` comment lines and any line whose value cannot be
    parsed as a float (a malformed/exemplar line must never crash the HEALTHCHECK
    process with a traceback).
    """
    # The gateway breaker gauge is unlabelled by design, so prometheus emits the bare
    # "name value" form; a future labelled variant ("name{...} value") would need a parser change.
    sample_prefix = f"{_BREAKER_METRIC} "
    for line in metrics_text.splitlines():
        if line.startswith("#"):
            continue
        if not line.startswith(sample_prefix):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            return float(parts[1]) >= 1.0
        except ValueError:
            continue
    return False


def healthcheck_gateway() -> None:
    """Two-tier Docker healthcheck (G6-0).

    Liveness: the /metrics endpoint is reachable. Readiness: the ReplayBuffer
    back-pressure breaker is NOT latched. A core-down gateway that is buffering is
    HEALTHY (only wedged-past-breaker is unhealthy). Exits 0 (healthy) or 1
    (unhealthy); never raises a traceback.
    """
    from alfred.gateway.metrics_server import resolve_metrics_port

    try:
        port = resolve_metrics_port()
    except ValueError as exc:
        # Malformed ALFRED_GATEWAY_METRICS_PORT — can't probe; report unhealthy, not a traceback.
        log.warning("gateway.healthcheck.unreachable", port="unset", error=repr(exc))
        typer.echo(t("gateway.healthcheck.unreachable", port="unset"))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    try:
        metrics_text = _fetch_metrics_text(port)
    except OSError as exc:
        log.warning("gateway.healthcheck.unreachable", port=port, error=repr(exc))
        typer.echo(t("gateway.healthcheck.unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    if _breaker_latched(metrics_text):
        log.warning("gateway.healthcheck.breaker_open")
        typer.echo(t("gateway.healthcheck.breaker_open"))
        raise typer.Exit(code=_EXIT_UNHEALTHY)


__all__ = ["healthcheck_gateway", "start_gateway", "status_gateway"]
