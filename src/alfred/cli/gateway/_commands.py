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
from collections.abc import Iterator
from typing import Final, NoReturn, Protocol

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

# A friendly "the hosted-adapter config could not be resolved" refusal. The adapter-id
# resolution does manifest I/O, so an unreadable / missing manifest (an ``OSError``) or a
# malformed manifest (a :class:`ManifestError`) is a CONFIG fault — a distinct non-zero so
# an operator script (and the operator) sees a config-fault remediation, NOT the socket
# ``bind_failed`` line (which mislabels the cause). Resolved BEFORE the socket bind so a
# config fault can never be swallowed by the bind ``except OSError`` (CLAUDE.md hard #7).
_EXIT_CONFIG_FAILED = 6

# A friendly "the egress forward-proxy could not bind" refusal (Spec C G7-1b / #333). The
# gateway is the SOLE external egress plane, so a proxy bind failure is FAIL-CLOSED: it
# refuses the start (a distinct non-zero so an operator can tell an egress-plane outage apart
# from the client-socket bind / core-dial / config refusals) and the gateway crash-loops
# under ``restart: unless-stopped`` — the intended I/O-plane posture (CONTRAST the metrics
# server's loud-and-continue: the proxy IS the gateway's reason to exist, hard rule #7).
_EXIT_EGRESS_PROXY_BIND_FAILED = 7

# A friendly "the mode-(b) tool-egress relay could not bind" refusal (Spec C G7-2b /
# #333). Like the CONNECT proxy, the relay is a gateway egress plane, so a bind
# failure is FAIL-CLOSED — a DISTINCT non-zero (apart from the proxy / client-socket
# / core-dial / config refusals) so an operator can tell a relay-plane outage apart,
# and the gateway crash-loops under ``restart: unless-stopped``.
_EXIT_EGRESS_RELAY_BIND_FAILED = 8

# A friendly "the Discord-adapter AF_UNIX egress socket could not bind" refusal (Spec C
# G7-4 / #333). Like the CONNECT proxy and the relay, the adapter egress listener is a
# gateway egress plane, so a bind failure is FAIL-CLOSED — a DISTINCT non-zero (apart
# from the proxy / relay / client-socket / core-dial / config refusals) so an operator
# can tell an adapter-egress-plane outage apart, and the gateway crash-loops under
# ``restart: unless-stopped``.
_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED = 9

# A friendly "a hosted adapter's credential was refused" refusal (#469 [R1]). Distinct
# non-zero so an operator / healthcheck can tell a credential misconfig apart from the
# egress / bind / config refusals. Fail-closed: the gateway still aborts and crash-loops
# under ``restart: unless-stopped`` — this arm only replaces the raw traceback with a
# legible message (surviving the abort is #331; a wrong token is #493).
_EXIT_ADAPTER_SPAWN_FAILED = 10

# The adapter id the gateway dials on the core (the core binds ``comms-{adapter_kind}.sock``;
# the socket-backed ``alfred_tui`` adapter has manifest ``adapter_kind="tui"``). Operator-
# overridable via the env so the dial target is not a hidden constant (Spec B G6-0b / #288).
# The default mirrors ``alfred.gateway.core_link._DEFAULT_DIAL_ADAPTER_ID``.
_DIAL_ADAPTER_ID_ENV: Final[str] = "ALFRED_GATEWAY_DIAL_ADAPTER_ID"
_DEFAULT_DIAL_ADAPTER_ID: Final[str] = "tui"

# The TUI is the foreground DIAL-IN leg (it dials the gateway over the client socket),
# NOT a gateway-SPAWNED adapter child. So it is excluded from the supervised
# ``adapter_ids`` set even if an operator lists it in ``comms_enabled_adapters`` — the
# gateway never bwrap-spawns the TUI. Compared against the CANONICAL ``adapter_kind``
# (``tui``), not the plugin-package id (``alfred_tui``), so a TUI listed by either name
# is excluded after the resolve seam below.
_TUI_DIAL_IN_ADAPTER_ID: Final[str] = "tui"


def _resolve_adapter_kind(plugin_package_id: str) -> str:
    """Map one enabled plugin-package id to its canonical ``adapter_id`` (G6-5 Task 10, #288).

    THE single adapter-id reconciliation seam. ``Settings.comms_enabled_adapters`` holds
    the **plugin-package id** — the ``plugins/<id>/`` directory name (``alfred_discord``) —
    because its validator probes ``plugins/<id>/manifest.toml``. But every collaborator in
    the gateway-hosted spawn chain (the leg routing, the status observer, the credential
    resolver allowlist
    :data:`alfred.comms_mcp.adapter_credential_resolver._ADAPTER_SECRET_ALLOWLIST`, and the
    child factory's
    :data:`alfred.gateway.adapter_child_factory._ADAPTER_LAUNCH_TARGETS`) keys on the
    **canonical ``adapter_id``** — the manifest ``[comms_mcp] adapter_kind``
    (``discord``). Resolving the kind HERE, at the one seam where the configured set
    becomes ``GatewayProcess(adapter_ids=...)``, is what keeps that whole chain
    consistent (spec §8.3 id-triplet).

    The canonical id comes from the manifest (the source of truth — the same field the
    daemon's ``_resolve_comms_adapter_wire_spec`` reads), NOT a second hardcoded map that
    could drift from the factory's launch-target keys. The ``comms_enabled_adapters``
    validator already proved the manifest file exists; this reads its ``adapter_kind``.
    A manifest with no ``[comms_mcp] adapter_kind`` is a misconfigured comms adapter:
    the parser surfaces the typed :class:`alfred.plugins.errors.ManifestError`, which the
    gateway boot maps to a loud refusal (CLAUDE.md hard rule #7 — never a silent
    fall-through to the plugin-package id, which the factory would then reject anyway).
    """
    from alfred.cli._launcher_spawn import repo_root
    from alfred.plugins.errors import ManifestError
    from alfred.plugins.manifest import parse_manifest

    manifest_path = repo_root() / "plugins" / plugin_package_id / "manifest.toml"
    manifest = parse_manifest(manifest_path.read_text(encoding="utf-8"))
    adapter_kind = manifest.comms_mcp_adapter_kind
    if adapter_kind is None:
        raise ManifestError(t("gateway.adapters.no_adapter_kind", plugin=plugin_package_id))
    return adapter_kind


def _resolve_hosted_adapter_ids() -> list[str]:
    """The gateway-hosted (bwrap-spawned) adapter subset from settings (G6-5 Task 7/10, #288).

    Sources the configured comms-adapter allowlist from
    :attr:`alfred.config.settings.Settings.comms_enabled_adapters` (env
    ``ALFRED_COMMS_ENABLED_ADAPTERS``, holding plugin-package ids), maps each through the
    :func:`_resolve_adapter_kind` reconciliation seam to its canonical ``adapter_id``, and
    EXCLUDES the TUI dial-in kind — the TUI dials the gateway, it is not a spawned adapter.
    The remaining canonical ids are the children the gateway supervises + spawns, and are
    the SAME strings the factory + credential allowlist key on. An empty / TUI-only set
    yields ``[]`` so the supervisor is a clean no-op (behaviour-preserving for G5).
    """
    from alfred.config.settings import Settings

    settings: Settings = Settings()  # type: ignore[no-untyped-call]  # BaseSettings __init__ is untyped
    resolved = (_resolve_adapter_kind(a) for a in settings.comms_enabled_adapters)
    return [kind for kind in resolved if kind != _TUI_DIAL_IN_ADAPTER_ID]


class _EgressProxyLike(Protocol):
    """The minimal egress-proxy surface ``_main`` co-runs (Spec C G7-1b / #333)."""

    async def serve(self, shutdown_event: asyncio.Event) -> None: ...


async def _serve_egress_proxy_failclosed(
    proxy: _EgressProxyLike, shutdown_event: asyncio.Event
) -> None:
    """Serve the egress proxy, mapping a bind ``OSError`` to ``IOPlaneUnavailableError``.

    The proxy's ``serve`` raises ``OSError`` ONLY on the listener bind (a post-bind
    per-connection fault is handled inside the proxy). A bind failure is the gateway's
    fail-closed I/O-plane outage, so it is re-raised as the typed
    :class:`alfred.egress.errors.IOPlaneUnavailableError` — distinct from the client-socket
    bind ``OSError`` — so ``start_gateway`` renders the egress-proxy refusal (never the
    mislabelled client ``bind_failed`` line) and the gateway crash-loops under
    ``restart: unless-stopped``.
    """
    from alfred.egress.errors import IOPlaneUnavailableError

    try:
        await proxy.serve(shutdown_event)
    except OSError as exc:
        raise IOPlaneUnavailableError(detail=repr(exc)) from exc


async def _serve_egress_relay_failclosed(
    relay: _EgressProxyLike, shutdown_event: asyncio.Event
) -> None:
    """Serve the mode-(b) tool-egress relay, mapping a bind ``OSError`` to the typed
    :class:`alfred.egress.errors.EgressRelayUnavailableError`.

    The relay's ``serve`` raises ``OSError`` ONLY on the listener bind (a post-bind
    per-connection fault is handled inside the relay). A bind failure is the gateway's
    fail-closed relay-plane outage, so it is re-raised as the RELAY-specific subtype of
    ``IOPlaneUnavailableError`` — distinct from the CONNECT proxy's outage — so
    ``start_gateway`` renders the relay refusal (never the proxy ``egress_proxy_bind_failed``
    line) and the gateway crash-loops under ``restart: unless-stopped``.
    """
    from alfred.egress.errors import EgressRelayUnavailableError

    try:
        await relay.serve(shutdown_event)
    except OSError as exc:
        raise EgressRelayUnavailableError(detail=repr(exc)) from exc


def _iter_leaf_exceptions(group: BaseExceptionGroup[BaseException]) -> Iterator[BaseException]:
    """Yield every LEAF exception of a (possibly nested) ``ExceptionGroup``, in tree order."""
    for exc in group.exceptions:
        if isinstance(exc, BaseExceptionGroup):
            yield from _iter_leaf_exceptions(exc)
        else:
            yield exc


def _reraise_first_meaningful(group: BaseExceptionGroup[BaseException]) -> NoReturn:
    """Re-raise the first non-cancellation LEAF of a TaskGroup ``ExceptionGroup``.

    ``_main`` co-runs the egress proxy + the gateway process under an ``asyncio.TaskGroup``,
    which raises an ``ExceptionGroup`` when a sibling fails (the other is cancelled). The
    start is fail-closed and single-cause, so the first REAL leaf is surfaced RAW — restoring
    the flat typed-exception contract ``start_gateway``'s handlers depend on. Nested subgroups
    are FLATTENED first, so a leading pure-cancellation subgroup can never mask a real sibling
    leaf later in the tree. A pure-cancellation group (no real fault) is re-raised unchanged.
    """
    for exc in _iter_leaf_exceptions(group):
        if not isinstance(exc, asyncio.CancelledError):
            raise exc
    raise group


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
    from alfred.config.settings import SettingsError
    from alfred.egress.allowlist import exact_match, provider_egress_allowlist
    from alfred.egress.errors import (
        EgressAdapterProxyUnavailableError,
        EgressRelayUnavailableError,
        IOPlaneUnavailableError,
    )
    from alfred.gateway.adapter_egress_listener import (
        build_adapter_egress_proxy,
        serve_adapter_egress_failclosed,
    )
    from alfred.gateway.adapter_supervisor import GatewayAdapterCredentialError
    from alfred.gateway.client_link import GatewayHandshakeError
    from alfred.gateway.egress_audit import record_egress_connect
    from alfred.gateway.egress_proxy import (
        _PROVIDER_HANDSHAKE_TIMEOUT_S,
        EgressForwardProxy,
        resolve_deepseek_base_url,
        resolve_egress_proxy_bind,
        resolve_egress_proxy_port,
    )
    from alfred.gateway.egress_relay import (
        EgressRelay,
        build_gateway_egress_dlp,
        resolve_egress_relay_bind,
        resolve_egress_relay_port,
        resolve_tool_egress_allowlist,
    )
    from alfred.gateway.egress_relay_audit import record_egress_relay
    from alfred.gateway.process import GatewayProcess
    from alfred.plugins.errors import ManifestError

    typer.echo(t("gateway.start.starting"))

    # Resolve the hosted-adapter ids BEFORE any socket work (CR / hard rule #7). This does
    # manifest I/O, so an unreadable manifest (``OSError``) or a malformed one
    # (:class:`ManifestError`) is a CONFIG fault — reported with the config-fault
    # remediation, NOT mislabelled as a socket ``bind_failed`` (which it would be if the
    # resolution ran inside the bind ``try``'s ``except OSError``). A config fault refuses
    # the start LOUD before the process is ever constructed. ``SettingsError`` (a
    # ``ValueError`` subclass every ``Settings()`` construction failure is lifted to — see
    # ``settings.py``) is ALSO a config fault: an operator who opts in with the CANONICAL
    # ``adapter_id`` (``discord``) instead of the plugin-package id
    # (``alfred_discord``) fails the ``comms_enabled_adapters`` validator inside
    # ``_resolve_hosted_adapter_ids``'s ``Settings()`` call, and without this arm that
    # escaped as a raw traceback instead of this same refusal (#469 Blocker 2 Task 4).
    try:
        hosted_adapter_ids = _resolve_hosted_adapter_ids()
    except (OSError, ManifestError, SettingsError) as exc:
        log.warning("gateway.cli.config_failed", error=repr(exc))
        typer.echo(t("gateway.start.config_failed"))
        raise typer.Exit(code=_EXIT_CONFIG_FAILED) from exc

    # G6-0: stand up the Prometheus exposition before the relay so a scrape can read
    # gateway_* series. Loud-and-continue on a bind failure; the healthcheck surfaces
    # a degraded endpoint.
    from alfred.observability.metrics_server import resolve_metrics_port, start_metrics_server

    start_metrics_server(
        resolve_metrics_port(_GATEWAY_METRICS_PORT_ENV, _GATEWAY_METRICS_DEFAULT_PORT)
    )

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

        # Spec C G7-1b (#333): the gateway is the SOLE external egress plane, so its start
        # co-runs the L7 CONNECT forward-proxy alongside the gateway process. The allowlist is
        # derived from the public ``ALFRED_DEEPSEEK_BASE_URL`` (compose threads the SAME value
        # to the core's Settings — no drift) WITHOUT constructing the secret-requiring Settings
        # model, since the gateway holds no provider key (ADR-0036). Fail-CLOSED: a proxy bind
        # failure aborts the start (CONTRAST the metrics server's loud-and-continue above).
        proxy = EgressForwardProxy(
            allowlist=provider_egress_allowlist(resolve_deepseek_base_url()),
            # Provider TCP path uses exact_match (same semantics as the prior ``in``
            # membership check; Discord will inject suffix_match via its own instance).
            match=exact_match,
            bind_host=resolve_egress_proxy_bind(),
            port=resolve_egress_proxy_port(),
            # The field-allowlisted ({destination, reason}) gateway-local egress audit sink.
            audit=record_egress_connect,
            plane="proxy",
            # Provider plane ONLY: raise the handshake idle reap to 22s so a late-retry
            # pre-brokered one-shot socket (attempt 3 ~ t=17.5s, still inside the 20s child
            # budget) survives — the Discord/relay planes keep the tight 10s default
            # slow-loris guard (spec §21.5 / R.1 D1 / ADR-0052; nesting pinned by
            # test_handshake_timeout_nesting).
            handshake_timeout_s=_PROVIDER_HANDSHAKE_TIMEOUT_S,
        )

        # Spec C G7-2b (#333): the gateway is also the SOLE maker of inspectable tool
        # HTTP requests, so its start co-runs the mode-(b) relay alongside the CONNECT
        # proxy. Its tool allowlist + canary tokens + DLP are derived from PUBLIC
        # compose-threaded env (never the secret-requiring Settings — ADR-0036). The
        # relay has NO live consumer until G7-2.5, so an unset allowlist default-denies
        # (safe). Fail-CLOSED like the proxy (distinct relay refusal line + exit).
        relay = EgressRelay(
            tool_allowlist=resolve_tool_egress_allowlist(),
            dlp=build_gateway_egress_dlp(),
            audit=record_egress_relay,
            bind_host=resolve_egress_relay_bind(),
            port=resolve_egress_relay_port(),
        )

        # Spec C G7-4 (#333): the gateway is also the SOLE maker of adapter (Discord)
        # egress connections. Its start co-runs the Discord-adapter AF_UNIX egress
        # listener alongside the CONNECT proxy, relay, and gateway process. The
        # extra-allowlist env is PUBLIC (gateway reads env, never Settings — ADR-0036).
        # No bind here — FIX-2: the bind happens inside serve(), keeping it atomic with
        # the TaskGroup start. Fail-CLOSED like the proxy + relay.
        adapter_proxy = build_adapter_egress_proxy(
            extra_allowlist=os.environ.get("ALFRED_DISCORD_EGRESS_ALLOWLIST", ""),
        )

        async def _run_gateway() -> None:
            try:
                await GatewayProcess(
                    shutdown_event=shutdown_event,
                    dial_adapter_id=dial_adapter_id,
                    # Resolved BEFORE the bind (above) so a manifest/config fault is a config
                    # refusal, never swallowed by the bind ``except OSError`` as ``bind_failed``.
                    adapter_ids=hosted_adapter_ids,
                ).run()
            finally:
                # The proxy serves only as long as the gateway leg lives: when the gateway
                # returns (clean stop) or raises (fail-closed), release the proxy's serve
                # loop so the co-run TaskGroup unwinds promptly.
                shutdown_event.set()

        # Co-run under a TaskGroup so a proxy bind failure (mapped to
        # IOPlaneUnavailableError) cancels the gateway leg and aborts the start. The group
        # is unwrapped to the first real leaf so ``start_gateway``'s flat typed handlers
        # below see a raw exception, not an ExceptionGroup.
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_serve_egress_proxy_failclosed(proxy, shutdown_event))
                tg.create_task(_serve_egress_relay_failclosed(relay, shutdown_event))
                tg.create_task(serve_adapter_egress_failclosed(adapter_proxy, shutdown_event))
                tg.create_task(_run_gateway())
        except BaseExceptionGroup as group:
            _reraise_first_meaningful(group)

    try:
        asyncio.run(_main())
    except EgressRelayUnavailableError as exc:
        # Friendly refusal — the mode-(b) tool-egress relay could not bind (Spec C G7-2b /
        # #333). Caught BEFORE IOPlaneUnavailableError (it is a subtype) so the relay
        # renders its OWN line + exit, distinct from the CONNECT proxy's. Fail-closed: the
        # gateway crash-loops under ``restart: unless-stopped`` (intended posture).
        log.warning("gateway.cli.egress_relay_bind_failed", error=repr(exc))
        typer.echo(t("gateway.start.egress_relay_bind_failed"))
        raise typer.Exit(code=_EXIT_EGRESS_RELAY_BIND_FAILED) from exc
    except EgressAdapterProxyUnavailableError as exc:
        # Friendly refusal — the Discord-adapter AF_UNIX egress socket could not bind
        # (Spec C G7-4 / #333). Caught BEFORE IOPlaneUnavailableError (it is a subtype)
        # so the adapter renders its OWN line + exit, distinct from the CONNECT proxy's
        # and the relay's. Fail-closed: the gateway crash-loops under
        # ``restart: unless-stopped`` (intended posture).
        log.warning("gateway.cli.egress_adapter_bind_failed", error=repr(exc))
        typer.echo(t("gateway.start.egress_adapter_bind_failed"))
        raise typer.Exit(code=_EXIT_EGRESS_ADAPTER_PROXY_BIND_FAILED) from exc
    except IOPlaneUnavailableError as exc:
        # Friendly refusal — the egress forward-proxy could not bind (Spec C G7-1b / #333).
        # The gateway is the sole external egress plane, so this is fail-closed: refuse the
        # start with a DISTINCT line + exit (never the client-socket ``bind_failed`` line),
        # and the gateway crash-loops under ``restart: unless-stopped`` (intended posture).
        log.warning("gateway.cli.egress_proxy_bind_failed", error=repr(exc))
        typer.echo(t("gateway.start.egress_proxy_bind_failed"))
        raise typer.Exit(code=_EXIT_EGRESS_PROXY_BIND_FAILED) from exc
    except GatewayAdapterCredentialError as exc:
        # Friendly refusal — a hosted adapter's credential was refused at first spawn
        # (#469 [R1]). Distinct from a bare GatewayAdapterSpawnError (a bug / a
        # LaunchTargetOverrideRefusedError security refusal), which is NOT caught here and
        # surfaces loud (hard rule #7). The supervisor already wrote the audit row before
        # the raise. adapter_id + closed-vocab reason go to the log, never the operator text.
        #
        # NOTE: deliberately NO ``exc_info=True`` (unlike the brief's sketch) — every
        # sibling arm in this function omits it, and with it structlog's UNCONFIGURED
        # default (this CLI path never calls ``alfred.cli._bootstrap.configure_logging``
        # — that needs a ``SecretBroker`` the gateway process does not hold, ADR-0036)
        # renders a real pretty traceback into this line via its default
        # ``ConsoleRenderer``, which prints to ``sys.stdout`` — reintroducing the exact
        # raw-traceback leak this whole handler exists to prevent (verified: without this
        # note, ``test_start_credential_refusal_is_friendly_not_traceback`` fails).
        log.warning("gateway.cli.adapter_spawn_failed", error=repr(exc), reason=exc.reason)
        typer.echo(t("gateway.start.adapter_spawn_failed"))
        raise typer.Exit(code=_EXIT_ADAPTER_SPAWN_FAILED) from exc
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


_BREAKER_METRIC: Final[str] = "gateway_circuit_breaker_open"
_EXIT_UNHEALTHY: Final[int] = 1

# The gateway's own exposition families are all named ``gateway_…`` (see
# ``alfred.gateway.metrics``, which registers them on the default registry at import). The
# healthcheck uses this to tell the gateway's OWN /metrics apart from any other HTTP server
# answering 200 on the same port — a squatter, prose, or the CORE's ``alfred_`` exposition on
# a mis-set ``ALFRED_GATEWAY_METRICS_PORT`` used to read HEALTHY (the same false-healthy class
# #482/P4 closed for the daemon; shared predicate, different prefix).
_GATEWAY_METRIC_FAMILY_PREFIX: Final[str] = "gateway_"

# The env var + fallback port for the gateway's Prometheus exposition (G6-0). Single
# source of truth for every `resolve_metrics_port(...)` call site in this module and
# in `_egress.py` (which imports these two constants rather than repeating the literal
# pair — DRY finding from the #470 PR1 Task 1 review).
_GATEWAY_METRICS_PORT_ENV: Final[str] = "ALFRED_GATEWAY_METRICS_PORT"
_GATEWAY_METRICS_DEFAULT_PORT: Final[int] = 9464


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

    Liveness has two parts: the /metrics endpoint is reachable AND what answered is the
    gateway's OWN exposition (a 200 from a squatter, prose, or the core's ``alfred_``
    exposition on a mis-set port is NOT liveness — same false-healthy class #482/P4 closed for
    the daemon). Readiness: the ReplayBuffer back-pressure breaker is NOT latched. A core-down
    gateway that is buffering is HEALTHY (only wedged-past-breaker is unhealthy). Exits 0
    (healthy) or 1 (unhealthy); never raises a traceback.
    """
    from alfred.observability.metrics_server import (
        declares_metric_family,
        fetch_metrics_text,
        resolve_metrics_port,
    )

    try:
        port = resolve_metrics_port(_GATEWAY_METRICS_PORT_ENV, _GATEWAY_METRICS_DEFAULT_PORT)
    except ValueError as exc:
        # Malformed ALFRED_GATEWAY_METRICS_PORT — can't probe; report unhealthy, not a traceback.
        log.warning("gateway.healthcheck.unreachable", port="unset", error=repr(exc))
        typer.echo(t("gateway.healthcheck.unreachable", port="unset"))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    try:
        metrics_text = fetch_metrics_text(port)
    except OSError as exc:
        log.warning("gateway.healthcheck.unreachable", port=port, error=repr(exc))
        typer.echo(t("gateway.healthcheck.unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    if not declares_metric_family(metrics_text, _GATEWAY_METRIC_FAMILY_PREFIX):
        # Something answered 200 but it is not the gateway's exposition. Fail closed with a
        # distinct message: the remedy (check what is bound to the port) differs from the
        # unreachable arm (check the bind) and the breaker arm (core back-pressure).
        log.warning(
            "gateway.healthcheck.not_gateway_exposition", port=port, body_len=len(metrics_text)
        )
        typer.echo(t("gateway.healthcheck.not_gateway_exposition", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY)
    if _breaker_latched(metrics_text):
        log.warning("gateway.healthcheck.breaker_open")
        typer.echo(t("gateway.healthcheck.breaker_open"))
        raise typer.Exit(code=_EXIT_UNHEALTHY)


__all__ = ["healthcheck_gateway", "start_gateway", "status_gateway"]
