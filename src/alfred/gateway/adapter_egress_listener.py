"""Gateway-side Discord-adapter AF_UNIX egress listener lifecycle (Spec C G7-4, #333).

A second :class:`~alfred.gateway.egress_proxy.EgressForwardProxy` instance wired onto the
GATEWAY-ONLY AF_UNIX socket (``DISCORD_EGRESS_SOCKET_PATH``; on an ``alfred_discord_egress``
volume, NEVER on ``alfred_run`` / ``runtime_dir()``). The Discord-only allowlist + anchored
suffix matcher enforce the destination set.

The bind happens INSIDE :func:`~alfred.gateway.egress_proxy.EgressForwardProxy.serve` (via
:func:`~alfred.plugins._local_socket.bind_owner_only_unix_socket`), NOT eagerly at
construction time. This avoids a race where the supervisor's adapter spawn dials the socket
before the TaskGroup is up — the bind and the TaskGroup start atomically.
``bind_owner_only_unix_socket`` already does unlink-before-bind, so a stale socket from a
prior crash cannot EADDRINUSE the restart.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from alfred.egress.adapter_egress_addr import DISCORD_EGRESS_SOCKET_PATH
from alfred.egress.allowlist import discord_egress_allowlist, suffix_match
from alfred.egress.errors import EgressAdapterProxyUnavailableError
from alfred.gateway import egress_proxy
from alfred.gateway.egress_audit import record_egress_connect


class _EgressProxyLike(Protocol):
    """Minimal surface :func:`serve_adapter_egress_failclosed` co-runs (mirrors _commands.py)."""

    async def serve(self, shutdown_event: asyncio.Event) -> None: ...


def build_adapter_egress_proxy(
    *,
    extra_allowlist: str = "",
) -> egress_proxy.EgressForwardProxy:
    """Build the Discord-adapter egress proxy instance (no eager bind).

    Returns the proxy ONLY — no socket is created or bound here. The bind happens
    inside ``proxy.serve(shutdown_event)`` (see FIX-2). This keeps the bind and the
    TaskGroup start atomic and avoids the adapter-spawn-before-bind race.

    ``extra_allowlist`` is the public ``ALFRED_DISCORD_EGRESS_ALLOWLIST`` env
    (gateway reads env, never Settings — ADR-0036): a comma-separated list of
    ``host[:port]`` tokens for additional exact-match destinations (e.g.
    ``cdn.discordapp.com`` when attachment fetch is enabled).
    """
    al = discord_egress_allowlist(extra_allowlist)
    exact = al.exact
    suffix_bases = al.suffix_bases

    def match(host: str, port: int, _allow: frozenset[tuple[str, int]]) -> bool:
        """Allow host+port if it is in the Discord exact set or the *.discord.gg suffix set."""
        return (host, port) in exact or suffix_match(host, port, suffix_bases)

    return egress_proxy.EgressForwardProxy(
        allowlist=exact,
        match=match,
        audit=record_egress_connect,
        unix_path=DISCORD_EGRESS_SOCKET_PATH,
        plane="adapter",
    )


async def serve_adapter_egress_failclosed(
    proxy: _EgressProxyLike,
    shutdown_event: asyncio.Event,
) -> None:
    """Serve the Discord egress proxy, mapping a bind ``OSError`` to the typed
    :class:`alfred.egress.errors.EgressAdapterProxyUnavailableError`.

    The proxy's ``serve`` raises ``OSError`` ONLY on the listener bind (a post-bind
    per-connection fault is handled inside the proxy). A bind failure is the gateway's
    fail-closed adapter-egress-plane outage — distinct from the CONNECT proxy's (exit
    code 7) and relay's (exit code 8) outages — so the gateway renders a Discord-egress-
    specific refusal and crash-loops under ``restart: unless-stopped``.

    Its ``except``-clause MUST precede ``except IOPlaneUnavailableError`` in any handler
    that wants adapter-specific behaviour (see ``_commands.py`` for the relay precedent).
    """
    try:
        await proxy.serve(shutdown_event)
    except OSError as exc:
        raise EgressAdapterProxyUnavailableError(detail=repr(exc)) from exc


__all__ = ["build_adapter_egress_proxy", "serve_adapter_egress_failclosed"]
