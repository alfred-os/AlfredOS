"""The in-child TCP→unix egress shim (Spec C G7-4, #333).

Runs INSIDE the --unshare-net Discord adapter child. discord.py's
``Client(proxy="http://127.0.0.1:PORT")`` needs a TCP proxy URL; aiohttp has no unix-socket
proxy. This shim is the thin bridge: accept on child-loopback, splice each connection to the
bind-mounted gateway AF_UNIX egress socket. It is TRANSPORT GLUE, not a policy plane — zero
CONNECT parsing, zero allowlisting; the gateway proxy is the sole enforcement point.
"""
from __future__ import annotations

import asyncio
import contextlib

import structlog

from alfred.egress.adapter_egress_addr import (
    DISCORD_EGRESS_SHIM_PORT,
    DISCORD_EGRESS_SOCKET_PATH,
)
from alfred.egress.byte_splice import splice

_log = structlog.get_logger(__name__)


async def _bridge(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        up_reader, up_writer = await asyncio.open_unix_connection(str(DISCORD_EGRESS_SOCKET_PATH))
    except OSError as exc:
        _log.warning("discord.egress.shim.upstream_unavailable", error=repr(exc))
        writer.close()
        return
    try:
        await asyncio.gather(splice(reader, up_writer), splice(up_reader, writer))
    finally:
        for w in (up_writer, writer):
            with contextlib.suppress(OSError):  # pragma: no cover - defensive close
                w.close()


async def start_shim() -> asyncio.AbstractServer:
    """Bind 127.0.0.1:PORT and serve the bridge. The caller AWAITS this (listening) before
    discord.py's first egress, and binds the returned server to the adapter crash discipline."""
    server = await asyncio.start_server(_bridge, "127.0.0.1", DISCORD_EGRESS_SHIM_PORT)
    _log.info("discord.egress.shim.listening", port=DISCORD_EGRESS_SHIM_PORT)
    return server
