"""Shared bidirectional byte-splice for the egress proxy + the in-child shim (Spec C G7-4).

Extracted from ``EgressForwardProxy._pipe`` so the AF_UNIX bridge's shim reuses the SAME
audited copy loop instead of importing a gateway-private symbol across the package boundary.
Payload-blind: never buffers-until-EOF, so native TLS streaming survives.
"""
from __future__ import annotations

import asyncio
import contextlib

_SPLICE_CHUNK = 65536


async def splice(
    src: asyncio.StreamReader, dst: asyncio.StreamWriter, *, chunk: int = _SPLICE_CHUNK
) -> None:
    """Copy ``src``→``dst`` incrementally until EOF, then half-close ``dst``.

    A mid-splice ``OSError`` (peer reset) is NOT swallowed — it propagates to the caller's
    bounded handler. On normal EOF we ``write_eof`` so the peer observes the close;
    ``suppress(OSError)`` covers a transport that cannot half-close.
    """
    try:
        while True:
            data = await src.read(chunk)
            if not data:
                break
            dst.write(data)
            await dst.drain()
            await asyncio.sleep(0)
    finally:
        with contextlib.suppress(OSError):
            dst.write_eof()
