"""Discord adapter lifecycle handlers: ``lifecycle.start`` / ``stop`` / ``health``.

``DiscordLifecycle`` is the stateful machine the MCP server's request handlers
dispatch into. It:

* authenticates by reading ``discord_bot_token`` from LITERAL fd 3 — the core
  injects the token at child spawn over fd 3 (Spec B G6-5, #288), the EXACT
  peer of :func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3`'s
  4-byte-length-prefix framing. The adapter no longer self-brokers the token,
  and it NEVER reads the token from the process environment directly nor logs
  the token bytes (the structlog events below carry only the ``error_class``,
  never the secret);
* opens the Discord WSS through an injected ``GatewayProtocol`` seam. The real
  ``discord.Client`` wrapper lands in Wave 3 (``discord_gateway.py``); injecting
  the seam keeps the lifecycle logic unit-testable without a live gateway;
* reports the ADR-0024 protocol-model results
  (:class:`LifecycleStartResult` / :class:`LifecycleStopResult` /
  :class:`HealthReport`) so the wire contract matches the host exactly.

structlog event names stay English + machine-readable (closure i18n-2's explicit
carve-out for log lines); no user-facing ``t()`` string originates here.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from typing import Final, Protocol

import structlog

from alfred.comms_mcp.protocol import HealthReport, LifecycleStartResult, LifecycleStopResult

_log = structlog.get_logger(__name__)

# Self-reported adapter version (spec §8.1), threaded into the host's lifecycle
# audit. Module-level constant mirrors the reference plugin's precedent.
_PLUGIN_VERSION: Final[str] = "0.1.0"

# The LITERAL fd the core delivers the bot token over at child spawn (ADR-0015
# #218; Spec B G6-5, #288). The reader is the exact peer of
# ``deliver_provider_key_via_fd3`` — a 4-byte big-endian length prefix followed
# by exactly that many key bytes. Hard-coded fd, not an env-named fd.
_PROVIDER_KEY_FD: Final[int] = 3

# 4-byte big-endian length prefix — peer to ``deliver_provider_key_via_fd3``.
_LENGTH_PREFIX: Final[struct.Struct] = struct.Struct(">I")
_LENGTH_HEADER_BYTES: Final[int] = _LENGTH_PREFIX.size


class GatewayError(RuntimeError):
    """Raised by a :class:`GatewayProtocol` implementation on connect failure.

    The message must never embed the bot token — the lifecycle handler logs only
    the exception's class name, not its rendered text, to keep the redaction
    contract trivially auditable.
    """


class TokenSource(Protocol):
    """The seam ``DiscordLifecycle`` reads its bot token from at ``start``.

    Injected so the lifecycle is unit-testable without a real fd-3 pipe. The
    production default is :class:`Fd3TokenSource`. ``read`` returns the token
    string; it may raise on a torn / mis-framed / closed-without-data read — the
    caller maps ANY such failure to ``ok=False`` (never across the wire).
    """

    def read(self) -> str: ...


def _read_exactly(fd: int, count: int) -> bytes:
    """Read exactly ``count`` bytes from ``fd``, looping over short reads.

    Mirrors ``quarantine_child_io._blocking_read_exactly``: a short read that
    reaches EOF before ``count`` bytes are in hand is a torn frame and raises
    ``EOFError`` — the loud-on-truncation contract the fd-3 peer requires. Never
    returns a partial buffer.
    """
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            msg = "fd-3 token frame truncated"
            raise EOFError(msg)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class Fd3TokenSource:
    """Default :class:`TokenSource`: read the token from LITERAL fd 3.

    The exact peer of
    :func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3`: read
    the 4-byte big-endian length prefix, then exactly that many key bytes, then
    UTF-8 decode. The fd is closed after the (single) read on every path so the
    channel does not linger open in the child. A short / torn / mis-framed read
    raises (``EOFError`` / ``struct.error`` / ``OSError``); :meth:`Lifecycle.start`
    maps that to ``ok=False`` without ever logging the (possibly partial) bytes.
    """

    def __init__(self, *, fd: int = _PROVIDER_KEY_FD) -> None:
        self._fd = fd

    def read(self) -> str:
        try:
            header = _read_exactly(self._fd, _LENGTH_HEADER_BYTES)
            (length,) = _LENGTH_PREFIX.unpack(header)
            body = _read_exactly(self._fd, length)
        finally:
            # Single-use channel: close the fd whether the frame parsed or tore,
            # so a half-read pipe never lingers open in the adapter child.
            with contextlib.suppress(OSError):
                os.close(self._fd)
        return body.decode("utf-8")


class GatewayProtocol(Protocol):
    """The Discord WSS seam the lifecycle drives (Wave-3 ``discord_gateway.py``)."""

    async def connect(self, token: str) -> None: ...

    async def close(self) -> int: ...

    @property
    def queue_depth(self) -> int: ...


class DiscordLifecycle:
    """Stateful lifecycle machine for the Discord adapter (one subprocess lifetime)."""

    def __init__(self, *, token_source: TokenSource, gateway: GatewayProtocol) -> None:
        self._token_source = token_source
        self._gateway = gateway
        self._running = False
        self._error_count = 0
        # Serialises ``start`` / ``stop`` transitions. Without it two overlapping
        # ``start`` calls can both pass the ``_running`` check and both open the
        # gateway, and a ``stop`` can interleave mid-start — duplicating sessions
        # or tearing down a half-opened gateway. The lock makes the check + the
        # gateway call + the ``_running`` update one atomic transition.
        self._transition_lock = asyncio.Lock()

    async def start(self) -> LifecycleStartResult:
        """Authenticate + open the gateway; idempotent and serialized.

        A failure — fd-3 read, transport, or gateway — is reported as ``ok=False``
        (never a raised exception across the wire) with a loud, secret-free
        structlog event so the supervisor can act. The transition is serialised
        under ``_transition_lock`` so concurrent callers cannot open the gateway
        twice or race a ``stop``.
        """
        async with self._transition_lock:
            if self._running:
                # Idempotent: a repeated start does not reopen the gateway.
                return LifecycleStartResult(ok=True, plugin_version=_PLUGIN_VERSION)

            try:
                # Read the token INSIDE the try: a torn / mis-framed / closed
                # fd-3 frame (or any transport error) must surface as ``ok=False``
                # (M3), never as a raised ``struct.error`` / ``OSError`` /
                # ``EOFError`` across the RPC boundary.
                token = self._token_source.read()
                await self._gateway.connect(token)
            except Exception as exc:  # wire contract: never raise across the RPC boundary
                self._error_count += 1
                # Log the error CLASS only — never the rendered message (which a
                # buggy gateway/source could let leak the token, or a torn read
                # could carry as partial token bytes) and never the token itself.
                _log.error(
                    "comms.lifecycle.start_failed",
                    adapter="discord",
                    error_class=type(exc).__name__,
                )
                return LifecycleStartResult(ok=False, plugin_version=_PLUGIN_VERSION)

            self._running = True
            _log.info("comms.lifecycle.started", adapter="discord")
            return LifecycleStartResult(ok=True, plugin_version=_PLUGIN_VERSION)

    async def stop(self) -> LifecycleStopResult:
        """Close the gateway, flushing in-flight outbound; report the flushed count.

        Serialised under the same ``_transition_lock`` as :meth:`start` so a stop
        cannot interleave with a concurrent start and leave a half-open gateway.
        """
        async with self._transition_lock:
            flushed = await self._gateway.close()
            self._running = False
            _log.info("comms.lifecycle.stopped", adapter="discord", flushed_messages=flushed)
            return LifecycleStopResult(ok=True, flushed_messages=flushed)

    def health(self) -> HealthReport:
        """Report a health snapshot: running state + queue depth + error count.

        ``last_inbound_at`` is ``None`` in Wave 2 — the inbound-receipt timestamp
        is threaded in by Wave 3's gateway event loop.
        """
        return HealthReport(
            ok=self._running,
            last_inbound_at=None,
            queue_depth=self._gateway.queue_depth,
            error_count=self._error_count,
        )


__all__ = [
    "DiscordLifecycle",
    "Fd3TokenSource",
    "GatewayError",
    "GatewayProtocol",
    "TokenSource",
]
