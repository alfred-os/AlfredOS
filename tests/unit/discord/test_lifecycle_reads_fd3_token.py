"""``DiscordLifecycle.start`` reads its bot token from fd-3, not the broker (G6-5).

Under the gateway-hosted spawn model (Spec B G6-5, #288) the core injects the
Discord bot token over LITERAL fd 3 at child spawn (the exact peer of
:func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3`'s
4-byte-length-prefix framing). The adapter child no longer self-brokers the token.

These tests pin the new contract:

* ``start`` consumes the fd-3 token and hands it to ``gateway.connect``;
* a missing / torn / mis-framed / closed-without-data fd-3 read maps to
  ``ok=False`` — never an unhandled ``struct.error`` / ``OSError`` across the
  RPC boundary (M3), never partial token bytes into a log;
* the token never appears in ``capture_logs`` (C3 — preserved against the NEW
  source);
* the broker is NOT consulted for the token (C3 — a lingering ``broker.get``
  would be a dual-source regression).
"""

from __future__ import annotations

import contextlib
import os
import struct

import pytest
from structlog.testing import capture_logs

from alfred.comms_mcp.protocol import LifecycleStartResult
from plugins.alfred_discord.lifecycle import DiscordLifecycle, GatewayError

_LENGTH_PREFIX = struct.Struct(">I")


class _FakeGateway:
    """Injected stand-in for the Wave-3 discord.Client WSS wrapper."""

    def __init__(self, *, fail_connect: bool = False) -> None:
        self.connected_with: str | None = None
        self._fail_connect = fail_connect

    async def connect(self, token: str) -> None:
        if self._fail_connect:
            raise GatewayError("bad credentials")
        self.connected_with = token

    async def close(self) -> int:
        return 0

    @property
    def queue_depth(self) -> int:
        return 0


class _FakeTokenSource:
    """A fd-3 token source double: returns a pre-staged token string."""

    def __init__(self, token: str) -> None:
        self._token = token
        self.read_calls = 0

    def read(self) -> str:
        self.read_calls += 1
        return self._token


class _RaisingTokenSource:
    """A token source whose read raises (a torn / mis-framed fd-3 read)."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def read(self) -> str:
        raise self._exc


def _make_fd3_pipe(frame: bytes) -> int:
    """Write ``frame`` to a pipe and return the read end (the default reader's fd).

    The default token source reads from a fixed fd; tests inject the read end so
    we exercise the REAL length-prefix reader rather than a double.
    """
    read_fd, write_fd = os.pipe()
    os.write(write_fd, frame)
    os.close(write_fd)
    return read_fd


@pytest.mark.asyncio
async def test_start_reads_token_from_fd3_source_and_connects() -> None:
    gateway = _FakeGateway()
    source = _FakeTokenSource("tok-fd3-abc")
    lifecycle = DiscordLifecycle(token_source=source, gateway=gateway)

    result = await lifecycle.start()

    assert isinstance(result, LifecycleStartResult)
    assert result.ok is True
    assert gateway.connected_with == "tok-fd3-abc"
    assert source.read_calls == 1


@pytest.mark.asyncio
async def test_default_source_reads_length_prefixed_frame_from_fd() -> None:
    """The default reader is the EXACT peer of ``deliver_provider_key_via_fd3``."""
    from plugins.alfred_discord.lifecycle import Fd3TokenSource

    token = "tok-from-real-frame"  # noqa: S105 -- fabricated test token, not a credential
    frame = _LENGTH_PREFIX.pack(len(token.encode())) + token.encode()
    read_fd = _make_fd3_pipe(frame)
    try:
        source = Fd3TokenSource(fd=read_fd)
        assert source.read() == token
    finally:
        # The reader closes the fd itself; closing again would EBADF — tolerate.
        with contextlib.suppress(OSError):
            os.close(read_fd)


@pytest.mark.asyncio
async def test_torn_fd3_frame_maps_to_not_ok_never_raises() -> None:
    """A short / torn fd-3 read → ``ok=False`` (M3), never an unhandled error."""
    gateway = _FakeGateway()
    # struct.error is the shape a too-short length-prefix read would raise.
    source = _RaisingTokenSource(struct.error("unpack requires 4 bytes"))
    lifecycle = DiscordLifecycle(token_source=source, gateway=gateway)

    result = await lifecycle.start()

    assert result.ok is False
    assert gateway.connected_with is None


@pytest.mark.asyncio
async def test_default_source_torn_frame_via_lifecycle_is_not_ok() -> None:
    """End-to-end: a real truncated fd-3 frame through the default reader → ok=False."""
    from plugins.alfred_discord.lifecycle import Fd3TokenSource

    # A length prefix promising 16 bytes but only 3 delivered (torn body).
    frame = _LENGTH_PREFIX.pack(16) + b"abc"
    read_fd = _make_fd3_pipe(frame)
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(token_source=Fd3TokenSource(fd=read_fd), gateway=gateway)

    result = await lifecycle.start()

    assert result.ok is False
    assert gateway.connected_with is None


@pytest.mark.asyncio
async def test_closed_without_data_fd3_maps_to_not_ok() -> None:
    """An fd-3 closed before any bytes arrive → ``ok=False`` (M3)."""
    from plugins.alfred_discord.lifecycle import Fd3TokenSource

    read_fd = _make_fd3_pipe(b"")  # EOF immediately
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(token_source=Fd3TokenSource(fd=read_fd), gateway=gateway)

    result = await lifecycle.start()

    assert result.ok is False


@pytest.mark.asyncio
async def test_token_never_appears_in_capture_logs() -> None:
    """C3: the token must not surface in the structured log records (new source)."""
    secret = "tok-super-secret-fd3"  # noqa: S105 -- fabricated leak marker, not a credential
    gateway = _FakeGateway(fail_connect=True)
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(secret), gateway=gateway)

    with capture_logs() as logs:
        result = await lifecycle.start()

    assert result.ok is False
    assert logs, "start_failed should have logged at least one event"
    for event in logs:
        for value in event.values():
            assert secret not in str(value)


@pytest.mark.asyncio
async def test_partial_token_bytes_never_logged_on_torn_read() -> None:
    """M3: a torn read must not leak partial token bytes into any log value."""
    partial_marker = "PARTIALTOKENBYTES"  # fabricated leak marker, not a credential
    gateway = _FakeGateway()
    source = _RaisingTokenSource(ValueError(partial_marker))
    lifecycle = DiscordLifecycle(token_source=source, gateway=gateway)

    with capture_logs() as logs:
        result = await lifecycle.start()

    assert result.ok is False
    for event in logs:
        for value in event.values():
            assert partial_marker not in str(value)


@pytest.mark.asyncio
async def test_lifecycle_has_no_broker_token_dependency() -> None:
    """C3: ``DiscordLifecycle`` no longer accepts/uses a broker for the token.

    A lingering ``broker.get(token)`` would be a dual-source regression. The
    constructor must not bind a broker at all for the token path.
    """
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource("tok"), gateway=_FakeGateway())
    assert not hasattr(lifecycle, "_broker")
