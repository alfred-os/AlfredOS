"""Child-side brokered-egress transport (spike M1 port, #340 PR2b-golive).

Covers the transport primitives that drive the official Anthropic SDK over a
single bare TCP fd the core has already CONNECTed to the gateway proxy:

* ``PassedFdBackend`` — an ``httpcore.AsyncNetworkBackend`` that yields ONE
  stream over the passed fd and raises ``RedialError`` on any 2nd dial;
* ``_BlockingFdStream`` — the blocking-socket ``AsyncNetworkStream`` driven
  off-loop, with the read timeout enforced as a HARD socket-level ceiling
  (rev.2 / prov-001);
* ``build_child_client`` — assembles the ``AnthropicProvider`` (#339 seam) +
  backend, single-dial, no keepalive, no redirects.

100% line+branch coverage on ``brokered_egress`` is the release gate (test-001).
"""

from __future__ import annotations

import socket
from unittest.mock import Mock

import anyio
import httpx
import pytest

from alfred.security.quarantine_child.brokered_egress import (
    MissingReadTimeoutError,
    PassedFdBackend,
    RedialError,
    _BlockingFdStream,
    build_child_client,
)


def test_backend_second_connect_tcp_raises() -> None:
    a, b = socket.socketpair()
    backend = PassedFdBackend(a.detach(), read_timeout=5.0)

    async def _drive() -> None:
        stream = await backend.connect_tcp("ignored.invalid", 443)
        with pytest.raises(RuntimeError):  # RedialError subclass
            await backend.connect_tcp("ignored.invalid", 443)
        await stream.aclose()

    anyio.run(_drive)
    assert backend.calls == 2
    b.close()


def test_build_child_client_is_single_dial_and_no_keepalive() -> None:
    a, b = socket.socketpair()
    provider, backend = build_child_client(
        a.detach(), model="claude-haiku-4-5", api_key="stub", timeout=httpx.Timeout(8.0)
    )
    assert provider.name  # AnthropicProvider seam
    assert backend.calls == 0  # not yet dialed
    b.close()


def test_redial_error_is_runtime_error() -> None:
    assert issubclass(RedialError, RuntimeError)


def test_connect_tcp_applies_read_timeout_ceiling() -> None:
    """The rev.2 crux (prov-001): the read budget is a HARD socket-level ceiling, so the
    blocking, un-cancellable recv cannot outrun the child's wall-clock budget."""
    a, b = socket.socketpair()
    backend = PassedFdBackend(a.detach(), read_timeout=5.0)

    async def _drive() -> None:
        stream = await backend.connect_tcp("ignored.invalid", 443)
        assert stream._sock.gettimeout() == 5.0  # settimeout applied, not blocking (None)
        await stream.aclose()

    anyio.run(_drive)
    b.close()


def test_stream_read_write_roundtrip() -> None:
    a, b = socket.socketpair()
    stream = _BlockingFdStream(a)

    async def _drive() -> None:
        await stream.write(b"ping")
        assert b.recv(4) == b"ping"
        b.sendall(b"pong")
        assert await stream.read(4) == b"pong"
        await stream.aclose()

    anyio.run(_drive)
    b.close()


def test_stream_get_extra_info_branches() -> None:
    sslobj = object()
    sock = Mock()
    sock._sslobj = sslobj
    stream = _BlockingFdStream(sock)
    assert stream.get_extra_info("ssl_object") is sslobj  # if-branch forwards the SSL object
    assert stream.get_extra_info("server_addr") is None  # else-branch


def test_stream_get_extra_info_ssl_object_absent_is_none() -> None:
    a, b = socket.socketpair()
    stream = _BlockingFdStream(a)
    assert stream.get_extra_info("ssl_object") is None  # plain socket has no _sslobj
    a.close()
    b.close()


def test_stream_start_tls_wraps_socket_with_handshake() -> None:
    a, b = socket.socketpair()
    stream = _BlockingFdStream(a)
    wrapped = Mock()
    ctx = Mock()
    ctx.wrap_socket.return_value = wrapped

    async def _drive() -> _BlockingFdStream:
        return await stream.start_tls(ctx, server_hostname="api.anthropic.com")  # type: ignore[arg-type,return-value]

    tls_stream = anyio.run(_drive)
    assert tls_stream._sock is wrapped
    ctx.wrap_socket.assert_called_once_with(
        a, server_hostname="api.anthropic.com", do_handshake_on_connect=True
    )
    a.close()
    b.close()


def test_connect_unix_socket_not_implemented() -> None:
    backend = PassedFdBackend(-1, read_timeout=5.0)

    async def _drive() -> None:
        with pytest.raises(NotImplementedError):
            await backend.connect_unix_socket("/ignored.sock")

    anyio.run(_drive)


def test_backend_sleep_delegates_to_anyio() -> None:
    backend = PassedFdBackend(-1, read_timeout=5.0)

    async def _drive() -> None:
        await backend.sleep(0.0)  # returns promptly; proves the delegation path runs

    anyio.run(_drive)


def test_backend_rejects_missing_read_timeout() -> None:
    """HARD #7: a missing ceiling must fail LOUD at construction, not degrade to a
    blocking-forever socket (the ``sock.settimeout(None)`` silent fail-open)."""
    with pytest.raises(MissingReadTimeoutError):
        PassedFdBackend(-1)  # default read_timeout=None


@pytest.mark.parametrize("bad_timeout", [0, 0.0, -1.0])
def test_backend_rejects_non_positive_read_timeout(bad_timeout: float) -> None:
    """Zero/negative would also never elapse or elapse immediately — both silently void
    the intended ceiling, so both are rejected alongside ``None`` (HARD #7)."""
    with pytest.raises(MissingReadTimeoutError):
        PassedFdBackend(-1, read_timeout=bad_timeout)


def test_missing_read_timeout_error_is_value_error() -> None:
    assert issubclass(MissingReadTimeoutError, ValueError)


def test_build_child_client_rejects_missing_read_timeout() -> None:
    """The 2nd reachable path (rev.2 finding): ``httpx.Timeout(read=None)`` threads
    ``timeout.read=None`` into ``PassedFdBackend`` unchecked — must also fail loud."""
    a, b = socket.socketpair()
    try:
        with pytest.raises(MissingReadTimeoutError):
            build_child_client(
                a.detach(),
                model="claude-haiku-4-5",
                api_key="stub",
                timeout=httpx.Timeout(read=None, connect=5.0, write=5.0, pool=5.0),
            )
    finally:
        b.close()
