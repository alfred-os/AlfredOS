"""#340 golive Task 9: connect-defer broker-N + the ``_SubprocessChildIO.broker_sockets`` seam.

Two layers under test:

* :func:`alfred.egress.control_fd_broker.broker_connected_sockets` — CONNECT-DEFER: open all
  ``count`` gateway sockets FIRST, then ``sendmsg`` them to the child only if every connect
  succeeded. A partial connect failure sends the child NOTHING (nothing to reclaim), closes every
  connected-but-unsent host socket (no fd leak), and raises a :class:`ControlFdBrokerError` stamped
  with the ``host:port`` destination.
* :meth:`alfred.security.quarantine_child_io._SubprocessChildIO.broker_sockets` — the auditor-FREE
  delegation to the batch primitive: it refuses loudly when unconfigured (no control-end / no
  egress config) and otherwise returns the ``(host, port)`` destinations for the transport to audit.
"""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock

import pytest

import alfred.egress.control_fd_broker as cfb
from alfred.egress.control_fd_broker import ControlFdBrokerError, broker_connected_sockets
from alfred.security.quarantine_child_io import QuarantineChildSpawnError, _SubprocessChildIO


class _Cfg:
    """A minimal ``EgressProxyConfig``-shaped stub (structural, PEP 544)."""

    def __init__(self, url: str = "http://gw:8889") -> None:
        self.egress_proxy_url = url


class _MinimalPopen:
    """A ``subprocess.Popen``-shaped stand-in — ``broker_sockets`` never touches the process."""

    def __init__(self) -> None:
        self.stdin = self.stdout = self.stderr = None
        self.returncode: int | None = 0

    def poll(self) -> int | None:
        return 0


def _fresh_inet_socket() -> socket.socket:
    """A real, closeable INET socket — a stand-in for a gateway-connected host socket.

    Unconnected (no dial), but a genuine fd the connect-defer ``finally`` can close; after close
    ``.fileno()`` is ``-1``, which the leak assertions key on.
    """
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# ---------------------------------------------------------------------------
# broker_connected_sockets — connect-defer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broker_sockets_sends_nothing_on_partial_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect fails on socket 2 of 3 → ZERO sendmsg, connected-but-unsent socket closed, raises.

    The load-bearing connect-defer property: a partial connect failure never reaches the SEND
    phase, so the child buffer never sees a partial batch (nothing to reclaim). The already-
    connected host socket is closed (no fd leak), and the raised error carries the destination.
    """
    made: list[socket.socket] = []
    sent: list[socket.socket] = []
    connect_calls = {"n": 0}

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        connect_calls["n"] += 1
        if connect_calls["n"] == 2:  # second connect fails — SEND phase must never run
            raise ControlFdBrokerError("gateway_unreachable")
        sock = _fresh_inet_socket()
        made.append(sock)
        return sock

    def _spy_send_one(parent_end: socket.socket, sock: socket.socket) -> None:
        sent.append(sock)

    monkeypatch.setattr(cfb, "_connect_one", _fake_connect_one)
    monkeypatch.setattr(cfb, "_send_one", _spy_send_one)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            await broker_connected_sockets(parent_end=parent, proxy_config=_Cfg(), count=3)
        assert exc.value.reason == "gateway_unreachable"
        assert exc.value.destination == "gw:8889"  # stamped, never the raw URL
        assert sent == []  # SEND phase never ran — the child got NOTHING
        assert len(made) == 1  # only the first connect succeeded
        assert made[0].fileno() == -1  # the connected-but-unsent socket was closed (no leak)
    finally:
        parent.close()
        child.close()


@pytest.mark.asyncio
async def test_broker_sockets_sends_all_on_full_connect_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All ``count`` connect → all ``count`` sendmsg'd → returns ``count`` destinations."""
    made: list[socket.socket] = []
    sent: list[socket.socket] = []

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        sock = _fresh_inet_socket()
        made.append(sock)
        return sock

    def _spy_send_one(parent_end: socket.socket, sock: socket.socket) -> None:
        sent.append(sock)

    monkeypatch.setattr(cfb, "_connect_one", _fake_connect_one)
    monkeypatch.setattr(cfb, "_send_one", _spy_send_one)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        dests = await broker_connected_sockets(parent_end=parent, proxy_config=_Cfg(), count=3)
        assert dests == [("gw", 8889)] * 3
        assert sent == made  # every connected socket was sent
        for sock in made:
            assert sock.fileno() == -1  # finally closed the host copy of each
    finally:
        parent.close()
        child.close()


@pytest.mark.asyncio
async def test_broker_sockets_send_failure_mid_batch_closes_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``sendmsg`` failure mid-batch (all connects succeeded) closes every connected socket.

    Connect-defer removes the COMMON partial case; this rarer send-phase failure still leaks no fd
    (every connected host socket is closed by the ``finally``) and still stamps the destination.
    """
    made: list[socket.socket] = []
    send_calls = {"n": 0}

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        sock = _fresh_inet_socket()
        made.append(sock)
        return sock

    def _fake_send_one(parent_end: socket.socket, sock: socket.socket) -> None:
        send_calls["n"] += 1
        # _send_one owns each socket's close in its own finally; emulate that here so the double
        # is faithful to the real split (the batch finally then double-closes — a safe no-op).
        sock.close()
        if send_calls["n"] == 2:
            raise ControlFdBrokerError("short_data_send")

    monkeypatch.setattr(cfb, "_connect_one", _fake_connect_one)
    monkeypatch.setattr(cfb, "_send_one", _fake_send_one)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            await broker_connected_sockets(parent_end=parent, proxy_config=_Cfg(), count=3)
        assert exc.value.reason == "short_data_send"
        assert exc.value.destination == "gw:8889"
        for sock in made:  # all three connected sockets closed — no leak
            assert sock.fileno() == -1
    finally:
        parent.close()
        child.close()


# ---------------------------------------------------------------------------
# _SubprocessChildIO.broker_sockets — the auditor-free delegation seam
# ---------------------------------------------------------------------------


async def test_subprocess_broker_sockets_unconfigured_raises() -> None:
    """``broker_sockets`` on an unconfigured IO refuses loudly (fail-loud security branch, #7)."""
    io = _SubprocessChildIO(_MinimalPopen(), control_parent=None, egress_config=None)
    with pytest.raises(QuarantineChildSpawnError):
        await io.broker_sockets(3)


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_subprocess_broker_sockets_delegates_and_returns_destinations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configured IO delegates to ``broker_connected_sockets`` and RETURNS its destinations.

    Auditor-FREE: this seam records NO audit rows (the transport owns the ``EgressBrokerAuditor``);
    it only brokers + returns the ``(host, port)`` list.
    """
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    io = _SubprocessChildIO(_MinimalPopen(), control_parent=parent, egress_config=_Cfg())
    destinations = [("gw", 8889), ("gw", 8889), ("gw", 8889)]
    batch_mock = AsyncMock(return_value=destinations)
    # Patch the egress module object directly — quarantine_child_io imported this SAME module
    # object (``from alfred.egress import control_fd_broker``), so the delegation call inside
    # broker_sockets resolves to the mock.
    monkeypatch.setattr(cfb, "broker_connected_sockets", batch_mock)
    try:
        result = await io.broker_sockets(3)
        assert result == destinations
        batch_mock.assert_awaited_once()
        call = batch_mock.await_args
        assert call is not None
        assert call.kwargs["parent_end"] is parent
        assert call.kwargs["proxy_config"] is io._egress_config
        assert call.kwargs["count"] == 3
    finally:
        parent.close()
        child.close()
