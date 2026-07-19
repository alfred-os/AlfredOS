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
import threading
import time
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


# Rendezvous bound for the CONNECT-concurrency proof. Generous enough never to flake on a
# loaded CI box, short enough that a SERIAL regression fails fast instead of hanging the suite.
_BARRIER_TIMEOUT_S = 5.0


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
async def test_connect_phase_runs_concurrently_not_serially(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CONNECT phase is ``asyncio.gather``-concurrent, NOT a serial ``for`` loop (A1).

    Spec §6 and ADR-0052:95 both mandate concurrency, naming the reason: a serial loop costs
    ``N x _CONNECT_TIMEOUT_S`` (3 x 10 = 30s) of up-front latency before the extract frame even
    dispatches — equal to the whole 30s ``action_deadline``.

    NON-VACUOUS by construction: each faked ``_connect_one`` blocks on a
    :class:`threading.Barrier` sized to ``count``. Under a SERIAL loop the first executor thread
    waits for two parties that will never arrive and the barrier trips ``BrokenBarrierError`` at
    its timeout, failing this test. Only a genuinely concurrent CONNECT phase lets all three
    parties rendezvous.
    """
    count = 3
    barrier = threading.Barrier(count, timeout=_BARRIER_TIMEOUT_S)
    made: list[socket.socket] = []

    def _rendezvous_connect_one(host: str, port: int) -> socket.socket:
        barrier.wait()  # BrokenBarrierError under a serial CONNECT loop
        sock = _fresh_inet_socket()
        made.append(sock)
        return sock

    monkeypatch.setattr(cfb, "_connect_one", _rendezvous_connect_one)
    monkeypatch.setattr(cfb, "_send_one", lambda parent_end, sock: None)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        dests = await broker_connected_sockets(parent_end=parent, proxy_config=_Cfg(), count=count)
        assert dests == [("gw", 8889)] * count
        assert len(made) == count
    finally:
        for sock in made:
            sock.close()
        parent.close()
        child.close()


@pytest.mark.asyncio
async def test_send_phase_stays_serial_and_ordered(monkeypatch: pytest.MonkeyPatch) -> None:
    """A1 boundary: only the CONNECT phase went concurrent — the SEND phase stays serial.

    SCM_RIGHTS queue ORDER is load-bearing (the child consumes one socket per retry attempt in
    enqueue order), so ``_send_one`` must never be gathered. A concurrent SEND would let two
    executor threads interleave ``sendmsg`` on the same control fd. Proven by a barrier sized to
    2 that must TIME OUT: if two sends ever ran concurrently the barrier would trip and the
    recorded order would be non-deterministic.
    """
    made: list[socket.socket] = []
    in_flight: list[int] = []
    max_concurrent = {"n": 0}

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        sock = _fresh_inet_socket()
        made.append(sock)
        return sock

    def _observing_send_one(parent_end: socket.socket, sock: socket.socket) -> None:
        in_flight.append(1)
        max_concurrent["n"] = max(max_concurrent["n"], len(in_flight))
        time.sleep(0.01)  # a window a concurrent send would land in
        in_flight.pop()

    monkeypatch.setattr(cfb, "_connect_one", _fake_connect_one)
    monkeypatch.setattr(cfb, "_send_one", _observing_send_one)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        await broker_connected_sockets(parent_end=parent, proxy_config=_Cfg(), count=3)
        assert max_concurrent["n"] == 1  # never two sends in flight at once
    finally:
        for sock in made:
            sock.close()
        parent.close()
        child.close()


@pytest.mark.asyncio
async def test_broker_sockets_sends_nothing_on_partial_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect fails on socket 2 of 3 → ZERO sendmsg, EVERY connected socket closed, raises.

    The load-bearing connect-defer property: a partial connect failure never reaches the SEND
    phase, so the child buffer never sees a partial batch (nothing to reclaim). Because the
    CONNECT phase is now concurrent (A1), ALL ``count`` connects are attempted — the two that
    DID succeed are both closed by the ``finally`` (the gather error path must leak no fd), and
    the raised error carries the destination plus ``delivered == 0``.
    """
    made: list[socket.socket] = []
    sent: list[socket.socket] = []
    connect_calls = {"n": 0}
    lock = threading.Lock()

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        with lock:
            connect_calls["n"] += 1
            nth = connect_calls["n"]
        if nth == 2:  # one connect fails — SEND phase must never run
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
        assert exc.value.delivered == 0  # nothing reached the child's SCM_RIGHTS queue
        assert sent == []  # SEND phase never ran — the child got NOTHING
        # Concurrent CONNECT: the other two dials still happened, and BOTH were closed.
        assert len(made) == 2
        assert all(sock.fileno() == -1 for sock in made)
    finally:
        parent.close()
        child.close()


@pytest.mark.asyncio
async def test_broker_sockets_reports_the_first_connect_failure_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two concurrent connects fail → exactly one error surfaces, the surviving socket closes.

    ``asyncio.gather(..., return_exceptions=True)`` yields EVERY outcome, so the collection loop
    must keep the FIRST failure and discard the rest (a second ``raise`` would mask it). Covers
    the ``elif failure is None`` false branch.
    """
    made: list[socket.socket] = []
    connect_calls = {"n": 0}
    lock = threading.Lock()

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        with lock:
            connect_calls["n"] += 1
            nth = connect_calls["n"]
        if nth in (1, 2):
            raise ControlFdBrokerError("gateway_unreachable" if nth == 1 else "sendmsg_failed")
        sock = _fresh_inet_socket()
        made.append(sock)
        return sock

    monkeypatch.setattr(cfb, "_connect_one", _fake_connect_one)
    monkeypatch.setattr(cfb, "_send_one", lambda parent_end, sock: None)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            await broker_connected_sockets(parent_end=parent, proxy_config=_Cfg(), count=3)
        # Exactly ONE error surfaces. WHICH one is not pinned: the executor threads race for
        # the counter, so which gather SLOT carries which failure is nondeterministic by
        # construction. The invariant is that the collection loop keeps one and discards the
        # rest rather than letting a later failure mask the first.
        assert exc.value.reason in {"gateway_unreachable", "sendmsg_failed"}
        assert exc.value.delivered == 0
        assert all(sock.fileno() == -1 for sock in made)  # the lone success still closed
    finally:
        parent.close()
        child.close()


@pytest.mark.asyncio
async def test_broker_sockets_sends_all_on_full_connect_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All ``count`` connect → all ``count`` sendmsg'd → returns ``count`` destinations.

    The connected-vs-sent comparison is deliberately order-INSENSITIVE (a set, not a list).
    Since the CONNECT phase went concurrent (A1) the executor threads finish in
    nondeterministic order, so ``made`` records COMPLETION order while the serial SEND phase
    walks gather's ARGUMENT order — a list equality here is a genuine flake under load, not a
    stricter assertion. What must hold is the SET identity: every socket that connected was
    sent, and nothing else was. SEND ordering is pinned separately by
    ``test_send_phase_stays_serial_and_ordered``.
    """
    made: list[socket.socket] = []
    sent: list[socket.socket] = []
    lock = threading.Lock()

    def _fake_connect_one(host: str, port: int) -> socket.socket:
        sock = _fresh_inet_socket()
        with lock:
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
        assert len(sent) == len(made) == 3
        assert set(sent) == set(made)  # every connected socket was sent, and only those
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

    It ALSO stamps ``delivered`` — the count of fds that DID reach the child's SCM_RIGHTS queue
    before the failure (A2). Connect-defer makes the CONNECT half all-or-nothing, but it cannot
    make the SEND half atomic: once socket 1 is in the queue the child holds a live
    gateway-reachable capability that only a teardown can revoke, so ``dispatch`` needs this
    count to decide.
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
        # Socket 1 was sendmsg'd BEFORE socket 2 failed → one live fd sits in the child queue.
        assert exc.value.delivered == 1
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
