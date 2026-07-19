"""Unit tests for the core-side SCM_RIGHTS reachability-broker primitives (#340 PR2a).

Covers: the control-socketpair inheritability contract (core-001), the fd-passing
recv path (happy path, zero-fd loud refusal, MSG_CTRUNC loud refusal + no fd leak,
and the non-SCM_RIGHTS ancillary-data branch that a real socket cannot produce so a
class-level monkeypatch drives it), and the proxy-URL-to-(host, port) resolver
(blank/unset, missing port, and the happy split).
"""

from __future__ import annotations

import array
import os
import socket
import sys
import threading

import pytest

from alfred.egress.control_fd_broker import (
    ControlFdBrokerError,
    _connect_one,
    _resolve_proxy_addr,
    _send_one,
    broker_connected_socket,
    make_control_socketpair,
    recv_passed_fd,
)
from alfred.egress.errors import IOPlaneUnavailableError


class _Cfg:
    def __init__(self, url: str | None) -> None:
        self.egress_proxy_url = url


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_make_control_socketpair_child_end_is_inheritable() -> None:
    parent, child = make_control_socketpair()
    try:
        assert child.get_inheritable() is True  # non-CLOEXEC so bwrap inherits it (core-001)
        assert parent.get_inheritable() is False  # parent end must NOT leak to the child
        assert child.family == socket.AF_UNIX
    finally:
        parent.close()
        child.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_returns_frame_and_one_fd() -> None:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    donor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        parent.sendmsg(
            [b"\x01"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [donor.fileno()]))],
        )
        data, fd = recv_passed_fd(child)
        assert data == b"\x01"
        got = socket.socket(fileno=fd)
        try:
            assert got.family == socket.AF_INET
        finally:
            # SCM_RIGHTS installed a DISTINCT descriptor in this process (not an alias of
            # donor's fd) — close it here; donor is closed separately in its own finally below.
            got.close()
    finally:
        parent.close()
        child.close()
        donor.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_no_fd_is_loud() -> None:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        parent.sendall(b"\x01")  # data only, no ancillary fd
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd(child)
        assert exc.value.reason == "expected_exactly_one_fd"
    finally:
        parent.close()
        child.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_ancillary_truncation_closes_received_fds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSG_CTRUNC branch: recv_passed_fd closes any installed fd, then raises ancillary_truncated.

    A real 2-fd frame into a 1-fd buffer sets MSG_CTRUNC on macOS/BSD but on Linux instead
    delivers the extra fd (tripping the count check) — so the MSG_CTRUNC arc is driven
    DETERMINISTICALLY via a class-level ``recvmsg`` monkeypatch (fold-log H item 1; a real
    socket cannot be coaxed into a portable MSG_CTRUNC). The installed fd is a real ``dup`` that
    recv_passed_fd must reclaim (fold-log L-2) — proven OBSERVABLY by the failing re-close below.
    """
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())  # a real, closeable fd recv_passed_fd must reclaim
    cmsg = array.array("i", [victim]).tobytes()

    def _fake_recvmsg(
        self: socket.socket, bufsize: int, ancbufsize: int = 0, flags: int = 0
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        return b"\x01", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)], socket.MSG_CTRUNC, None

    monkeypatch.setattr(socket.socket, "recvmsg", _fake_recvmsg)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd(child)
        assert exc.value.reason == "ancillary_truncated"
        with pytest.raises(OSError):
            os.close(victim)  # recv_passed_fd already reclaimed it — no leak
    finally:
        parent.close()
        child.close()
        keeper.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_multi_fd_without_ctrunc_closes_and_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """len(fds) != 1 with fds installed (no MSG_CTRUNC): recv_passed_fd closes them + refuses.

    This is the Linux signature of a >1-fd frame — the kernel delivers both descriptors rather
    than setting MSG_CTRUNC, landing on the exactly-one-fd check. That refusal MUST also reclaim
    every descriptor it received (a compromised child must not leak fds into this process by
    over-stuffing a frame). Driven via a class-level ``recvmsg`` monkeypatch so the arc + its
    fd-close are covered on every platform; the no-leak is proven by the failing re-closes.
    """
    keeper_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    keeper_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    v_a = os.dup(keeper_a.fileno())
    v_b = os.dup(keeper_b.fileno())
    cmsg = array.array("i", [v_a, v_b]).tobytes()

    def _fake_recvmsg(
        self: socket.socket, bufsize: int, ancbufsize: int = 0, flags: int = 0
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        return b"\x01", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)], 0, None

    monkeypatch.setattr(socket.socket, "recvmsg", _fake_recvmsg)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd(child)
        assert exc.value.reason == "expected_exactly_one_fd"
        for v in (v_a, v_b):
            with pytest.raises(OSError):
                os.close(v)  # both received copies already reclaimed — no leak
    finally:
        parent.close()
        child.close()
        keeper_a.close()
        keeper_b.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_non_scm_rights_cmsg_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``level == SOL_SOCKET and typ == SCM_RIGHTS`` inner-if False branch.

    A real socket cannot be coaxed into delivering a non-SCM_RIGHTS ancillary message on an
    AF_UNIX stream pair, so this monkeypatches ``socket.socket.recvmsg`` at the CLASS level
    (fold-log H item 2) — ``socket.socket`` instances have no ``__dict__``, so an
    instance-level monkeypatch raises ``AttributeError: ... no __dict__ for setting new
    attributes``; the class-level patch is the only way to fake this return value, and
    pytest's ``monkeypatch`` fixture restores the original method after the test.
    """
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def _fake_recvmsg(
        self: socket.socket, bufsize: int, ancbufsize: int = 0, flags: int = 0
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        return b"\x01", [(socket.SOL_SOCKET, 0, b"")], 0, None

    monkeypatch.setattr(socket.socket, "recvmsg", _fake_recvmsg)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd(child)
        assert exc.value.reason == "expected_exactly_one_fd"
    finally:
        parent.close()
        child.close()


def test_resolve_proxy_addr_blank_is_io_plane_unavailable() -> None:
    with pytest.raises(IOPlaneUnavailableError):
        _resolve_proxy_addr(_Cfg("   "))
    with pytest.raises(IOPlaneUnavailableError):
        _resolve_proxy_addr(_Cfg(None))


def test_resolve_proxy_addr_missing_port_is_io_plane_unavailable() -> None:
    with pytest.raises(IOPlaneUnavailableError):
        _resolve_proxy_addr(_Cfg("http://alfred-gateway"))  # no :port


def test_resolve_proxy_addr_splits_host_port() -> None:
    assert _resolve_proxy_addr(_Cfg("http://alfred-gateway:8889")) == ("alfred-gateway", 8889)


def _accept_once(listener: socket.socket) -> None:
    """Accept exactly one connection and let it EOF-close; used to give ``_connect_one``'s
    ``socket.create_connection`` a real peer to connect to."""
    conn, _ = listener.accept()
    conn.recv(16)  # let the client connect; we only need the connection to exist
    conn.close()


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_broker_connected_socket_passes_a_live_fd() -> None:
    """A live, connected socket crosses via SCM_RIGHTS with exactly the ``\\x01`` framing byte.

    This does NOT (and, portably, cannot) assert that the core drops its own copy of the fd —
    Task 7's docker integration test proves that via ``/proc/self/fd`` count stability, which is
    Linux-only and would break on this macOS dev host if asserted here (fold-log M3).
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    t = threading.Thread(target=_accept_once, args=(listener,), daemon=True)
    t.start()
    parent, child = make_control_socketpair()
    try:
        await broker_connected_socket(parent_end=parent, proxy_config=_Cfg(f"http://{host}:{port}"))
        data, fd = recv_passed_fd(child)
        assert data == b"\x01"  # exactly the framing byte — zero application bytes (HARD #5)
        passed = socket.socket(fileno=fd)
        try:
            assert passed.getpeername() == (host, port)  # a LIVE connected socket crossed
            assert passed.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
            # settimeout(None) restored blocking after the timed connect
            assert passed.getblocking() is True
        finally:
            # .close() (not .detach()): this is the DISTINCT descriptor SCM_RIGHTS installed in
            # this process, so closing it lets the accept-thread observe EOF and t.join return
            # promptly, and it does not double-close anything (fold-log M3 / Task-1 detach fix).
            passed.close()
    finally:
        parent.close()
        child.close()
        # Join BEFORE closing the listener: create_connection completes the TCP handshake at the
        # kernel level before the OS necessarily schedules the accept thread, so closing the
        # listener fd first can abort a still-in-flight accept() (ConnectionAbortedError surfacing
        # as PytestUnhandledThreadExceptionWarning). By the time broker_connected_socket returned,
        # its finally: sock.close() + the passed.close() above closed the client end, so the
        # accept thread's recv() has returned EOF and the thread is ending — join returns promptly.
        t.join(timeout=2)
        assert not t.is_alive()  # a silent join-timeout must fail the test, not pass quietly
        listener.close()


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_broker_connected_socket_returns_destination() -> None:
    """``broker_connected_socket`` returns the resolved ``(host, port)`` it brokered to.

    Behavior-neutral (#340 broker-audit pre-gate, Task 3): golive's ``broker_sockets`` will
    pass this tuple as the ``destination`` to ``EgressBrokerAuditor.record_broker_success``.
    The only current caller (the PR2a docker probe) ignores the return value, so nothing else
    changes. Reuses the real-listener + accept-thread harness from
    ``test_broker_connected_socket_passes_a_live_fd`` above (no stubbed executor exists in this
    suite — the existing tests all drive ``_connect_one`` + ``_send_one`` against a live socket).
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    t = threading.Thread(target=_accept_once, args=(listener,), daemon=True)
    t.start()
    parent, child = make_control_socketpair()
    try:
        result = await broker_connected_socket(
            parent_end=parent, proxy_config=_Cfg(f"http://{host}:{port}")
        )
        assert result == (host, port)
        _data, fd = recv_passed_fd(child)  # drain the passed fd so the accept thread completes
        os.close(fd)
    finally:
        parent.close()
        child.close()
        # Join BEFORE closing the listener (see the happy-path test's finally for the rationale).
        t.join(timeout=2)
        assert not t.is_alive()  # a silent join-timeout must fail the test, not pass quietly
        listener.close()


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_broker_connected_socket_unreachable_is_loud() -> None:
    """A refused connection (closed port, immediate ECONNREFUSED) raises ``gateway_unreachable``.

    Fold-log M2: bind-then-close a local port instead of dialing TEST-NET-3 (RFC 5737,
    ``203.0.113.1``) — a TEST-NET-3 address blackholes rather than refusing, so the connect
    blocks for the full 10s ``_CONNECT_TIMEOUT_S`` and makes this test slow/flaky. A closed
    127.0.0.1 port refuses immediately.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    _, closed_port = probe.getsockname()
    probe.close()  # nothing listens on this port now — connecting refuses immediately
    parent, child = make_control_socketpair()
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            await broker_connected_socket(
                parent_end=parent, proxy_config=_Cfg(f"http://127.0.0.1:{closed_port}")
            )
        assert exc.value.reason == "gateway_unreachable"
    finally:
        parent.close()
        child.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_send_one_short_write_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fold-log H item 1 (coverage-gate MANDATORY): a ``sendmsg`` returning fewer bytes than the
    1-byte frame (e.g. 0, a short write) must raise ``short_data_send`` loud, not silently report
    success. ``socket.socket`` instances have no per-instance ``__dict__`` (same constraint noted
    on ``test_recv_passed_fd_non_scm_rights_cmsg_is_loud`` above), so this patches the CLASS. The
    connect + send are the SPLIT ``_connect_one`` / ``_send_one`` (golive Task 9)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    t = threading.Thread(target=_accept_once, args=(listener,), daemon=True)
    t.start()
    parent, child = make_control_socketpair()
    sock = _connect_one(host, port)

    def _short_sendmsg(self: socket.socket, *args: object, **kwargs: object) -> int:
        return 0

    monkeypatch.setattr(socket.socket, "sendmsg", _short_sendmsg)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            _send_one(parent, sock)
        assert exc.value.reason == "short_data_send"
    finally:
        parent.close()
        child.close()
        # Join BEFORE closing the listener (see the happy-path test's finally for the rationale):
        # _send_one's finally: sock.close() closed the client end, so the accept thread's recv()
        # has returned and the thread is ending — join returns promptly.
        t.join(timeout=2)
        assert not t.is_alive()  # a silent join-timeout must fail the test, not pass quietly
        listener.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_send_one_sendmsg_oserror_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fold-log H item 1 (coverage-gate MANDATORY): a raw ``OSError`` from ``sendmsg`` (e.g.
    ``EPIPE``) must raise ``sendmsg_failed`` loud, not propagate the raw ``OSError`` past this
    module's boundary."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    t = threading.Thread(target=_accept_once, args=(listener,), daemon=True)
    t.start()
    parent, child = make_control_socketpair()
    sock = _connect_one(host, port)

    def _raising_sendmsg(self: socket.socket, *args: object, **kwargs: object) -> int:
        raise OSError("simulated sendmsg failure")

    monkeypatch.setattr(socket.socket, "sendmsg", _raising_sendmsg)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            _send_one(parent, sock)
        assert exc.value.reason == "sendmsg_failed"
    finally:
        parent.close()
        child.close()
        # Join BEFORE closing the listener (see the happy-path test's finally for the rationale):
        # _send_one's finally: sock.close() closed the client end, so the accept thread's recv()
        # has returned and the thread is ending — join returns promptly.
        t.join(timeout=2)
        assert not t.is_alive()  # a silent join-timeout must fail the test, not pass quietly
        listener.close()


# --- recv_passed_fd_nonblocking (#340 PR2b-golive Task 4: the drain-sweep variant) ---------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_nonblocking_returns_one_fd() -> None:
    """Happy path: a single SCM_RIGHTS fd is returned as an int."""
    from alfred.egress.control_fd_broker import recv_passed_fd_nonblocking

    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    donor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        parent.sendmsg(
            [b"\x01"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [donor.fileno()]))],
        )
        fd = recv_passed_fd_nonblocking(child)
        assert fd is not None
        got = socket.socket(fileno=fd)
        try:
            assert got.family == socket.AF_INET
        finally:
            got.close()
    finally:
        parent.close()
        child.close()
        donor.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_nonblocking_peer_close_returns_none() -> None:
    """Peer-close EOF (empty frame, zero fds) returns ``None`` — the sweep's benign terminator."""
    from alfred.egress.control_fd_broker import recv_passed_fd_nonblocking

    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    parent.close()  # EOF on child, nothing queued
    try:
        assert recv_passed_fd_nonblocking(child) is None
    finally:
        child.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_nonblocking_no_data_raises_blockingio() -> None:
    """Nothing queued (peer still open) raises ``BlockingIOError`` (EAGAIN) — caller stops sweep."""
    from alfred.egress.control_fd_broker import recv_passed_fd_nonblocking

    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(BlockingIOError):
            recv_passed_fd_nonblocking(child)
    finally:
        parent.close()
        child.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_nonblocking_ctrunc_closes_and_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSG_CTRUNC is a loud fault (not a benign terminator): close any installed fd, then raise.

    Reuses the SHARED leaked-fd-close hardening — the installed fd (a real ``dup``) must be
    reclaimed, proven by the failing re-close. Driven via a class-level ``recvmsg`` monkeypatch
    since a portable MSG_CTRUNC cannot be coaxed from a real socket.
    """
    from alfred.egress.control_fd_broker import recv_passed_fd_nonblocking

    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    cmsg = array.array("i", [victim]).tobytes()

    def _fake_recvmsg(
        self: socket.socket, bufsize: int, ancbufsize: int = 0, flags: int = 0
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        return b"\x01", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)], socket.MSG_CTRUNC, None

    monkeypatch.setattr(socket.socket, "recvmsg", _fake_recvmsg)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd_nonblocking(child)
        assert exc.value.reason == "ancillary_truncated"
        with pytest.raises(OSError):
            os.close(victim)  # already reclaimed — no leak
    finally:
        parent.close()
        child.close()
        keeper.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_recv_passed_fd_nonblocking_multi_fd_closes_and_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A >1-fd frame (no MSG_CTRUNC) is a loud fault: close every received fd, then refuse."""
    from alfred.egress.control_fd_broker import recv_passed_fd_nonblocking

    keeper_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    keeper_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    v_a = os.dup(keeper_a.fileno())
    v_b = os.dup(keeper_b.fileno())
    cmsg = array.array("i", [v_a, v_b]).tobytes()

    def _fake_recvmsg(
        self: socket.socket, bufsize: int, ancbufsize: int = 0, flags: int = 0
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        return b"\x01", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)], 0, None

    monkeypatch.setattr(socket.socket, "recvmsg", _fake_recvmsg)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd_nonblocking(child)
        assert exc.value.reason == "expected_exactly_one_fd"
        for v in (v_a, v_b):
            with pytest.raises(OSError):
                os.close(v)  # both reclaimed — no leak
    finally:
        parent.close()
        child.close()
        keeper_a.close()
        keeper_b.close()
