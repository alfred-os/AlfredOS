"""Unit tests for the core-side SCM_RIGHTS reachability-broker primitives (#340 PR2a).

Covers: the control-socketpair inheritability contract (core-001), the fd-passing
recv path (happy path, zero-fd loud refusal, MSG_CTRUNC loud refusal + no fd leak,
and the non-SCM_RIGHTS ancillary-data branch that a real socket cannot produce so a
class-level monkeypatch drives it), and the proxy-URL-to-(host, port) resolver
(blank/unset, missing port, and the happy split).
"""

from __future__ import annotations

import array
import socket
import threading

import pytest

from alfred.egress.control_fd_broker import (
    ControlFdBrokerError,
    _connect_and_send,
    _resolve_proxy_addr,
    broker_connected_socket,
    make_control_socketpair,
    recv_passed_fd,
)
from alfred.egress.errors import IOPlaneUnavailableError


class _Cfg:
    def __init__(self, url: str | None) -> None:
        self.egress_proxy_url = url


def test_make_control_socketpair_child_end_is_inheritable() -> None:
    parent, child = make_control_socketpair()
    try:
        assert child.get_inheritable() is True  # non-CLOEXEC so bwrap inherits it (core-001)
        assert parent.get_inheritable() is False  # parent end must NOT leak to the child
        assert child.family == socket.AF_UNIX
    finally:
        parent.close()
        child.close()


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


def test_recv_passed_fd_ancillary_truncation_is_loud_and_closes_received_fds() -> None:
    """Sending 2 fds into recv_passed_fd's 1-fd-sized ancillary buffer truncates (MSG_CTRUNC).

    Fold-log H item 1: this exercises the MSG_CTRUNC branch explicitly (a coverage-gate
    requirement, not merely implied by the zero-fd test above). Fold-log L-2: whatever fd
    the kernel DID manage to install before truncating must be closed by recv_passed_fd
    itself before it raises — this test's job is to prove the raise happens with the right
    reason; the no-leak property is enforced by inspection of the implementation (a leaked
    fd here is not independently observable from the test process without an fd-count probe,
    since the "installed" copy lives in THIS process's own fd table alongside everything else
    pytest already opened).
    """
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    donor_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    donor_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        parent.sendmsg(
            [b"\x01"],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", [donor_a.fileno(), donor_b.fileno()]),
                )
            ],
        )
        with pytest.raises(ControlFdBrokerError) as exc:
            recv_passed_fd(child)
        assert exc.value.reason == "ancillary_truncated"
    finally:
        parent.close()
        child.close()
        donor_a.close()
        donor_b.close()


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
    """Accept exactly one connection and let it EOF-close; used to give ``_connect_and_send``'s
    ``socket.create_connection`` a real peer to connect to."""
    conn, _ = listener.accept()
    conn.recv(16)  # let the client connect; we only need the connection to exist
    conn.close()


@pytest.mark.asyncio
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


def test_connect_and_send_short_write_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fold-log H item 1 (coverage-gate MANDATORY): a ``sendmsg`` returning fewer bytes than the
    1-byte frame (e.g. 0, a short write) must raise ``short_data_send`` loud, not silently report
    success. ``socket.socket`` instances have no per-instance ``__dict__`` (same constraint noted
    on ``test_recv_passed_fd_non_scm_rights_cmsg_is_loud`` above), so this patches the CLASS.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    t = threading.Thread(target=_accept_once, args=(listener,), daemon=True)
    t.start()
    parent, child = make_control_socketpair()

    def _short_sendmsg(self: socket.socket, *args: object, **kwargs: object) -> int:
        return 0

    monkeypatch.setattr(socket.socket, "sendmsg", _short_sendmsg)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            _connect_and_send(parent, host, port)
        assert exc.value.reason == "short_data_send"
    finally:
        parent.close()
        child.close()
        # Join BEFORE closing the listener (see the happy-path test's finally for the rationale):
        # _connect_and_send's finally: sock.close() closed the client end, so the accept thread's
        # recv() has returned and the thread is ending — join returns promptly.
        t.join(timeout=2)
        assert not t.is_alive()  # a silent join-timeout must fail the test, not pass quietly
        listener.close()


def test_connect_and_send_sendmsg_oserror_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
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

    def _raising_sendmsg(self: socket.socket, *args: object, **kwargs: object) -> int:
        raise OSError("simulated sendmsg failure")

    monkeypatch.setattr(socket.socket, "sendmsg", _raising_sendmsg)
    try:
        with pytest.raises(ControlFdBrokerError) as exc:
            _connect_and_send(parent, host, port)
        assert exc.value.reason == "sendmsg_failed"
    finally:
        parent.close()
        child.close()
        # Join BEFORE closing the listener (see the happy-path test's finally for the rationale):
        # _connect_and_send's finally: sock.close() closed the client end, so the accept thread's
        # recv() has returned and the thread is ending — join returns promptly.
        t.join(timeout=2)
        assert not t.is_alive()  # a silent join-timeout must fail the test, not pass quietly
        listener.close()
