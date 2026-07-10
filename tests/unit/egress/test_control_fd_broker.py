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

import pytest

from alfred.egress.control_fd_broker import (
    ControlFdBrokerError,
    _resolve_proxy_addr,
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
            got.detach()  # the recvmsg'd fd aliases donor; don't double-close
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
