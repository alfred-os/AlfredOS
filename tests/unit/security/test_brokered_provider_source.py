"""§8 wrapper-provider: ``_ProviderFactory`` + ``BrokeredProviderSource`` (#340 PR2b-golive).

Covers the per-attempt provider binder that drives the official Anthropic SDK over ONE
core-brokered TCP fd received off the fd-4 control channel:

* ``_ProviderFactory`` — frozen, KEY-FREE ``__repr__`` (no secret in logs/tracebacks), and the
  child's SECONDARY refuse-boot guard (``from_key("")`` → ``QuarantineChildBootError``, §20.2);
* ``BrokeredProviderSource.capabilities()`` — a socket-free classvar read (never touches the
  control socket);
* ``BrokeredProviderSource.bind()`` — the fd-ownership crux (§8 D5): once the httpx client has
  DIALED it is the SOLE fd owner and closes the fd; before any dial (pre-build raise /
  wait_for-cancel) the source closes the raw fd itself — NEVER both (no double-close, no leak);
* ``BrokeredProviderSource.drain_leftovers()`` — the non-blocking sweep of un-consumed
  pre-brokered sockets: closes each, stops on ``EAGAIN``/peer-close EOF, and does NOT swallow a
  malformed-frame fault (HARD #7);
* ``ProviderSource`` — the typed seam Task 5/6 dispatch codes against (not ``Any``).

``brokered_egress`` is on the ``security/*`` 100%-line+branch coverage gate — this file plus
``test_brokered_egress_transport.py`` must prove every branch of the appended code.
"""

from __future__ import annotations

import array
import asyncio
import os
import socket

import anyio
import httpx
import pytest

import alfred.security.quarantine_child.brokered_egress as be
from alfred.egress.control_fd_broker import ControlFdBrokerError, recv_passed_fd_nonblocking
from alfred.providers.base import ProviderCapability
from alfred.security.quarantine_child.brokered_egress import (
    BrokeredProviderSource,
    ProviderSource,
    QuarantineChildBootError,
    _ProviderFactory,
)


def _factory(timeout: httpx.Timeout | None = None) -> _ProviderFactory:
    return _ProviderFactory(
        api_key="super-secret", model="claude-haiku-4-5", max_tokens=8192, timeout=timeout
    )


# --- _ProviderFactory ---------------------------------------------------------------------


def test_factory_repr_hides_key() -> None:
    """The api_key must never reach a log line or a traceback frame (HARD #5)."""
    assert "super-secret" not in repr(_factory())


def test_factory_refuses_empty_key() -> None:
    """An empty provider key means the child cannot build a real provider — refuse boot (§20.2)."""
    with pytest.raises(QuarantineChildBootError):
        _ProviderFactory.from_key("", model="claude-haiku-4-5", max_tokens=8192)


def test_factory_from_key_builds_frozen_config() -> None:
    """A non-empty key yields a factory carrying the fixed child read-timeout ceiling."""
    f = _ProviderFactory.from_key("realkey", model="claude-haiku-4-5", max_tokens=4096)
    assert f.model == "claude-haiku-4-5"
    assert f.max_tokens == 4096
    assert f.timeout is be._CHILD_SDK_READ_TIMEOUT
    assert "realkey" not in repr(f)  # from_key path also key-free


def test_quarantine_child_boot_error_is_runtime_error() -> None:
    assert issubclass(QuarantineChildBootError, RuntimeError)


@pytest.mark.parametrize(
    ("factory_timeout", "expected_read"),
    [
        (None, 8.0),  # None -> the module _CHILD_SDK_READ_TIMEOUT (read=8.0)
        (httpx.Timeout(connect=1.0, read=3.0, write=1.0, pool=1.0), 3.0),  # explicit wins
    ],
)
def test_factory_build_resolves_read_timeout(
    factory_timeout: httpx.Timeout | None, expected_read: float
) -> None:
    """``build`` threads the factory timeout (or the default) into the backend's HARD ceiling."""
    a, b = socket.socketpair()
    fd = a.detach()
    provider, backend = _factory(factory_timeout).build(fd)
    try:
        assert backend._read_timeout == expected_read  # assert the resolved socket ceiling
        assert backend.calls == 0  # not yet dialed
    finally:
        anyio.run(provider.aclose)  # release the (un-dialed) httpx client
        os.close(fd)  # un-dialed -> the client never wrapped/owns the fd; the test owns it
        b.close()


# --- capabilities() -----------------------------------------------------------------------


def test_capabilities_is_socket_free() -> None:
    """Reading capabilities must not touch the control socket (classvar read only)."""
    a, b = socket.socketpair()
    source = BrokeredProviderSource(_factory(), a)
    caps = source.capabilities()
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION in caps
    a.close()
    b.close()


def test_source_satisfies_provider_source_protocol() -> None:
    """``BrokeredProviderSource`` structurally satisfies the ``ProviderSource`` seam."""
    a, b = socket.socketpair()
    source = BrokeredProviderSource(_factory(), a)
    assert isinstance(source, ProviderSource)
    a.close()
    b.close()


# --- bind() fd-ownership (§8 D5) ----------------------------------------------------------


def test_bind_closes_fd_when_never_dialed(monkeypatch: pytest.MonkeyPatch) -> None:
    """No dial → the httpx client never wrapped the fd → the SOURCE closes the raw fd (no leak).

    Uses the REAL ``AnthropicProvider``/client so the production teardown is exercised: the real
    ``aclose`` closes the (never-dialed) httpx client without touching the passed fd, and the
    source's ``finally`` reclaims it.
    """
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())  # a real, closeable fd the source must reclaim
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        async with source.bind() as provider:
            assert provider.name == "anthropic"  # deliberately do NOT dial

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # already reclaimed by the source — EBADF proves no leak, single close
    keeper.close()
    a.close()
    b.close()


def test_bind_defers_fd_close_to_client_when_dialed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dialed (``backend.calls > 0``) → the client is the SOLE fd owner; the source must NOT
    also close it (no double-close)."""
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))

    class _FakeProvider:
        name = "anthropic"

        def __init__(self) -> None:
            self.closed = False

        async def aclose(self) -> None:
            os.close(victim)  # simulate the dialed httpx client (sole fd owner) closing the fd
            self.closed = True

    class _FakeBackend:
        calls = 1  # DIALED

    fake_provider = _FakeProvider()
    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd: (fake_provider, _FakeBackend())
    )
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        async with source.bind() as provider:
            assert provider.name == "anthropic"

    anyio.run(_drive)
    assert fake_provider.closed is True  # the client (aclose) closed the fd
    with pytest.raises(OSError):
        os.close(victim)  # already closed by the client; the source did NOT double-close
    keeper.close()
    a.close()
    b.close()


def test_bind_closes_fd_when_build_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pre-dial build failure leaves ``backend is None`` → the source closes the fd + reraises."""
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))

    def _boom(_self: object, _fd: int) -> tuple[object, object]:
        raise RuntimeError("build blew up before any dial")

    monkeypatch.setattr(be._ProviderFactory, "build", _boom)
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        with pytest.raises(RuntimeError):
            async with source.bind():
                pass  # never reached — build raised before yield

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # closed despite the failure — no leak on the fault path
    keeper.close()
    a.close()
    b.close()


def test_bind_closes_fd_on_cancel_before_dial(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``wait_for``-cancel that unwinds the CM before any dial still reclaims the fd (no leak).

    Uses a trivial fake ``aclose`` so the teardown is cancellation-safe and the branch under test
    (``backend.calls == 0`` under CancelledError) is isolated.
    """
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))

    class _FakeProvider:
        name = "anthropic"

        async def aclose(self) -> None:
            return None  # never dialed -> owns nothing; trivial + cancellation-safe

    class _FakeBackend:
        calls = 0  # never dialed

    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd: (_FakeProvider(), _FakeBackend())
    )
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), a)

    async def _body() -> None:
        async with source.bind():
            await asyncio.sleep(10)  # cancelled by wait_for before any dial

    async def _drive() -> None:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(_body(), timeout=0.05)

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # closed on the cancel-before-dial path — no leak
    keeper.close()
    a.close()
    b.close()


def test_bind_reclaims_fd_when_aclose_raises_never_dialed(monkeypatch: pytest.MonkeyPatch) -> None:
    """R.2.7: a raising ``aclose()`` on the never-dialed path must NOT skip the fd reclaim.

    Before the fix the ``finally`` ran ``await provider.aclose()`` THEN the ``os.close(fd)``
    reclaim sequentially — an ``aclose()`` raise would propagate straight out and skip the
    reclaim, leaking the never-dialed fd. The reclaim must be unconditional once the outer
    ``finally`` is reached, regardless of whether ``aclose()`` raised.
    """
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())  # a real, closeable fd the source must reclaim
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))

    class _FakeProvider:
        name = "anthropic"

        async def aclose(self) -> None:
            raise RuntimeError("aclose blew up before closing anything")

    class _FakeBackend:
        calls = 0  # never dialed

    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd: (_FakeProvider(), _FakeBackend())
    )
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        with pytest.raises(RuntimeError, match="aclose blew up"):
            async with source.bind() as provider:
                assert provider.name == "anthropic"  # deliberately do NOT dial

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # reclaimed despite aclose() raising — no leak (R.2.7)
    keeper.close()
    a.close()
    b.close()


# --- drain_leftovers() --------------------------------------------------------------------


def _broker_fd(parent: socket.socket, donor: socket.socket) -> None:
    parent.sendmsg(
        [b"\x01"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [donor.fileno()]))]
    )


def test_drain_sweeps_and_closes_all_leftovers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every un-consumed pre-brokered fd is closed; the sweep stops at ``EAGAIN``."""
    closed: list[int] = []
    real_close = os.close

    def _record_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(be.os, "close", _record_close)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    donors = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(3)]
    source = BrokeredProviderSource(_factory(), child)
    try:
        for d in donors:
            _broker_fd(parent, d)
        source.drain_leftovers()
        assert len(closed) == 3  # every swept fd was closed — no leak
        with pytest.raises(BlockingIOError):
            recv_passed_fd_nonblocking(child)  # queue drained -> EAGAIN
    finally:
        parent.close()
        child.close()
        for d in donors:
            d.close()


def test_drain_stops_on_peer_close_eof() -> None:
    """A peer-closed control end (EOF, no queued frames) terminates the sweep cleanly."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), child)
    parent.close()  # peer closed, nothing queued -> EOF terminator
    source.drain_leftovers()  # returns cleanly, no raise
    child.close()


def test_drain_does_not_swallow_malformed_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """HARD #7: a malformed-frame fault propagates loud out of the sweep — it is NOT swallowed."""
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = BrokeredProviderSource(_factory(), a)

    def _fault(_ce: socket.socket) -> int | None:
        raise ControlFdBrokerError("ancillary_truncated")

    monkeypatch.setattr(be, "recv_passed_fd_nonblocking", _fault)
    with pytest.raises(ControlFdBrokerError):
        source.drain_leftovers()
    a.close()
    b.close()
