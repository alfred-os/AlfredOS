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
import sys
import time

import anyio
import httpx
import pytest

import alfred.security.quarantine_child.brokered_egress as be
from alfred.egress.control_fd_broker import ControlFdBrokerError, recv_passed_fd_nonblocking
from alfred.providers.base import ProviderCapability, ProviderUnavailableError
from alfred.security.quarantine_child.brokered_egress import (
    BrokeredProviderSource,
    ProviderSource,
    QuarantineChildBootError,
    _ProviderFactory,
)

# Longer than any assertion here — used wherever the test is about something OTHER than
# the wall-clock ceiling.
_AMPLE_BUDGET_S = 60.0

# Applied to every test that performs a CRT-fd syscall on a SOCKET handle — `os.dup()` of a
# `socket.fileno()`, or `os.close()` of a `detach()`ed fd. Windows' `socket.socketpair()` is
# AF_INET-backed and its handles are NOT CRT file descriptors, so both raise EBADF there.
#
# Deliberately NARROW. Handing a detached fd to `PassedFdBackend` is portable: production
# reconstitutes it with `socket.socket(fileno=...)`, which accepts a SOCKET handle on Windows,
# and tears it down through the socket object. Tests that only do that (e.g.
# `test_stream_aclose_marks_the_fd_released_on_the_backend`) keep running on Windows — the
# Windows leg is a BLOCKING gate with an assert-RAN floor, so an over-broad guard hollows it.
#
# This is a DECORATOR rather than a call to `_af_unix_socketpair()` below because the guard has
# to be order-independent: the regression that made this file red twice was `os.dup()` running
# on line N while the helper's skip sat on line N+2, so the test died before it could skip.
_posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.dup()/os.close() of a socket fd (a SOCKET handle is not a CRT fd)",
)


def _af_unix_socketpair() -> tuple[socket.socket, socket.socket]:
    """An AF_UNIX pair for SCM_RIGHTS fd-passing — SKIPS on Windows.

    ``socket.AF_UNIX`` does not exist on Windows CPython, so every test that brokers a real
    descriptor is POSIX-only. Guarding at the single point of creation (rather than with a
    decorator per test) means a NEW fd-passing test is guarded for free — the failure mode
    this file just hit was new POSIX tests landing with no win32 guard at all.

    The rest of this module (factory/timeout/protocol-conformance assertions) is portable and
    keeps running on Windows, which is why this is a helper skip and not a module-level mark.
    """
    if sys.platform == "win32":
        pytest.skip("AF_UNIX SCM_RIGHTS fd-passing is POSIX-only; the Windows dev path is WSL2")
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)


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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.close() of a detached socket fd (a SOCKET handle is not a CRT fd)",
)
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
    provider, backend = _factory(factory_timeout).build(fd, budget_seconds=_AMPLE_BUDGET_S)
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


@_posix_only
def test_bind_closes_fd_when_never_dialed(monkeypatch: pytest.MonkeyPatch) -> None:
    """No dial → the httpx client never wrapped the fd → the SOURCE closes the raw fd (no leak).

    Uses the REAL ``AnthropicProvider``/client so the production teardown is exercised: the real
    ``aclose`` closes the (never-dialed) httpx client without touching the passed fd, and the
    source's ``finally`` reclaims it.
    """
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())  # a real, closeable fd the source must reclaim
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        async with source.bind(budget_seconds=_AMPLE_BUDGET_S) as provider:
            assert provider.name == "anthropic"  # deliberately do NOT dial

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # already reclaimed by the source — EBADF proves no leak, single close
    keeper.close()
    a.close()
    b.close()


@_posix_only
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
        fd_closed = True  # ... and its aclose() closed the fd

    fake_provider = _FakeProvider()
    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd, **_kw: (fake_provider, _FakeBackend())
    )
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        async with source.bind(budget_seconds=_AMPLE_BUDGET_S) as provider:
            assert provider.name == "anthropic"

    anyio.run(_drive)
    assert fake_provider.closed is True  # the client (aclose) closed the fd
    with pytest.raises(OSError):
        os.close(victim)  # already closed by the client; the source did NOT double-close
    keeper.close()
    a.close()
    b.close()


@_posix_only
def test_bind_closes_fd_when_build_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pre-dial build failure leaves ``backend is None`` → the source closes the fd + reraises."""
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))

    def _boom(_self: object, _fd: int, **_kw: object) -> tuple[object, object]:
        raise RuntimeError("build blew up before any dial")

    monkeypatch.setattr(be._ProviderFactory, "build", _boom)
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        with pytest.raises(RuntimeError):
            async with source.bind(budget_seconds=_AMPLE_BUDGET_S):
                pass  # never reached — build raised before yield

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # closed despite the failure — no leak on the fault path
    keeper.close()
    a.close()
    b.close()


@_posix_only
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
        fd_closed = False

    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd, **_kw: (_FakeProvider(), _FakeBackend())
    )
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _body() -> None:
        async with source.bind(budget_seconds=_AMPLE_BUDGET_S):
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


@_posix_only
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
        fd_closed = False

    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd, **_kw: (_FakeProvider(), _FakeBackend())
    )
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        with pytest.raises(RuntimeError, match="aclose blew up"):
            async with source.bind(budget_seconds=_AMPLE_BUDGET_S) as provider:
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
    parent, child = _af_unix_socketpair()
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
    parent, child = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), child)
    parent.close()  # peer closed, nothing queued -> EOF terminator
    source.drain_leftovers()  # returns cleanly, no raise
    child.close()


def test_drain_does_not_swallow_malformed_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """HARD #7: a malformed-frame fault propagates loud out of the sweep — it is NOT swallowed."""
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    def _fault(_ce: socket.socket) -> int | None:
        raise ControlFdBrokerError("ancillary_truncated")

    monkeypatch.setattr(be, "recv_passed_fd_nonblocking", _fault)
    with pytest.raises(ControlFdBrokerError):
        source.drain_leftovers()
    a.close()
    b.close()


# --- B1/B2: the attempt budget reaches the socket, and bind() is inside it -----------------


@_posix_only
def test_build_anchors_the_attempt_deadline_from_the_budget() -> None:
    """The socket's absolute deadline comes from the REMAINING extraction budget, so the LAST
    retry attempt gets a truncated ceiling instead of a fresh full SDK read past the 20s cap."""
    a, b = socket.socketpair()
    fd = a.detach()
    before = time.monotonic()
    provider, backend = _factory().build(fd, budget_seconds=1.0)
    try:
        assert before + 1.0 <= backend._deadline_at <= time.monotonic() + 1.0
        # The per-syscall idle cap still applies UNDER the absolute deadline.
        assert backend._read_timeout == 8.0
    finally:
        anyio.run(provider.aclose)
        os.close(fd)
        b.close()


@_posix_only
def test_bind_charges_control_recv_latency_to_the_attempt_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B2: ``remaining_budget`` was snapshotted BEFORE ``bind()``, so a slow control-fd recv
    escaped the cap entirely. The deadline is anchored at bind ENTRY, so recv latency is spent
    out of the same budget rather than added on top of it."""
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    recv_delay = 0.3

    def _slow_recv(_ce: socket.socket) -> tuple[bytes, int]:
        time.sleep(recv_delay)
        return (b"\x01", victim)

    monkeypatch.setattr(be, "recv_passed_fd", _slow_recv)
    seen: list[float] = []
    real_build = be._ProviderFactory.build

    def _spy(self: be._ProviderFactory, fd: int, *, budget_seconds: float) -> object:
        seen.append(budget_seconds)
        return real_build(self, fd, budget_seconds=budget_seconds)

    monkeypatch.setattr(be._ProviderFactory, "build", _spy)
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        async with source.bind(budget_seconds=2.0):
            pass

    anyio.run(_drive)
    assert seen, "build() was never reached"
    # The socket budget must be the REMAINDER after the recv, not the original 2.0s.
    assert seen[0] < 2.0 - recv_delay + 0.15
    keeper.close()
    a.close()
    b.close()


def test_bind_control_recv_is_bounded_and_refuses_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """B2 (the wedge): ``recv_passed_fd`` was an UNBOUNDED blocking recv inside a shielded
    worker thread, sitting outside every ceiling in the hierarchy. A socket-count desync (the
    child asking for socket N+1 the host never brokered) wedged the child forever: the host
    tore its own read_frame down at 25s but never reaped, so the process stayed resident
    holding T3. It must fail LOUD and BOUNDED instead.

    ``provider_unavailable`` (not ``cannot_extract``) is the faithful reason — the child could
    not obtain egress toward the provider. That is an infrastructure fault, and laundering it
    as a model-output failure is exactly the err-002 / HARD #7 anti-pattern. Same adjudication
    as the Task-9 broker-failure refusal (ADR-0052 C1).
    """
    a, b = _af_unix_socketpair()  # nothing ever queued on `a`
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> float:
        started = time.monotonic()
        with pytest.raises(ProviderUnavailableError):
            async with source.bind(budget_seconds=0.3):
                pass  # pragma: no cover - the recv refuses before the body runs
        return time.monotonic() - started

    elapsed = anyio.run(_drive)
    assert elapsed < 3.0, f"control recv ran {elapsed:.2f}s — the bound did not apply"
    a.close()
    b.close()


@_posix_only
def test_bind_restores_blocking_mode_so_the_drain_still_sees_eagain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bind bound is applied with ``settimeout`` on the SHARED control socket. Left in
    timeout mode, ``drain_leftovers``' ``MSG_DONTWAIT`` sweep would block-then-``TimeoutError``
    instead of raising ``BlockingIOError`` — silently breaking its EAGAIN terminator."""
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        async with source.bind(budget_seconds=_AMPLE_BUDGET_S):
            pass

    anyio.run(_drive)
    assert a.gettimeout() is None  # back to blocking mode
    source.drain_leftovers()  # EAGAIN terminator intact — no raise
    keeper.close()
    a.close()
    b.close()


# --- B4: the fd reclaim tracks OWNERSHIP, not merely "did it dial" -------------------------


@_posix_only
def test_bind_reclaims_fd_when_aclose_raises_after_dialing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reclaim gate was ``backend.calls == 0`` — "never dialed". But its own comment
    claimed to cover "an aclose() that raises before/without closing the fd", and a raise
    AFTER the client dialed has ``calls > 0``: the source skipped the reclaim and the client
    never got far enough to close it, leaking one descriptor per attempt on a persistent
    child. The gate must ask whether the fd was actually released."""
    keeper = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    victim = os.dup(keeper.fileno())
    monkeypatch.setattr(be, "recv_passed_fd", lambda _ce: (b"\x01", victim))

    class _FakeProvider:
        name = "anthropic"

        async def aclose(self) -> None:
            raise RuntimeError("aclose blew up AFTER the client dialed, before closing the fd")

    class _FakeBackend:
        calls = 1  # DIALED
        fd_closed = False  # ... but the stream's aclose never ran, so the fd is still ours

    monkeypatch.setattr(
        be._ProviderFactory, "build", lambda _self, _fd, **_kw: (_FakeProvider(), _FakeBackend())
    )
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)

    async def _drive() -> None:
        with pytest.raises(RuntimeError, match="AFTER the client dialed"):
            async with source.bind(budget_seconds=_AMPLE_BUDGET_S):
                pass

    anyio.run(_drive)
    with pytest.raises(OSError):
        os.close(victim)  # reclaimed despite calls > 0 — no leak
    keeper.close()
    a.close()
    b.close()


def test_stream_aclose_marks_the_fd_released_on_the_backend() -> None:
    """The ownership signal is set by the real stream teardown, not asserted into existence:
    once the client's stream closes the socket, the backend reports the fd as released so the
    source's reclaim stands down (no double-close)."""
    a, b = socket.socketpair()
    backend = be.PassedFdBackend(a.detach(), read_timeout=5.0, budget_seconds=_AMPLE_BUDGET_S)

    async def _drive() -> None:
        stream = await backend.connect_tcp("ignored.invalid", 443)
        assert backend.fd_closed is False  # dialed, still owned by the live stream
        await stream.aclose()

    anyio.run(_drive)
    assert backend.fd_closed is True
    b.close()


# --- B4: max_tokens is the validated factory value, not a per-call env re-read -------------


def test_source_exposes_the_validated_max_tokens() -> None:
    """``_ProviderFactory.max_tokens`` was dead state: ``build()`` never read it while the real
    per-request budget was re-read from ``os.environ`` on every extract, bypassing the
    boot-time ``> 0`` validation gate. The source now surfaces the validated value."""
    a, b = socket.socketpair()
    source = BrokeredProviderSource(_factory(), a)
    assert source.max_tokens == 8192
    a.close()
    b.close()


def test_control_recv_refuses_when_the_budget_is_already_spent() -> None:
    """An attempt whose budget expired before the descriptor arrived must refuse rather than
    issue a zero/negative-timeout ``recvmsg`` (which would silently become non-blocking)."""
    a, b = _af_unix_socketpair()
    source = BrokeredProviderSource(_factory(), a)
    with pytest.raises(ProviderUnavailableError, match="budget spent"):
        source._recv_one_fd(time.monotonic() - 1.0)
    assert a.gettimeout() is None  # refused before touching the shared socket's mode
    a.close()
    b.close()
