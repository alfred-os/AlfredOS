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

import os
import socket
import ssl
import threading
import time
from unittest.mock import Mock

import anyio
import certifi
import httpcore
import httpx
import pytest

from alfred.security.quarantine_child.brokered_egress import (
    InvalidAttemptBudgetError,
    MissingReadTimeoutError,
    PassedFdBackend,
    RedialError,
    _BlockingFdStream,
    _PassedFdTransport,
    build_child_client,
)

# A budget comfortably longer than any single assertion in this module — used wherever the
# test is about something OTHER than the wall-clock ceiling itself.
_AMPLE_BUDGET_S = 60.0


def _stream(
    sock: socket.socket, *, read_timeout: float = 5.0, budget: float = _AMPLE_BUDGET_S
) -> _BlockingFdStream:
    """Build a stream the way ``PassedFdBackend.connect_tcp`` does (absolute deadline)."""
    return _BlockingFdStream(sock, read_timeout=read_timeout, deadline_at=time.monotonic() + budget)


def test_backend_second_connect_tcp_raises() -> None:
    a, b = socket.socketpair()
    backend = PassedFdBackend(a.detach(), read_timeout=5.0, budget_seconds=_AMPLE_BUDGET_S)

    async def _drive() -> None:
        stream = await backend.connect_tcp("ignored.invalid", 443)
        with pytest.raises(RuntimeError):  # RedialError subclass
            await backend.connect_tcp("ignored.invalid", 443)
        await stream.aclose()

    anyio.run(_drive)
    assert backend.calls == 2
    b.close()


def test_redial_error_is_runtime_error() -> None:
    assert issubclass(RedialError, RuntimeError)


def test_connect_tcp_applies_read_timeout_ceiling() -> None:
    """The rev.2 crux (prov-001): the read budget is a HARD socket-level ceiling, so the
    blocking, un-cancellable recv cannot outrun the child's wall-clock budget."""
    a, b = socket.socketpair()
    backend = PassedFdBackend(a.detach(), read_timeout=5.0, budget_seconds=_AMPLE_BUDGET_S)

    async def _drive() -> None:
        stream = await backend.connect_tcp("ignored.invalid", 443)
        assert stream._sock.gettimeout() == 5.0  # settimeout applied, not blocking (None)
        await stream.aclose()

    anyio.run(_drive)
    b.close()


def test_stream_read_write_roundtrip() -> None:
    a, b = socket.socketpair()
    stream = _stream(a)

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
    stream = _stream(sock)
    assert stream.get_extra_info("ssl_object") is sslobj  # if-branch forwards the SSL object
    assert stream.get_extra_info("server_addr") is None  # else-branch


def test_stream_get_extra_info_ssl_object_absent_is_none() -> None:
    a, b = socket.socketpair()
    stream = _stream(a)
    assert stream.get_extra_info("ssl_object") is None  # plain socket has no _sslobj
    a.close()
    b.close()


def test_stream_start_tls_wraps_socket_with_handshake() -> None:
    a, b = socket.socketpair()
    stream = _stream(a)
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
    backend = PassedFdBackend(-1, read_timeout=5.0, budget_seconds=_AMPLE_BUDGET_S)

    async def _drive() -> None:
        with pytest.raises(NotImplementedError):
            await backend.connect_unix_socket("/ignored.sock")

    anyio.run(_drive)


def test_backend_sleep_delegates_to_anyio() -> None:
    backend = PassedFdBackend(-1, read_timeout=5.0, budget_seconds=_AMPLE_BUDGET_S)

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
                budget_seconds=_AMPLE_BUDGET_S,
            )
    finally:
        b.close()


# --- B1: the wall-clock ceiling is CUMULATIVE, not a per-syscall idle timeout ---------------

# A drip slower than the socket's idle timeout would trip it on its own and prove nothing; a
# drip FASTER than the idle timeout is what resets it forever. These are chosen so the peer
# always beats the 0.2s idle window, and the 0.3s absolute deadline is the only thing that can
# stop the read loop before the drip ends.
_DRIP_INTERVAL_S = 0.02
_DRIP_DURATION_S = 1.5
_IDLE_TIMEOUT_S = 0.2
_ABSOLUTE_DEADLINE_S = 0.3


def test_read_deadline_is_cumulative_not_per_syscall_idle() -> None:
    """B1 (the core defect): ``sock.settimeout`` is an IDLE timeout that RESETS on every byte.

    ``anyio.to_thread.run_sync`` runs with ``abandon_on_cancel=False``, so the dispatcher's
    ``asyncio.wait_for`` cancels and then *awaits* the shielded worker thread — it cannot stop a
    blocking ``recv``. The socket ceiling is therefore the ONLY bound, and an idle timeout is not
    one: a peer dripping a byte faster than the idle window keeps the read alive indefinitely.

    Every syscall must instead be clamped against ONE absolute deadline, so the child's
    cumulative wall clock is bounded near its budget rather than resetting per byte. Falsifier:
    with the clamp removed this loop runs for the full ``_DRIP_DURATION_S`` (plus one idle
    window) instead of stopping at ``_ABSOLUTE_DEADLINE_S``.
    """
    a, b = socket.socketpair()
    stop = threading.Event()

    def _drip() -> None:
        deadline = time.monotonic() + _DRIP_DURATION_S
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                b.sendall(b"x")
            except OSError:  # pragma: no cover - peer torn down first
                return
            time.sleep(_DRIP_INTERVAL_S)

    stream = _stream(a, read_timeout=_IDLE_TIMEOUT_S, budget=_ABSOLUTE_DEADLINE_S)
    dripper = threading.Thread(target=_drip, daemon=True)
    dripper.start()
    try:

        async def _drive() -> float:
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                while True:
                    await stream.read(1)
            return time.monotonic() - started

        elapsed = anyio.run(_drive)
        # The ONLY discriminator: a per-syscall idle timeout also raises eventually (once the
        # drip stops), just far too late. Pin the WHEN, not merely the raise.
        assert elapsed < _DRIP_DURATION_S / 2, (
            f"read ran {elapsed:.2f}s under a {_ABSOLUTE_DEADLINE_S}s deadline — the budget "
            "reset per syscall instead of accumulating"
        )
    finally:
        stop.set()
        dripper.join(timeout=5.0)
        a.close()
        b.close()


def test_read_past_the_deadline_raises_without_a_syscall() -> None:
    """An already-expired deadline must refuse the next operation outright (HARD #7) rather
    than issue a fresh blocking syscall with a rounded-up timeout."""
    a, b = socket.socketpair()
    b.sendall(b"readable-right-now")
    stream = _BlockingFdStream(a, read_timeout=5.0, deadline_at=time.monotonic() - 1.0)

    async def _drive() -> None:
        with pytest.raises(TimeoutError):
            await stream.read(4)  # data IS available; the deadline still wins

    anyio.run(_drive)
    a.close()
    b.close()


def test_write_is_clamped_by_the_same_absolute_deadline() -> None:
    """The write half shares the ceiling — a stalled ``sendall`` is as un-cancellable as recv."""
    a, b = socket.socketpair()
    stream = _BlockingFdStream(a, read_timeout=5.0, deadline_at=time.monotonic() - 1.0)

    async def _drive() -> None:
        with pytest.raises(TimeoutError):
            await stream.write(b"ping")

    anyio.run(_drive)
    a.close()
    b.close()


def test_start_tls_is_clamped_by_the_same_absolute_deadline() -> None:
    """The TLS handshake is a blocking syscall on the same socket — same ceiling."""
    a, b = socket.socketpair()
    stream = _BlockingFdStream(a, read_timeout=5.0, deadline_at=time.monotonic() - 1.0)
    ctx = Mock()

    async def _drive() -> None:
        with pytest.raises(TimeoutError):
            await stream.start_tls(ctx, server_hostname="api.anthropic.com")  # type: ignore[arg-type]

    anyio.run(_drive)
    ctx.wrap_socket.assert_not_called()  # refused BEFORE touching the socket
    a.close()
    b.close()


def test_start_tls_carries_the_deadline_onto_the_wrapped_stream() -> None:
    """The ceiling must survive the TLS wrap — the wrapped stream is where every response
    byte is actually read, so a deadline that stopped at the handshake would bound nothing."""
    a, b = socket.socketpair()
    deadline = time.monotonic() + _AMPLE_BUDGET_S
    stream = _BlockingFdStream(a, read_timeout=3.0, deadline_at=deadline)
    ctx = Mock()
    ctx.wrap_socket.return_value = Mock()

    async def _drive() -> _BlockingFdStream:
        return await stream.start_tls(ctx, server_hostname="api.anthropic.com")  # type: ignore[arg-type,return-value]

    tls_stream = anyio.run(_drive)
    assert tls_stream._deadline_at == deadline
    assert tls_stream._read_timeout == 3.0
    a.close()
    b.close()


def test_per_operation_timeout_is_clamped_to_the_remaining_budget() -> None:
    """The per-syscall value is ``min(read_timeout, remaining)`` — the idle cap still applies
    early in the attempt, and the remaining budget takes over near the deadline."""
    a, b = socket.socketpair()
    early = _BlockingFdStream(a, read_timeout=2.0, deadline_at=time.monotonic() + 60.0)
    assert early._next_op_timeout() == pytest.approx(2.0)  # idle cap dominates
    late = _BlockingFdStream(a, read_timeout=2.0, deadline_at=time.monotonic() + 0.4)
    assert late._next_op_timeout() == pytest.approx(0.4, abs=0.05)  # remaining budget dominates
    a.close()
    b.close()


def test_backend_rejects_missing_attempt_budget() -> None:
    """HARD #7 sibling of the read-timeout guard: an absent budget would leave the absolute
    deadline unset, silently restoring the per-syscall-idle-only ceiling."""
    with pytest.raises(InvalidAttemptBudgetError):
        PassedFdBackend(-1, read_timeout=5.0)  # default budget_seconds=None


@pytest.mark.parametrize("bad_budget", [0, 0.0, -1.0])
def test_backend_rejects_non_positive_attempt_budget(bad_budget: float) -> None:
    with pytest.raises(InvalidAttemptBudgetError):
        PassedFdBackend(-1, read_timeout=5.0, budget_seconds=bad_budget)


def test_invalid_attempt_budget_error_is_value_error() -> None:
    assert issubclass(InvalidAttemptBudgetError, ValueError)


def test_backend_anchors_the_absolute_deadline_at_construction() -> None:
    """The deadline is anchored when the client is built — i.e. AFTER the control-fd recv has
    already charged its latency to the same extraction budget (B2)."""
    before = time.monotonic()
    backend = PassedFdBackend(-1, read_timeout=5.0, budget_seconds=1.0)
    assert before + 1.0 <= backend._deadline_at <= time.monotonic() + 1.0


# --- B3: the shipped TLS / connection-reuse posture, asserted (not merely named) ------------


def _pool_of(provider: object) -> httpcore.AsyncHTTPProxy:
    """Walk ``build_child_client``'s real object graph to the shipped connection pool.

    Private-attribute walk on purpose: this is the ONLY path from the production factory to
    the posture it configures, and every hop is asserted, so an SDK/httpx reshape (or a swap
    of ``_PassedFdTransport`` for a stock transport) fails LOUD here instead of quietly
    turning this security pin into a no-op.
    """
    sdk_client = provider._client  # type: ignore[attr-defined]  # AnthropicProvider -> AsyncAnthropic
    http_client = sdk_client._client
    assert isinstance(http_client, httpx.AsyncClient)
    assert http_client.follow_redirects is False  # E2: no redirect off the pinned host
    transport = http_client._transport
    assert isinstance(transport, _PassedFdTransport)  # pins build_child_client's own wiring
    pool = transport._pool
    assert isinstance(pool, httpcore.AsyncHTTPProxy)
    return pool


def test_build_child_client_verifies_tls_against_the_system_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HARD #5: TLS terminates IN the child, fully verified. The prior version of this test
    asserted only ``provider.name`` and ``backend.calls == 0`` — a flip to
    ``ssl._create_unverified_context()`` would have passed green under a test named to forbid
    it. ``ssl.create_default_context()`` yields CERT_REQUIRED + check_hostname and honours
    ``SSL_CERT_FILE``; this pins that, it does not change it.

    ``SSL_CERT_FILE`` is pinned to a known bundle rather than trusted to the runner's default,
    because that is the mechanism production actually uses (the host exports it against the
    bwrap-bound ``/etc/ssl/certs``) *and* because ``get_ca_certs()`` reports anchors only for a
    CA *file*: under a hashed CApath directory — the usual Linux layout — OpenSSL resolves
    lazily and returns ``[]`` while verifying correctly, which reds this assertion off macOS.
    """
    monkeypatch.setenv("SSL_CERT_FILE", certifi.where())
    a, b = socket.socketpair()
    provider, backend = build_child_client(
        a.detach(),
        model="claude-haiku-4-5",
        api_key="stub",
        timeout=httpx.Timeout(8.0),
        budget_seconds=_AMPLE_BUDGET_S,
    )
    try:
        ctx = _pool_of(provider)._ssl_context
        assert ctx is not None, "no SSL context at all — the child would speak plaintext"
        assert ctx.verify_mode is ssl.CERT_REQUIRED  # never CERT_NONE
        assert ctx.check_hostname is True  # never a hostname-blind context
        assert ctx.get_ca_certs(), "no trust anchors — the child could not verify anyone"
    finally:
        anyio.run(provider.aclose)
        assert backend.calls == 0  # never dialed, so the client never owned the fd
        os.close(backend._fd)  # this test owns the un-dialed fd (bind() owns it in production)
        b.close()


def test_build_child_client_is_single_use_no_keepalive_no_retry() -> None:
    """Per-call, one-shot posture (spike A2 / §8): ONE connection, no keepalive, no transport
    retry. Any of these three relaxing would make the SDK re-dial a one-shot brokered socket."""
    a, b = socket.socketpair()
    provider, backend = build_child_client(
        a.detach(),
        model="claude-haiku-4-5",
        api_key="stub",
        timeout=httpx.Timeout(8.0),
        budget_seconds=_AMPLE_BUDGET_S,
    )
    try:
        pool = _pool_of(provider)
        assert pool._max_connections == 1
        assert pool._max_keepalive_connections == 0
        assert pool._retries == 0
        assert pool._network_backend is backend  # the brokered fd, not a real dialer
    finally:
        anyio.run(provider.aclose)
        os.close(backend._fd)
        b.close()
