"""Child-side per-call transport: the official Anthropic SDK over a bare TCP fd
brokered by the core (#340 PR2b-golive, spike verdict M1).

Egress-capable imports (httpx/httpcore/ssl/socket) live at THIS module's scope —
allowlisted in the in-core HTTP-egress guard (``test_in_core_http_egress_guard``).
This module is imported LAZILY from ``__main__.py``'s extract path, so the
child-import closure gate (``test_quarantine_child_import_closure``) never sees it
at ``__main__`` module scope.

Per-call, no-keepalive: one brokered socket -> one client -> one request -> close.
TLS terminates HERE (HARD #5) via the system-store verify path (``SSL_CERT_FILE``);
the core writes zero application bytes onto the brokered socket.

Wall-clock ceiling (rev.2 / prov-001, corrected): the blocking SDK ``recv`` runs in
``anyio.to_thread.run_sync`` with ``abandon_on_cancel=False`` (the default), so the
dispatcher's ``asyncio.wait_for`` cancels and then *awaits* the shielded worker thread
until it returns on its own. ``wait_for`` therefore cannot bound this path, and the
socket is the only place a ceiling can live.

``sock.settimeout(...)`` alone is NOT that ceiling: it is a per-syscall IDLE timeout that
RESETS on every byte received, so a peer dripping bytes slower than the budget but faster
than the idle window keeps the un-cancellable ``recv`` alive indefinitely. Every socket
operation is therefore clamped against ONE **absolute deadline** anchored at the start of
the attempt — each syscall gets ``min(read_timeout, deadline - now)`` and an expired
deadline refuses outright. The deadline is derived from the REMAINING per-extraction
wall-clock budget the dispatcher hands to ``BrokeredProviderSource.bind()``, so the child
cannot reply after its 20s budget (``provider_dispatch._MAX_TOTAL_WALL_CLOCK_SECONDS``)
even on the last retry attempt — which is what keeps it under the host's 25s
``_READ_FRAME_TIMEOUT_S`` and its in-budget refusal from being torn away unread.

The read component is also injected into the httpx client so httpcore computes matching
per-request budgets. httpcore's per-operation ``timeout`` arguments are deliberately NOT
re-applied to the socket: our clamp is always the tighter of the two and must never be
widened by a looser per-call value.
"""

from __future__ import annotations

import os
import socket
import ssl
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import anyio
import anyio.to_thread  # explicit submodule bind so pyright resolves run_sync (not a re-export)
import httpcore
import httpx
import structlog
from httpcore import AsyncNetworkBackend, AsyncNetworkStream

from alfred.egress.control_fd_broker import recv_passed_fd, recv_passed_fd_nonblocking
from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import ProviderCapability, ProviderUnavailableError

_log = structlog.get_logger(__name__)

# Upper bound on the fd-4 control-channel ``recvmsg`` that opens every attempt. Connect-defer
# means the host ``sendmsg``s ALL N sockets into the child's SCM_RIGHTS queue BEFORE writing the
# extract frame, so by the time the child binds, the descriptors are already queued and this recv
# returns immediately. It is bounded anyway because the failure mode is a WEDGE: on a socket-count
# desync (the child asking for socket N+1 the host never brokered) an unbounded blocking recv sits
# in a shielded worker thread outside every ceiling in the hierarchy — the host tears its own
# read_frame down at 25s but does not reap, leaving a T3-holding child resident forever. Clamped
# further by the attempt deadline, so this is a ceiling, not a floor.
_CONTROL_RECV_TIMEOUT_S = 2.0


def _noop() -> None:
    """Default fd-release callback — a plain function (not a branch) so the notify path stays
    unconditional and the 100%-branch gate has nothing spurious to cover."""


class RedialError(RuntimeError):
    """connect_tcp called a 2nd time — a re-dial the single passed fd cannot serve."""


class InvalidAttemptBudgetError(ValueError):
    """``budget_seconds`` was ``None`` or non-positive at ``PassedFdBackend`` construction.

    HARD #7 sibling of :class:`MissingReadTimeoutError`. Without a positive attempt budget the
    absolute deadline is unset, leaving the per-syscall idle timeout — which RESETS on every
    byte received — as the only bound. That is not a cumulative ceiling, so a slow-drip
    response would run unbounded inside an un-cancellable worker thread. Fail loud at build
    time instead of at exploit time.
    """


class MissingReadTimeoutError(ValueError):
    """``read_timeout`` was ``None`` or non-positive at ``PassedFdBackend`` construction.

    HARD #7 (no silent fail-open): a missing or non-positive read timeout would leave
    ``sock.settimeout(...)`` either unset (blocking-forever mode) or set to a value that
    can never elapse, silently voiding the wall-clock ceiling that is this module's whole
    purpose (prov-001). Fail loud at build time instead of at exploit time.
    """


class _BlockingFdStream(AsyncNetworkStream):
    """AsyncNetworkStream over ONE blocking socket, driven off-loop.

    Every operation is clamped against ``deadline_at`` — an ABSOLUTE ``time.monotonic``
    instant shared by every syscall of one extraction attempt. ``read_timeout`` remains the
    per-syscall idle cap (a dead peer is detected long before the budget expires), but it can
    only ever narrow the remaining budget, never extend it: the effective timeout is
    ``min(read_timeout, deadline_at - now)``. Without the absolute term a slow-drip peer resets
    the idle window on every byte and the un-cancellable ``recv`` runs unbounded.

    ``on_fd_released`` is invoked once the socket is closed. The passed fd has exactly one
    owner at a time (§8 D5) and this is how :meth:`BrokeredProviderSource.bind` learns the
    httpx client actually released it — "did it dial" is not the same question, and answering
    the wrong one leaks a descriptor whenever ``aclose()`` raises after dialing.
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        read_timeout: float,
        deadline_at: float,
        on_fd_released: Callable[[], None] = _noop,
    ) -> None:
        self._sock = sock
        self._read_timeout = read_timeout
        self._deadline_at = deadline_at
        self._on_fd_released = on_fd_released

    def _next_op_timeout(self) -> float:
        """The timeout for the NEXT blocking syscall, or raise if the attempt is already over.

        Raising ``TimeoutError`` (which ``socket.timeout`` aliases) keeps the shape identical
        to a socket-level expiry, so the dispatcher's existing terminal-timeout handling maps
        it the same way whether the deadline fired mid-syscall or between syscalls.
        """
        remaining = self._deadline_at - time.monotonic()
        if remaining <= 0.0:
            raise TimeoutError(
                "quarantine child attempt deadline exceeded — refusing a further socket "
                "operation (the per-extraction wall-clock budget is spent)"
            )
        return min(self._read_timeout, remaining)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        # timeout: httpcore's per-op value can only be looser than our clamp (it is the same
        # httpx read timeout, without the absolute-deadline term), so it is not re-applied.
        del timeout
        self._sock.settimeout(self._next_op_timeout())
        return await anyio.to_thread.run_sync(self._sock.recv, max_bytes)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout  # same clamp rationale as read()
        self._sock.settimeout(self._next_op_timeout())
        await anyio.to_thread.run_sync(self._sock.sendall, buffer)

    async def aclose(self) -> None:
        try:
            await anyio.to_thread.run_sync(self._sock.close)
        finally:
            # In a ``finally``: POSIX releases the descriptor even when ``close(2)`` reports an
            # error, so signalling release only on the happy path could make the source
            # double-close (and clobber an unrelated reused fd).
            self._on_fd_released()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> AsyncNetworkStream:
        del timeout  # the handshake is clamped by the same deadline (see module docstring)
        self._sock.settimeout(self._next_op_timeout())

        def _wrap() -> socket.socket:
            return ssl_context.wrap_socket(
                self._sock, server_hostname=server_hostname, do_handshake_on_connect=True
            )

        # The wrapped stream carries the SAME deadline and release callback: every response
        # byte is read through it, so a ceiling that stopped at the handshake would bound
        # nothing, and a release signal that stopped there would lose fd ownership.
        return _BlockingFdStream(
            await anyio.to_thread.run_sync(_wrap),
            read_timeout=self._read_timeout,
            deadline_at=self._deadline_at,
            on_fd_released=self._on_fd_released,
        )

    def get_extra_info(self, info: str) -> object | None:
        if info == "ssl_object":
            return getattr(self._sock, "_sslobj", None)
        return None


class PassedFdBackend(AsyncNetworkBackend):
    """httpcore backend over ONE passed fd; raises on any 2nd dial (re-dial instrument).

    Two independent bounds, both mandatory (HARD #7 — neither may silently default):

    * ``read_timeout`` — the per-syscall IDLE cap. Detects a dead peer quickly.
    * ``budget_seconds`` — the attempt's remaining wall-clock budget, anchored HERE into an
      absolute deadline every socket operation is clamped against. This is the real ceiling:
      the idle cap resets on every byte received and so bounds nothing cumulatively.

    A missing/non-positive value for either raises at construction rather than degrading to
    an unbounded socket. ``fd_closed`` reports whether the yielded stream actually released
    the passed descriptor — the fd-ownership signal :meth:`BrokeredProviderSource.bind` needs.
    """

    def __init__(
        self,
        fd: int,
        *,
        read_timeout: float | None = None,
        budget_seconds: float | None = None,
    ) -> None:
        if read_timeout is None or read_timeout <= 0:
            raise MissingReadTimeoutError(
                "read_timeout must be a positive number of seconds, got "
                f"{read_timeout!r} — a missing/non-positive ceiling would leave the "
                "child's blocking recv() unbounded (HARD #7)."
            )
        if budget_seconds is None or budget_seconds <= 0:
            raise InvalidAttemptBudgetError(
                "budget_seconds must be a positive number of seconds, got "
                f"{budget_seconds!r} — without it the absolute deadline is unset and the "
                "per-syscall idle timeout (which resets on every byte) becomes the only "
                "bound, i.e. no cumulative ceiling at all (HARD #7)."
            )
        self._fd = fd
        self._read_timeout = read_timeout
        # Anchored at construction, which is AFTER bind()'s control-fd recv — so that recv's
        # latency is spent out of the same budget rather than added on top of it.
        self._deadline_at = time.monotonic() + budget_seconds
        self.calls = 0
        self.fd_closed = False

    def _mark_fd_released(self) -> None:
        self.fd_closed = True

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object | None = None,
    ) -> AsyncNetworkStream:
        # host/port/timeout/local_address/socket_options: the brokered fd is ALREADY
        # connected to the gateway proxy — dial coordinates are ignored by design, and the
        # ceiling comes from self._read_timeout + self._deadline_at, not httpcore's timeouts.
        del host, port, timeout, local_address, socket_options
        self.calls += 1  # BEFORE touching the fd -> a re-dial is observable
        if self.calls > 1:
            raise RedialError(f"connect_tcp called {self.calls}x — one fd cannot serve a 2nd dial")
        sock = socket.socket(fileno=self._fd)
        # Seed the idle cap; every subsequent operation re-clamps it against the deadline.
        sock.settimeout(self._read_timeout)
        return _BlockingFdStream(
            sock,
            read_timeout=self._read_timeout,
            deadline_at=self._deadline_at,
            on_fd_released=self._mark_fd_released,
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: object | None = None
    ) -> AsyncNetworkStream:
        raise NotImplementedError

    async def sleep(self, seconds: float) -> None:
        await anyio.sleep(seconds)


class _PassedFdTransport(httpx.AsyncHTTPTransport):
    """httpx exposes no network_backend seam -> subclass and replace self._pool with an
    AsyncHTTPProxy on our backend. ssl_context = system store (SSL_CERT_FILE), NOT certifi."""

    def __init__(self, backend: PassedFdBackend) -> None:
        super().__init__()
        self._pool = httpcore.AsyncHTTPProxy(
            proxy_url="http://proxy.invalid:8888",  # host/port ignored by our connect_tcp
            ssl_context=ssl.create_default_context(),  # full verification via the system store
            network_backend=backend,
            retries=0,
            max_connections=1,
            max_keepalive_connections=0,
        )


def build_child_client(
    fd: int, *, model: str, api_key: str, timeout: httpx.Timeout, budget_seconds: float
) -> tuple[AnthropicProvider, PassedFdBackend]:
    """Build the #339-seam AnthropicProvider over the passed fd. max_retries=0 (spike A2),
    single connection, no keepalive, no redirects (E2). TLS terminates in-child (HARD #5).

    The read component of ``timeout`` becomes the backend's per-syscall idle cap AND is
    injected into the httpx client. ``budget_seconds`` — what remains of the per-extraction
    wall-clock budget — becomes the absolute deadline every socket operation is clamped
    against, which is the ceiling that actually holds (rev.2 / prov-001)."""
    backend = PassedFdBackend(fd, read_timeout=timeout.read, budget_seconds=budget_seconds)
    transport = _PassedFdTransport(backend)
    http_client = httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=timeout)
    provider = AnthropicProvider.from_settings(
        api_key=api_key, model=model, http_client=http_client, max_retries=0, timeout=timeout
    )
    return provider, backend


# The child read component must sit UNDER the wall-clock budget (spec §4 P1e / §19-A3) and stay
# strictly positive so it satisfies PassedFdBackend's MissingReadTimeoutError guard (Task 3).
_CHILD_SDK_READ_TIMEOUT = httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0)


class QuarantineChildBootError(RuntimeError):
    """The child cannot build a real provider (empty key) — refuse boot (HARD #7, §20.2 secondary).

    RuntimeError-rooted like this module's sibling transport errors (``RedialError``,
    ``MissingReadTimeoutError``): these are child-subprocess-local boot/transport faults, not part
    of the in-core ``AlfredError`` flow that traverses the orchestrator.
    """


@dataclass(frozen=True, slots=True)
class _ProviderFactory:
    """Frozen, key-free-repr builder for the child's per-attempt Anthropic provider (§8).

    ``build(fd)`` assembles the #339-seam ``AnthropicProvider`` over ONE brokered TCP fd via
    ``build_child_client``. ``from_key`` is the child's SECONDARY refuse-boot guard (§20.2): an
    empty provider key means the child cannot build a real provider, so it refuses to boot with a
    loud :class:`QuarantineChildBootError` rather than silently degrading to a dead LLM (HARD #7).
    The HOST pre-spawn key check (Task 6/7) is the PRIMARY guard; this is defence-in-depth.
    """

    api_key: str
    model: str
    max_tokens: int
    timeout: httpx.Timeout | None

    @classmethod
    def from_key(cls, key: str, *, model: str, max_tokens: int) -> _ProviderFactory:
        if not key:
            raise QuarantineChildBootError(
                "quarantine provider key is empty — refusing to boot a dead-LLM child (§20.2)"
            )
        return cls(api_key=key, model=model, max_tokens=max_tokens, timeout=_CHILD_SDK_READ_TIMEOUT)

    def build(self, fd: int, *, budget_seconds: float) -> tuple[AnthropicProvider, PassedFdBackend]:
        """Assemble the per-attempt client. ``budget_seconds`` is what remains of the
        extraction's wall-clock budget and becomes the attempt's absolute socket deadline."""
        return build_child_client(
            fd,
            model=self.model,
            api_key=self.api_key,
            timeout=self.timeout or _CHILD_SDK_READ_TIMEOUT,
            budget_seconds=budget_seconds,
        )

    def __repr__(self) -> str:
        # Key-free repr (anti-leak, the _DeterministicProvider discipline): the api_key must never
        # reach a log line or a traceback frame (HARD #5 / no-secret-in-logs).
        return f"_ProviderFactory(model={self.model!r}, max_tokens={self.max_tokens})"


@runtime_checkable
class ProviderSource(Protocol):
    """The provider-binding seam Task 5/6 dispatch code depends on — typed, not ``Any``.

    ``BrokeredProviderSource`` is the concrete brokered-egress impl; a future in-process or test
    source can satisfy the same surface. Kept a Protocol so ``dispatch_extraction(source:
    ProviderSource)`` type-checks structurally under ``mypy --strict`` without importing the
    concrete class. ``@runtime_checkable`` lets a boot assertion confirm the method surface too.
    """

    @property
    def max_tokens(self) -> int: ...

    def capabilities(self) -> frozenset[ProviderCapability]: ...

    def bind(self, *, budget_seconds: float) -> AbstractAsyncContextManager[AnthropicProvider]: ...

    def drain_leftovers(self) -> None: ...


class BrokeredProviderSource:
    """Per-attempt provider binder over the fd-4 control channel (§8 wrapper-provider).

    Each :meth:`bind` receives ONE pre-brokered, gateway-connected TCP fd off-loop, assembles the
    Anthropic SDK over it, and yields the provider for exactly one extraction attempt. On exit it
    owns the fd's lifecycle (§8 D5): the httpx client's ``aclose`` is the SOLE fd owner once it has
    dialed; before any dial the source closes the raw fd itself. :meth:`drain_leftovers` sweeps any
    pre-brokered sockets an early-success retry loop never consumed.
    """

    _CAPS = AnthropicProvider.CAPABILITIES  # model-invariant classvar — reading it is socket-free

    def __init__(self, factory: _ProviderFactory, control_end: socket.socket) -> None:
        self._factory = factory
        self._control_end = control_end

    @property
    def max_tokens(self) -> int:
        """The boot-validated per-request token budget (``ALFRED_QUARANTINE_MAX_TOKENS``).

        Surfaced off the factory so the request loop uses the value ``_build_provider``'s
        ``> 0`` guard already vetted, instead of re-reading ``os.environ`` per extraction and
        routing around that gate.
        """
        return self._factory.max_tokens

    def capabilities(self) -> frozenset[ProviderCapability]:
        return self._CAPS

    def _recv_one_fd(self, deadline_at: float) -> tuple[bytes, int]:
        """Receive ONE brokered descriptor, bounded by the attempt deadline (never unbounded).

        The bound is applied with ``settimeout`` on the SHARED control socket and restored to
        blocking mode in a ``finally``: left in timeout mode, ``drain_leftovers``'
        ``MSG_DONTWAIT`` sweep would block-then-``TimeoutError`` instead of raising
        ``BlockingIOError``, silently breaking its EAGAIN terminator.

        A timeout means the host never brokered this attempt's socket, so the child has no
        route to the provider: :class:`ProviderUnavailableError` (a terminal
        ``provider_unavailable`` refusal), NOT the ``cannot_extract`` an unmapped
        ``TimeoutError`` would land as. Laundering an egress fault as a model-output failure
        is the err-002 / HARD #7 anti-pattern, and it is the same adjudication the Task-9
        broker-failure path took (ADR-0052 C1).
        """
        remaining = deadline_at - time.monotonic()
        timeout_s = min(_CONTROL_RECV_TIMEOUT_S, remaining)
        if timeout_s <= 0.0:
            raise ProviderUnavailableError(
                "quarantine child: attempt budget spent before a brokered socket was received"
            )
        self._control_end.settimeout(timeout_s)
        try:
            return recv_passed_fd(self._control_end)
        except TimeoutError as exc:
            raise ProviderUnavailableError(
                "quarantine child: no brokered socket arrived on the control channel within "
                f"{timeout_s:.2f}s — the host did not broker this attempt's egress"
            ) from exc
        finally:
            # settimeout(None) == setblocking(True), spelled as the inverse of the
            # settimeout above so the restore is obviously symmetric (and FBT003-free).
            self._control_end.settimeout(None)

    @asynccontextmanager
    async def bind(self, *, budget_seconds: float) -> AsyncIterator[AnthropicProvider]:
        """Bind ONE attempt's provider over ONE brokered socket.

        ``budget_seconds`` is what REMAINS of the extraction's wall-clock budget. The deadline
        is anchored HERE, before the control recv, so every step of the attempt — receiving the
        descriptor, the TLS handshake, the request, the response — is spent out of one budget
        rather than each getting a fresh one.
        """
        deadline_at = time.monotonic() + budget_seconds
        _data, fd = await anyio.to_thread.run_sync(self._recv_one_fd, deadline_at)
        provider: AnthropicProvider | None = None
        backend: PassedFdBackend | None = None
        try:
            # The REMAINING budget, not the original: the recv above already spent part of it.
            # A budget exhausted by the recv raises InvalidAttemptBudgetError out of the
            # backend ctor, and the finally below reclaims the fd (backend is still None).
            provider, backend = self._factory.build(
                fd, budget_seconds=deadline_at - time.monotonic()
            )
            yield provider
        finally:
            # R.2.7: the fd reclaim below MUST run even if provider.aclose() raises — nest it in
            # its own inner finally rather than sequencing `os.close` after a bare `await`. If
            # aclose() raised and the reclaim were skipped, the never-dialed fd would leak (the
            # exact leak R.2.7 targets); this way it is unconditional once we reach the outer
            # finally, regardless of whether aclose() completed, raised, or was never called
            # (provider is None).
            try:
                if provider is not None:
                    await provider.aclose()
            finally:
                # §8 D5 fd ownership, decided by RELEASE not by DIAL. Once the httpx client's
                # stream has actually closed the socket (backend.fd_closed), it was the sole
                # owner and closing here too would double-close — possibly clobbering an
                # unrelated reused fd. In every other case the descriptor is still ours and the
                # persistent child leaks one per attempt unless we reclaim it (core-002/err-006):
                # a pre-build raise (backend is None), a wait_for-cancel that unwinds the CM
                # before .complete() dials, an aclose() that raises before closing anything —
                # and, the case the old `backend.calls == 0` gate got WRONG despite its own
                # comment claiming otherwise, an aclose() that raises AFTER the client dialed
                # but before its stream teardown ran.
                if backend is None or not backend.fd_closed:
                    os.close(fd)

    def drain_leftovers(self) -> None:
        """Non-blocking sweep of pre-brokered sockets an early-success retry never consumed (§6).

        Closes each swept fd. Stops on ``EAGAIN`` (nothing more queued) or peer-close EOF — both
        benign terminators. A malformed frame (truncation / wrong fd count) is NOT swallowed: the
        loud :class:`ControlFdBrokerError` from ``recv_passed_fd_nonblocking`` propagates (HARD #7).
        """
        swept = 0
        terminator = "eof"
        while True:
            try:
                fd = recv_passed_fd_nonblocking(self._control_end)
            except BlockingIOError:
                terminator = "eagain"
                break
            if fd is None:
                break
            os.close(fd)
            swept += 1
        _log.debug(
            "quarantine_child.brokered_egress.drain_complete", swept=swept, terminator=terminator
        )


if TYPE_CHECKING:
    # Static-only conformance gate (Task 4 hardening): `@runtime_checkable` only checks that
    # `ProviderSource`'s method NAMES exist on an instance (`isinstance`), never that their
    # SIGNATURES line up. Without this binding, nothing makes `mypy --strict src/` verify
    # `BrokeredProviderSource` structurally satisfies `ProviderSource` until Task 5/6's dispatch
    # code first imports it as the seam type. Declaring the check here instead means a signature
    # drift (e.g. `bind()` losing its context-manager return type, or `drain_leftovers` gaining a
    # required arg) fails `mypy --strict` on THIS PR, not several tasks downstream. Guarded by
    # `TYPE_CHECKING` so it never executes and adds zero runtime cost / no unused-import lint.
    def _assert_conforms(source: BrokeredProviderSource) -> ProviderSource:
        return source
