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

Wall-clock ceiling (rev.2 / prov-001): the blocking SDK ``recv`` runs in
``anyio.to_thread.run_sync`` with ``abandon_on_cancel=False`` (the default), so it is
un-cancellable by ``asyncio.wait_for``. The child's read budget is therefore made a
HARD ceiling at the socket layer — ``connect_tcp`` sets ``sock.settimeout(read_timeout)``
once (preserved across the TLS wrap by ``SSLSocket._create``), so every subsequent
blocking ``recv``/``sendall`` raises after ``read_timeout`` seconds instead of hanging
forever. The same timeout is injected into the httpx client so httpcore computes matching
per-request budgets. Per-operation ``timeout`` arguments are deliberately NOT re-applied
to the socket: the fixed connect-time ceiling must never be widened by a looser per-call
value.
"""

from __future__ import annotations

import os
import socket
import ssl
from collections.abc import AsyncIterator
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
from alfred.providers.base import ProviderCapability

_log = structlog.get_logger(__name__)


class RedialError(RuntimeError):
    """connect_tcp called a 2nd time — a re-dial the single passed fd cannot serve."""


class MissingReadTimeoutError(ValueError):
    """``read_timeout`` was ``None`` or non-positive at ``PassedFdBackend`` construction.

    HARD #7 (no silent fail-open): a missing or non-positive read timeout would leave
    ``sock.settimeout(...)`` either unset (blocking-forever mode) or set to a value that
    can never elapse, silently voiding the wall-clock ceiling that is this module's whole
    purpose (prov-001). Fail loud at build time instead of at exploit time.
    """


class _BlockingFdStream(AsyncNetworkStream):
    """AsyncNetworkStream over ONE blocking socket, driven off-loop. The socket carries
    the HARD read ceiling set by the backend; per-op ``timeout`` args are not re-applied."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        # timeout: the ceiling is enforced once at connect_tcp (settimeout); a per-read
        # value must not widen it, so it is intentionally not re-applied here.
        del timeout
        return await anyio.to_thread.run_sync(self._sock.recv, max_bytes)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout  # same fixed-ceiling rationale as read()
        await anyio.to_thread.run_sync(self._sock.sendall, buffer)

    async def aclose(self) -> None:
        await anyio.to_thread.run_sync(self._sock.close)

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> AsyncNetworkStream:
        del timeout  # the handshake inherits the socket's fixed ceiling (see module docstring)

        def _wrap() -> socket.socket:
            return ssl_context.wrap_socket(
                self._sock, server_hostname=server_hostname, do_handshake_on_connect=True
            )

        return _BlockingFdStream(await anyio.to_thread.run_sync(_wrap))

    def get_extra_info(self, info: str) -> object | None:
        if info == "ssl_object":
            return getattr(self._sock, "_sslobj", None)
        return None


class PassedFdBackend(AsyncNetworkBackend):
    """httpcore backend over ONE passed fd; raises on any 2nd dial (re-dial instrument).

    ``read_timeout`` is the HARD socket-level ceiling applied to the yielded stream so the
    child's blocking, un-cancellable ``recv`` cannot outrun its wall-clock budget (prov-001).
    A missing or non-positive ``read_timeout`` raises ``MissingReadTimeoutError`` at
    construction rather than silently degrading to blocking-forever mode (HARD #7).
    """

    def __init__(self, fd: int, *, read_timeout: float | None = None) -> None:
        if read_timeout is None or read_timeout <= 0:
            raise MissingReadTimeoutError(
                "read_timeout must be a positive number of seconds, got "
                f"{read_timeout!r} — a missing/non-positive ceiling would leave the "
                "child's blocking recv() unbounded (HARD #7)."
            )
        self._fd = fd
        self._read_timeout = read_timeout
        self.calls = 0

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
        # read ceiling comes from self._read_timeout, not httpcore's connect timeout.
        del host, port, timeout, local_address, socket_options
        self.calls += 1  # BEFORE touching the fd -> a re-dial is observable
        if self.calls > 1:
            raise RedialError(f"connect_tcp called {self.calls}x — one fd cannot serve a 2nd dial")
        sock = socket.socket(fileno=self._fd)
        sock.settimeout(self._read_timeout)  # HARD ceiling on the blocking recv (prov-001)
        return _BlockingFdStream(sock)

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
    fd: int, *, model: str, api_key: str, timeout: httpx.Timeout
) -> tuple[AnthropicProvider, PassedFdBackend]:
    """Build the #339-seam AnthropicProvider over the passed fd. max_retries=0 (spike A2),
    single connection, no keepalive, no redirects (E2). TLS terminates in-child (HARD #5).

    The read component of ``timeout`` becomes the backend's HARD socket ceiling AND is
    injected into the httpx client, so the child's wall-clock budget has real teeth
    (rev.2 / prov-001)."""
    backend = PassedFdBackend(fd, read_timeout=timeout.read)
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

    def build(self, fd: int) -> tuple[AnthropicProvider, PassedFdBackend]:
        return build_child_client(
            fd,
            model=self.model,
            api_key=self.api_key,
            timeout=self.timeout or _CHILD_SDK_READ_TIMEOUT,
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

    def capabilities(self) -> frozenset[ProviderCapability]: ...

    def bind(self) -> AbstractAsyncContextManager[AnthropicProvider]: ...

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

    def capabilities(self) -> frozenset[ProviderCapability]:
        return self._CAPS

    @asynccontextmanager
    async def bind(self) -> AsyncIterator[AnthropicProvider]:
        _data, fd = await anyio.to_thread.run_sync(recv_passed_fd, self._control_end)
        provider: AnthropicProvider | None = None
        backend: PassedFdBackend | None = None
        try:
            provider, backend = self._factory.build(fd)
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
                # §8 D5 fd ownership. Once the httpx client has DIALED (backend.calls > 0) its
                # aclose() is the SOLE owner of the passed fd and closes it — closing it here too
                # would double-close (and could clobber an unrelated reused fd). Before any dial
                # (a pre-build raise, an aclose() that raises before/without closing the fd, or a
                # wait_for-cancel that unwinds the CM before .complete() dials), the client never
                # wrapped the fd, so the source MUST close the raw fd itself or the persistent
                # child leaks one descriptor per un-dialed attempt (core-002/err-006).
                if backend is None or backend.calls == 0:
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
