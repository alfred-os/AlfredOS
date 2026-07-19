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

import socket
import ssl

import anyio
import anyio.to_thread  # explicit submodule bind so pyright resolves run_sync (not a re-export)
import httpcore
import httpx
from httpcore import AsyncNetworkBackend, AsyncNetworkStream

from alfred.providers.anthropic_native import AnthropicProvider


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
