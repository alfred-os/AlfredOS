"""The gateway L7 CONNECT forward-proxy (Spec C §4.1, epic #333).

This is the gateway-side egress ENFORCEMENT plane. The connectivity-free core dials
this proxy (via the in-core ``EgressClient``'s proxied ``httpx.AsyncClient``); the
proxy enforces the destination allowlist and tunnels the opaque TLS bytes through to
the resolved upstream. It is **payload-blind** — a CONNECT tunnel is an opaque byte
splice, so the prompt/response never leave the tunnel and native SDK streaming is
preserved.

Enforcement per CONNECT (each connection is its own task):

* the request-line **authority is the SOLE allowlist source** — the ``Host:`` header
  is never trusted (sec-004);
* a **literal-IP** target is refused (the allowlist is hostname-based; an IP target
  is an attempt to dodge gateway-side DNS) (sec-003 partner);
* a destination not in the live-config allowlist is refused (default-deny);
* DNS is resolved **gateway-side**, and a resolved IP that is **not globally
  routable** is refused — closing the DNS-rebinding TOCTOU (sec-003);
* the request-line read is **bounded** (a small byte cap + a per-handshake timeout),
  so a slow-loris / oversized handshake cannot pin a task;
* every CONNECT — allowed or denied — is audited (gateway-local structlog tier).

A bind failure is **fail-closed**: the ``OSError`` propagates (B2 maps it to
``IOPlaneUnavailableError`` and the gateway crash-loops under
``restart: unless-stopped`` — the proxy IS the gateway's reason to exist).

NOTE: ``import socket`` for the default resolver is permitted in-core (the
HTTP-egress import-guard forbids only provider SDKs / alt-HTTP libs / httpx client
construction; this module constructs neither — it splices raw asyncio streams).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from collections.abc import Awaitable, Callable
from typing import Final

import structlog
from prometheus_client import Counter

from alfred.egress.allowlist import EgressDestination, is_globally_routable, is_literal_ip
from alfred.gateway.egress_audit import (
    EGRESS_CONNECT_ALLOWED_EVENT,
    EGRESS_CONNECT_DENIED_EVENT,
    EgressDenyReason,
)

_log = structlog.get_logger(__name__)

_DEFAULT_EGRESS_PROXY_PORT: Final[int] = 8889
_EGRESS_PROXY_PORT_ENV: Final[str] = "ALFRED_EGRESS_PROXY_PORT"
_EGRESS_PROXY_BIND_ENV: Final[str] = "ALFRED_EGRESS_PROXY_BIND"
# Never host-published (a compose-invariant test asserts it); the destination
# allowlist is the control during the pre-internal:true window (closed at G7-3).
_DEFAULT_EGRESS_PROXY_BIND: Final[str] = "0.0.0.0"  # noqa: S104

# The public DeepSeek provider base URL the gateway adds to its egress allowlist. Read from
# env (NOT the secret-requiring Settings) so the gateway derives the allowlist without a
# provider key (ADR-0036); compose threads the SAME value to the core's Settings.
_DEEPSEEK_BASE_URL_ENV: Final[str] = "ALFRED_DEEPSEEK_BASE_URL"
_DEFAULT_DEEPSEEK_BASE_URL: Final[str] = "https://api.deepseek.com/v1"

# Bounded request-line read: a CONNECT handshake is tiny; cap the buffer + the read
# so a slow-loris / oversized line is refused rather than pinning a task.
_REQUEST_LINE_CAP: Final[int] = 8192
_HANDSHAKE_TIMEOUT_S: Final[float] = 10.0
_SPLICE_CHUNK: Final[int] = 65536

# Provisional metric (G7-5 owns the canonical egress metric/alert set). Default
# registry so the existing gateway /metrics exposition serves it automatically.
GATEWAY_EGRESS_CONNECT: Final[Counter] = Counter(
    "gateway_egress_connect_total",
    "Gateway L7 CONNECT forward-proxy outcomes (provisional; G7-5 finalises).",
    ["outcome"],
)

_AuditSink = Callable[[str, dict[str, object]], None]
_Resolver = Callable[[str], str]
_UpstreamOpener = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


def resolve_egress_proxy_port() -> int:
    """Resolve the proxy port from ``ALFRED_EGRESS_PROXY_PORT`` (default 8889).

    Raises ``ValueError`` loudly on a non-integer / out-of-range value (operator
    misconfig — never silently fall back). Mirrors ``resolve_metrics_port``.
    """
    raw = os.environ.get(_EGRESS_PROXY_PORT_ENV)
    if raw is None or raw == "":
        return _DEFAULT_EGRESS_PROXY_PORT
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{_EGRESS_PROXY_PORT_ENV} must be an integer, got {raw!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{_EGRESS_PROXY_PORT_ENV} must be in 1..65535, got {port}")
    return port


def resolve_egress_proxy_bind() -> str:
    """Resolve the proxy bind interface from ``ALFRED_EGRESS_PROXY_BIND`` (default
    ``0.0.0.0``). The proxy is never host-published; the allowlist is the control."""
    raw = os.environ.get(_EGRESS_PROXY_BIND_ENV)
    if raw is None or raw == "":
        return _DEFAULT_EGRESS_PROXY_BIND
    return raw


def resolve_deepseek_base_url() -> str:
    """Resolve the DeepSeek provider base URL from ``ALFRED_DEEPSEEK_BASE_URL`` (default
    ``https://api.deepseek.com/v1``) — the public host the gateway adds to its egress
    allowlist. Read from env (NOT the secret-requiring Settings) so the gateway derives the
    allowlist without a provider key; compose threads the SAME value to the core's Settings."""
    raw = os.environ.get(_DEEPSEEK_BASE_URL_ENV)
    if raw is None or raw == "":
        return _DEFAULT_DEEPSEEK_BASE_URL
    return raw


def _default_resolve(host: str) -> str:
    """Resolve ``host`` to a single IPv4 literal (gateway-side DNS)."""
    return socket.gethostbyname(host)


async def _default_open_upstream(
    ip: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(ip, port)


class EgressForwardProxy:
    """A TLS-passthrough L7 CONNECT forward-proxy with destination enforcement."""

    def __init__(
        self,
        *,
        allowlist: frozenset[EgressDestination],
        bind_host: str,
        port: int,
        audit: _AuditSink,
        resolve: _Resolver = _default_resolve,
        open_upstream: _UpstreamOpener = _default_open_upstream,
    ) -> None:
        self._allowlist = allowlist
        self._bind_host = bind_host
        self._port = port
        self._audit = audit
        self._resolve = resolve
        self._open_upstream = open_upstream
        self._conns: set[asyncio.Task[None]] = set()

    async def serve(self, shutdown_event: asyncio.Event) -> None:
        """Bind + serve until ``shutdown_event``, then close the listener and reap.

        Fail-closed: an ``OSError`` from ``start_server`` (e.g. EADDRINUSE) propagates
        — B2 maps it to ``IOPlaneUnavailableError``.
        """
        server = await asyncio.start_server(
            self._handle_client, self._bind_host, self._port, limit=_REQUEST_LINE_CAP
        )
        _log.info("gateway.egress.serving", bind=self._bind_host, port=self._port)
        try:
            async with server:
                await shutdown_event.wait()
        finally:
            await self._drain_connections()

    async def _drain_connections(self) -> None:
        """Cancel + await every in-flight connection task on shutdown.

        Each task is awaited INDIVIDUALLY (not via ``gather(return_exceptions=True)``,
        which does not cleanly capture an externally-cancelled child's
        ``CancelledError`` and can hang) so shutdown is deterministic and bounded.
        """
        for task in list(self._conns):
            task.cancel()
        for task in list(self._conns):
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.ensure_future(self._serve_connection(reader, writer))
        self._conns.add(task)
        task.add_done_callback(self._on_connection_done)

    def _on_connection_done(self, task: asyncio.Task[None]) -> None:
        """Reap a finished connection task + surface any ESCAPED exception LOUD.

        A non-cancellation exception escaping ``_serve_connection`` (the audit sink rejecting a
        non-allowlisted field — the fail-loud payload-blindness guard — or any programming bug)
        would otherwise vanish as a GC-time "exception never retrieved". Retrieve + log it at
        ``error`` so hard rule #7 (no silent failure) holds for the WHOLE per-connection task,
        not only the OSError path handled inside ``_serve_connection``.
        """
        self._conns.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _log.error("gateway.egress.connection_failed", error=repr(exc))

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # The CONNECT authority, captured so a pre-/mid-tunnel OSError (DNS gaierror, upstream
        # ECONNREFUSED, mid-splice reset) is ATTRIBUTABLE in the error breadcrumb. A resolution
        # / upstream failure is an UPSTREAM error, NOT a policy denial, so it is recorded as a
        # distinct ``error`` outcome (never mislabelled ``connect_denied``); the durable
        # signed/structured upstream-failure audit is the deferred G7-5 observability set.
        destination_label = "<unread>"
        try:
            destination = await self._read_connect_target(writer, reader)
            if destination is None:
                return
            host, port = destination
            destination_label = f"{host}:{port}"
            if not await self._authorize(host, port, writer):
                return
            # Gateway-side DNS, off the event loop. NOTE: run_in_executor(None, ...) uses the
            # SHARED default thread pool; under a burst of concurrent CONNECTs a slow resolver
            # can queue head-of-line + contend with other default-pool users. A dedicated
            # resolver executor / async resolver is the G7-3/G7-5 head-of-line-isolation
            # hardening (Spec C lists full HoL isolation as out-of-scope for G7-1).
            resolved_ip = await asyncio.get_running_loop().run_in_executor(
                None, self._resolve, host
            )
            if not is_globally_routable(resolved_ip):
                await self._deny(
                    writer, 403, EgressDenyReason.RESOLVED_IP_NOT_GLOBAL, f"{host}:{port}"
                )
                return
            await self._tunnel(host, port, resolved_ip, reader, writer)
        except asyncio.CancelledError:
            raise
        except OSError as exc:  # DNS / upstream open / splice I/O error — loud, bounded, counted
            GATEWAY_EGRESS_CONNECT.labels(outcome="error").inc()
            _log.warning(
                "gateway.egress.connection_error", destination=destination_label, error=repr(exc)
            )
            self._close(writer)

    async def _read_connect_target(
        self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader
    ) -> EgressDestination | None:
        """Read + parse the bounded CONNECT request line. None => already denied."""
        try:
            raw = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=_HANDSHAKE_TIMEOUT_S
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            await self._deny(writer, 400, EgressDenyReason.MALFORMED_CONNECT, "<unread>")
            return None
        request_line = raw.split(b"\r\n", 1)[0].decode("latin-1")
        parts = request_line.split(" ")
        # The request-line authority is the SOLE allowlist source — the Host: header
        # (anywhere in ``raw``) is never parsed (sec-004).
        if len(parts) != 3 or parts[0] != "CONNECT":
            await self._deny(writer, 400, EgressDenyReason.MALFORMED_CONNECT, request_line[:120])
            return None
        host, sep, port_str = parts[1].rpartition(":")
        # ``str.isdigit()`` alone accepts non-ASCII Unicode digits that then make ``int()``
        # raise — which would escape ``_serve_connection`` as an uncaught task exception
        # (no clean 400, no audit row). Require ASCII digits so a crafted port stays a CLEAN
        # malformed_connect refusal (sec-002).
        if not sep or not host or not (port_str.isascii() and port_str.isdigit()):
            await self._deny(writer, 400, EgressDenyReason.MALFORMED_CONNECT, parts[1][:120])
            return None
        # DNS is case-insensitive and the allowlist is lowercased (``urlsplit().hostname``);
        # lowercase the request-line authority so a mixed-case allowlisted host is not
        # spuriously denied (fail-safe today, but a needless availability nit).
        return (host.lower(), int(port_str))

    async def _authorize(self, host: str, port: int, writer: asyncio.StreamWriter) -> bool:
        if is_literal_ip(host):
            await self._deny(writer, 403, EgressDenyReason.LITERAL_IP_TARGET, f"{host}:{port}")
            return False
        if (host, port) not in self._allowlist:
            await self._deny(
                writer, 403, EgressDenyReason.DESTINATION_NOT_ALLOWLISTED, f"{host}:{port}"
            )
            return False
        return True

    async def _tunnel(
        self,
        host: str,
        port: int,
        resolved_ip: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        up_reader, up_writer = await self._open_upstream(resolved_ip, port)
        # Everything after the upstream is open runs inside the try, so BOTH writers are
        # reaped in the finally on EVERY exit — a 200-write error, an audit-sink exception
        # (the fail-loud payload-blindness guard), or a splice fault — never a leaked socket.
        try:
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            GATEWAY_EGRESS_CONNECT.labels(outcome="allowed").inc()
            # Field-allowlisted audit ({destination} only — the resolved IP is gateway-internal
            # and deliberately NOT logged, keeping the row to the CONNECT authority).
            self._audit(EGRESS_CONNECT_ALLOWED_EVENT, {"destination": f"{host}:{port}"})
            await asyncio.gather(
                self._pipe(client_reader, up_writer),
                self._pipe(up_reader, client_writer),
            )
        finally:
            self._close(up_writer)
            self._close(client_writer)

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        """Splice src→dst incrementally (NEVER buffer-until-EOF, so streaming survives).

        A mid-splice ``OSError`` (peer reset) is NOT swallowed here — it propagates to
        the ``_tunnel`` gather → ``_serve_connection``'s bounded OSError handler, which
        tears the whole tunnel down. On normal EOF we half-close (``write_eof``) so the
        peer observes the close; ``suppress`` covers a transport that cannot half-close.
        """
        try:
            while True:
                chunk = await src.read(_SPLICE_CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
                await asyncio.sleep(0)  # yield so the reverse direction interleaves
        finally:
            with contextlib.suppress(OSError):
                dst.write_eof()

    async def _deny(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        reason: EgressDenyReason,
        destination: str,
    ) -> None:
        GATEWAY_EGRESS_CONNECT.labels(outcome="denied").inc()
        # The writer is reaped in the finally even if the audit sink raises (the fail-loud
        # payload-blindness guard) — a refusal must never leak the client socket.
        try:
            # Field-allowlisted audit ({reason, destination} only — the audit sink rejects any
            # other field, so the row is payload-blind by construction).
            self._audit(
                EGRESS_CONNECT_DENIED_EVENT, {"reason": reason.value, "destination": destination}
            )
            with contextlib.suppress(OSError):
                writer.write(f"HTTP/1.1 {status} {reason.value}\r\n\r\n".encode("latin-1"))
                await writer.drain()
        finally:
            self._close(writer)

    @staticmethod
    def _close(writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError):
            writer.close()


__all__ = [
    "GATEWAY_EGRESS_CONNECT",
    "EgressForwardProxy",
    "resolve_deepseek_base_url",
    "resolve_egress_proxy_bind",
    "resolve_egress_proxy_port",
]
