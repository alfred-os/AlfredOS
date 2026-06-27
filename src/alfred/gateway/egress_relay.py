"""The gateway mode-(b) inspecting tool-egress relay (Spec C §4.2, epic #333).

This is the gateway-side egress ENFORCEMENT plane for *inspectable* tool egress —
the second DLP chokepoint and the sole maker of tool HTTP requests. Unlike the
payload-blind CONNECT forward-proxy (``egress_proxy.py``), this relay deliberately
reads the request body: it re-runs the secret-INDEPENDENT DLP stages (regex +
canary) on the redacted body the connectivity-free core sent, enforces the tool
destination allowlist (the G7-1 SSRF chain), and originates the real outbound TLS
itself before returning the response.

Wire: a **length-prefixed JSON-frame protocol over ``asyncio.start_server``** (the
architect's round-2 ruling — NOT HTTP, NOT extending the CONNECT splicer). One
``EgressRequest`` frame in, one ``EgressRelayReply`` frame out (a forwarded
``EgressResponse`` or a closed-vocab deny). An upstream *connect* failure writes
NO frame — the core's truncated read surfaces as an I/O-plane outage.

Enforcement per request (order is load-bearing):

* **method allowlist (H6)** — GET-only for the live path; a non-member or a
  CRLF-bearing method is a malformed envelope;
* **SSRF chain** — the request-URL authority is the SOLE allowlist source; a
  literal-IP target is refused; a non-allowlisted destination is refused
  (default-deny); DNS is resolved gateway-side and a non-globally-routable
  resolved IP is refused (DNS-rebinding TOCTOU);
* **gateway DLP second pass (decision 12)** — re-runs the regex + real canary on
  the body; a body the gateway changes (the core failed to redact) is refused, a
  canary trip is refused (loud) — neither is forwarded;
* **real TLS origination** — connect to the validated IP (IP-in-URL host) while
  TLS SNI + cert identity validate against the original hostname
  (``request.extensions["sni_hostname"]``), so the TCP connect targets the pinned
  IP with no re-resolution / DNS-rebinding window; redirects are NOT followed; the
  response read is bounded by a byte cap.

TLS origination requires the gateway to BUILD an ``httpx.AsyncClient`` — the ONE
sanctioned in-core (gateway-side) httpx construction site (the in-core
HTTP-egress import-guard allowlists this file: the gateway IS the egress plane). A
fresh client is built per request (``max_keepalive_connections=0`` too) so two
allowlisted hostnames on one IP can never share a TLS connection and bypass the
per-request cert-vs-hostname check.

A bind failure is **fail-closed**: the ``OSError`` propagates (B5 maps it to
``IOPlaneUnavailableError`` and the gateway crash-loops under
``restart: unless-stopped`` — the relay IS part of the gateway's reason to exist).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from collections.abc import Callable, Mapping
from typing import Final
from urllib.parse import urlsplit, urlunsplit

import httpx
import structlog
from pydantic import ValidationError

from alfred.egress.allowlist import (
    EgressDestination,
    host_port_from_url,
    is_globally_routable,
    is_literal_ip,
)
from alfred.egress.relay_protocol import (
    EgressRelayReply,
    EgressRequest,
    EgressResponse,
    FrameTooLargeError,
    read_frame,
    write_frame,
)
from alfred.gateway.egress_relay_audit import (
    EGRESS_RELAY_CANARY_EVENT,
    EGRESS_RELAY_DENIED_EVENT,
    EGRESS_RELAY_FORWARDED_EVENT,
    GATEWAY_EGRESS_RELAY,
    EgressRelayDenyReason,
)
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.dlp import OutboundCanaryTripped, OutboundDlp

_log = structlog.get_logger(__name__)

_DEFAULT_RELAY_PORT: Final[int] = 8890
_RELAY_PORT_ENV: Final[str] = "ALFRED_EGRESS_RELAY_PORT"
_RELAY_BIND_ENV: Final[str] = "ALFRED_EGRESS_RELAY_BIND"
# Public (non-secret) compose-threaded config the gateway derives its relay config
# from, WITHOUT constructing the secret-requiring Settings (ADR-0036). The tool
# allowlist is the web-fetch egress set (NOT the provider one); the canary tokens
# arriving via public env is an accepted §9/ADR-0040 residual (G7-5).
_TOOL_ALLOWLIST_ENV: Final[str] = "ALFRED_TOOL_EGRESS_ALLOWLIST"
_CANARY_TOKENS_ENV: Final[str] = "ALFRED_CANARY_TOKENS"
_DEFAULT_TOOL_PORT: Final[int] = 443
# Never host-published (a compose-invariant test asserts it at G7-2.5); the tool
# allowlist + the SSRF chain are the controls.
_DEFAULT_RELAY_BIND: Final[str] = "0.0.0.0"  # noqa: S104

# GET-only for the live path (H6). A non-member OR a CRLF-bearing method (request-
# line smuggling) fails this membership check → MALFORMED_ENVELOPE.
_ALLOWED_METHODS: Final[frozenset[str]] = frozenset({"GET"})

# Bound the request frame the core sends (redacted body + headers + URL). The
# response cap is a separate, per-relay-configurable bound.
_REQUEST_FRAME_CAP: Final[int] = 4 * 1024 * 1024
_FRAME_READ_TIMEOUT_S: Final[float] = 30.0
_DEFAULT_RESPONSE_CAP: Final[int] = 10 * 1024 * 1024
_UPSTREAM_TIMEOUT_S: Final[float] = 30.0

# Headers never forwarded upstream: hop-by-hop (RFC 7230 §6.1) + the caller-
# supplied Host / Content-Length / Transfer-Encoding (H6 — request smuggling /
# vhost spoofing). The Host is then set explicitly to the original hostname.
_STRIP_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "host",
        "content-length",
    }
)

_Resolver = Callable[[str], str]
_ClientFactory = Callable[[], httpx.AsyncClient]
_AuditSink = Callable[[str, Mapping[str, object]], None]


def resolve_egress_relay_port() -> int:
    """Resolve the relay port from ``ALFRED_EGRESS_RELAY_PORT`` (default 8890).

    Raises ``ValueError`` loudly on a non-integer / out-of-range value (operator
    misconfig — never silently fall back). Mirrors ``resolve_egress_proxy_port``.
    """
    raw = os.environ.get(_RELAY_PORT_ENV)
    if raw is None or raw == "":
        return _DEFAULT_RELAY_PORT
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{_RELAY_PORT_ENV} must be an integer, got {raw!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{_RELAY_PORT_ENV} must be in 1..65535, got {port}")
    return port


def resolve_egress_relay_bind() -> str:
    """Resolve the relay bind interface from ``ALFRED_EGRESS_RELAY_BIND`` (default
    ``0.0.0.0``). The relay is never host-published; the allowlist is the control."""
    raw = os.environ.get(_RELAY_BIND_ENV)
    if raw is None or raw == "":
        return _DEFAULT_RELAY_BIND
    return raw


def resolve_tool_egress_allowlist() -> frozenset[EgressDestination]:
    """Parse the tool-egress allowlist from ``ALFRED_TOOL_EGRESS_ALLOWLIST`` (public env).

    Comma-separated ``host`` or ``host:port`` entries; a bare host defaults to 443.
    Unset / empty yields the EMPTY set (default-deny everything — safe; the live
    consumer arrives at G7-2.5). A non-integer / out-of-range port or an empty host
    raises ``ValueError`` LOUDLY (operator misconfig — never silently widen / drop).
    """
    raw = os.environ.get(_TOOL_ALLOWLIST_ENV)
    if raw is None or raw == "":
        return frozenset()
    destinations: set[EgressDestination] = set()
    for item in raw.split(","):
        entry = item.strip()
        if not entry:
            continue
        host, sep, port_str = entry.rpartition(":")
        if not sep:
            destinations.add((entry.lower(), _DEFAULT_TOOL_PORT))
            continue
        if not (port_str.isascii() and port_str.isdigit()):
            raise ValueError(f"{_TOOL_ALLOWLIST_ENV} entry {entry!r} has a non-integer port")
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError(f"{_TOOL_ALLOWLIST_ENV} entry {entry!r} port must be in 1..65535")
        if not host:
            raise ValueError(f"{_TOOL_ALLOWLIST_ENV} entry {entry!r} has an empty host")
        destinations.add((host.lower(), port))
    return frozenset(destinations)


def resolve_canary_tokens() -> CanaryMatcher:
    """Build the gateway canary matcher from ``ALFRED_CANARY_TOKENS`` (public env).

    Comma-separated tokens; blank entries are skipped. Unset / empty yields a matcher
    with no tokens (the stage-3 canary scan is a no-op until tokens are configured).
    """
    raw = os.environ.get(_CANARY_TOKENS_ENV, "")
    tokens = [CanaryToken(part.strip()) for part in raw.split(",") if part.strip()]
    return CanaryMatcher(tokens=tokens)


def _drop_dlp_audit(*, event: str, subject: Mapping[str, object]) -> None:
    """No-op sink for the gateway second-pass DLP's OWN audit rows.

    The relay's :func:`record_egress_relay` (``DLP_REDACTED`` / ``CANARY_TRIPPED``)
    is the SINGLE gateway-side egress audit surface, so a DLP-level row here would be
    a redundant double-log. NOT a silent failure — a canary hit RAISES
    ``OutboundCanaryTripped`` and the relay catches + loudly audits it.
    """
    del event, subject


def build_gateway_egress_dlp() -> OutboundDlp:
    """Assemble the gateway second-pass ``OutboundDlp`` from public env.

    ``broker=None`` (the gateway holds no vault — ADR-0036) so it runs the
    secret-INDEPENDENT stages 2+3 only; the canary matcher comes from public env.
    """
    return OutboundDlp(broker=None, audit=_drop_dlp_audit, canary=resolve_canary_tokens())


def _default_resolve(host: str) -> str:
    """Resolve ``host`` to a single IPv4 literal (gateway-side DNS)."""
    return socket.gethostbyname(host)


def _default_httpx_client() -> httpx.AsyncClient:
    """The sanctioned gateway-side egress-origination client (Spec C G7-2b).

    ``trust_env=False`` so ambient proxy env (``HTTPS_PROXY`` …) cannot redirect
    mode-(b) egress. ``max_keepalive_connections=0`` so no connection is pooled —
    belt-and-braces with the per-request fresh client, since pool reuse across two
    allowlisted hostnames on one IP would bypass the per-request cert-vs-hostname
    check. This is the ONLY new in-core httpx construction site in G7-2 (the gateway
    IS the egress plane); it is allowlisted in the in-core HTTP-egress import-guard.
    """
    return httpx.AsyncClient(
        trust_env=False,
        timeout=_UPSTREAM_TIMEOUT_S,
        limits=httpx.Limits(max_keepalive_connections=0),
    )


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Drop hop-by-hop + caller Host/Content-Length/Transfer-Encoding (H6).

    Used on BOTH the forwarded request headers (the caller Host is then replaced by
    the original hostname) and the returned response headers.
    """
    return {key: value for key, value in headers.items() if key.lower() not in _STRIP_HEADERS}


def _ip_url(url: str, resolved_ip: str) -> str:
    """Rewrite ``url``'s host to the validated ``resolved_ip`` (bracket IPv6).

    Scheme / port / path / query are preserved; any URL userinfo is dropped (a
    URL-embedded credential must not ride a tool egress — credentials come via the
    secret broker). The TCP connect then targets the pinned IP.
    """
    parts = urlsplit(url)
    host_for_url = f"[{resolved_ip}]" if ":" in resolved_ip else resolved_ip
    netloc = host_for_url if parts.port is None else f"{host_for_url}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


class EgressRelay:
    """A length-prefixed JSON-frame inspecting tool-egress relay endpoint."""

    def __init__(
        self,
        *,
        tool_allowlist: frozenset[EgressDestination],
        dlp: OutboundDlp,
        audit: _AuditSink,
        bind_host: str,
        port: int,
        resolve: _Resolver = _default_resolve,
        open_client: _ClientFactory = _default_httpx_client,
        response_byte_cap: int = _DEFAULT_RESPONSE_CAP,
    ) -> None:
        self._allowlist = tool_allowlist
        self._dlp = dlp
        self._audit = audit
        self._bind_host = bind_host
        self._port = port
        self._resolve = resolve
        self._open_client = open_client
        self._response_byte_cap = response_byte_cap
        self._conns: set[asyncio.Task[None]] = set()

    async def serve(self, shutdown_event: asyncio.Event) -> None:
        """Bind + serve the framed endpoint until ``shutdown_event``, then drain.

        Fail-closed: an ``OSError`` from ``start_server`` (e.g. EADDRINUSE)
        propagates — B5 maps it to ``IOPlaneUnavailableError``.
        """
        server = await asyncio.start_server(
            self._handle_client, self._bind_host, self._port, limit=_REQUEST_FRAME_CAP
        )
        _log.info("gateway.egress.relay_serving", bind=self._bind_host, port=self._port)
        try:
            async with server:
                await shutdown_event.wait()
        finally:
            await self._drain_connections()

    async def _drain_connections(self) -> None:
        """Cancel + await every in-flight connection task on shutdown (deterministic)."""
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

        A non-cancellation exception escaping ``_serve_connection`` (the audit sink
        rejecting a non-allowlisted field, or any programming bug) would otherwise
        vanish as a GC-time "exception never retrieved". Retrieve + log it at
        ``error`` so hard rule #7 holds for the whole per-connection task.
        """
        self._conns.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            _log.error("gateway.egress.relay_connection_failed", error=repr(exc))

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # ``destination`` is captured as we go so a pre-/mid-forward OSError (DNS
        # gaierror, upstream connect) is attributable in the error breadcrumb.
        destination = "<unread>"
        try:
            # 0. Read ONE length-prefixed frame (bounded + timeout) and parse it.
            try:
                frame = await asyncio.wait_for(
                    read_frame(reader, max_len=_REQUEST_FRAME_CAP), timeout=_FRAME_READ_TIMEOUT_S
                )
                req = EgressRequest.model_validate_json(frame)
            except (FrameTooLargeError, asyncio.IncompleteReadError, TimeoutError, ValidationError):
                await self._emit(
                    writer, self._deny(EgressRelayDenyReason.MALFORMED_ENVELOPE, destination)
                )
                return
            # 1. Method allowlist (H6) — GET-only; a CRLF-bearing method is not a member.
            if req.method not in _ALLOWED_METHODS:
                await self._emit(
                    writer, self._deny(EgressRelayDenyReason.MALFORMED_ENVELOPE, destination)
                )
                return
            # 2. Authority from the URL ONLY (never a Host header).
            try:
                host, port = host_port_from_url(req.url)
            except ValueError:
                await self._emit(
                    writer, self._deny(EgressRelayDenyReason.MALFORMED_ENVELOPE, destination)
                )
                return
            destination = f"{host}:{port}"
            # 3. SSRF chain — re-run per relay (these do NOT come for free).
            if is_literal_ip(host):
                await self._emit(
                    writer, self._deny(EgressRelayDenyReason.LITERAL_IP_TARGET, destination)
                )
                return
            if (host, port) not in self._allowlist:
                await self._emit(
                    writer,
                    self._deny(EgressRelayDenyReason.DESTINATION_NOT_ALLOWLISTED, destination),
                )
                return
            # Gateway-side DNS, off the event loop (shared default pool; HoL isolation
            # is the deferred G7-3/G7-5 hardening, as for the CONNECT proxy).
            resolved_ip = await asyncio.get_running_loop().run_in_executor(
                None, self._resolve, host
            )
            if not is_globally_routable(resolved_ip):
                await self._emit(
                    writer, self._deny(EgressRelayDenyReason.RESOLVED_IP_NOT_GLOBAL, destination)
                )
                return
            # 4. Gateway DLP second pass (decision 12) on the redacted body the core sent.
            try:
                redacted_text, scan_result = self._dlp.scan_for_outbound(req.body)
            except OutboundCanaryTripped:
                await self._emit(
                    writer,
                    self._deny(EgressRelayDenyReason.CANARY_TRIPPED, destination, canary=True),
                )
                return
            if redacted_text != req.body:
                # The core failed to redact — refuse, do NOT forward (the gateway is
                # the second chokepoint, not a re-redacting forwarder).
                await self._emit(
                    writer, self._deny(EgressRelayDenyReason.DLP_REDACTED, destination)
                )
                return
            # 5. Originate the real upstream TLS + reply.
            reply = await self._forward(
                req,
                host=host,
                resolved_ip=resolved_ip,
                forward_body=redacted_text,
                destination=destination,
                dlp_redactions=scan_result.dlp_redactions_count,
            )
            await self._emit(writer, reply)
        except asyncio.CancelledError:
            raise
        except (httpx.TransportError, OSError) as exc:
            # Gateway-side DNS, the gateway↔upstream connect/read, or the
            # core↔gateway frame write failed. NOT a policy deny → no reply frame;
            # the core's truncated read surfaces as IOPlaneUnavailableError. Loud +
            # counted (hard rule #7).
            GATEWAY_EGRESS_RELAY.labels(outcome="error").inc()
            _log.warning(
                "gateway.egress.relay_connection_error", destination=destination, error=repr(exc)
            )
        finally:
            self._close(writer)

    async def _forward(
        self,
        req: EgressRequest,
        *,
        host: str,
        resolved_ip: str,
        forward_body: str,
        destination: str,
        dlp_redactions: int,
    ) -> EgressRelayReply:
        """Originate the real upstream request; return a forwarded or deny reply.

        A fresh client per request (no pooling) so the per-request cert-vs-hostname
        check can never be bypassed by connection reuse. The response is streamed so
        the byte cap can refuse an oversized body before it is fully buffered.
        """
        client = self._open_client()
        try:
            headers = _safe_headers(req.headers)
            headers["Host"] = host  # PROV-1: explicit Host = ORIGINAL hostname (not the IP)
            request = client.build_request(
                req.method, _ip_url(req.url, resolved_ip), headers=headers, content=forward_body
            )
            # PROV-3: TLS SNI + cert identity validate against the hostname while the
            # TCP connect targets the pinned IP (the URL host). ``host`` is the
            # already-unbracketed hostname (never a literal IP — refused above).
            request.extensions["sni_hostname"] = host
            response = await client.send(request, follow_redirects=False, stream=True)
            try:
                if response.is_redirect:
                    # A 3xx to an unchecked host must not be followed.
                    return self._deny(EgressRelayDenyReason.UPSTREAM_REDIRECT_REFUSED, destination)
                body = await self._bounded_read(response)
                if body is None:
                    return self._deny(EgressRelayDenyReason.RESPONSE_TOO_LARGE, destination)
                return self._forwarded(
                    req=req,
                    status=response.status_code,
                    response_headers=dict(response.headers),
                    body=body,
                    destination=destination,
                    dlp_redactions=dlp_redactions,
                )
            finally:
                await response.aclose()
        finally:
            await client.aclose()

    async def _bounded_read(self, response: httpx.Response) -> bytes | None:
        """Buffer the streamed body up to the cap; ``None`` signals over-cap."""
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > self._response_byte_cap:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    def _forwarded(
        self,
        *,
        req: EgressRequest,
        status: int,
        response_headers: Mapping[str, str],
        body: bytes,
        destination: str,
        dlp_redactions: int,
    ) -> EgressRelayReply:
        # ``dlp_redactions`` is the gateway pass's redaction count — 0 on a forward
        # by construction (a redaction would have denied DLP_REDACTED); recorded so
        # the row documents that the gateway DLP ran and found nothing to redact.
        self._audit(
            EGRESS_RELAY_FORWARDED_EVENT,
            {
                "destination": destination,
                "method": req.method,
                "status": status,
                "egress_id": req.egress_id,
                "dlp_redactions": dlp_redactions,
            },
        )
        return EgressRelayReply(
            response=EgressResponse(
                status=status, headers=_safe_headers(response_headers), body=body
            )
        )

    def _deny(
        self, reason: EgressRelayDenyReason, destination: str, *, canary: bool = False
    ) -> EgressRelayReply:
        event = EGRESS_RELAY_CANARY_EVENT if canary else EGRESS_RELAY_DENIED_EVENT
        self._audit(event, {"destination": destination, "reason": reason.value})
        return EgressRelayReply(deny_reason=reason.value)

    async def _emit(self, writer: asyncio.StreamWriter, reply: EgressRelayReply) -> None:
        """Write the reply frame, then count the outcome (exactly one per connection).

        The count is AFTER the write so a write failure is counted ``error`` by the
        caller's except (never double-counted); the audit row already fired at the
        decision point inside ``_deny`` / ``_forwarded``.
        """
        await write_frame(writer, reply.model_dump_json().encode("utf-8"))
        GATEWAY_EGRESS_RELAY.labels(
            outcome="forwarded" if reply.response is not None else "denied"
        ).inc()

    @staticmethod
    def _close(writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError):
            writer.close()


__all__ = [
    "EgressRelay",
    "build_gateway_egress_dlp",
    "resolve_canary_tokens",
    "resolve_egress_relay_bind",
    "resolve_egress_relay_port",
    "resolve_tool_egress_allowlist",
]
