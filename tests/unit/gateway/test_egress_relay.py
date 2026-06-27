"""The gateway mode-(b) inspecting tool-egress relay (Spec C G7-2b, #333) — the crux.

The relay accepts ONE length-prefixed JSON ``EgressRequest`` frame from the
in-core relay client, runs the enforcement pipeline (method allowlist → SSRF
chain → gateway DLP second pass → real TLS origination to the validated IP), and
writes back ONE ``EgressRelayReply`` frame (a forwarded ``EgressResponse`` or a
closed-vocab deny). An upstream *connect* failure writes NO frame (the core's
truncated read becomes an I/O-plane outage). Unlike the CONNECT proxy it is NOT
payload-blind — it inspects the body — but it never logs one.

The per-connection logic is driven through ``_serve_connection`` with IN-MEMORY
streams (a fed ``StreamReader`` + a capture writer) and a FAKE httpx client
capturing the originated request — so every behavioural test is deterministic
with no real listener, port, TLS, or socket-teardown timing. Only the bind /
shutdown LIFECYCLE tests stand up a real ``asyncio`` server.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator

import httpx
import pytest
import structlog

from alfred.egress.relay_protocol import EgressRelayReply, EgressRequest
from alfred.gateway.egress_relay import (
    EgressRelay,
    _default_httpx_client,
    _safe_headers,
    resolve_egress_relay_bind,
    resolve_egress_relay_port,
)
from alfred.gateway.egress_relay_audit import (
    EGRESS_RELAY_CANARY_EVENT,
    EGRESS_RELAY_FORWARDED_EVENT,
    EgressRelayDenyReason,
    record_egress_relay,
)
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.dlp import OutboundDlp

_ALLOWLIST = frozenset({("api.example.com", 443)})


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> AsyncIterator[None]:
    """Join the per-test loop's default executor on teardown — the relay resolves
    DNS off-loop via ``run_in_executor(None, ...)`` and the workers otherwise leak."""
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


# --- doubles ---------------------------------------------------------------


class _CaptureWriter:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buf += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _reader_with(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        chunks: tuple[bytes, ...] = (b"upstream-body",),
        is_redirect: bool = False,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/html"}
        self._chunks = chunks
        self.is_redirect = is_redirect
        self.closed = False

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class _FakeClient:
    """Captures the originated request + flags; returns a canned response."""

    def __init__(
        self, captured: dict[str, object], response: object, send_error: Exception | None
    ) -> None:
        self._captured = captured
        self._response = response
        self._send_error = send_error

    def build_request(
        self, method: str, url: str, *, headers: dict[str, str], content: object
    ) -> httpx.Request:
        return httpx.Request(method, url, headers=headers, content=content)  # type: ignore[arg-type]

    async def send(
        self, request: httpx.Request, *, follow_redirects: bool, stream: bool = False
    ) -> object:
        self._captured["request"] = request
        self._captured["follow_redirects"] = follow_redirects
        self._captured["stream"] = stream
        if self._send_error is not None:
            raise self._send_error
        return self._response

    async def aclose(self) -> None:
        self._captured["client_close_count"] = int(self._captured.get("client_close_count", 0)) + 1


def _open_client_factory(
    captured: dict[str, object], *, response: object = None, send_error: Exception | None = None
) -> object:
    captured["open_calls"] = 0
    resp = response if response is not None else _FakeResponse()

    def _factory() -> _FakeClient:
        captured["open_calls"] = int(captured["open_calls"]) + 1
        return _FakeClient(captured, resp, send_error)

    return _factory


def _relay(
    *,
    open_client: object,
    resolve: object = None,
    dlp: OutboundDlp | None = None,
    allowlist: frozenset[tuple[str, int]] = _ALLOWLIST,
    response_byte_cap: int = 4096,
) -> EgressRelay:
    return EgressRelay(
        tool_allowlist=allowlist,
        dlp=dlp or OutboundDlp(broker=None, audit=lambda **_kw: None),
        audit=record_egress_relay,
        bind_host="127.0.0.1",
        port=0,
        resolve=resolve or (lambda _h: "1.1.1.1"),  # type: ignore[arg-type, return-value]
        open_client=open_client,  # type: ignore[arg-type]
        response_byte_cap=response_byte_cap,
    )


def _req(
    *,
    url: str = "https://api.example.com/v1/x",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    egress_id: str = "e" * 64,
) -> EgressRequest:
    return EgressRequest(
        method=method, url=url, headers=headers or {}, body=body, egress_id=egress_id
    )


def _frame(req: EgressRequest) -> bytes:
    payload = req.model_dump_json().encode("utf-8")
    return len(payload).to_bytes(4, "big") + payload


async def _drive(relay: EgressRelay, frame: bytes) -> _CaptureWriter:
    writer = _CaptureWriter()
    await asyncio.wait_for(
        relay._serve_connection(_reader_with(frame), writer),  # type: ignore[arg-type]
        timeout=5,
    )
    return writer


def _reply(writer: _CaptureWriter) -> EgressRelayReply:
    buf = bytes(writer.buf)
    length = int.from_bytes(buf[:4], "big")
    return EgressRelayReply.model_validate_json(buf[4 : 4 + length])


# --- happy path + the originated request shape -----------------------------


@pytest.mark.asyncio
async def test_happy_forward_returns_response_and_audits() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    with structlog.testing.capture_logs() as logs:
        writer = await _drive(relay, _frame(_req()))
    reply = _reply(writer)
    assert reply.deny_reason is None
    assert reply.response is not None
    assert reply.response.status == 200
    assert reply.response.body == b"upstream-body"
    assert any(e.get("event") == EGRESS_RELAY_FORWARDED_EVENT for e in logs)


@pytest.mark.asyncio
async def test_forward_sends_to_resolved_ip_with_sni_hostname_and_host_header() -> None:
    # PROV-1 (Host = hostname, not the IP) + PROV-3 (URL host = resolved IP, SNI =
    # hostname). The TCP connect targets the pinned IP; cert identity validates
    # against the hostname — no re-resolution, no DNS-rebinding window.
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured), resolve=lambda _h: "1.1.1.1")
    await _drive(relay, _frame(_req(url="https://api.example.com/v1/x?q=1")))
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.url.host == "1.1.1.1"  # connect targets the validated IP
    assert request.url.path == "/v1/x"
    assert request.url.query == b"q=1"
    assert request.extensions["sni_hostname"] == "api.example.com"  # cert identity = hostname
    assert request.headers["host"] == "api.example.com"  # PROV-1: NOT the IP
    assert captured["follow_redirects"] is False  # never chase a 3xx


@pytest.mark.asyncio
async def test_forward_brackets_ipv6_in_url_but_not_in_sni() -> None:
    # PROV-3: the resolved IPv6 is bracketed in the URL host, unbracketed in SNI;
    # the SNI is the hostname (cert identity), never the IP.
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured), resolve=lambda _h: "2606:4700::1111")
    await _drive(relay, _frame(_req(url="https://api.example.com/p")))
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.url.host == "2606:4700::1111"
    assert "[2606:4700::1111]" in str(request.url)  # bracketed in the URL authority
    assert request.extensions["sni_hostname"] == "api.example.com"


@pytest.mark.asyncio
async def test_caller_host_and_smuggling_headers_are_dropped() -> None:
    # H6: a caller-supplied Host/Content-Length/Transfer-Encoding never reaches the
    # upstream; the Host is replaced by the resolved hostname. A benign header rides.
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    await _drive(
        relay,
        _frame(
            _req(
                headers={
                    "Host": "evil.example",
                    "Content-Length": "999",
                    "Transfer-Encoding": "chunked",
                    "X-Custom": "kept",
                }
            )
        ),
    )
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.headers["host"] == "api.example.com"  # NOT evil.example
    assert request.headers.get("x-custom") == "kept"
    # The caller's chunked TE never rides (httpx sets framing from the content).
    assert "chunked" not in request.headers.get("transfer-encoding", "")


# --- the SSRF chain (these do NOT come for free; per-path) ------------------


@pytest.mark.asyncio
async def test_literal_ip_target_denied() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    with structlog.testing.capture_logs() as logs:
        writer = await _drive(relay, _frame(_req(url="https://1.2.3.4/x")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.LITERAL_IP_TARGET.value
    assert captured.get("open_calls", 0) == 0  # never originated
    assert any(e.get("reason") == "literal_ip_target" for e in logs)


@pytest.mark.asyncio
async def test_non_allowlisted_destination_denied() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    writer = await _drive(relay, _frame(_req(url="https://not-allowed.example/x")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.DESTINATION_NOT_ALLOWLISTED.value
    assert captured.get("open_calls", 0) == 0


@pytest.mark.asyncio
async def test_resolved_private_ip_denied() -> None:
    # Allowlisted host, but gateway-side resolve returns a private IP → the
    # DNS-rebinding TOCTOU guard refuses.
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured), resolve=lambda _h: "10.0.0.1")
    writer = await _drive(relay, _frame(_req()))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.RESOLVED_IP_NOT_GLOBAL.value
    assert captured.get("open_calls", 0) == 0


# --- the gateway DLP second pass (decision 12) -----------------------------


@pytest.mark.asyncio
async def test_dlp_second_pass_catches_unredacted_secret_shape() -> None:
    # The "core forgot to redact" case: a body the gateway DLP changes is NOT
    # forwarded — DLP_REDACTED deny + audit (the gateway is the second chokepoint).
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    writer = await _drive(relay, _frame(_req(body="leak sk-AAAAAAAAAAAAAAAAAAAA")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.DLP_REDACTED.value
    assert captured.get("open_calls", 0) == 0  # never originated


@pytest.mark.asyncio
async def test_canary_trip_denied_and_audited_as_canary_event() -> None:
    captured: dict[str, object] = {}
    dlp = OutboundDlp(
        broker=None,
        audit=lambda **_kw: None,
        canary=CanaryMatcher(tokens=[CanaryToken("CANARY-EGRESS-1")]),
    )
    relay = _relay(open_client=_open_client_factory(captured), dlp=dlp)
    with structlog.testing.capture_logs() as logs:
        writer = await _drive(relay, _frame(_req(body="exfil CANARY-EGRESS-1 here")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.CANARY_TRIPPED.value
    assert captured.get("open_calls", 0) == 0
    assert any(e.get("event") == EGRESS_RELAY_CANARY_EVENT for e in logs)


# --- upstream-response handling --------------------------------------------


@pytest.mark.asyncio
async def test_upstream_redirect_refused() -> None:
    captured: dict[str, object] = {}
    resp = _FakeResponse(status_code=302, headers={"location": "https://evil/"}, is_redirect=True)
    relay = _relay(open_client=_open_client_factory(captured, response=resp))
    writer = await _drive(relay, _frame(_req()))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.UPSTREAM_REDIRECT_REFUSED.value
    assert resp.closed  # the streamed response is closed even on a deny


@pytest.mark.asyncio
async def test_response_too_large_denied() -> None:
    captured: dict[str, object] = {}
    resp = _FakeResponse(chunks=(b"a" * 4, b"b" * 4))  # 8 bytes > cap 5
    relay = _relay(open_client=_open_client_factory(captured, response=resp), response_byte_cap=5)
    writer = await _drive(relay, _frame(_req()))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.RESPONSE_TOO_LARGE.value
    assert resp.closed


@pytest.mark.asyncio
async def test_response_at_cap_boundary_forwards() -> None:
    captured: dict[str, object] = {}
    resp = _FakeResponse(chunks=(b"abcde",))  # exactly 5 == cap
    relay = _relay(open_client=_open_client_factory(captured, response=resp), response_byte_cap=5)
    writer = await _drive(relay, _frame(_req()))
    reply = _reply(writer)
    assert reply.response is not None
    assert reply.response.body == b"abcde"


@pytest.mark.asyncio
async def test_response_headers_are_safe_headered() -> None:
    captured: dict[str, object] = {}
    resp = _FakeResponse(headers={"content-type": "text/html", "connection": "keep-alive"})
    relay = _relay(open_client=_open_client_factory(captured, response=resp))
    writer = await _drive(relay, _frame(_req()))
    reply = _reply(writer)
    assert reply.response is not None
    assert reply.response.headers.get("content-type") == "text/html"
    assert "connection" not in reply.response.headers  # hop-by-hop stripped


# --- method allowlist / framing (H6) ---------------------------------------


@pytest.mark.asyncio
async def test_non_get_method_denied() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    writer = await _drive(relay, _frame(_req(method="POST", body="x")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.MALFORMED_ENVELOPE.value
    assert captured.get("open_calls", 0) == 0


@pytest.mark.asyncio
async def test_crlf_bearing_method_denied() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    writer = await _drive(relay, _frame(_req(method="GET\r\nHost: evil")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.MALFORMED_ENVELOPE.value
    assert captured.get("open_calls", 0) == 0


@pytest.mark.asyncio
async def test_junk_frame_is_malformed_envelope() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    payload = b"this is not json"
    writer = await _drive(relay, len(payload).to_bytes(4, "big") + payload)
    assert _reply(writer).deny_reason == EgressRelayDenyReason.MALFORMED_ENVELOPE.value


@pytest.mark.asyncio
async def test_oversized_frame_is_malformed_envelope_without_reading_body() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    # Declare a 2 GiB payload but feed NO body — read_frame must refuse on the
    # prefix alone (FrameTooLargeError → MALFORMED_ENVELOPE), never read the body.
    writer = await _drive(relay, (2**31).to_bytes(4, "big"))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.MALFORMED_ENVELOPE.value


@pytest.mark.asyncio
async def test_url_without_host_is_malformed_envelope() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    writer = await _drive(relay, _frame(_req(url="https:///no-host-path")))
    assert _reply(writer).deny_reason == EgressRelayDenyReason.MALFORMED_ENVELOPE.value


# --- no connection pooling (PROV-2) ----------------------------------------


@pytest.mark.asyncio
async def test_fresh_client_per_request_no_pooling() -> None:
    # Two requests to two allowlisted hostnames resolving to the SAME IP must NOT
    # share a TLS connection — a fresh client is built per request, so the
    # per-request cert-vs-hostname check can never be bypassed by pool reuse.
    allowlist = frozenset({("a.example.com", 443), ("b.example.com", 443)})
    captured: dict[str, object] = {}
    relay = _relay(
        open_client=_open_client_factory(captured),
        resolve=lambda _h: "1.1.1.1",
        allowlist=allowlist,
    )
    await _drive(relay, _frame(_req(url="https://a.example.com/x")))
    await _drive(relay, _frame(_req(url="https://b.example.com/x")))
    assert captured["open_calls"] == 2  # one client construction per request


# --- upstream / resolver faults: NO reply, error outcome -------------------


@pytest.mark.asyncio
async def test_upstream_connect_failure_writes_no_reply() -> None:
    # An upstream connect failure is NOT a policy deny — no reply frame, so the
    # core's truncated read surfaces as IOPlaneUnavailableError. Loud + counted.
    captured: dict[str, object] = {}
    relay = _relay(
        open_client=_open_client_factory(captured, send_error=httpx.ConnectError("boom"))
    )
    with structlog.testing.capture_logs() as logs:
        writer = await _drive(relay, _frame(_req()))
    assert bytes(writer.buf) == b""  # NO reply frame
    assert writer.closed
    assert any(e.get("event") == "gateway.egress.relay_connection_error" for e in logs)


@pytest.mark.asyncio
async def test_resolver_failure_writes_no_reply() -> None:
    def _boom(_host: str) -> str:
        raise socket.gaierror("name resolution failed")

    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured), resolve=_boom)
    with structlog.testing.capture_logs() as logs:
        writer = await _drive(relay, _frame(_req()))
    assert bytes(writer.buf) == b""
    assert any(e.get("event") == "gateway.egress.relay_connection_error" for e in logs)
    assert captured.get("open_calls", 0) == 0


# --- connection task plumbing ----------------------------------------------


@pytest.mark.asyncio
async def test_handle_client_registers_and_reaps_task() -> None:
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    relay._handle_client(_reader_with(_frame(_req())), _CaptureWriter())  # type: ignore[attr-defined, arg-type]
    assert len(relay._conns) == 1  # type: ignore[attr-defined]
    for _ in range(50):
        if not relay._conns:  # type: ignore[attr-defined]
            break
        await asyncio.sleep(0.01)
    assert not relay._conns  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_connection_done_surfaces_escaped_exception_loud() -> None:
    # A non-cancellation exception escaping _serve_connection (here a raising audit
    # sink) must not vanish as a GC-time "never retrieved" — the done-callback
    # retrieves + logs it at error (hard rule #7).
    def _raising_audit(event: str, fields: dict[str, object]) -> None:
        raise ValueError("audit sink rejected the row")

    relay = EgressRelay(
        tool_allowlist=_ALLOWLIST,
        dlp=OutboundDlp(broker=None, audit=lambda **_kw: None),
        audit=_raising_audit,
        bind_host="127.0.0.1",
        port=0,
        resolve=lambda _h: "1.1.1.1",
        open_client=_open_client_factory({}),  # type: ignore[arg-type]
    )
    with structlog.testing.capture_logs() as logs:
        relay._handle_client(
            _reader_with(_frame(_req(url="https://not-allowed/x"))), _CaptureWriter()
        )  # type: ignore[attr-defined, arg-type]
        for _ in range(50):
            if not relay._conns:  # type: ignore[attr-defined]
                break
            await asyncio.sleep(0.01)
    assert any(e.get("event") == "gateway.egress.relay_connection_failed" for e in logs), logs


@pytest.mark.asyncio
async def test_connection_done_ignores_cancelled_task() -> None:
    relay = _relay(open_client=_open_client_factory({}))

    async def _block() -> None:
        await asyncio.Event().wait()

    task = asyncio.ensure_future(_block())
    relay._conns.add(task)  # type: ignore[attr-defined]
    await asyncio.sleep(0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    relay._on_connection_done(task)  # type: ignore[attr-defined] — must not raise
    assert task not in relay._conns  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_drain_connections_cancels_in_flight_tasks() -> None:
    # Deterministic unit test of the shutdown reap: a blocking connection task is
    # cancelled + awaited (no real socket).
    relay = _relay(open_client=_open_client_factory({}))

    async def _block() -> None:
        await asyncio.Event().wait()

    task = asyncio.ensure_future(_block())
    relay._conns.add(task)  # type: ignore[attr-defined]
    task.add_done_callback(relay._conns.discard)  # type: ignore[attr-defined]
    await asyncio.sleep(0)
    await asyncio.wait_for(relay._drain_connections(), timeout=5)  # type: ignore[attr-defined]
    assert task.cancelled()


@pytest.mark.asyncio
async def test_serve_connection_cancellation_propagates() -> None:
    # A connection cancelled while the upstream send is in flight re-raises
    # CancelledError (the reap path) — never swallowed as an error outcome.
    blocker = asyncio.Event()

    class _BlockingClient:
        def build_request(
            self, method: str, url: str, *, headers: dict[str, str], content: object
        ) -> httpx.Request:
            return httpx.Request(method, url, headers=headers, content=content)  # type: ignore[arg-type]

        async def send(
            self, request: httpx.Request, *, follow_redirects: bool, stream: bool = False
        ) -> object:
            await blocker.wait()  # blocks until the task is cancelled
            raise AssertionError("unreachable")

        async def aclose(self) -> None:
            return None

    relay = _relay(open_client=lambda: _BlockingClient())
    task = asyncio.ensure_future(
        relay._serve_connection(_reader_with(_frame(_req())), _CaptureWriter())  # type: ignore[arg-type]
    )
    await asyncio.sleep(0.05)  # let it reach the blocking upstream send
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# --- lifecycle (real listener) ---------------------------------------------


@pytest.mark.asyncio
async def test_bind_failure_propagates_oserror() -> None:
    blocker = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    busy_port = blocker.sockets[0].getsockname()[1]
    async with blocker:
        relay = _relay(open_client=_open_client_factory({}))
        relay._port = busy_port  # type: ignore[attr-defined]
        with pytest.raises(OSError):
            await relay.serve(asyncio.Event())


@pytest.mark.asyncio
async def test_serve_binds_and_stops_on_shutdown() -> None:
    free = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = free.sockets[0].getsockname()[1]
    free.close()
    await free.wait_closed()
    relay = _relay(open_client=_open_client_factory({}))
    relay._port = port  # type: ignore[attr-defined]
    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(relay.serve(shutdown))
    await asyncio.sleep(0.05)
    shutdown.set()
    await asyncio.wait_for(serve_task, timeout=5)
    assert serve_task.done()


@pytest.mark.asyncio
async def test_serve_end_to_end_over_a_real_socket() -> None:
    # A real connection: dial the bound relay, write a frame, read the reply frame.
    captured: dict[str, object] = {}
    relay = _relay(open_client=_open_client_factory(captured))
    server = await asyncio.start_server(relay._handle_client, "127.0.0.1", 0)  # type: ignore[attr-defined]
    port = server.sockets[0].getsockname()[1]
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_frame(_req()))
            await writer.drain()
            prefix = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            body = await reader.readexactly(int.from_bytes(prefix, "big"))
        finally:
            writer.close()
            await writer.wait_closed()
    reply = EgressRelayReply.model_validate_json(body)
    assert reply.response is not None
    assert reply.response.body == b"upstream-body"


# --- pure helpers + env resolvers ------------------------------------------


def test_safe_headers_strips_hop_by_hop_and_smuggling() -> None:
    out = _safe_headers(
        {
            "Host": "caller",
            "Content-Length": "5",
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
            "X-Keep": "yes",
        }
    )
    assert "host" not in {k.lower() for k in out}
    assert "content-length" not in {k.lower() for k in out}
    assert "transfer-encoding" not in {k.lower() for k in out}
    assert "connection" not in {k.lower() for k in out}
    assert out["X-Keep"] == "yes"


@pytest.mark.asyncio
async def test_default_httpx_client_disables_trust_env() -> None:
    client = _default_httpx_client()
    try:
        assert client.trust_env is False  # ambient proxy env must not redirect mode-b
    finally:
        await client.aclose()


def test_resolve_relay_port_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_EGRESS_RELAY_PORT", raising=False)
    assert resolve_egress_relay_port() == 8890


def test_resolve_relay_port_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_RELAY_PORT", "9100")
    assert resolve_egress_relay_port() == 9100


def test_resolve_relay_port_rejects_non_int(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_RELAY_PORT", "nope")
    with pytest.raises(ValueError, match="ALFRED_EGRESS_RELAY_PORT"):
        resolve_egress_relay_port()


def test_resolve_relay_port_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_RELAY_PORT", "70000")
    with pytest.raises(ValueError, match=r"1\.\.65535"):
        resolve_egress_relay_port()


def test_resolve_relay_bind_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_EGRESS_RELAY_BIND", raising=False)
    assert resolve_egress_relay_bind() == "0.0.0.0"  # noqa: S104 — documented default; never published


def test_resolve_relay_bind_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_RELAY_BIND", "127.0.0.1")
    assert resolve_egress_relay_bind() == "127.0.0.1"


def test_default_resolve_resolves_localhost() -> None:
    from alfred.gateway.egress_relay import _default_resolve

    resolved = _default_resolve("localhost")
    assert resolved.count(".") == 3 or ":" in resolved  # IPv4 dotted-quad or IPv6
