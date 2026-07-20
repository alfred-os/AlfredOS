"""Unit tests for the gateway L7 CONNECT forward-proxy (Spec C G7-1b, #333).

The proxy is the gateway-side egress enforcement plane: it accepts a CONNECT from
the in-core proxied httpx client, enforces the destination allowlist + literal-IP
refusal + gateway-side DNS + resolved-IP-globally-routable guard, then splices the
opaque TLS bytes through to the resolved upstream. It is payload-blind and audits
every CONNECT incl. refusals.

The per-CONNECT logic is exercised by driving ``_serve_connection`` directly with
IN-MEMORY streams (an ``asyncio.StreamReader`` fed crafted bytes + a capture-only
writer). That keeps every behavioural test deterministic — no real listeners,
ports, or socket-teardown timing — so the 100% line+branch gate is stable. Only
the bind / shutdown LIFECYCLE tests stand up a real ``asyncio`` server.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import pytest
import structlog
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.egress.allowlist import exact_match
from alfred.gateway import egress_metrics
from alfred.gateway.egress_proxy import (
    GATEWAY_EGRESS_CONNECT,
    EgressForwardProxy,
    resolve_egress_proxy_bind,
    resolve_egress_proxy_port,
)

_ALLOWLIST = frozenset({("api.anthropic.com", 443)})


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> AsyncIterator[None]:
    """Join the per-test loop's default ``ThreadPoolExecutor`` on teardown.

    The proxy resolves DNS off-loop via ``loop.run_in_executor(None, ...)`` (so a
    slow resolver never stalls the gateway event loop). pytest-asyncio's
    function-scoped loop only ``shutdown(wait=False)``s the default executor on
    close, leaving non-daemon worker threads that accumulate across tests and hang
    the interpreter-exit join — draining the executor here keeps the suite clean.
    """
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


class _CaptureWriter:
    """An in-memory ``StreamWriter`` stand-in: captures bytes, records close/eof."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False
        self.eof = False

    def write(self, data: bytes) -> None:
        self.buf += data

    async def drain(self) -> None:
        return None

    def write_eof(self) -> None:
        self.eof = True

    def close(self) -> None:
        self.closed = True


def _reader_with(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


def _proxy(
    audit: list[tuple[str, dict[str, object]]],
    *,
    resolve_to: str = "1.1.1.1",
    upstream: tuple[asyncio.StreamReader, _CaptureWriter] | None = None,
    open_error: Exception | None = None,
    plane: str = "proxy",
    denied_counter: object | None = None,
) -> EgressForwardProxy:
    async def _open(_ip: str, _port: int) -> tuple[asyncio.StreamReader, _CaptureWriter]:
        if open_error is not None:
            raise open_error
        assert upstream is not None
        return upstream

    return EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=lambda event, fields: audit.append((event, fields)),
        resolve=lambda _h: resolve_to,
        open_upstream=_open,  # type: ignore[arg-type]
        plane=plane,
        denied_counter=denied_counter,  # type: ignore[arg-type]
    )


async def _serve(proxy: EgressForwardProxy, request: bytes, writer: _CaptureWriter) -> None:
    await asyncio.wait_for(
        proxy._serve_connection(_reader_with(request), writer),  # type: ignore[arg-type]
        timeout=5,
    )


@pytest.mark.asyncio
async def test_connect_allowlisted_succeeds_and_splices_both_ways() -> None:
    audit: list[tuple[str, dict[str, object]]] = []
    up_writer = _CaptureWriter()
    upstream = (_reader_with(b"UPSTREAM-REPLY"), up_writer)
    proxy = _proxy(audit, upstream=upstream)
    client_writer = _CaptureWriter()
    await _serve(
        proxy, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\nCLIENT-HELLO", client_writer
    )

    assert b"200 Connection Established" in client_writer.buf
    assert b"UPSTREAM-REPLY" in client_writer.buf  # upstream → client splice
    assert bytes(up_writer.buf) == b"CLIENT-HELLO"  # client → upstream splice
    assert any(e == "gateway.egress.connect_allowed" for e, _ in audit)


@pytest.mark.asyncio
async def test_connect_non_allowlisted_denied() -> None:
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n", writer)
    assert b"403" in writer.buf
    assert writer.closed
    assert any(f.get("reason") == "destination_not_allowlisted" for _, f in audit)


@pytest.mark.asyncio
async def test_connect_literal_ip_denied() -> None:
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n", writer)
    assert b"403" in writer.buf
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit)


@pytest.mark.asyncio
async def test_connect_resolved_private_ip_denied() -> None:
    # Host is allowlisted, but gateway-side resolve returns a private IP → the
    # DNS-rebinding TOCTOU guard refuses (sec-003).
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit, resolve_to="127.0.0.1")
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n", writer)
    assert b"403" in writer.buf
    assert any(f.get("reason") == "resolved_ip_not_global" for _, f in audit)


@pytest.mark.asyncio
async def test_host_header_is_not_trusted() -> None:
    # The request-line authority is the SOLE allowlist source — a spoofed Host:
    # header naming an allowlisted host must NOT smuggle a non-allowlisted authority
    # past the gate (sec-004).
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(
        proxy, b"CONNECT evil.example:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n", writer
    )
    assert b"403" in writer.buf
    assert any(f.get("reason") == "destination_not_allowlisted" for _, f in audit)


@pytest.mark.asyncio
async def test_non_connect_method_denied() -> None:
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"GET http://evil/ HTTP/1.1\r\n\r\n", writer)
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_authority_without_port_denied() -> None:
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT no-colon-authority HTTP/1.1\r\n\r\n", writer)
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_non_numeric_port_denied() -> None:
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT api.anthropic.com:https HTTP/1.1\r\n\r\n", writer)
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_unicode_digit_port_is_clean_malformed_not_a_crash() -> None:
    # ``\xb2`` (latin-1 SUPERSCRIPT TWO) passes str.isdigit() but int() raises ValueError —
    # the require-ASCII guard keeps it a CLEAN 400 + malformed_connect audit instead of an
    # uncaught task exception (sec-002).
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT api.anthropic.com:\xb2 HTTP/1.1\r\n\r\n", writer)
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_mixed_case_allowlisted_host_is_lowercased_and_allowed() -> None:
    # DNS is case-insensitive; the request-line host is lowercased before the allowlist check,
    # so a mixed-case authority for an allowlisted host is NOT spuriously denied (sec-002 nit).
    audit: list[tuple[str, dict[str, object]]] = []
    up_writer = _CaptureWriter()
    proxy = _proxy(audit, upstream=(_reader_with(b"UP"), up_writer))
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT API.Anthropic.COM:443 HTTP/1.1\r\n\r\n", writer)
    assert b"200 Connection Established" in writer.buf
    assert any(
        e == "gateway.egress.connect_allowed" and f.get("destination") == "api.anthropic.com:443"
        for e, f in audit
    )


@pytest.mark.asyncio
async def test_incomplete_request_line_denied() -> None:
    # EOF before the CRLF-CRLF terminator → IncompleteReadError → malformed.
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n", writer)
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_oversized_request_line_denied() -> None:
    # A long request line that hits EOF without a terminator → IncompleteReadError carrying a
    # LARGE partial → malformed. (This test used to claim it exercised LimitOverrunError; it
    # never did — ``_reader_with`` builds a DEFAULT-limit (64 KiB) StreamReader, so 9 KB fits.
    # The genuine overrun path is covered by the limit-matched test below.)
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT " + b"a" * 9000, writer)
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_request_line_overrunning_the_read_cap_denied() -> None:
    # The REAL LimitOverrunError arm. Production builds the reader with
    # ``limit=_REQUEST_LINE_CAP`` (``start_server(..., limit=...)``), so a request line that
    # exceeds the cap before any terminator overruns the buffer rather than hitting EOF. The
    # reader here is limit-matched to production so the branch is genuinely exercised.
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    writer = _CaptureWriter()
    reader = asyncio.StreamReader(limit=8192)
    reader.feed_data(b"CONNECT " + b"a" * 20000)  # no terminator, no EOF: pure overrun
    await asyncio.wait_for(
        proxy._serve_connection(reader, writer),  # type: ignore[arg-type]
        timeout=5,
    )
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit)


@pytest.mark.asyncio
async def test_idle_peer_trips_the_handshake_timeout_and_is_denied() -> None:
    # The slow-loris arm: a peer that connects, sends NOTHING, and holds the socket open. It
    # must stay a DENIAL — it is exactly what the per-handshake timeout exists to reap, and it
    # is the case the #340 C1 abandon-split must NOT swallow (an abandoned broker socket
    # CLOSES, producing a clean zero-byte EOF; this peer does not).
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=lambda event, fields: audit.append((event, fields)),
        resolve=lambda _h: "1.1.1.1",
        handshake_timeout_s=0.01,
    )
    writer = _CaptureWriter()
    reader = asyncio.StreamReader()  # never fed, never EOF'd
    await asyncio.wait_for(
        proxy._serve_connection(reader, writer),  # type: ignore[arg-type]
        timeout=5,
    )
    assert b"400" in writer.buf
    assert any(f.get("reason") == "malformed_connect" for _, f in audit), (
        "an idle peer must remain a counted denial, not a benign abandon"
    )


@pytest.mark.asyncio
async def test_upstream_open_failure_is_logged_with_destination() -> None:
    # open_upstream raising an OSError (ECONNREFUSED) is an UPSTREAM error, not a policy
    # denial: the bounded handler closes the client (no 200), counts a distinct ``error``
    # outcome, and logs the connection_error breadcrumb ATTRIBUTED to the destination.
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit, open_error=ConnectionRefusedError("upstream down"))
    writer = _CaptureWriter()
    with structlog.testing.capture_logs() as logs:
        await _serve(proxy, b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n", writer)
    assert b"200" not in writer.buf
    assert writer.closed
    errors = [e for e in logs if e.get("event") == "gateway.egress.connection_error"]
    assert errors and errors[0]["destination"] == "api.anthropic.com:443", logs
    # NOT mislabelled as a policy denial.
    assert not any(e == "gateway.egress.connect_denied" for e, _ in audit)


def test_default_resolve_resolves_localhost() -> None:
    from alfred.gateway.egress_proxy import _default_resolve

    assert _default_resolve("localhost").count(".") == 3  # an IPv4 dotted-quad


@pytest.mark.asyncio
async def test_default_open_upstream_connects() -> None:
    from alfred.gateway.egress_proxy import _default_open_upstream

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"OK")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    async with server:
        reader, writer = await _default_open_upstream(host, port)
        data = await asyncio.wait_for(reader.read(8), timeout=5)
        writer.close()
        await writer.wait_closed()
    assert data == b"OK"


def test_resolve_egress_proxy_port_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_PORT", raising=False)
    assert resolve_egress_proxy_port() == 8889


def test_resolve_egress_proxy_port_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_PORT", "9001")
    assert resolve_egress_proxy_port() == 9001


def test_resolve_egress_proxy_port_rejects_non_int(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_PORT", "notaport")
    with pytest.raises(ValueError, match="ALFRED_EGRESS_PROXY_PORT"):
        resolve_egress_proxy_port()


def test_resolve_egress_proxy_port_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_PORT", "70000")
    with pytest.raises(ValueError, match=r"1\.\.65535"):
        resolve_egress_proxy_port()


def test_resolve_egress_proxy_bind_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_EGRESS_PROXY_BIND", raising=False)
    assert resolve_egress_proxy_bind() == "0.0.0.0"  # noqa: S104 — documented default; never published


def test_resolve_egress_proxy_bind_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_EGRESS_PROXY_BIND", "127.0.0.1")
    assert resolve_egress_proxy_bind() == "127.0.0.1"


def test_resolve_deepseek_base_url_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from alfred.gateway.egress_proxy import resolve_deepseek_base_url

    monkeypatch.delenv("ALFRED_DEEPSEEK_BASE_URL", raising=False)
    assert resolve_deepseek_base_url() == "https://api.deepseek.com/v1"


def test_resolve_deepseek_base_url_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from alfred.gateway.egress_proxy import resolve_deepseek_base_url

    monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", "https://custom.deepseek.proxy/v1")
    assert resolve_deepseek_base_url() == "https://custom.deepseek.proxy/v1"


@pytest.mark.asyncio
async def test_handle_client_registers_and_reaps_connection_task() -> None:
    # Drive the accept callback directly: it must register the connection task and
    # the done-callback must discard it on completion.
    proxy = _proxy([], upstream=(_reader_with(b"UP"), _CaptureWriter()))
    proxy._handle_client(  # type: ignore[attr-defined]
        _reader_with(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"), _CaptureWriter()
    )
    assert len(proxy._conns) == 1  # type: ignore[attr-defined]
    for _ in range(50):
        if not proxy._conns:  # type: ignore[attr-defined]
            break
        await asyncio.sleep(0.01)
    assert not proxy._conns  # type: ignore[attr-defined] — done-callback discarded it


@pytest.mark.asyncio
async def test_connection_done_surfaces_an_escaped_exception_loud() -> None:
    # A non-cancellation exception escaping _serve_connection (here the audit sink raising —
    # the fail-loud payload-blindness guard) must NOT vanish as a GC-time "never retrieved":
    # the done-callback retrieves + logs it at error (hard rule #7).
    def _raising_audit(event: str, fields: dict[str, object]) -> None:
        raise ValueError("audit sink rejected the row")

    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST, match=exact_match, bind_host="127.0.0.1", port=0, audit=_raising_audit
    )
    writer = _CaptureWriter()
    with structlog.testing.capture_logs() as logs:
        proxy._handle_client(  # type: ignore[attr-defined]
            _reader_with(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n"), writer
        )
        for _ in range(50):
            if not proxy._conns:  # type: ignore[attr-defined]
                break
            await asyncio.sleep(0.01)
    assert any(e.get("event") == "gateway.egress.connection_failed" for e in logs), logs
    assert writer.closed  # the deny path closes the client socket even when the audit raises


@pytest.mark.asyncio
async def test_audit_failure_on_allowed_path_still_reaps_both_writers() -> None:
    # An audit-sink exception on the ALLOWED path (after the 200) must still tear down BOTH
    # the client and upstream writers — never a leaked tunnel socket.
    def _raising_audit(event: str, fields: dict[str, object]) -> None:
        raise ValueError("audit sink rejected the allowed row")

    up_writer = _CaptureWriter()
    client_writer = _CaptureWriter()

    async def _open(_ip: str, _port: int) -> tuple[asyncio.StreamReader, _CaptureWriter]:
        return (_reader_with(b"UP"), up_writer)

    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=_raising_audit,
        resolve=lambda _h: "1.1.1.1",
        open_upstream=_open,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="allowed row"):
        await proxy._serve_connection(  # type: ignore[attr-defined]
            _reader_with(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"), client_writer
        )
    assert client_writer.closed
    assert up_writer.closed


@pytest.mark.asyncio
async def test_connection_done_ignores_a_cancelled_task() -> None:
    # A cancelled connection task is reaped without touching .exception() (which would raise).
    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=lambda e, f: None,
    )

    async def _block() -> None:
        await asyncio.Event().wait()

    task = asyncio.ensure_future(_block())
    proxy._conns.add(task)  # type: ignore[attr-defined]
    await asyncio.sleep(0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    proxy._on_connection_done(task)  # type: ignore[attr-defined] — must not raise
    assert task not in proxy._conns  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_serve_connection_cancellation_propagates() -> None:
    # A connection cancelled mid-splice re-raises CancelledError (the reap path).
    never_eof_upstream = asyncio.StreamReader()  # blocks: data never arrives, no EOF
    proxy = _proxy([], upstream=(never_eof_upstream, _CaptureWriter()))
    client_reader = asyncio.StreamReader()
    client_reader.feed_data(
        b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"
    )  # no EOF → splice blocks
    task = asyncio.ensure_future(
        proxy._serve_connection(client_reader, _CaptureWriter())  # type: ignore[arg-type]
    )
    await asyncio.sleep(0.05)  # let it establish the tunnel + block in the splice
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# --- Lifecycle (real listener): bind fail-closed + clean shutdown. ---


@pytest.mark.asyncio
async def test_bind_failure_propagates_oserror() -> None:
    blocker = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    busy_port = blocker.sockets[0].getsockname()[1]
    async with blocker:
        proxy = EgressForwardProxy(
            allowlist=_ALLOWLIST,
            match=exact_match,
            bind_host="127.0.0.1",
            port=busy_port,
            audit=lambda e, f: None,
        )
        with pytest.raises(OSError):
            await proxy.serve(asyncio.Event())


@pytest.mark.asyncio
async def test_serve_binds_and_stops_on_shutdown() -> None:
    free = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = free.sockets[0].getsockname()[1]
    free.close()
    await free.wait_closed()
    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=port,
        audit=lambda e, f: None,
        resolve=lambda _h: "1.1.1.1",
    )
    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(proxy.serve(shutdown))
    await asyncio.sleep(0.05)  # let serve() bind
    shutdown.set()
    await asyncio.wait_for(serve_task, timeout=5)
    assert serve_task.done()


@pytest.mark.asyncio
async def test_drain_connections_cancels_in_flight_tasks() -> None:
    # Deterministic unit test of the shutdown reap: a blocking connection task is
    # cancelled + awaited (no real socket, no nested-timeout cancellation hazard).
    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=0,
        audit=lambda e, f: None,
    )

    async def _block() -> None:
        await asyncio.Event().wait()

    task = asyncio.ensure_future(_block())
    proxy._conns.add(task)  # type: ignore[attr-defined]
    task.add_done_callback(proxy._conns.discard)  # type: ignore[attr-defined]
    await asyncio.sleep(0)  # let it start blocking
    await asyncio.wait_for(proxy._drain_connections(), timeout=5)  # type: ignore[attr-defined]
    assert task.cancelled()


# --- Egress metrics (G7-5): plane label + denied_total counter wiring. ---


@pytest.mark.asyncio
async def test_literal_ip_deny_increments_denied_total_after_audit() -> None:
    reg = CollectorRegistry()
    denied = egress_metrics.build_denied_counter(reg)
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit, plane="proxy", denied_counter=denied)
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT 203.0.113.5:443 HTTP/1.1\r\n\r\n", writer)
    # audit fired before the counter increment
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit)
    # AND the new counter incremented, keyed by plane+reason
    fam = next(
        f
        for f in text_string_to_metric_families(generate_latest(reg).decode())
        if f.name == "gateway_egress_denied"  # parser strips the _total suffix
    )
    hit = next(
        s for s in fam.samples if s.labels == {"plane": "proxy", "reason": "literal_ip_target"}
    )
    assert hit.value == 1.0


@pytest.mark.asyncio
async def test_deny_still_audits_and_refuses_when_metric_raises() -> None:
    audit: list[tuple[str, dict[str, object]]] = []

    class _Boom:
        def labels(self, **_: str) -> _Boom:
            return self

        def inc(self) -> None:
            raise RuntimeError("metrics backend down")

    proxy = _proxy(audit, plane="proxy", denied_counter=_Boom())
    writer = _CaptureWriter()
    with contextlib.suppress(RuntimeError):
        await _serve(proxy, b"CONNECT 203.0.113.5:443 HTTP/1.1\r\n\r\n", writer)
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit), (
        "audit must fire before the metric"
    )
    assert b"403" in writer.buf, "refusal must be written before/independent of the metric"


# --- Abandoned connection vs malformed handshake (#340 golive C1). ---
#
# The golive host brokers BROKER_SOCKET_COUNT (3) gateway-connected sockets per extraction and
# the child consumes ONE per retry attempt, so a first-attempt success discards 2 of them
# UNUSED — closed without ever writing a request line. Counting those as MALFORMED_CONNECT
# denials meant two false denials per SUCCESSFUL extraction, which pins
# ``ops/alerts/gateway.yml``'s GatewayEgressDenyRate permanently on and swamps the ADR-0040
# residual (vii) exfiltration deny-log. The proxy must therefore separate:
#
#   * clean EOF with ZERO bytes read  -> benign abandon (not a denial, not alerted);
#   * ANY partial bytes then EOF      -> still a real MALFORMED_CONNECT denial (a truncated
#                                        handshake is a security signal and must not be
#                                        laundered into the benign bucket).
#
# ``asyncio.IncompleteReadError.partial`` is what makes the two decidable at the read site.


def _connect_outcome(outcome: str, plane: str = "proxy") -> float:
    """Current value of ``gateway_egress_connect_total{outcome=...,plane=...}``.

    ``plane`` is part of the series contract (#340 golive) — matching on outcome ALONE would
    silently sum the provider and adapter planes back together, which is precisely the
    conflation the label exists to prevent, so this helper requires both. Returns 0.0 for a
    series that has not been touched yet (prometheus_client only materialises a child on the
    first ``.labels(...)`` call).
    """
    for metric in GATEWAY_EGRESS_CONNECT.collect():
        for sample in metric.samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("outcome") == outcome
                and sample.labels.get("plane") == plane
            ):
                return float(sample.value)
    return 0.0


@pytest.mark.asyncio
async def test_peer_close_before_any_request_byte_is_not_a_denial() -> None:
    reg = CollectorRegistry()
    denied = egress_metrics.build_denied_counter(reg)
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit, plane="proxy", denied_counter=denied)
    writer = _CaptureWriter()

    await _serve(proxy, b"", writer)  # connected, then closed without a single byte

    assert audit == [], "an abandoned pre-brokered socket must write NO audit row"
    assert writer.buf == b"", "no 4xx may be written to a peer that already went away"
    assert writer.closed, "the client writer must still be reaped"
    # ``build_denied_counter`` pre-declares every plane/reason series at 0, so assert the VALUES
    # stay zero rather than the absence of the lines.
    fam = next(
        f
        for f in text_string_to_metric_families(generate_latest(reg).decode())
        if f.name == "gateway_egress_denied"
    )
    assert [s.value for s in fam.samples if s.value] == [], (
        "gateway_egress_denied_total must NOT move — it drives GatewayEgressDenyRate"
    )


@pytest.mark.asyncio
async def test_partial_request_line_then_close_is_still_a_denial() -> None:
    # The security-signal half of the split: a peer that sends SOME bytes and then closes is a
    # truncated/slow-loris handshake, NOT the benign broker-discard. This pins that the C1 fix
    # cannot be widened into "any IncompleteReadError is benign".
    reg = CollectorRegistry()
    denied = egress_metrics.build_denied_counter(reg)
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit, plane="proxy", denied_counter=denied)
    writer = _CaptureWriter()

    await _serve(proxy, b"CONNECT api.anthropic.com:44", writer)

    assert any(f.get("reason") == "malformed_connect" for _, f in audit)
    assert b"400" in writer.buf
    fam = next(
        f
        for f in text_string_to_metric_families(generate_latest(reg).decode())
        if f.name == "gateway_egress_denied"
    )
    hit = next(
        s for s in fam.samples if s.labels == {"plane": "proxy", "reason": "malformed_connect"}
    )
    assert hit.value == 1.0, "a truncated handshake must stay a counted denial"


@pytest.mark.asyncio
async def test_abandoned_connect_is_counted_as_its_own_outcome() -> None:
    # Benign != invisible. The abandon still increments a DISTINCT outcome so a connect-flood
    # stays observable, and so the documented sum invariant
    # (sum_reason(denied_total{plane=P}) == connect_total{outcome="denied",plane=P}) is
    # preserved — now exactly, PER PLANE, rather than only after summing the planes together.
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit)
    before_abandoned = _connect_outcome("abandoned")
    before_denied = _connect_outcome("denied")

    await _serve(proxy, b"", _CaptureWriter())

    assert _connect_outcome("abandoned") == before_abandoned + 1.0
    assert _connect_outcome("denied") == before_denied, "abandon must not count as a denial"


@pytest.mark.asyncio
async def test_abandoned_connect_is_attributable_to_its_plane() -> None:
    """A zero-byte flood must be distinguishable per plane — the whole point of the label.

    On the PROVIDER plane an abandon storm is expected (the quarantine broker pre-connects a
    socket per extraction retry and discards the unused ones). The identical storm on the
    ADAPTER plane is an unauthenticated peer probing the egress listener. Before ``plane``
    joined the label set the two shared ONE series, so the benign case masked the attack and
    ``ops/alerts/gateway.yml``'s GatewayEgressAbandonedConnectFlood could not be written at
    all. Distinct plane names keep this independent of test ordering on the shared default
    registry.
    """
    audit: list[tuple[str, dict[str, object]]] = []
    before_adapter = _connect_outcome("abandoned", plane="unittest_plane_adapter")
    before_other = _connect_outcome("abandoned", plane="unittest_plane_other")

    await _serve(_proxy(audit, plane="unittest_plane_adapter"), b"", _CaptureWriter())

    assert _connect_outcome("abandoned", plane="unittest_plane_adapter") == before_adapter + 1.0
    assert _connect_outcome("abandoned", plane="unittest_plane_other") == before_other, (
        "an abandon on one plane must NOT move another plane's series"
    )


@pytest.mark.asyncio
async def test_every_connect_outcome_carries_the_plane_label() -> None:
    """All FOUR ``.labels(...)`` call sites must pass ``plane`` — not just the abandoned one.

    A Counter's label set is all-or-nothing: a site that omitted ``plane`` would raise at
    runtime inside the per-connection task rather than under-count, so this doubles as a
    smoke test that none of the four paths blew up. Driven on a plane of its own so each
    series is asserted absolutely (== 1.0) instead of by delta.
    """
    plane = "unittest_all_outcomes"
    audit: list[tuple[str, dict[str, object]]] = []
    ok = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"

    # allowed — full tunnel through a stub upstream.
    await _serve(
        _proxy(audit, upstream=(_reader_with(b""), _CaptureWriter()), plane=plane),
        ok,
        _CaptureWriter(),
    )
    # denied — destination not on the allowlist.
    await _serve(
        _proxy(audit, plane=plane), b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n", _CaptureWriter()
    )
    # abandoned — peer closed having sent zero bytes.
    await _serve(_proxy(audit, plane=plane), b"", _CaptureWriter())
    # error — allowlisted + resolvable, but the upstream open fails (OSError path).
    await _serve(
        _proxy(audit, open_error=ConnectionRefusedError("upstream down"), plane=plane),
        ok,
        _CaptureWriter(),
    )

    for outcome in ("allowed", "denied", "abandoned", "error"):
        assert _connect_outcome(outcome, plane=plane) == 1.0, (
            f"gateway_egress_connect_total{{outcome={outcome},plane={plane}}} must be labelled"
        )


@pytest.mark.asyncio
async def test_real_socket_broker_discard_produces_no_denial() -> None:
    # End-to-end over a REAL listener + REAL TCP socket, reproducing what the golive broker
    # actually does to an unused pre-brokered socket: connect, never write, close. The
    # in-memory tests above assert the same thing deterministically; this one proves the
    # premise (a discarded broker socket really does arrive as a zero-byte clean EOF).
    import socket as _socket

    free = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = free.sockets[0].getsockname()[1]
    free.close()
    await free.wait_closed()

    audit: list[tuple[str, dict[str, object]]] = []
    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        match=exact_match,
        bind_host="127.0.0.1",
        port=port,
        audit=lambda event, fields: audit.append((event, fields)),
        resolve=lambda _h: "1.1.1.1",
    )
    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(proxy.serve(shutdown))
    await asyncio.sleep(0.05)  # let serve() bind
    try:
        sock = _socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.close()  # exactly the broker's discard of an unused socket
        await asyncio.sleep(0.1)  # let the connection task run to completion
    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)

    assert audit == [], f"a discarded broker socket must produce no audit row, got {audit!r}"
