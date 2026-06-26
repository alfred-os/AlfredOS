"""End-to-end mode-(a) provider forward-proxy proof (Spec C G7-1b, #333).

Stands up the REAL :class:`alfred.gateway.egress_proxy.EgressForwardProxy` on loopback +
a fake upstream + the REAL in-core :class:`alfred.egress.client.EgressClient`'s proxied
``httpx`` client, and proves the mode-(a) properties the slice promises:

* **payload-blindness** — an allowlisted CONNECT is spliced and the proxy forwards the
  opaque tunnel bytes (a raw TLS ``ClientHello``) it never parses;
* **refusal** — a non-allowlisted CONNECT is refused (the in-core proxied client's request
  fails) and the gateway audits it;
* **streaming survives the splice** — a chunked upstream response reaches the client
  INCREMENTALLY, before the upstream EOF (the splice is not buffer-until-EOF);
* **audit rows land** — every CONNECT, allowed or denied, is audited through the REAL
  field-allowlisted :func:`alfred.gateway.egress_audit.record_egress_connect` sink (so a
  proxy field that breaks the payload-blindness floor would fail this proof LOUD).

Loopback sockets only — this is NOT an integration test (it pulls no testcontainers
Postgres fixture). The proxy resolves DNS off-loop via ``run_in_executor`` even with an
injected resolver, so the autouse fixture drains the per-test default ThreadPoolExecutor
(B1's lesson — otherwise the non-daemon worker threads hang the interpreter-exit join).

The injected ``resolve`` returns a GLOBALLY-ROUTABLE IP (so the resolved-IP guard passes)
while the injected ``open_upstream`` redirects the actual socket to the loopback fake
upstream — the standard pattern for proving a forward-proxy against a loopback upstream
(the resolved IP is only fed to the guard + the opener, which here ignores it).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import httpx
import pytest

from alfred.egress.client import EgressClient
from alfred.gateway.egress_audit import record_egress_connect
from alfred.gateway.egress_proxy import EgressForwardProxy

_ALLOWED_HOST = "api.anthropic.com"
_ALLOWLIST = frozenset({(_ALLOWED_HOST, 443)})
_GLOBALLY_ROUTABLE_IP = "1.1.1.1"  # passes is_globally_routable; the opener ignores it

_UpstreamHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
_AuditRow = tuple[str, dict[str, object]]


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> AsyncIterator[None]:
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


async def _free_port() -> int:
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    server.close()
    await server.wait_closed()
    return port


async def _await_proxy_ready(port: int, serve_task: asyncio.Task[None]) -> None:
    """Wait until the proxy listener accepts a TCP connection — a readiness probe instead of a
    fixed sleep, so a busy runner cannot race the bind. A bind failure surfaces via the serve
    task rather than spinning. The benign probe connection is reaped by the proxy as a
    malformed CONNECT, harmless to the row assertions."""
    for _ in range(500):
        if serve_task.done():
            await serve_task  # re-raise a bind error instead of spinning forever
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.005)
            continue
        writer.close()
        return
    raise AssertionError("egress proxy did not become ready")


@asynccontextmanager
async def _serving_proxy(
    *, upstream_handler: _UpstreamHandler | None = None
) -> AsyncIterator[tuple[int, list[_AuditRow]]]:
    """Run the real proxy on a free loopback port; yield (port, captured-audit-rows).

    When ``upstream_handler`` is given, a loopback fake upstream is started and the proxy's
    ``open_upstream`` is redirected to it (the resolved IP is globally-routable, so the
    resolved-IP guard passes, but the opener ignores it). When it is ``None`` the opener
    fails loud (a deny-only test must never reach a tunnel). The audit sink wraps the REAL
    ``record_egress_connect`` (which raises if the proxy emits a non-allowlisted field) AND
    records the row — so the proof also pins the proxy↔audit field contract end-to-end.
    """
    rows: list[_AuditRow] = []

    def _audit(event: str, fields: dict[str, object]) -> None:
        record_egress_connect(event, fields)
        rows.append((event, dict(fields)))

    async def _deny_only_opener(
        _ip: str, _port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise AssertionError("open_upstream reached on a path that should never tunnel")

    upstream_server: asyncio.Server | None = None
    open_upstream = _deny_only_opener
    if upstream_handler is not None:
        upstream_server = await asyncio.start_server(upstream_handler, "127.0.0.1", 0)
        up_host, up_port = upstream_server.sockets[0].getsockname()[:2]

        async def _open(_ip: str, _port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return await asyncio.open_connection(up_host, up_port)

        open_upstream = _open

    port = await _free_port()
    proxy = EgressForwardProxy(
        allowlist=_ALLOWLIST,
        bind_host="127.0.0.1",
        port=port,
        audit=_audit,
        resolve=lambda _host: _GLOBALLY_ROUTABLE_IP,
        open_upstream=open_upstream,
    )
    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(proxy.serve(shutdown))
    await _await_proxy_ready(port, serve_task)
    try:
        yield port, rows
    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
        if upstream_server is not None:
            upstream_server.close()
            await upstream_server.wait_closed()


@pytest.mark.asyncio
async def test_egress_client_refuses_non_allowlisted_destination() -> None:
    """The in-core proxied client's CONNECT to a non-allowlisted host is refused + audited."""
    async with _serving_proxy() as (port, rows):
        client = EgressClient(proxy_url=f"http://127.0.0.1:{port}")
        http_client = client.build_provider_http_client()
        assert http_client is not None
        try:
            with pytest.raises(httpx.HTTPError):
                await http_client.get("https://evil.example/", timeout=5.0)
        finally:
            await http_client.aclose()

    denied = [f for e, f in rows if e == "gateway.egress.connect_denied"]
    assert any(f.get("reason") == "destination_not_allowlisted" for f in denied), rows
    assert all("resolved_ip" not in f for _e, f in rows)  # payload-blind row shape


@pytest.mark.asyncio
async def test_egress_client_allowlisted_connect_is_payload_blind() -> None:
    """The in-core proxied client's allowlisted CONNECT forwards the opaque TLS ClientHello.

    The proxy never parses the tunnel bytes: the fake upstream receives the raw TLS
    ``ClientHello`` (record-type 0x16) httpx writes after the CONNECT 200, then closes —
    httpx's TLS handshake fails (the upstream is not a TLS server), which is expected and
    irrelevant: the point is that the opaque bytes were spliced verbatim + the CONNECT was
    audited as allowed.
    """
    received = bytearray()
    got_bytes = asyncio.Event()

    async def _upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.extend(await reader.read(4096))
        got_bytes.set()
        writer.close()

    async with _serving_proxy(upstream_handler=_upstream) as (port, rows):
        client = EgressClient(proxy_url=f"http://127.0.0.1:{port}")
        http_client = client.build_provider_http_client()
        assert http_client is not None
        try:
            with pytest.raises(httpx.HTTPError):  # TLS fails against the non-TLS upstream
                await http_client.get(f"https://{_ALLOWED_HOST}/", timeout=5.0)
        finally:
            await http_client.aclose()
        await asyncio.wait_for(got_bytes.wait(), timeout=5)

    assert received, "the proxy forwarded no tunnel bytes to the upstream"
    assert received[0] == 0x16, (  # TLS handshake record type — the opaque ClientHello
        "expected an opaque TLS ClientHello spliced verbatim; the proxy must not parse it"
    )
    assert any(e == "gateway.egress.connect_allowed" for e, _f in rows), rows


@pytest.mark.asyncio
async def test_proxy_splices_opaque_bytes_in_both_directions() -> None:
    """A raw CONNECT client proves the splice forwards opaque (non-HTTP) bytes verbatim."""
    opaque_request = bytes([0x16, 0x03, 0x01, 0xDE, 0xAD, 0xBE, 0xEF])  # TLS-shaped garbage
    opaque_reply = b"\x17\x03\x03OPAQUE-UPSTREAM-REPLY"
    upstream_received = bytearray()

    async def _upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_received.extend(await reader.readexactly(len(opaque_request)))
        writer.write(opaque_reply)
        await writer.drain()
        writer.close()

    async with _serving_proxy(upstream_handler=_upstream) as (port, rows):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"CONNECT {_ALLOWED_HOST}:443 HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        status = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert b"200" in status
        writer.write(opaque_request)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(len(opaque_reply)), timeout=5)
        writer.close()

    assert bytes(upstream_received) == opaque_request  # client → upstream, verbatim
    assert reply == opaque_reply  # upstream → client, verbatim
    assert any(e == "gateway.egress.connect_allowed" for e, _f in rows), rows


@pytest.mark.asyncio
async def test_proxy_streams_chunked_response_before_upstream_eof() -> None:
    """A chunked upstream response reaches the client BEFORE the upstream EOF.

    The upstream sends the first chunk, then BLOCKS until the test confirms it received that
    chunk, then sends the second chunk + closes. A buffer-until-EOF proxy would deadlock (the
    client never sees chunk one, so the test never unblocks the upstream) → the
    ``wait_for`` times out. An incremental splice delivers chunk one immediately → pass.
    """
    chunk_one = b"FIRST-CHUNK-"
    chunk_two = b"SECOND-CHUNK"
    proceed = asyncio.Event()

    async def _upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        writer.write(chunk_one)
        await writer.drain()
        await proceed.wait()  # only set AFTER the client has the first chunk
        writer.write(chunk_two)
        await writer.drain()
        writer.close()

    async with _serving_proxy(upstream_handler=_upstream) as (port, _rows):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"CONNECT {_ALLOWED_HOST}:443 HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        first = await asyncio.wait_for(reader.readexactly(len(chunk_one)), timeout=5)
        assert first == chunk_one  # arrived BEFORE the upstream produced chunk two
        proceed.set()
        second = await asyncio.wait_for(reader.readexactly(len(chunk_two)), timeout=5)
        assert second == chunk_two
        writer.close()
