"""EgressForwardProxy bind selector + injected match predicate (G7-4 Task 3, #333).

The proxy class is now bind-mode-agnostic so the SAME class runs as the provider TCP
instance (G7-1b) and the Discord AF_UNIX instance (G7-4) without changing the
``serve(shutdown_event)`` signature the ``_EgressProxyLike`` Protocol declares.

Covers:
  - Construction: exactly-one-bind-mode invariant (both / neither / partial raises
    ``ValueError`` loudly in ``__init__``).
  - ``_authorize`` honours the injected ``exact_match`` and ``suffix_match`` predicates.
  - Provider exact-match equivalence: the refactor is non-widening relative to the
    prior ``(host, port) in allowlist`` membership check.
  - In-process AF_UNIX serve: the ``unix_path`` ``serve`` branch binds, accepts
    connections, and handles CONNECT correctly (allowlisted -> 200; non-allowlisted -> 403).
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from alfred.egress.allowlist import EgressDestination, Match, exact_match, suffix_match
from alfred.gateway.egress_proxy import EgressForwardProxy

_PROVIDER_ALLOWLIST: frozenset[EgressDestination] = frozenset({("api.anthropic.com", 443)})


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> AsyncIterator[None]:
    """Drain the per-test loop's default executor on teardown (mirrors test_egress_proxy.py).

    ``serve`` resolves DNS via ``loop.run_in_executor(None, ...)``; pytest-asyncio's
    function-scoped loop only ``shutdown(wait=False)``s that executor, leaving worker
    threads that accumulate and hang interpreter-exit. Draining here keeps the suite clean.
    """
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


def _proxy_tcp(match: Match, allow: frozenset[EgressDestination]) -> EgressForwardProxy:
    """A minimal TCP-mode proxy for predicate tests (constructed, never bound)."""
    return EgressForwardProxy(
        allowlist=allow,
        match=match,
        audit=lambda _e, _f: None,
        bind_host="127.0.0.1",
        port=0,
    )


async def _read_until(
    reader: asyncio.StreamReader, marker: bytes, *, timeout: float = 5.0
) -> bytes:
    """Accumulate from ``reader`` until ``marker`` appears or EOF — avoids a single-read race.

    The proxy writes the ``200`` status line BEFORE the upstream bytes arrive, so a lone
    ``read(512)`` could return either chunk depending on scheduling. Reading until the
    marker makes the tunnel assertion deterministic.
    """

    async def _loop() -> bytes:
        buf = bytearray()
        while marker not in buf:
            chunk = await reader.read(512)
            if not chunk:
                break
            buf += chunk
        return bytes(buf)

    return await asyncio.wait_for(_loop(), timeout=timeout)


# --- Construction invariant: exactly one bind mode -------------------------------------


def test_construction_both_tcp_and_unix_raises() -> None:
    """Supplying both (bind_host, port) AND unix_path is a programmer error."""
    with pytest.raises(ValueError, match="exactly one"):
        EgressForwardProxy(
            allowlist=_PROVIDER_ALLOWLIST,
            match=exact_match,
            audit=lambda _e, _f: None,
            bind_host="0.0.0.0",  # noqa: S104 -- never bound; construction raises first
            port=8889,
            unix_path=Path("unused.sock"),
        )


def test_construction_neither_mode_raises() -> None:
    """Supplying neither (bind_host, port) nor unix_path is a programmer error."""
    with pytest.raises(ValueError, match="exactly one"):
        EgressForwardProxy(
            allowlist=_PROVIDER_ALLOWLIST,
            match=exact_match,
            audit=lambda _e, _f: None,
        )


def test_construction_partial_tcp_only_bind_host_raises() -> None:
    """bind_host without port is a partial TCP config — raises before the one-mode check."""
    with pytest.raises(ValueError, match="bind_host and port must be set together"):
        EgressForwardProxy(
            allowlist=_PROVIDER_ALLOWLIST,
            match=exact_match,
            audit=lambda _e, _f: None,
            bind_host="127.0.0.1",
        )


def test_construction_partial_tcp_bind_host_without_port_with_unix_raises() -> None:
    """bind_host set + port=None + unix_path set: partial TCP config is rejected even though
    unix_path is provided — the partial-TCP guard fires first with its own message."""
    with pytest.raises(ValueError, match="bind_host and port must be set together"):
        EgressForwardProxy(
            allowlist=_PROVIDER_ALLOWLIST,
            match=exact_match,
            audit=lambda _e, _f: None,
            bind_host="127.0.0.1",
            unix_path=Path("unused.sock"),
        )


# --- _authorize honours the injected match predicate -----------------------------------


def test_authorize_exact_match_allowlisted_passes() -> None:
    p = _proxy_tcp(exact_match, frozenset({("discord.com", 443)}))
    assert p._match("discord.com", 443, p._allowlist) is True


def test_authorize_exact_match_non_member_denied() -> None:
    p = _proxy_tcp(exact_match, frozenset({("discord.com", 443)}))
    assert p._match("evil.com", 443, p._allowlist) is False


def test_authorize_suffix_match_subdomain_passes() -> None:
    """A subdomain of an allowlisted suffix base is allowed (the Discord-instance shape)."""
    p = _proxy_tcp(suffix_match, frozenset({("discord.gg", 443)}))
    assert p._match("gateway-us-east1-b.discord.gg", 443, p._allowlist) is True


def test_authorize_suffix_match_apex_passes() -> None:
    """The apex hostname itself is also allowed by suffix_match."""
    p = _proxy_tcp(suffix_match, frozenset({("discord.gg", 443)}))
    assert p._match("discord.gg", 443, p._allowlist) is True


def test_authorize_suffix_match_bare_endswith_denied() -> None:
    """``evildiscord.gg`` must NOT match ``discord.gg`` (the bare-``endswith`` pitfall)."""
    p = _proxy_tcp(suffix_match, frozenset({("discord.gg", 443)}))
    assert p._match("evildiscord.gg", 443, p._allowlist) is False


# --- Provider exact-match ≡ prior membership: the refactor is non-widening --------------


def test_exact_match_equivalence_allowlisted_allowed() -> None:
    """An allowlisted (host, port) pair is allowed — identical to the prior ``in`` check."""
    p = _proxy_tcp(exact_match, _PROVIDER_ALLOWLIST)
    assert p._match("api.anthropic.com", 443, p._allowlist) is True


def test_exact_match_equivalence_wrong_host_denied() -> None:
    """A non-member host is denied — consistent with the prior ``in`` check."""
    p = _proxy_tcp(exact_match, _PROVIDER_ALLOWLIST)
    assert p._match("evil.com", 443, p._allowlist) is False


def test_exact_match_equivalence_wrong_port_denied() -> None:
    """Correct host but wrong port is denied — exact_match is not port-blind."""
    p = _proxy_tcp(exact_match, _PROVIDER_ALLOWLIST)
    assert p._match("api.anthropic.com", 80, p._allowlist) is False


# --- In-process AF_UNIX serve: drives the unix_path serve branch (no Docker) ------------


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_serve_unix_path_bind_and_connect() -> None:
    """AF_UNIX serve branch: the proxy binds a unix socket and handles CONNECT correctly.

    Drives the ``unix_path`` branch of ``serve()`` in-process so the 100% line+branch gate
    covers it without Docker. Verifies an allowlisted CONNECT -> ``200 Connection
    Established`` with real upstream bytes relayed through the tunnel, a non-allowlisted
    CONNECT -> ``403``, and a clean shutdown on ``shutdown_event.set()``.

    The upstream is a REAL in-process loopback server (not a stub writer) so ``open_upstream``
    keeps its true ``(StreamReader, StreamWriter)`` type — no type suppression. A short
    ``TemporaryDirectory`` socket path avoids the macOS AF_UNIX 104-byte limit that the deep
    pytest ``tmp_path`` overflows (mirrors test_local_socket.py's ``short_runtime``).
    """

    async def _upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"UPSTREAM-DATA")
        await writer.drain()
        writer.write_eof()
        await reader.read()  # drain client->upstream bytes until EOF, then close
        writer.close()

    up_server = await asyncio.start_server(_upstream, "127.0.0.1", 0)
    up_host, up_port = up_server.sockets[0].getsockname()[:2]

    async def _open(_ip: str, _port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        # Stands in for the gateway-side resolved upstream; the globally-routable resolve
        # below is what clears the DNS-rebinding guard, not this loopback target.
        return await asyncio.open_connection(up_host, up_port)

    with tempfile.TemporaryDirectory(prefix="egressproxy-") as tmp:
        unix_path = Path(tmp) / "egress.sock"
        proxy = EgressForwardProxy(
            allowlist=_PROVIDER_ALLOWLIST,
            match=exact_match,
            audit=lambda _e, _f: None,
            resolve=lambda _h: "1.1.1.1",  # globally routable -> DNS-rebinding guard passes
            open_upstream=_open,
            unix_path=unix_path,
        )

        async def _wait_until_connectable(path: Path, *, timeout: float = 5.0) -> None:
            """Poll until the AF_UNIX socket at ``path`` is connectable (or deadline)."""

            async def _poll() -> None:
                while True:
                    if path.exists():
                        try:
                            _r, _w = await asyncio.open_unix_connection(str(path))
                            _w.close()
                            await _w.wait_closed()
                            return
                        except OSError:
                            pass
                    await asyncio.sleep(0.005)

            await asyncio.wait_for(_poll(), timeout=timeout)

        shutdown = asyncio.Event()
        serve_task = asyncio.ensure_future(proxy.serve(shutdown))
        try:
            async with up_server:
                await _wait_until_connectable(unix_path)  # wait until serve() has bound the socket

                # allowlisted CONNECT -> 200 + the upstream bytes relayed back
                reader1, writer1 = await asyncio.open_unix_connection(str(unix_path))
                writer1.write(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
                await writer1.drain()
                resp1 = await _read_until(reader1, b"UPSTREAM-DATA")
                assert b"200 Connection Established" in resp1, resp1
                assert b"UPSTREAM-DATA" in resp1, resp1
                writer1.close()
                await asyncio.wait_for(writer1.wait_closed(), timeout=5)

                # non-allowlisted CONNECT -> 403
                reader2, writer2 = await asyncio.open_unix_connection(str(unix_path))
                writer2.write(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n")
                await writer2.drain()
                resp2 = await _read_until(reader2, b"403")
                assert b"403" in resp2, resp2
                writer2.close()
                await asyncio.wait_for(writer2.wait_closed(), timeout=5)
        finally:
            shutdown.set()
            await asyncio.wait_for(serve_task, timeout=5)
