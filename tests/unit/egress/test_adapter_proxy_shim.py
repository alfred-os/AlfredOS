"""Unit test: the in-child TCP→unix egress shim splices bytes verbatim (Spec C G7-4, #333)."""

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

import alfred.egress.adapter_proxy_shim as shim


@pytest.mark.asyncio
async def test_shim_closes_connection_on_upstream_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # macOS AF_UNIX pathname limit is 104 bytes; use a short-prefixed mkdtemp.
    tmpdir = tempfile.mkdtemp(prefix="ashim_")
    try:
        # Point to a non-existent socket path; open_unix_connection raises
        # FileNotFoundError (an OSError subclass) — _bridge must catch it,
        # log a warning, close the downstream writer, and return.  The client
        # must then read EOF (b"") without hanging.
        missing_sock = Path(tmpdir) / "nope.sock"
        monkeypatch.setattr(shim, "DISCORD_EGRESS_SOCKET_PATH", missing_sock)
        monkeypatch.setattr(shim, "DISCORD_EGRESS_SHIM_PORT", 0)  # ephemeral
        server = await shim.start_shim()
        port = server.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"CONNECT discord.com:443 HTTP/1.1\r\n\r\n")
        await w.drain()
        # _bridge closes the writer on OSError → client gets EOF or RST.
        # On Linux the peer sees a clean FIN (b""); on macOS/Python 3.14
        # writer.close() without wait_closed() may send RST instead, which
        # surfaces as ConnectionResetError.  Both mean the connection is closed.
        # wait_for guards against an infinite hang if the branch is not reached.
        try:
            data = await asyncio.wait_for(r.read(1024), timeout=5.0)
            assert data == b""
        except ConnectionResetError:
            pass  # RST is a valid close signal on this platform
        finally:
            server.close()
            await server.wait_closed()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.mark.asyncio
async def test_shim_splices_bytes_verbatim_to_unix(monkeypatch: pytest.MonkeyPatch) -> None:
    # macOS AF_UNIX pathname limit is 104 bytes; pytest's tmp_path can exceed it,
    # so we use a short-prefixed mkdtemp to stay well within the limit.
    tmpdir = tempfile.mkdtemp(prefix="ashim_")
    try:
        sock_path = Path(tmpdir) / "eg.sock"
        received = bytearray()

        async def upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            received.extend(await reader.read(64))
            writer.write(b"PONG")
            await writer.drain()
            writer.close()

        unix_server = await asyncio.start_unix_server(upstream, path=str(sock_path))
        monkeypatch.setattr(shim, "DISCORD_EGRESS_SOCKET_PATH", sock_path)
        monkeypatch.setattr(shim, "DISCORD_EGRESS_SHIM_PORT", 0)  # ephemeral
        server = await shim.start_shim()
        port = server.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"CONNECT discord.com:443 HTTP/1.1\r\n\r\n")
        await w.drain()
        assert await r.read(4) == b"PONG"
        assert bytes(received).startswith(b"CONNECT discord.com:443")
        server.close()
        unix_server.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
