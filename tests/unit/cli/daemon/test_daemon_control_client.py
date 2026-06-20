"""Daemon control-plane client: dial + one request + one response (#288, ADR-0038).

These pin the client's error mapping (correction sec-HIGH-4 / test-M4):

* a MISSING socket -> ``DaemonControlUnavailableError`` (via ``assert_path_owned``'s bare
  ``FileNotFoundError``) — the operator-facing "daemon not running" path;
* a stale inode with NO listener -> ``DaemonControlUnavailableError`` (via the connect
  ``ConnectionRefusedError`` arm);
* a dialed path that is not a socket-we-own -> ``DaemonControlAuthError``;
* a post-connect peer-uid mismatch -> ``DaemonControlAuthError``;
* an EMPTY response (EOF) and an OVER-BOUND response are SEPARATE tests (test-M4 — the
  ``or`` short-circuits otherwise), plus a malformed (non-JSON) response arm.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

import alfred.cli.daemon._daemon_control_client as client_mod
from alfred.cli.daemon._daemon_control_client import (
    DaemonControlAuthError,
    DaemonControlError,
    DaemonControlProtocolError,
    DaemonControlUnavailableError,
    query_daemon_control,
)
from alfred.cli.daemon._daemon_control_protocol import STATUS_QUERY_METHOD
from alfred.plugins._local_socket import bind_owner_only_unix_socket

pytestmark = pytest.mark.asyncio


@pytest.fixture
def short_runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="alfcli-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


async def test_missing_socket_raises_unavailable(short_runtime: Path) -> None:
    short_runtime.mkdir(parents=True)
    with pytest.raises(DaemonControlUnavailableError):
        await query_daemon_control(STATUS_QUERY_METHOD, path=short_runtime / "absent.sock")


async def test_stale_inode_no_listener_raises_unavailable(short_runtime: Path) -> None:
    # A socket WE own but with NO accepting server -> connect raises
    # ConnectionRefusedError -> mapped to Unavailable (distinct from the missing arm).
    path = short_runtime / "stale.sock"
    sock = bind_owner_only_unix_socket(path)
    sock.close()  # leave the inode, but nothing is listening
    with pytest.raises(DaemonControlUnavailableError):
        await query_daemon_control(STATUS_QUERY_METHOD, path=path)


async def test_connect_time_oserror_maps_to_unavailable(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # T2 / CR Major: a connect-time OSError that is NEITHER FileNotFound NOR
    # ConnectionRefused (a TOCTOU after ``assert_path_owned``'s lstat — here a
    # ``PermissionError``/EACCES) must still map into the taxonomy as Unavailable, not
    # escape ``DaemonControlError`` raw. The path is one we own so the pre-dial
    # ``assert_path_owned`` passes and the connect is reached.
    path = short_runtime / "ctl.sock"
    sock = bind_owner_only_unix_socket(path)
    sock.close()  # leave an owned inode so assert_path_owned passes

    async def _boom_connect(*_args: object, **_kwargs: object) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(client_mod.asyncio, "open_unix_connection", _boom_connect)
    with pytest.raises(DaemonControlUnavailableError):
        await query_daemon_control(STATUS_QUERY_METHOD, path=path)


async def test_unowned_path_raises_auth_error(short_runtime: Path) -> None:
    short_runtime.mkdir(parents=True)
    f = short_runtime / "notasock"
    f.write_text("x")
    with pytest.raises(DaemonControlAuthError):
        await query_daemon_control(STATUS_QUERY_METHOD, path=f)


async def test_post_connect_peer_uid_mismatch_raises_auth_error(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stand up a real accepting server, but force the CLIENT-side peer-uid resolution to
    # report a foreign uid -> the dial is refused post-connect.
    path = short_runtime / "ctl.sock"

    async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        writer.close()

    sock = bind_owner_only_unix_socket(path)
    server = await asyncio.start_unix_server(_accept, sock=sock)
    monkeypatch.setattr(client_mod, "resolve_peer_uid", lambda _sock, **_kw: os.getuid() + 5)
    try:
        with pytest.raises(DaemonControlAuthError):
            await query_daemon_control(STATUS_QUERY_METHOD, path=path)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def _stub_server(path: Path, response: bytes) -> asyncio.AbstractServer:
    async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()  # consume the request
        writer.write(response)
        await writer.drain()
        writer.close()

    sock = bind_owner_only_unix_socket(path)
    return await asyncio.start_unix_server(_accept, sock=sock)


async def test_empty_response_raises_protocol_error(short_runtime: Path) -> None:
    # test-M4 (arm 1): an EOF / empty response is its own protocol error.
    path = short_runtime / "ctl.sock"
    server = await _stub_server(path, b"")  # writes nothing -> EOF
    try:
        with pytest.raises(DaemonControlProtocolError):
            await query_daemon_control(STATUS_QUERY_METHOD, path=path)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def test_over_bound_response_raises_protocol_error(short_runtime: Path) -> None:
    # test-M4 (arm 2): an over-bound response line is its own protocol error (the ``or``
    # short-circuits, so this needs an independent test from the empty-read arm).
    from alfred.plugins._local_socket import MAX_LOCAL_SOCKET_LINE_BYTES

    path = short_runtime / "ctl.sock"
    server = await _stub_server(path, b"x" * (MAX_LOCAL_SOCKET_LINE_BYTES + 10) + b"\n")
    try:
        with pytest.raises(DaemonControlProtocolError):
            await query_daemon_control(STATUS_QUERY_METHOD, path=path)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def test_malformed_response_raises_protocol_error(short_runtime: Path) -> None:
    # test-M4 (arm 3): a bounded but non-JSON response line.
    path = short_runtime / "ctl.sock"
    server = await _stub_server(path, b"not json at all\n")
    try:
        with pytest.raises(DaemonControlProtocolError):
            await query_daemon_control(STATUS_QUERY_METHOD, path=path)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


class _OverBoundStubReader:
    """Hands a single over-bound line through whole (the real readline raises first).

    Drives the belt-and-braces ``len(raw) > MAX`` guard in ``_read_response`` directly —
    a defensive re-check of the StreamReader limit (a line at exactly the limit can slip
    through readline without raising).
    """

    def __init__(self, line: bytes) -> None:
        self._line = line

    async def readline(self) -> bytes:
        line, self._line = self._line, b""
        return line


async def test_read_response_belt_and_braces_over_bound_guard() -> None:
    from alfred.cli.daemon._daemon_control_client import _read_response
    from alfred.plugins._local_socket import MAX_LOCAL_SOCKET_LINE_BYTES

    reader = _OverBoundStubReader(b"x" * (MAX_LOCAL_SOCKET_LINE_BYTES + 1))
    with pytest.raises(DaemonControlProtocolError, match="over-bound"):
        await _read_response(reader)  # type: ignore[arg-type]


async def test_server_drop_mid_exchange_maps_to_daemon_control_error(short_runtime: Path) -> None:
    # The portable server-drop case: a real server accepts then immediately closes WITHOUT
    # sending a frame. On Linux the close-with-unread-data delivers an RST so the client's
    # drain/read raises ECONNRESET -> mapped to DaemonControlUnavailableError; on macOS the
    # same close surfaces as a clean EOF -> DaemonControlProtocolError("empty…"). BOTH are
    # DaemonControlError subclasses, so the operator-facing render's ``except
    # DaemonControlError`` catches it on either platform — the portable assertion. The key
    # guarantee: a raw ConnectionResetError never escapes the taxonomy.
    path = short_runtime / "ctl.sock"

    async def _accept_then_close(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        del reader  # drop immediately, before consuming/answering the request
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    sock = bind_owner_only_unix_socket(path)
    server = await asyncio.start_unix_server(_accept_then_close, sock=sock)
    try:
        with pytest.raises(DaemonControlError):  # NOT a raw ConnectionResetError
            await query_daemon_control(STATUS_QUERY_METHOD, path=path)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def test_read_response_connection_reset_maps_to_unavailable() -> None:
    # Deterministic on BOTH platforms: a reader whose readline raises ECONNRESET (the
    # Linux mid-read drop) is mapped to Unavailable, never propagated raw — covers the
    # ``_read_response`` ConnectionReset branch without depending on socket-close timing.
    from alfred.cli.daemon._daemon_control_client import _read_response

    class _ResettingReader:
        async def readline(self) -> bytes:
            raise ConnectionResetError(104, "Connection reset by peer")

    with pytest.raises(DaemonControlUnavailableError, match="dropped"):
        await _read_response(_ResettingReader())  # type: ignore[arg-type]


async def test_drain_connection_reset_maps_to_unavailable(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deterministic cover of the OUTER write/drain ConnectionReset branch: a real accepting
    # server passes the pre-dial + peer-uid checks, then a patched writer.drain raises
    # ECONNRESET (the Linux drop on flush). Mapped to Unavailable, never raw.
    path = short_runtime / "ctl.sock"

    async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        writer.close()

    sock = bind_owner_only_unix_socket(path)
    server = await asyncio.start_unix_server(_accept, sock=sock)

    real_open = asyncio.open_unix_connection

    async def _open(*args: object, **kwargs: object) -> object:
        reader, writer = await real_open(*args, **kwargs)  # type: ignore[arg-type]

        async def _boom_drain() -> None:
            raise ConnectionResetError(104, "Connection reset by peer")

        monkeypatch.setattr(writer, "drain", _boom_drain)
        return reader, writer

    monkeypatch.setattr(client_mod.asyncio, "open_unix_connection", _open)
    try:
        with pytest.raises(DaemonControlUnavailableError):
            await query_daemon_control(STATUS_QUERY_METHOD, path=path)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()
