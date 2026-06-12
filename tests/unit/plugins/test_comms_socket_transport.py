"""``CommsSocketTransport`` + ``CommsSocketListener`` — the foreground-TUI wire (ADR-0031).

The socket transport is the same DUMB line-delimited JSON-RPC duplex carrier as
:class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport` (ADR-0025), but
the byte-carrier is a 0600 owner-only unix socket between two already-running
peers (the daemon + the operator's foreground ``alfred chat``) rather than an
anonymous pipe to a daemon-spawned child. It carries no DLP, no secret
substitution, no T3 tagging — that work lives in ``process_inbound_message`` +
``ScannedOutboundBody`` upstream. Its only security duty is a frame-size bound +
loud failure on a broken/malformed wire, and a 0600 owner-only local socket.

These unit cases drive:

* the listener lifecycle (bind under ~/.run/alfred at 0600, unlink-stale-then-bind,
  accept one connection, reap on aclose — every exit path);
* the transport's ``_CommsTransportLike`` conformance (spawn no-op, send/read_frame
  over the accepted streams, idempotent close);
* loud failure on an over-bound / non-JSON / non-object frame.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from alfred.plugins.comms_runner import _CommsTransportLike
from alfred.plugins.comms_socket_transport import (
    CommsProtocolError,
    CommsSocketListener,
    CommsSocketTransport,
    default_comms_socket_path,
)

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "tui-test-0001"


@pytest.fixture
def runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the socket runtime dir at a SHORT tmp HOME so tests never touch ~/.run.

    A short prefix (``/tmp/...`` not the deep pytest ``tmp_path``) is load-bearing:
    AF_UNIX socket paths have a ~108-byte limit, and the pytest ``tmp_path`` on macOS
    is already long enough to overflow it. Production paths (``~/.run/alfred/...``)
    are short, so this is a fixture concern only.
    """
    with tempfile.TemporaryDirectory(prefix="alfsock-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


async def test_default_socket_path_is_adapter_keyed_under_runtime_dir(runtime_dir: Path) -> None:
    path = default_comms_socket_path(_ADAPTER_ID)
    assert path == runtime_dir / f"comms-{_ADAPTER_ID}.sock"


@pytest.mark.parametrize(
    "bad_id",
    [
        "",  # empty
        "..",  # traversal
        "../escape",  # traversal with separator
        "a/b",  # path separator
        "/etc",  # absolute escape
        "tui.sock",  # dot (could compose a traversal segment)
        "TUI",  # uppercase (outside the lowercase charset)
        "tui id",  # whitespace
    ],
)
async def test_default_socket_path_rejects_unsafe_adapter_id(
    runtime_dir: Path, bad_id: str
) -> None:
    """An ``adapter_id`` that could escape ``~/.run/alfred`` is refused loudly.

    The id is interpolated into the socket FILENAME, so a ``/`` / ``..`` / empty / and
    any out-of-charset value must raise rather than silently yielding a path outside
    the 0700 runtime dir (defence-in-depth — host-controlled today, future-proofed).
    """
    del runtime_dir
    with pytest.raises(ValueError, match="adapter_id must match"):
        default_comms_socket_path(bad_id)


async def test_transport_satisfies_comms_transport_like() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport: _CommsTransportLike = CommsSocketTransport(
        adapter_id=_ADAPTER_ID,
        reader=reader,
        writer=writer,  # type: ignore[arg-type]
    )
    # A real structural check: all four awaitables the runner's
    # ``_CommsTransportLike`` seam drives must exist AND be coroutine functions.
    assert inspect.iscoroutinefunction(transport.spawn)
    assert inspect.iscoroutinefunction(transport.send)
    assert inspect.iscoroutinefunction(transport.read_frame)
    assert inspect.iscoroutinefunction(transport.close)


async def test_spawn_is_a_noop() -> None:
    """The accepted connection IS the wire — spawn() establishes nothing."""
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    # No subprocess, no connect — just an inert success.
    await transport.spawn()
    assert writer.buffer == b""


async def test_send_writes_one_line_delimited_json_frame() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    await transport.send({"jsonrpc": "2.0", "method": "lifecycle.start"})
    assert writer.buffer == b'{"jsonrpc": "2.0", "method": "lifecycle.start"}\n'
    assert writer.drained >= 1


async def test_read_frame_decodes_one_object() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_data(b'{"id": 1, "result": {"ok": true}}\n')
    frame = await transport.read_frame()
    assert frame == {"id": 1, "result": {"ok": True}}


async def test_read_frame_returns_none_on_clean_eof() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_eof()
    assert await transport.read_frame() is None


async def test_read_frame_raises_on_non_json() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_data(b"not json at all\n")
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_read_frame_raises_on_non_object_top_level() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_data(b"[1, 2, 3]\n")
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_read_frame_raises_on_over_bound_line() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(
        adapter_id=_ADAPTER_ID,
        reader=reader,
        writer=writer,  # type: ignore[arg-type]
        max_line_bytes=16,
    )
    reader.feed_data(b'{"x": "' + b"a" * 64 + b'"}\n')
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_send_loud_on_broken_pipe() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter(broken=True)
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    with pytest.raises((BrokenPipeError, ConnectionResetError)):
        await transport.send({"method": "outbound.message"})


async def test_close_is_idempotent() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    await transport.close()
    await transport.close()
    assert writer.closed is True


# ---------------------------------------------------------------------------
# Listener lifecycle — real unix socket under a tmp HOME.
# ---------------------------------------------------------------------------


async def test_listener_binds_socket_0600_owner_only(runtime_dir: Path) -> None:
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    try:
        await listener.bind()
        sock_path = default_comms_socket_path(_ADAPTER_ID)
        assert sock_path.exists()
        st = sock_path.stat()
        assert stat.S_ISSOCK(st.st_mode)
        assert st.st_mode & 0o777 == 0o600
        assert st.st_uid == os.getuid()
        # Parent runtime dir is 0700.
        assert runtime_dir.stat().st_mode & 0o777 == 0o700
    finally:
        await listener.aclose()


async def test_listener_tightens_preexisting_loose_runtime_dir_to_0700(
    runtime_dir: Path,
) -> None:
    """A pre-existing too-open runtime dir is corrected to 0700 before bind.

    ``mkdir(mode=...)`` applies only at CREATION, so a runtime dir left at 0755 by a
    prior looser-umask boot would otherwise host the 0600 socket under a too-open
    parent. ``bind()`` chmods the dir to 0700 unconditionally (fail-closed).
    """
    runtime_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    runtime_dir.chmod(0o755)  # defeat the umask masking of the mkdir mode
    assert runtime_dir.stat().st_mode & 0o777 == 0o755
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    try:
        await listener.bind()
        # The dir is tightened to 0700, and the socket itself is 0600.
        assert runtime_dir.stat().st_mode & 0o777 == 0o700
        sock_path = default_comms_socket_path(_ADAPTER_ID)
        assert sock_path.stat().st_mode & 0o777 == 0o600
    finally:
        await listener.aclose()


async def test_listener_unlinks_stale_socket_before_bind(runtime_dir: Path) -> None:
    """A crashed prior boot leaves a socket inode; bind unlinks-then-binds."""
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    # Plant a stale regular file at the socket path (simulates leftover inode).
    sock_path.write_bytes(b"stale")
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    try:
        await listener.bind()
        st = sock_path.stat()
        assert stat.S_ISSOCK(st.st_mode)
    finally:
        await listener.aclose()


async def test_listener_accept_yields_a_working_transport(runtime_dir: Path) -> None:
    """Accept one connection; the returned transport carries a full round-trip."""
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        # A peer dials in and speaks the line-delimited wire.
        client_reader, client_writer = await asyncio.open_unix_connection(str(sock_path))
        transport = await accept_task

        # peer -> host inbound frame reaches read_frame.
        client_writer.write(b'{"method": "inbound.message"}\n')
        await client_writer.drain()
        frame = await transport.read_frame()
        assert frame == {"method": "inbound.message"}

        # host -> peer send reaches the peer.
        await transport.send({"id": 1, "result": {"ok": True}})
        line = await client_reader.readline()
        assert json.loads(line) == {"id": 1, "result": {"ok": True}}

        client_writer.close()
        await transport.close()
    finally:
        await listener.aclose()


async def test_listener_bounds_accepted_reader_to_max_line_bytes(runtime_dir: Path) -> None:
    """The listener's ``max_line_bytes`` actually bounds the ACCEPTED reader.

    A directly-constructed transport's bound is already covered; this drives the bound
    through the real ``start_unix_server(limit=...)`` path so a regression that drops
    the ``limit=`` kwarg (leaving the accepted reader unbounded) would FAIL here. Binds
    a listener with a tiny ``_max_line_bytes``, dials a real client, sends an over-bound
    line, and asserts the accepted transport's ``read_frame`` raises ``CommsProtocolError``.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID, max_line_bytes=16)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        _client_reader, client_writer = await asyncio.open_unix_connection(str(sock_path))
        transport = await accept_task

        # An over-bound line (no newline within the 16-byte reader limit) must trip
        # the accepted reader's limit, surfaced as CommsProtocolError.
        client_writer.write(b'{"x": "' + b"a" * 64 + b'"}\n')
        await client_writer.drain()
        with pytest.raises(CommsProtocolError):
            await asyncio.wait_for(transport.read_frame(), timeout=2.0)

        client_writer.close()
        await transport.close()
    finally:
        await listener.aclose()


async def test_listener_aclose_reaps_socket_file(runtime_dir: Path) -> None:
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    assert sock_path.exists()
    await listener.aclose()
    assert not sock_path.exists()
    # aclose is idempotent — a double close on a teardown path is safe.
    await listener.aclose()


async def test_read_frame_raises_on_reader_limit_overrun() -> None:
    """A StreamReader limit overrun surfaces as CommsProtocolError, not ValueError."""
    reader = asyncio.StreamReader(limit=8)
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    # No newline within the limit -> readline() raises LimitOverrunError.
    reader.feed_data(b"a" * 64)
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_close_skips_close_when_writer_already_closing() -> None:
    """An already-closing writer is not re-closed (idempotent-friendly branch)."""
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    writer.closed = True  # is_closing() -> True
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    await transport.close()
    # close() was NOT called again (it was already closing); wait_closed still ran.
    assert writer.close_calls == 0


async def test_listener_bind_twice_raises(runtime_dir: Path) -> None:
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        with pytest.raises(RuntimeError, match="called twice"):
            await listener.bind()
    finally:
        await listener.aclose()


async def test_listener_path_property(runtime_dir: Path) -> None:
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    assert listener.path == default_comms_socket_path(_ADAPTER_ID)


async def test_listener_refuses_anomalous_path_type(runtime_dir: Path) -> None:
    """A FIFO (not socket/regular) at the runtime path is refused, never unlinked."""
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    os.mkfifo(sock_path)
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    try:
        with pytest.raises(RuntimeError, match="not a socket or regular file"):
            await listener.bind()
        # The FIFO was NOT removed — the listener refuses to touch a path it does
        # not recognise as its own.
        assert sock_path.exists()
    finally:
        sock_path.unlink(missing_ok=True)


async def test_listener_bind_failure_cleans_up(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure mid-bind closes the socket + unlinks the partial inode, then re-raises.

    Drives the post-``bind()`` failure arm by making the ``chmod`` step (which runs
    AFTER the socket is bound + the inode exists) raise: the ``except`` arm must close
    the socket, unlink the just-created socket file, and re-raise — leaving no leaked
    inode behind.
    """
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    sock_path = default_comms_socket_path(_ADAPTER_ID)

    real_chmod = Path.chmod

    def _boom_chmod(self: Path, mode: int, *a: object, **k: object) -> None:
        if self == sock_path:
            raise OSError("chmod boom (test)")
        real_chmod(self, mode, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "chmod", _boom_chmod)
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    with pytest.raises(OSError, match="chmod boom"):
        await listener.bind()
    # The except arm unlinked the partially-bound socket inode — no leak.
    assert not sock_path.exists()


async def test_listener_accept_before_bind_raises(runtime_dir: Path) -> None:
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    with pytest.raises(RuntimeError, match="called before bind"):
        await listener.accept()


async def test_listener_second_connection_is_closed(runtime_dir: Path) -> None:
    """The single-connection cut closes a second dial-in rather than racing the first.

    The first transport stays fully usable (a host -> peer send round-trips) AFTER the
    second peer has dialled in and been closed — proving the second connection did not
    displace or race the first.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        first_r, first_w = await asyncio.open_unix_connection(str(sock_path))
        transport = await accept_task

        # A second peer dials in; the server's _on_connect closes it immediately
        # (its accept future is already done). Bounded so a regression that DOESN'T
        # close it surfaces as a timeout, not a hang.
        second_r, second_w = await asyncio.open_unix_connection(str(sock_path))
        assert await asyncio.wait_for(second_r.read(), timeout=2.0) == b""
        second_w.close()

        # The FIRST connection is unaffected — a host send still reaches it.
        await transport.send({"id": 1, "result": {"ok": True}})
        line = await asyncio.wait_for(first_r.readline(), timeout=2.0)
        assert json.loads(line) == {"id": 1, "result": {"ok": True}}

        first_w.close()
        await transport.close()
    finally:
        await listener.aclose()


async def test_listener_second_accept_call_raises(runtime_dir: Path) -> None:
    """A SECOND ``accept()`` *call* raises — one-shot lifecycle (ADR-0031 Decision 4).

    Distinct from ``test_listener_second_connection_is_closed`` (a second *socket*
    dial-in, closed by ``_on_connect``): this proves a second invocation of the
    ``accept()`` method itself is refused loudly rather than re-arming the future and
    accepting another client.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client_r, client_w = await asyncio.open_unix_connection(str(sock_path))
        transport = await accept_task

        # The second call is a programming error — refused before re-arming.
        with pytest.raises(RuntimeError, match="called twice"):
            await listener.accept()

        client_w.close()
        await transport.close()
        del client_r
    finally:
        await listener.aclose()


class _FakeWriter:
    """Records everything written; configurable broken-pipe + EOF/close tracking."""

    def __init__(self, *, broken: bool = False) -> None:
        self.buffer = bytearray()
        self.drained = 0
        self.closed = False
        self.close_calls = 0
        self._broken = broken

    def write(self, data: bytes) -> None:
        if self._broken:
            raise BrokenPipeError("socket closed")
        self.buffer.extend(data)

    async def drain(self) -> None:
        if self._broken:
            raise ConnectionResetError("socket reset")
        self.drained += 1

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    async def wait_closed(self) -> None:
        return None
