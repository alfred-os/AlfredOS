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
import socket
import stat
import struct
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
    dial_comms_socket,
)
from alfred.plugins.comms_stdio_transport import _MAX_COMMS_LINE_BYTES

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


async def test_listener_rejects_mismatched_uid_peer_then_serves_same_uid(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mismatched-uid peer is refused without wedging a legitimate same-uid dial-in.

    Drives the ``_on_connect`` peer-auth REJECT arm (log + ``writer.close`` + no
    future resolution) in the unit tier so the per-file 100%-branch gate — which
    reports against the unit-only ``.coverage`` data — covers it. ``_resolve_peer_uid``
    is monkeypatched to report a FOREIGN uid for the first connection and OUR uid for
    the second; the accept must resolve to the SECOND transport.
    """
    import alfred.plugins.comms_socket_transport as cst

    uids = iter([os.getuid() + 7777, os.getuid()])
    monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: next(uids))
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        # Impostor: refused; the accept future stays pending (no ack-and-drop).
        imp_r, imp_w = await asyncio.open_unix_connection(str(sock_path))
        await asyncio.sleep(0.1)
        assert not accept_task.done()
        # Legitimate same-uid peer: the accept resolves.
        leg_r, leg_w = await asyncio.open_unix_connection(str(sock_path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        for w in (imp_w, leg_w):
            w.close()
        del imp_r, leg_r
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


# ---------------------------------------------------------------------------
# Client dialer — ``dial_comms_socket`` (PR-S4-237-2, ADR-0031 amendment).
#
# The connect-analog of ``CommsSocketListener.accept``: the foreground
# ``alfred chat`` dials the daemon's already-bound socket and gets the SAME
# carrier-symmetric ``CommsSocketTransport``. These cases prove the dial round-trips
# both directions over a real in-process unix socket, and that establishment
# failure (no listener) and the over-bound DoS guard surface LOUD.
# ---------------------------------------------------------------------------


async def test_dial_round_trips_both_directions_against_a_real_listener(
    runtime_dir: Path,
) -> None:
    """Bind a listener, dial it, and assert frames round-trip both ways.

    The peer-end transport returned by ``dial_comms_socket`` must be a working
    duplex: a ``read_frame`` reads what the host ``send``s, and a ``send`` reaches
    the host's ``read_frame``. The host (accept) end and the client (dial) end run
    on the same loop over a real ``AF_UNIX`` socket.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client = await dial_comms_socket(_ADAPTER_ID)
        host = await accept_task

        # host -> client.
        await host.send({"jsonrpc": "2.0", "method": "lifecycle.start", "id": 1})
        assert await client.read_frame() == {
            "jsonrpc": "2.0",
            "method": "lifecycle.start",
            "id": 1,
        }

        # client -> host (the ``inbound.message`` direction).
        await client.send({"jsonrpc": "2.0", "method": "inbound.message"})
        assert await host.read_frame() == {"jsonrpc": "2.0", "method": "inbound.message"}

        await client.close()
        await host.close()
    finally:
        await listener.aclose()


async def test_dial_with_no_listener_raises_loud(runtime_dir: Path) -> None:
    """Dialing a path with no bound listener surfaces the connect error LOUD.

    A daemon-absent / socket-missing dial must NOT be swallowed — the
    ``ConnectionRefusedError`` / ``FileNotFoundError`` from
    ``open_unix_connection`` propagates so ``_chat_main`` can map it to the
    daemon-required operator message (CLAUDE.md hard rule #7).
    """
    # The runtime dir does not exist yet (no listener bound), so the socket file
    # is absent -> FileNotFoundError; a present-but-unbound path would refuse.
    with pytest.raises((ConnectionRefusedError, FileNotFoundError, OSError)):
        await dial_comms_socket(_ADAPTER_ID)


async def test_dial_bounds_the_reader_to_max_line_bytes(runtime_dir: Path) -> None:
    """An over-bound line from the host trips the DIALED reader's limit.

    Proves the ``limit=_MAX_COMMS_LINE_BYTES`` is wired on the client reader (the
    same frame-DoS bound the accept side pins): the listener sends a line longer
    than the bound and the dialed transport's ``read_frame`` raises
    ``CommsProtocolError`` rather than buffering unboundedly.
    """
    # Bind a listener whose accepted writer can emit an over-bound line; the dialer
    # uses the production _MAX_COMMS_LINE_BYTES bound, so we must overflow THAT.
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client = await dial_comms_socket(_ADAPTER_ID)
        host = await accept_task

        # One JSON frame whose single line is longer than the client's
        # _MAX_COMMS_LINE_BYTES bound -> the dialed reader's limit trips when the
        # client reads it. ``host.send`` emits exactly one ``json.dumps(frame)+"\n"``
        # line, so an over-long string value overflows the bound.
        await host.send({"x": "a" * (_MAX_COMMS_LINE_BYTES + 64)})
        with pytest.raises(CommsProtocolError):
            await asyncio.wait_for(client.read_frame(), timeout=2.0)

        await client.close()
        await host.close()
    finally:
        await listener.aclose()


# ---------------------------------------------------------------------------
# Peer-auth predicate (Spec A G3-1 / ADR-0032): cross-platform same-uid check.
# ---------------------------------------------------------------------------


def test_peer_uid_same_uid_accepted() -> None:
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    # SO_PEERCRED reports our own uid -> authorized.
    assert _peer_uid_authorized(reported_uid=os.getuid()) is True


def test_peer_uid_different_uid_rejected() -> None:
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    assert _peer_uid_authorized(reported_uid=os.getuid() + 1) is False


def test_peer_uid_unknown_accepted_on_fs_perms() -> None:
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    # A platform without SO_PEERCRED reports None -> the 0600/0700 FS perms are the
    # enforcement-of-record; the check degrades to accept rather than fail-closing
    # the mac dev loop.
    assert _peer_uid_authorized(reported_uid=None) is True


def test_resolve_peer_uid_none_socket_is_none() -> None:
    """A ``None`` socket (no per-connection socket available) resolves to ``None``.

    Drives the ``sock is None`` short-circuit branch of ``_resolve_peer_uid`` so the
    accept callback degrades to the FS-perms guarantee instead of raising — keeps the
    per-file 100%-branch gate green on the no-creds path.
    """
    from alfred.plugins.comms_socket_transport import _resolve_peer_uid

    assert _resolve_peer_uid(None) is None


class _FakeSock:
    """Minimal ``socket``-shaped stub whose ``getsockopt`` is scripted per test.

    ``_resolve_peer_uid`` only calls ``getsockopt(level, optname, buflen)``, so a
    stub that returns canned bytes (or raises) drives every kernel-creds branch
    deterministically — no real ``SO_PEERCRED`` peer needed, so the short-read /
    ``OSError`` arms are covered on every platform (the per-file 100%-branch gate
    runs on Linux CI but the real getsockopt cannot synthesise a short read).
    """

    def __init__(
        self, *, returns: bytes | None = None, raises: BaseException | None = None
    ) -> None:
        self._returns = returns
        self._raises = raises

    def getsockopt(self, _level: int, _optname: int, _buflen: int) -> bytes:
        if self._raises is not None:
            raise self._raises
        assert self._returns is not None
        return self._returns


def test_resolve_peer_uid_no_so_peercred_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """A platform without ``SO_PEERCRED`` (macOS) resolves to ``None`` (FS-perms).

    Deletes the constant so the ``not hasattr(socket, "SO_PEERCRED")`` arm is hit
    deterministically even on Linux CI, where the attribute is otherwise present.
    """
    from alfred.plugins.comms_socket_transport import _resolve_peer_uid

    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    assert _resolve_peer_uid(_FakeSock(returns=b"")) is None  # type: ignore[arg-type]


def test_resolve_peer_uid_short_read_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """A short ``getsockopt`` read (fewer bytes than the ucred width) resolves None.

    Ensures ``SO_PEERCRED`` is present (so the body runs even on macOS) then feeds a
    truncated buffer; the ``len(creds) != width`` guard returns ``None`` rather than
    letting ``struct.unpack`` raise.
    """
    from alfred.plugins.comms_socket_transport import _UCRED_STRUCT, _resolve_peer_uid

    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    short = b"\x00" * (struct.calcsize(_UCRED_STRUCT) - 1)
    assert _resolve_peer_uid(_FakeSock(returns=short)) is None  # type: ignore[arg-type]


def test_resolve_peer_uid_getsockopt_oserror_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """A closed / non-AF_UNIX socket (``getsockopt`` raises ``OSError``) resolves None.

    Drives the ``except (OSError, struct.error)`` arm so a getsockopt failure degrades
    to the FS-perms guarantee instead of crashing the accept callback.
    """
    from alfred.plugins.comms_socket_transport import _resolve_peer_uid

    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    sock = _FakeSock(raises=OSError("socket closed"))
    assert _resolve_peer_uid(sock) is None  # type: ignore[arg-type]


def test_resolve_peer_uid_returns_uid_on_full_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """A full ``struct ucred`` read returns the unpacked (unsigned) uid.

    Drives the happy path + the ``int(uid)`` coercion with a synthesised kernel-creds
    buffer, so the success arm is covered without a real same-uid peer.
    """
    from alfred.plugins.comms_socket_transport import _UCRED_STRUCT, _resolve_peer_uid

    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    creds = struct.pack(_UCRED_STRUCT, 4321, 1000, 1000)
    assert _resolve_peer_uid(_FakeSock(returns=creds)) == 1000  # type: ignore[arg-type]


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


# ---------------------------------------------------------------------------
# Spec A G3-2 (#237) C2: single-writer lock — the boot lifecycle-send is now a
# SECOND writer racing the pump's send_request, so two concurrent ``send`` calls
# must produce two WHOLE, non-interleaved seq frames (never a torn write).
# ---------------------------------------------------------------------------


class _YieldingFakeWriter:
    """Records per-send critical-section entry/exit ordering; ``drain`` yields.

    ``drain`` yields control (``asyncio.sleep(0)``) so a concurrent ``send`` gets a
    chance to run mid-critical-section. The C2 lock spans ``encode -> write -> drain
    -> seq-increment``, so a second ``send`` must NOT begin writing while the first
    is suspended at ``drain``. ``events`` records ``"write"`` / ``"drain_exit"`` so
    the test can assert the two sends did NOT interleave.
    """

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.drained = 0
        self.events: list[str] = []

    def write(self, data: bytes) -> None:
        self.events.append("write")
        self.buffer.extend(data)

    async def drain(self) -> None:
        self.drained += 1
        # Yield control mid-send so a concurrent send would interleave absent a lock.
        await asyncio.sleep(0)
        self.events.append("drain_exit")

    def is_closing(self) -> bool:
        return False

    async def wait_closed(self) -> None:
        return None


async def test_concurrent_sends_do_not_interleave() -> None:
    """Two gathered sends each run write->drain atomically — never interleaved.

    Without the C2 lock the gather schedules write_A, drain_A(yield), write_B,
    drain_B(yield), drain_exit_A, drain_exit_B — write_B lands BEFORE drain_exit_A,
    so the critical sections overlap (event order ``write, write, drain_exit,
    drain_exit``). With the lock the order is ``write, drain_exit, write,
    drain_exit`` (each send completes before the next begins), and the seqs are the
    contiguous 0, 1 with both payloads intact (no torn frame).
    """
    from alfred.plugins.comms_seq_codec import decode_seq_frame

    reader = asyncio.StreamReader()
    writer = _YieldingFakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    transport.enable_seq_ack()

    await asyncio.gather(
        transport.send({"jsonrpc": "2.0", "method": "a"}),
        transport.send({"jsonrpc": "2.0", "method": "b"}),
    )

    # The lock serialises the critical sections: each ``write`` is immediately
    # followed by its own ``drain_exit`` before the next ``write`` begins.
    assert writer.events == ["write", "drain_exit", "write", "drain_exit"]

    # Each written unit decodes cleanly with contiguous seqs (0, 1) and intact bodies.
    units = [line + b"\n" for line in bytes(writer.buffer).split(b"\n") if line]
    decoded = [decode_seq_frame(u) for u in units]
    assert sorted(f.seq for f in decoded if f.seq is not None) == [0, 1]
    assert {json.loads(f.payload)["method"] for f in decoded} == {"a", "b"}
