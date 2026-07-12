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
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from alfred.plugins.comms_runner import _CommsTransportLike
from alfred.plugins.comms_seq_codec import SeqFrame, decode_seq_frame
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: test fixture patches $HOME via monkeypatch.setenv, which "
    "Windows' Path.home()/expanduser ignores in favor of %USERPROFILE% — the "
    "resolved default_comms_socket_path() diverges from the fixture's runtime_dir "
    "(#246 review)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: file mode/permissions (chmod bits do not carry the same "
    "meaning under Windows ACLs) (#246 review)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.mkfifo",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
async def test_listener_fires_on_peer_rejected_callback_with_uid(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec A G3-2 (#237): a rejected peer fires ``on_peer_rejected`` with its uid.

    The daemon supplies this callback to write the ``comms.socket.peer_uid_rejected``
    audit row at the reject point. It must receive the REJECTED peer's uid (a counter
    would lose it — security M-3) and fire BEFORE the impostor's writer is closed,
    while a legitimate same-uid dial-in still serves (boot is not refused).
    """
    import alfred.plugins.comms_socket_transport as cst

    uids = iter([os.getuid() + 7777, os.getuid()])
    monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: next(uids))

    rejected: list[int | None] = []
    # Deterministic callback-gated wait (CR #264): the reject fires
    # ``_on_rejected`` asynchronously, so signal an Event from it and await that
    # instead of a fixed ``asyncio.sleep`` that can flake under slow scheduling.
    rejected_fired = asyncio.Event()

    async def _on_rejected(peer_uid: int | None) -> None:
        rejected.append(peer_uid)
        rejected_fired.set()

    listener = CommsSocketListener(adapter_id=_ADAPTER_ID, on_peer_rejected=_on_rejected)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        imp_r, imp_w = await asyncio.open_unix_connection(str(sock_path))
        await asyncio.wait_for(rejected_fired.wait(), timeout=2.0)
        assert not accept_task.done()
        # The callback fired with the impostor's foreign uid.
        assert rejected == [os.getuid() + 7777]
        # A legitimate same-uid peer still serves — the reject did not wedge the boot.
        leg_r, leg_w = await asyncio.open_unix_connection(str(sock_path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        # The legitimate accept did NOT fire the reject callback again.
        assert rejected == [os.getuid() + 7777]
        for w in (imp_w, leg_w):
            w.close()
        del imp_r, leg_r
        await transport.close()
    finally:
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_reject_callback_audit_failure_escalates_to_accept(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec A G3-2 (#237): a FAILED audit-write of a peer reject fails LOUD.

    The reject ITSELF is benign (keep waiting), but a broken audit write on a
    security-boundary reject is hard-rule-#7 territory and must NOT be orphaned in
    the detached ``start_unix_server`` callback. ``_on_connect`` escalates the
    callback's exception onto the supervised ``accept()`` future, so the awaiter
    raises it (an audited supervisor crash, not a silent asyncio swallow).
    Corroborated finding from the PR #264 fleet (core/comms/security/error).
    """
    import alfred.plugins.comms_socket_transport as cst

    monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: os.getuid() + 7777)

    class _AuditUnwritableError(Exception):
        pass

    async def _failing_reject(_peer_uid: int | None) -> None:
        raise _AuditUnwritableError("audit log unwritable")

    listener = CommsSocketListener(adapter_id=_ADAPTER_ID, on_peer_rejected=_failing_reject)
    await listener.bind()
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        imp_r, imp_w = await asyncio.open_unix_connection(str(sock_path))
        with pytest.raises(_AuditUnwritableError):
            await asyncio.wait_for(accept_task, timeout=2.0)
        imp_w.close()
        del imp_r
    finally:
        await listener.aclose()


def test_resolve_peer_uid_no_so_peercred_logs_breadcrumb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """devex-263-002: the no-``SO_PEERCRED`` degrade leaves a structlog breadcrumb.

    On a macOS dev host the peer-uid check is SKIPPED (platform), not
    attempted-and-failed; the breadcrumb lets a trace tell those apart.
    """
    import alfred.plugins.comms_socket_transport as cst

    events: list[tuple[str, dict[str, object]]] = []

    class _RecLog:
        def debug(self, event: str, **kw: object) -> None:
            events.append((event, kw))

        def warning(self, event: str, **kw: object) -> None: ...

    monkeypatch.setattr(cst, "log", _RecLog())
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    assert cst._resolve_peer_uid(_FakeSock(returns=b"")) is None  # type: ignore[arg-type]
    assert any(e == "comms.socket.peer_cred_unsupported" for e, _ in events)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
def test_peer_uid_same_uid_accepted() -> None:
    from alfred.plugins.comms_socket_transport import _peer_uid_authorized

    # SO_PEERCRED reports our own uid -> authorized.
    assert _peer_uid_authorized(reported_uid=os.getuid()) is True


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
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


# ---------------------------------------------------------------------------
# Dial-side peer-auth (Spec A G3-3b / ADR-0031): the "both-direction SO_PEERCRED"
# the G3-1 accept side already has, now hardened on the DIAL side. The gateway
# dials the core socket and must verify (a) the dialed inode is a socket it owns
# (the pre-dial lstat backstop — the only owner enforcement on a no-SO_PEERCRED
# host where the post-connect check returns None->authorized), and (b) the
# connected peer's SO_PEERCRED uid is ours (Linux-enforcing).
# ---------------------------------------------------------------------------


def _has_peer(sock: socket.socket) -> bool:
    """True if ``sock`` is a CONNECTED socket (``getpeername`` succeeds).

    A connected ``AF_UNIX`` peer socket answers ``getpeername``; a bound-but-
    unconnected listener socket raises ``OSError`` (ENOTCONN). Used to assert the
    dial-side peer-auth read creds off the CONNECTED socket, not the listener. Accepts
    the duck-typed ``asyncio.trsock.TransportSocket`` that ``get_extra_info("socket")``
    returns (it exposes ``getpeername`` too).
    """
    try:
        sock.getpeername()
    except OSError:
        return False
    return True


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_dial_peer_auth_succeeds_same_uid_loopback(runtime_dir: Path) -> None:
    """A same-uid loopback dial passes both the pre-dial lstat + post-connect check.

    The listener is bound by the current uid, so the dialed inode is an owned socket
    (pre-dial lstat passes) and the connected peer's SO_PEERCRED uid is ours (or
    ``None`` on a no-SO_PEERCRED host — both authorized). The dial SUCCEEDS.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client = await dial_comms_socket(_ADAPTER_ID)
        host = await accept_task
        await client.close()
        await host.close()
    finally:
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_dial_peer_auth_rejects_mismatched_uid_and_closes_writer(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-connect SO_PEERCRED mismatch raises ``CommsPeerAuthError`` + reaps the FD.

    ``_resolve_peer_uid`` is monkeypatched to report a FOREIGN uid for the connected
    socket, so the post-connect check refuses the dial. The error is a
    ``CommsProtocolError`` subclass (the runner's malformed-wire arm handles it), and
    the dialed writer is closed — no FD leak.
    """
    import alfred.plugins.comms_socket_transport as cst

    # Capture the dialed writer so the test can assert it was closed on the reject
    # path (no FD leak). The monkeypatched ``_resolve_peer_uid`` reports a foreign uid
    # for EVERY connected socket, so the listener's accept arm refuses the peer too
    # and never resolves — the dangling accept is cancelled in the finally.
    dialed_writers: list[asyncio.StreamWriter] = []
    real_open = asyncio.open_unix_connection

    async def _capturing_open(
        *a: object, **k: object
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await real_open(*a, **k)  # type: ignore[arg-type]
        dialed_writers.append(writer)
        return reader, writer

    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    accept_task = asyncio.ensure_future(listener.accept())
    try:
        monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: os.getuid() + 1)
        monkeypatch.setattr(cst.asyncio, "open_unix_connection", _capturing_open)
        with pytest.raises(cst.CommsPeerAuthError) as exc_info:
            await dial_comms_socket(_ADAPTER_ID)
        # A CommsPeerAuthError is a CommsProtocolError so the runner's existing
        # malformed-wire arm routes it uniformly.
        assert isinstance(exc_info.value, CommsProtocolError)
        # No FD leak: the dialed writer was closed on the reject path BEFORE raising.
        assert len(dialed_writers) == 1
        assert dialed_writers[0].is_closing()
    finally:
        accept_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await accept_task
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_dial_peer_auth_reads_creds_off_connected_socket_not_listener(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-2b: the dial-side ``_resolve_peer_uid`` is called on the CONNECTED socket.

    Reading creds off the wrong socket (e.g. re-resolving the listener) returns our
    OWN uid and always passes, defeating the check. A spy captures the socket passed
    to ``_resolve_peer_uid`` and asserts it is exactly ``writer.get_extra_info("socket")``
    of the dialed connection — a real connected ``AF_UNIX`` socket, and that a real
    same-uid loopback resolves to ``os.getuid()``.
    """
    import alfred.plugins.comms_socket_transport as cst

    # Record the socket the DIAL side passes to ``_resolve_peer_uid``. The spy returns
    # our own uid unconditionally so the dial is authorized (the check is satisfied);
    # we only care WHICH socket the resolve saw. Capturing the FIRST call is the dial
    # side — ``dial_comms_socket`` resolves the peer immediately after connecting,
    # before the listener's detached accept callback gets a turn.
    dial_sockets: list[socket.socket | None] = []

    def _spy(sock: socket.socket | None) -> int | None:
        dial_sockets.append(sock)
        return os.getuid()

    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    accept_task = asyncio.ensure_future(listener.accept())
    try:
        monkeypatch.setattr(cst, "_resolve_peer_uid", _spy)
        client = await dial_comms_socket(_ADAPTER_ID)
        # The dial resolved exactly once at connect time; the first capture is the
        # dial-side socket.
        assert dial_sockets, "dial-side _resolve_peer_uid was never called"
        dial_sock = dial_sockets[0]
        # It must be the socket of the dialed CONNECTED connection
        # (``writer.get_extra_info("socket")`` — an ``asyncio.trsock.TransportSocket``
        # wrapping the connected fd), NOT the listener's bound socket. Reading creds
        # off the listener returns our own uid and silently defeats the check, so
        # prove the resolve saw a CONNECTED peer socket: it is ``AF_UNIX`` and answers
        # ``getpeername`` with the dialed path (the listener's bound-only socket does
        # not). It is duck-typed (a ``TransportSocket``, not a bare ``socket.socket``),
        # so assert the socket-shaped attributes rather than the concrete class.
        assert dial_sock is not None
        assert dial_sock.family == socket.AF_UNIX
        assert _has_peer(dial_sock), (
            "dial-side _resolve_peer_uid was not called on the CONNECTED socket "
            "(it must read the PEER's creds off the dialed connection, not the listener)"
        )
        # The connected peer is the listener's bound socket path (proving the dialed
        # connection, not some other socket).
        assert str(dial_sock.getpeername()) == str(listener.path)
        await client.close()
    finally:
        accept_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await accept_task
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_dial_peer_auth_pre_dial_lstat_refuses_non_socket(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC-2: a non-socket inode at the dial path raises BEFORE ``open_unix_connection``.

    On a no-SO_PEERCRED host the post-connect check returns ``None``->authorized, so
    the pre-dial lstat is the ONLY owner enforcement. A regular file at the resolved
    path must raise ``CommsPeerAuthError`` and never attempt to connect.
    """
    import alfred.plugins.comms_socket_transport as cst

    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    sock_path = default_comms_socket_path(_ADAPTER_ID)
    sock_path.write_bytes(b"not a socket")

    connect_called = False

    async def _spy_connect(*a: object, **k: object) -> tuple[object, object]:
        nonlocal connect_called
        connect_called = True
        raise AssertionError("open_unix_connection must not be reached")

    monkeypatch.setattr(cst.asyncio, "open_unix_connection", _spy_connect)
    with pytest.raises(cst.CommsPeerAuthError):
        await dial_comms_socket(_ADAPTER_ID)
    assert connect_called is False


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
def test_dial_path_owned_helper_rejects_foreign_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """SEC-2: the FS-guard helper refuses a socket owned by a DIFFERENT uid.

    A non-root unit cannot chown a socket to another uid, so monkeypatch ``Path.lstat``
    to report a socket inode with a foreign ``st_uid``. The helper must raise
    ``CommsPeerAuthError`` — the wider-perm / stale-socket-race backstop.
    """
    import alfred.plugins.comms_socket_transport as cst

    # A synthetic label only — ``Path.lstat`` is monkeypatched below, so this path is
    # never touched on disk (it is the stat-source, not an FS access).
    path = Path("/nonexistent/alfred-test-foreign.sock")

    class _Stat:
        st_mode = stat.S_IFSOCK | 0o600
        st_uid = os.getuid() + 4242

    monkeypatch.setattr(Path, "lstat", lambda _self: _Stat())
    with pytest.raises(cst.CommsPeerAuthError):
        cst._assert_dial_path_owned(path)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_dial_path_owned_helper_accepts_owned_socket(runtime_dir: Path) -> None:
    """SEC-2: the FS-guard helper accepts a same-uid socket inode (no raise).

    Binds a real listener (an owned 0600 socket) and asserts the helper returns
    without raising — the happy-path owner branch.
    """
    import alfred.plugins.comms_socket_transport as cst

    async def _bound() -> Path:
        listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
        await listener.bind()
        return listener.path

    sock_path = asyncio.run(_bound())
    try:
        # No raise -> the owned-socket branch passes.
        cst._assert_dial_path_owned(sock_path)
    finally:
        sock_path.unlink(missing_ok=True)


def test_dial_path_owned_helper_passes_missing_path_through(
    runtime_dir: Path,
) -> None:
    """SEC-2: a MISSING dial path is NOT swallowed by the FS guard.

    The daemon-absent path is the loud operator-facing contract: lstat raises
    ``FileNotFoundError`` and the helper must let it surface (or let the subsequent
    ``open_unix_connection`` fire its own ``FileNotFoundError``) — never silently
    treat an absent socket as authorized.
    """
    import alfred.plugins.comms_socket_transport as cst

    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    missing = default_comms_socket_path(_ADAPTER_ID)
    with pytest.raises(FileNotFoundError):
        cst._assert_dial_path_owned(missing)


# ---------------------------------------------------------------------------
# Spec A G4b-2a-pre (#237) — read_frame folds the decoded wire seq into the
# returned frame under the reserved key so the host can bind it to ITS frame's
# params (F1: the seq travels WITH its frame, never via a shared slot).
# ---------------------------------------------------------------------------


async def test_read_frame_folds_wire_seq_when_seq_enabled() -> None:
    """A seq-enabled inbound unit surfaces its decoded seq under the reserved key."""
    from alfred.plugins.comms_seq_codec import WIRE_SEQ_FRAME_KEY, encode_seq_frame

    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    transport.enable_seq_ack()
    body = json.dumps({"jsonrpc": "2.0", "method": "inbound.message", "params": {}}).encode()
    reader.feed_data(encode_seq_frame(body, seq=5, ack=0, max_unit_bytes=_MAX_COMMS_LINE_BYTES))
    frame = await transport.read_frame()
    assert frame is not None
    assert frame[WIRE_SEQ_FRAME_KEY] == 5
    assert frame["method"] == "inbound.message"


async def test_read_frame_omits_wire_seq_when_seq_disabled() -> None:
    """A plain (seq-OFF / stdio) frame carries NO reserved seq key — byte-for-byte back-compat.

    The fold only runs on the seq-enabled leg, so a stdio adapter's frames stay the
    plain ADR-0025 object the rest of the host expects.
    """
    from alfred.plugins.comms_seq_codec import WIRE_SEQ_FRAME_KEY

    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_data(b'{"jsonrpc": "2.0", "method": "inbound.message", "params": {}}\n')
    frame = await transport.read_frame()
    assert frame is not None
    assert WIRE_SEQ_FRAME_KEY not in frame


async def test_read_frame_strips_smuggled_wire_seq_when_seq_disabled() -> None:
    """A stdio frame whose BODY smuggles a top-level ``_wire_seq`` has it STRIPPED.

    ADR-0032: ``wire_seq`` is carrier HEADER metadata, never payload-derived. Even on
    the seq-disabled leg (no host ack tracker observes it), the reserved key is popped
    so a peer can never inject host-authored sequence metadata — defence-in-depth.
    """
    from alfred.plugins.comms_seq_codec import WIRE_SEQ_FRAME_KEY

    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_data(
        b'{"jsonrpc": "2.0", "method": "inbound.message", "params": {}, "_wire_seq": 5}\n'
    )
    frame = await transport.read_frame()
    assert frame is not None
    assert WIRE_SEQ_FRAME_KEY not in frame  # the smuggled 5 was stripped


async def test_read_frame_clears_smuggled_wire_seq_on_unsequenced_unit() -> None:
    """A seq-enabled leg reading a plain mixed-wire unit CLEARS a smuggled ``_wire_seq`` to None.

    On the seq-enabled leg the host folds its own ``frame.seq`` (``None`` for a bare
    un-upgraded-peer line), overwriting any peer-supplied ``"_wire_seq"`` in the body
    so it can never reach the host ack tracker.
    """
    from alfred.plugins.comms_seq_codec import WIRE_SEQ_FRAME_KEY

    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    transport.enable_seq_ack()
    reader.feed_data(
        b'{"jsonrpc": "2.0", "method": "inbound.message", "params": {}, "_wire_seq": 5}\n'
    )
    frame = await transport.read_frame()
    assert frame is not None
    assert frame[WIRE_SEQ_FRAME_KEY] is None  # the smuggled 5 was cleared


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


# ---------------------------------------------------------------------------
# Spec A G3-3b-2 (#237) / ADR-0032: the opaque-payload seam.
#
# ``read_payload_unit`` / ``send_payload_unit`` are the RAW-byte seam the G3 relay
# uses to forward the opaque ADR-0025 inner payload between its two legs (the
# seq/ack-enabled core leg and the PLAIN TUI leg) WITHOUT ``json.loads``-ing it (T3
# stays in the core; the gateway is a T1 carrier — CLAUDE.md hard rule #5). The seam
# returns the raw ``SeqFrame`` (header seq/ack + opaque payload bytes) and lets the
# caller supply the ack (NOT the ``a=0`` placeholder ``send`` carries). It shares the
# read+bound+deframe discipline of ``read_frame`` via the ``_read_seq_frame`` helper,
# so a future bound-fix patches both paths.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_read_payload_unit_plain_leg_returns_unsequenced_frame(
    runtime_dir: Path,
) -> None:
    """seq DISABLED (production TUI leg): ``send_payload_unit`` writes a PLAIN line.

    With seq/ack OFF the seam is byte-for-byte the existing ADR-0025 plain frame: no
    header, just ``payload + "\\n"``. The peer's ``read_payload_unit`` returns an
    UN-sequenced ``SeqFrame(seq=None, ack=None, payload=...)`` — the opaque bytes
    verbatim. The supplied ``ack`` is IGNORED on the seq-off branch (no header).
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client = await dial_comms_socket(_ADAPTER_ID)
        host = await accept_task

        # Both legs seq-OFF (production client leg) — ``seq``/``ack`` ignored.
        await host.send_payload_unit(b'{"x":1}', seq=0, ack=0)
        unit = await client.read_payload_unit()
        assert unit == SeqFrame(seq=None, ack=None, payload=b'{"x":1}')

        await client.close()
        await host.close()
    finally:
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_send_read_payload_unit_seq_enabled_round_trips_non_json(
    runtime_dir: Path,
) -> None:
    """seq ENABLED (core leg): the seam carries seq + the SUPPLIED ack, byte-for-byte.

    With seq/ack ON both peers, ``send_payload_unit(payload, seq=0, ack=5)`` emits the
    out-of-band header carrying the sender's monotonic ``seq`` and the caller's ``ack``
    (NOT the ``a=0`` placeholder ``send`` uses). The peer's ``read_payload_unit``
    returns the raw ``SeqFrame`` with the opaque payload verbatim — a NON-JSON payload
    round-trips intact, proving the seam never ``json.loads`` the body.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client = await dial_comms_socket(_ADAPTER_ID)
        host = await accept_task
        host.enable_seq_ack()
        client.enable_seq_ack()

        # First send: the caller OWNS the seq (G4b-2-pre); ack is 5 (not a=0).
        await host.send_payload_unit(b'{"x":1}', seq=0, ack=5)
        unit = await client.read_payload_unit()
        assert unit == SeqFrame(seq=0, ack=5, payload=b'{"x":1}')

        # A NON-JSON payload round-trips byte-for-byte — the seam never parses it.
        await host.send_payload_unit(b"\x00not-json", seq=1, ack=9)
        unit2 = await client.read_payload_unit()
        assert unit2 == SeqFrame(seq=1, ack=9, payload=b"\x00not-json")

        await client.close()
        await host.close()
    finally:
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_read_payload_unit_seq_enabled_reads_plain_line_as_unsequenced(
    runtime_dir: Path,
) -> None:
    """MIXED-WIRE: a seq-ENABLED reader reads a PLAIN line as ``SeqFrame(seq=None, ...)``.

    ``decode_seq_frame`` is magic-gated, so a seq-enabled ``read_payload_unit`` reading
    a line WITHOUT the magic (written by a seq-disabled peer) falls back to the
    un-sequenced frame rather than raising — mirroring ``read_frame``'s mixed-wire
    safety. The host leg is seq-ON; the client leg stays seq-OFF and writes a plain line.
    """
    listener = CommsSocketListener(adapter_id=_ADAPTER_ID)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        client = await dial_comms_socket(_ADAPTER_ID)
        host = await accept_task
        # Only the HOST upgrades; the client stays plain (one-direction-only wire).
        host.enable_seq_ack()

        await client.send_payload_unit(b'{"x":1}', seq=0, ack=0)
        unit = await host.read_payload_unit()
        assert unit == SeqFrame(seq=None, ack=None, payload=b'{"x":1}')

        await client.close()
        await host.close()
    finally:
        await listener.aclose()


async def test_read_payload_unit_returns_none_on_clean_eof() -> None:
    """A clean EOF (peer closed) resolves ``read_payload_unit`` to ``None``.

    Mirrors ``read_frame``'s clean-EOF contract: the relay ends its pump loop when the
    peer closes, rather than seeing a spurious empty frame.
    """
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_eof()
    assert await transport.read_payload_unit() is None


async def test_read_payload_unit_raises_on_reader_limit_overrun() -> None:
    """THREE-point bound (a): a ``readline`` limit overrun raises ``CommsProtocolError``.

    The first bound check — the ``StreamReader`` limit tripping in ``readline`` — must
    surface as a protocol error from the seam too, not a raw ``ValueError``.
    """
    reader = asyncio.StreamReader(limit=8)
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    reader.feed_data(b"a" * 64)  # no newline within the limit -> LimitOverrunError
    with pytest.raises(CommsProtocolError):
        await transport.read_payload_unit()


async def test_read_payload_unit_raises_on_explicit_over_bound_line() -> None:
    """THREE-point bound (b): a line AT/over ``_max_line_bytes`` raises (belt-and-braces).

    A line that slips past ``readline`` but exceeds the explicit ``_max_line_bytes``
    belt-and-braces check must still raise — the seam shares ``read_frame``'s explicit
    length re-check.
    """
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
        await transport.read_payload_unit()


async def test_read_payload_unit_raises_on_malformed_seq_header() -> None:
    """THREE-point bound (c): a seq-enabled malformed header raises ``CommsProtocolError``.

    The third bound is ``decode_seq_frame``'s own validation — here a declared-length
    mismatch (``n=`` disagreeing with the payload run). A seq-enabled reader fed such a
    line must raise through the SAME arm as a malformed plain frame.
    """
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    transport.enable_seq_ack()
    # ``n=99`` but the payload is 3 bytes -> decode_seq_frame declared-length mismatch.
    reader.feed_data(b"A1 s=0 a=0 n=99 |abc\n")
    with pytest.raises(CommsProtocolError):
        await transport.read_payload_unit()


async def test_send_payload_unit_reframe_ceiling_raises_seq_enabled() -> None:
    """REFRAME CEILING (seq on): a payload at ``_max_line_bytes`` leaves no header room.

    With seq/ack ON, ``encode_seq_frame`` bounds the WHOLE unit (header + payload +
    newline) by ``max_unit_bytes``. A payload whose length already equals
    ``_max_line_bytes`` cannot fit the header/newline, so ``encode_seq_frame`` raises
    ``CommsProtocolError`` and ``send_payload_unit`` lets it propagate (loud, hard
    rule #7).
    """
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(
        adapter_id=_ADAPTER_ID,
        reader=reader,
        writer=writer,  # type: ignore[arg-type]
        max_line_bytes=32,
    )
    transport.enable_seq_ack()
    with pytest.raises(CommsProtocolError):
        await transport.send_payload_unit(b"a" * 32, seq=0, ack=0)


async def test_send_payload_unit_loud_on_broken_pipe() -> None:
    """A broken pipe mid-send_payload_unit re-raises loud (hard rule #7).

    Mirrors ``send``: the ``BrokenPipeError`` / ``ConnectionResetError`` propagates so
    the relay's crash arm can route the failure, never swallowed.
    """
    reader = asyncio.StreamReader()
    writer = _FakeWriter(broken=True)
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    with pytest.raises((BrokenPipeError, ConnectionResetError)):
        await transport.send_payload_unit(b'{"x":1}', seq=0, ack=0)


# ---------------------------------------------------------------------------
# Spec A G4b-2-pre (#237) / ADR-0032: caller-owned send seq.
#
# ``send_payload_unit`` now requires an explicit ``seq`` (the gateway relay mints it,
# so a G4b-2a buffered frame's wire seq equals its ReplayBuffer key). The internal
# ``_send_seq`` auto-increment is reserved for the lifecycle ``send`` path; an
# explicit-seq relay send encodes the caller's seq verbatim and does NOT advance the
# internal counter.
# ---------------------------------------------------------------------------


def _make_seq_enabled_transport() -> tuple[CommsSocketTransport, _FakeWriter]:
    """A seq/ack-ON transport over a capturing fake writer (relay-path tests)."""
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    transport = CommsSocketTransport(adapter_id=_ADAPTER_ID, reader=reader, writer=writer)  # type: ignore[arg-type]
    transport.enable_seq_ack()
    return transport, writer


def _last_written_unit(writer: _FakeWriter) -> bytes:
    """The final newline-terminated unit handed to the writer."""
    units = [line + b"\n" for line in bytes(writer.buffer).split(b"\n") if line]
    return units[-1]


async def test_send_payload_unit_encodes_the_caller_supplied_seq() -> None:
    """The relay path encodes the caller's explicit seq, not the internal counter."""
    transport, writer = _make_seq_enabled_transport()
    await transport.send_payload_unit(b"hello", seq=7, ack=2)
    frame = decode_seq_frame(_last_written_unit(writer))
    assert frame.seq == 7
    assert frame.ack == 2
    assert frame.payload == b"hello"


async def test_relay_path_does_not_touch_internal_send_seq() -> None:
    """An explicit-seq send must NOT advance the internal ``_send_seq`` (that counter is
    only for the lifecycle ``send()`` path)."""
    transport, _writer = _make_seq_enabled_transport()
    before = transport._send_seq
    await transport.send_payload_unit(b"a", seq=100, ack=0)
    await transport.send_payload_unit(b"b", seq=101, ack=0)
    assert transport._send_seq == before  # untouched by the relay path


async def test_send_lifecycle_path_still_uses_and_increments_internal_seq() -> None:
    """``send()`` (an ``a=0`` lifecycle frame) keeps minting from the internal counter."""
    transport, writer = _make_seq_enabled_transport()
    start = transport._send_seq
    await transport.send({"jsonrpc": "2.0", "method": "ping"})
    assert transport._send_seq == start + 1
    frame = decode_seq_frame(_last_written_unit(writer))
    assert frame.seq == start
    assert frame.ack == 0
