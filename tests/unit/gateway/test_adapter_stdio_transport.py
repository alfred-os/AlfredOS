"""Unit tests for :class:`GatewayAdapterStdioTransport` (Spec B G6-5 Task 4a, #288).

The Popen-backed comms transport the gateway adapter factory wraps around an
ALREADY-LIVE :class:`subprocess.Popen` (spawned via the literal-fd-3 dup2 window
so the credential can cross fd 3). The whole point of this transport is:

* :meth:`spawn` is a NO-OP — the child already exists; the factory owns the spawn
  + credential delivery. Calling it must NOT create a process and must be safe so
  ``CommsPluginRunner.start_and_handshake`` (which calls ``transport.spawn()``)
  drives only the handshake.
* :meth:`read_frame` / :meth:`send` round-trip the SAME line-delimited JSON frame
  the :class:`CommsStdioTransport` uses on the wire, over the Popen's RAW pipes
  via ``run_in_executor`` (NOT a ``StreamReader`` / ``connect_read_pipe`` — that
  is the [Errno 22] footgun the plan warns about, mirroring
  ``quarantine_child_io._SubprocessChildIO``).
* a closed / broken pipe surfaces a LOUD typed transport error consistent with
  ``CommsStdioTransport`` (CLAUDE.md hard rule #7), never a silent swallow nor a
  raw ``OSError`` escaping unwrapped.
* :meth:`close` closes the pipes but does NOT reap the Popen — child lifecycle is
  the factory's ``_GatewayAdapterChild`` job.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
from typing import IO, Any, cast

import pytest

from alfred.gateway.adapter_stdio_transport import GatewayAdapterStdioTransport
from alfred.plugins.comms_runner import _CommsTransportLike
from alfred.plugins.comms_wire import CommsProtocolError


def _build(
    stub: Any, *, adapter_id: str = "discord", max_line_bytes: int | None = None
) -> GatewayAdapterStdioTransport:
    """Construct the transport over a stub Popen (cast for the typed seam).

    The transport touches ONLY ``.stdin``/``.stdout`` raw pipes, so a stub double
    is faithful; the ``cast`` satisfies the ``Popen[bytes]`` parameter type without
    a real subprocess.
    """
    process = cast("subprocess.Popen[bytes]", stub)
    if max_line_bytes is None:
        return GatewayAdapterStdioTransport(process=process, adapter_id=adapter_id)
    return GatewayAdapterStdioTransport(
        process=process, adapter_id=adapter_id, max_line_bytes=max_line_bytes
    )


class _StubPopen:
    """A minimal stand-in for ``subprocess.Popen`` exposing raw ``.stdin``/``.stdout``.

    The transport only touches ``.stdin`` (write) and ``.stdout`` (read) raw
    binary pipes — never spawns, signals, or reaps the process — so a stub holding
    two real OS pipes is a faithful double. ``terminate``/``kill``/``wait`` track
    whether the transport (incorrectly) tried to reap the child.
    """

    def __init__(self, *, stdin: IO[bytes] | None, stdout: IO[bytes] | None) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.terminated = False
        self.killed = False
        self.waited = False
        self.returncode: int | None = None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        return 0

    def poll(self) -> int | None:
        return self.returncode


def _pipe_reader() -> tuple[IO[bytes], IO[bytes]]:
    """Return ``(read_file, write_file)`` over a real ``os.pipe`` as binary streams."""
    read_fd, write_fd = os.pipe()
    return os.fdopen(read_fd, "rb"), os.fdopen(write_fd, "wb")


def test_satisfies_comms_transport_like_protocol() -> None:
    """The transport is a structural :class:`_CommsTransportLike` (runner seam)."""
    stub = _StubPopen(stdin=None, stdout=None)
    transport = _build(stub)
    assert isinstance(transport, _CommsTransportLike)


async def test_spawn_is_a_noop_creates_no_process() -> None:
    """``spawn()`` does NOT create / touch a process — the factory already spawned it."""
    stub = _StubPopen(stdin=None, stdout=None)
    transport = _build(stub)
    await transport.spawn()
    # No reaping / signalling / waiting happened — spawn is inert.
    assert stub.terminated is False
    assert stub.killed is False
    assert stub.waited is False
    # Idempotent: a second call (the runner only calls once, but defensive) is safe.
    await transport.spawn()


async def test_send_writes_line_delimited_json_frame() -> None:
    """``send`` writes exactly ``json.dumps(frame) + "\\n"`` to the child's stdin."""
    child_read, host_write = _pipe_reader()
    stub = _StubPopen(stdin=host_write, stdout=None)
    transport = _build(stub)
    frame = {"jsonrpc": "2.0", "id": 0, "method": "lifecycle.start"}
    await transport.send(frame)
    line = child_read.readline()
    assert line == json.dumps(frame).encode() + b"\n"
    host_write.close()
    child_read.close()


async def test_read_frame_decodes_line_delimited_json() -> None:
    """``read_frame`` decodes one ``json.dumps(frame) + "\\n"`` line into a dict."""
    host_read, child_write = _pipe_reader()
    stub = _StubPopen(stdin=None, stdout=host_read)
    transport = _build(stub)
    frame = {"jsonrpc": "2.0", "id": 0, "result": {"ok": True}}
    child_write.write(json.dumps(frame).encode() + b"\n")
    child_write.flush()
    decoded = await transport.read_frame()
    assert decoded == frame
    child_write.close()
    host_read.close()


async def test_send_then_read_frame_round_trip() -> None:
    """A frame written by ``send`` round-trips back through ``read_frame``.

    Wires the host's stdin write-end to the host's stdout read-end so a ``send``
    on the transport is observable via the SAME transport's ``read_frame`` — the
    end-to-end framing contract on the wire.
    """
    loop_read, loop_write = _pipe_reader()
    stub = _StubPopen(stdin=loop_write, stdout=loop_read)
    transport = _build(stub)
    frame = {"jsonrpc": "2.0", "method": "inbound.message", "params": {"x": 1}}
    await transport.send(frame)
    decoded = await transport.read_frame()
    assert decoded == frame
    await transport.close()


async def test_read_frame_returns_none_on_clean_eof() -> None:
    """A clean EOF (child closed stdout) reads as ``None`` — not an error."""
    host_read, child_write = _pipe_reader()
    stub = _StubPopen(stdin=None, stdout=host_read)
    transport = _build(stub)
    child_write.close()  # child closed its stdout cleanly
    assert await transport.read_frame() is None
    host_read.close()


async def test_read_frame_raises_protocol_error_on_non_json() -> None:
    """A non-JSON line is a loud :class:`CommsProtocolError`, not a silent skip."""
    host_read, child_write = _pipe_reader()
    stub = _StubPopen(stdin=None, stdout=host_read)
    transport = _build(stub)
    child_write.write(b"not json at all\n")
    child_write.flush()
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()
    child_write.close()
    host_read.close()


async def test_read_frame_raises_protocol_error_on_non_object_json() -> None:
    """A top-level JSON array/scalar is a protocol violation (not a routable frame)."""
    host_read, child_write = _pipe_reader()
    stub = _StubPopen(stdin=None, stdout=host_read)
    transport = _build(stub)
    child_write.write(b"[1, 2, 3]\n")
    child_write.flush()
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()
    child_write.close()
    host_read.close()


async def test_read_frame_raises_protocol_error_on_over_bound_line() -> None:
    """An over-bound line fails fast as :class:`CommsProtocolError` (DoS bound)."""
    host_read, child_write = _pipe_reader()
    stub = _StubPopen(stdin=None, stdout=host_read)
    transport = _build(stub, max_line_bytes=16)
    child_write.write(b'{"k": "' + b"x" * 64 + b'"}\n')
    child_write.flush()
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()
    child_write.close()
    host_read.close()


async def test_send_raises_runtime_error_when_stdin_missing() -> None:
    """A child with no stdin pipe is a programming error — loud ``RuntimeError``."""
    stub = _StubPopen(stdin=None, stdout=None)
    transport = _build(stub)
    with pytest.raises(RuntimeError):
        await transport.send({"a": 1})


async def test_read_frame_raises_runtime_error_when_stdout_missing() -> None:
    """A child with no stdout pipe is a programming error — loud ``RuntimeError``."""
    stub = _StubPopen(stdin=None, stdout=None)
    transport = _build(stub)
    with pytest.raises(RuntimeError):
        await transport.read_frame()


async def test_send_raises_protocol_error_on_broken_pipe() -> None:
    """A broken stdin pipe surfaces a loud typed transport error, never silently.

    The read-end is closed before the write so the write hits ``BrokenPipeError``;
    the transport must surface it as a :class:`CommsProtocolError` (the typed
    transport-death signal) — never let a raw ``OSError`` escape unwrapped.
    """
    child_read, host_write = _pipe_reader()
    child_read.close()  # reader gone -> next write to host_write breaks the pipe
    stub = _StubPopen(stdin=host_write, stdout=None)
    transport = _build(stub)
    with pytest.raises(CommsProtocolError):
        # Write enough to actually flush past the OS pipe buffer and trip the break.
        await transport.send({"k": "x" * 1024})
    # The buffer still holds the failed write; closing re-raises BrokenPipeError —
    # suppress it (the reader is already gone, this is cleanup only).
    with contextlib.suppress(BrokenPipeError, OSError):
        host_write.close()


class _RaisingStdout:
    """A stdout stand-in whose ``readline`` raises a transport-death ``OSError``.

    Models a child whose stdout pipe broke / was reset mid-read — the executor
    thread's blocking ``readline`` raises and the transport must wrap it in the
    typed :class:`CommsProtocolError`, never let the raw ``OSError`` escape.
    """

    def readline(self) -> bytes:
        raise OSError("simulated read-side pipe failure")


async def test_read_frame_raises_protocol_error_on_broken_pipe() -> None:
    """A read-side pipe failure surfaces a loud typed transport error, never raw."""
    stub = _StubPopen(stdin=None, stdout=cast("IO[bytes]", _RaisingStdout()))
    transport = _build(stub)
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_close_closes_pipes_without_reaping_process() -> None:
    """``close`` closes the pipes but does NOT terminate/kill/wait the Popen.

    Child lifecycle (reaping) is the factory's ``_GatewayAdapterChild`` job — this
    transport owns ONLY the pipe IO boundary.
    """
    host_read, child_write = _pipe_reader()
    child_read, host_write = _pipe_reader()
    stub = _StubPopen(stdin=host_write, stdout=host_read)
    transport = _build(stub)
    await transport.close()
    assert host_write.closed is True
    assert host_read.closed is True
    # The child was NOT reaped here.
    assert stub.terminated is False
    assert stub.killed is False
    assert stub.waited is False
    child_write.close()
    child_read.close()


async def test_close_is_idempotent() -> None:
    """A second ``close`` is a no-op (no double-close error)."""
    host_read, child_write = _pipe_reader()
    child_read, host_write = _pipe_reader()
    stub = _StubPopen(stdin=host_write, stdout=host_read)
    transport = _build(stub)
    await transport.close()
    await transport.close()
    child_write.close()
    child_read.close()


async def test_close_with_no_pipes_is_safe() -> None:
    """``close`` on a child whose pipes are ``None`` does not raise."""
    stub = _StubPopen(stdin=None, stdout=None)
    transport = _build(stub)
    await transport.close()


def test_enable_seq_ack_is_a_sync_noop_flip() -> None:
    """``enable_seq_ack`` is the sync seam flip the runner calls — present + safe.

    The gateway adapter leg is plain ADR-0025 (the gateway itself is the seq/ack
    peer, not its hosted children), so the flip must EXIST to satisfy the seam but
    need not change the plain wire. Calling it must not raise.
    """
    stub = _StubPopen(stdin=None, stdout=None)
    transport = _build(stub)
    transport.enable_seq_ack()


async def test_read_frame_does_not_block_the_event_loop() -> None:
    """A pending ``read_frame`` (no data yet) yields the loop — proof of executor reads.

    A ``StreamReader``-over-Popen path is the [Errno 22] footgun; the executor
    pattern keeps blocking reads OFF the loop. We assert the loop stays live by
    scheduling a concurrent task that completes WHILE ``read_frame`` is parked on
    an empty pipe, then feed the frame from that task.
    """
    host_read, child_write = _pipe_reader()
    stub = _StubPopen(stdin=None, stdout=host_read)
    transport = _build(stub)
    frame = {"jsonrpc": "2.0", "method": "ping"}

    progressed = asyncio.Event()

    async def _feeder() -> None:
        # If the loop were wedged by a blocking read, this would never run.
        progressed.set()
        await asyncio.sleep(0)
        child_write.write(json.dumps(frame).encode() + b"\n")
        child_write.flush()

    feeder = asyncio.ensure_future(_feeder())
    decoded = await transport.read_frame()
    await feeder
    assert progressed.is_set()
    assert decoded == frame
    child_write.close()
    host_read.close()
