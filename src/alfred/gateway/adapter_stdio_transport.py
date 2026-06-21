"""``GatewayAdapterStdioTransport`` — Popen-backed comms transport, no-op spawn.

Spec B G6-5 Task 4a (#288, plan-review C1). The gateway hosts its comms-adapter
children itself: the adapter factory spawns the child INSIDE the literal-fd-3
``os.dup2`` window so the platform credential can cross fd 3 (the
:func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io` pattern),
then delivers the credential, then needs to drive the comms handshake +
single-reader pump via :class:`alfred.plugins.comms_runner.CommsPluginRunner`.

The runner calls ``transport.spawn()`` ITSELF as its first step, and the existing
:class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport` spawns the child
in ``spawn()`` via ``asyncio.create_subprocess_exec`` with an ENV-NAMED provider
fd — NOT literal fd 3. Reusing it would spawn a SECOND child (and could not deliver
the credential over fd 3). So this transport wraps an ALREADY-LIVE
:class:`subprocess.Popen` and makes ``spawn()`` a NO-OP; only the handshake +
pump run on it.

**The pipe-IO boundary, nothing more.** This transport owns ONLY the child's raw
``stdin``/``stdout`` pipe IO. It does NOT spawn the child (the factory does, in the
fd-3 window) and it does NOT reap the child on :meth:`close` (the factory's
``_GatewayAdapterChild`` reaps it on the supervisor restart/crash/shutdown path).
:meth:`close` closes the pipes so the child sees a clean EOF on stdin; the process
lifetime stays the factory's.

**Wire-compatible with the plugin runtime.** The framing is byte-for-byte the
line-delimited JSON the :class:`CommsStdioTransport` uses — one
``json.dumps(frame) + "\\n"`` per frame in each direction — so a comms plugin
spawned by the gateway speaks the SAME wire whether the daemon or the gateway
hosts it. The only difference from ``CommsStdioTransport`` is the IO substrate:
a :class:`subprocess.Popen` gives RAW blocking pipes (not an asyncio
``StreamReader``), so the blocking reads/writes run in the default executor —
mirroring :class:`alfred.security.quarantine_child_io._SubprocessChildIO`. Driving
a ``StreamReader`` / ``loop.connect_read_pipe`` over a ``Popen`` fd is the
``OSError: [Errno 22] Invalid argument`` footgun the plan warns about, so it is
deliberately avoided.

**Seq/ack is plain (ADR-0025).** The gateway IS the seq/ack peer for its upstream
link; the children it hosts speak the PLAIN frame (G2 lesson — only the gateway
deframes seq/ack). :meth:`enable_seq_ack` exists to satisfy the
``_CommsTransportLike`` seam but the wire stays plain; the runner never negotiates
it on this leg (the handshake omits the echo).

**Fail-loud (CLAUDE.md hard rule #7).** A broken/closed pipe surfaces a typed
:class:`alfred.plugins.comms_wire.CommsProtocolError` (the same loud-failure type
``CommsStdioTransport`` raises on a malformed wire) rather than a silent swallow or
a raw ``OSError`` escaping unwrapped; an over-bound, non-JSON, or non-object line
is the same :class:`CommsProtocolError`.

**Payload-blind (CLAUDE.md hard rule #5).** The transport never parses the frame
body beyond ``json.loads`` + the top-level-object check, and never logs it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
from collections.abc import Mapping
from typing import IO, Final

import structlog

from alfred.i18n import t
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError

log = structlog.get_logger(__name__)

#: The line terminator the line-delimited JSON wire uses, matching
#: :class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport`.
_FRAME_TERMINATOR: Final[bytes] = b"\n"


class GatewayAdapterStdioTransport:
    """A line-delimited JSON duplex pipe over an ALREADY-LIVE ``subprocess.Popen``.

    Constructed FROM the Popen the gateway adapter factory spawned in the fd-3
    window. :meth:`spawn` is a no-op (the child exists); the runner's
    ``start_and_handshake`` therefore drives only the handshake + pump. The raw
    pipe IO runs in the default executor so a wedged child never blocks the loop.
    """

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        adapter_id: str,
        max_line_bytes: int = _MAX_COMMS_LINE_BYTES,
    ) -> None:
        self._process = process
        self._adapter_id = adapter_id
        self._max_line_bytes = max_line_bytes
        self._closed = False

    async def spawn(self) -> None:
        """NO-OP — the factory already spawned the child in the fd-3 window.

        ``CommsPluginRunner.start_and_handshake`` calls ``transport.spawn()`` as
        its first step. For this transport the child already exists (spawned by the
        adapter factory inside the literal-fd-3 ``os.dup2`` window so the platform
        credential could cross fd 3), so spawning here would create a SECOND child.
        The method is intentionally inert + idempotent: it neither creates nor
        touches a process, so the runner proceeds straight to the handshake.
        """

    def enable_seq_ack(self) -> None:
        """Sync seam flip the runner calls post-handshake — a no-op on this leg.

        The gateway is the seq/ack peer for its upstream link; the children it
        hosts speak the PLAIN ADR-0025 frame (G2 lesson: only the gateway deframes
        seq/ack). The handshake on this leg never negotiates ``AlfredSeqAck/1``, so
        the runner never calls this in production — but the ``_CommsTransportLike``
        seam requires the method to exist, so it is present and inert.
        """

    async def send(self, frame: Mapping[str, object]) -> None:
        """Write one ``json.dumps(frame) + "\\n"`` frame to the child's stdin.

        Wire-identical to :meth:`CommsStdioTransport.send`. The blocking pipe write
        + flush run in the default executor so a child with a full pipe buffer does
        not block the event loop. A broken/closed pipe (the child died
        mid-conversation) surfaces a loud :class:`CommsProtocolError` (CLAUDE.md
        hard rule #7) rather than a raw ``OSError``. ``RuntimeError`` if the child
        exposes no stdin (a programming error — the factory always spawns with a
        stdin PIPE).
        """
        stdin = self._process.stdin
        if stdin is None:
            raise RuntimeError(
                f"GatewayAdapterStdioTransport.send() called with no child stdin for adapter "
                f"{self._adapter_id!r}"
            )
        payload = json.dumps(frame).encode() + _FRAME_TERMINATOR
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, _blocking_write, stdin, payload)
        except (BrokenPipeError, ConnectionResetError, ValueError, OSError) as exc:
            # The child died mid-conversation (broken pipe / reset) or the pipe was
            # closed under us (ValueError "I/O operation on closed file"). Surface
            # the typed transport-death signal so the runner's crash arm routes an
            # ``adapter.crashed`` and the breaker can trip — never a silent swallow,
            # never a raw OSError escaping unwrapped (CLAUDE.md hard rule #7). The
            # frame body is NEVER carried onto the error (payload-blind, #5).
            log.warning("gateway.adapter_transport.send_broken_pipe", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc

    async def read_frame(self) -> Mapping[str, object] | None:
        """Read one line-delimited JSON frame; ``None`` on clean EOF.

        Wire-identical to :meth:`CommsStdioTransport.read_frame`: returns the
        decoded top-level JSON object, ``None`` when the child closed its stdout
        cleanly (empty read), and raises :class:`CommsProtocolError` on an
        over-bound line, non-JSON bytes, or a non-object top-level value. The
        blocking ``readline`` runs in the default executor so a slow / wedged child
        never blocks the loop (the [Errno 22] footgun a ``StreamReader`` over a
        ``Popen`` fd would invite is avoided), and is BOUNDED to ``max_line_bytes + 1``
        bytes so a child emitting bytes with NO terminator can never force unbounded
        executor-thread buffering before the bound fires — the adversary-exposed
        ``kind=full`` (external Discord) leg. ``RuntimeError`` if the child exposes no
        stdout (a programming error).
        """
        stdout = self._process.stdout
        if stdout is None:
            raise RuntimeError(
                f"GatewayAdapterStdioTransport.read_frame() called with no child stdout for "
                f"adapter {self._adapter_id!r}"
            )
        loop = asyncio.get_running_loop()
        try:
            line = await loop.run_in_executor(
                None, _blocking_readline, stdout, self._max_line_bytes
            )
        except (BrokenPipeError, ConnectionResetError, ValueError, OSError) as exc:
            log.warning("gateway.adapter_transport.read_broken_pipe", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc
        if not line:
            # Clean EOF — the child closed stdout. The runner ends the pump.
            return None
        if len(line) > self._max_line_bytes:
            # An over-bound line is a DoS attempt / misbehaving child — refuse it
            # rather than route an unbounded frame. ``_blocking_readline`` reads at
            # most ``max_line_bytes + 1`` bytes, so a no-terminator flood is refused
            # the INSTANT the cap is exceeded — never buffered whole first. The bound
            # is enforced in the reader (the StreamReader-limit peer in
            # CommsStdioTransport); this check converts the over-bound read into the
            # typed loud refusal.
            log.warning("gateway.adapter_transport.frame_too_large", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            )
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("gateway.adapter_transport.malformed_frame", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc
        if not isinstance(decoded, dict):
            # A JSON-RPC frame is always a top-level object; a list / scalar is a
            # protocol violation, not a frame the dispatcher can route.
            log.warning("gateway.adapter_transport.non_object_frame", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            )
        return decoded

    async def close(self) -> None:
        """Close the child's pipes (clean stdin EOF for the child); idempotent.

        The transport/child boundary: this closes ONLY the pipe IO it owns. It does
        NOT terminate / kill / wait the :class:`subprocess.Popen` — child lifecycle
        + reaping is the factory's ``_GatewayAdapterChild`` job (the supervisor
        calls its teardown on the restart/crash/shutdown path). Closing stdin gives
        the child a clean EOF; closing stdout drops the host's read-end. A no-op on
        a second call.
        """
        if self._closed:
            return
        self._closed = True
        for stream in (self._process.stdin, self._process.stdout):
            if stream is not None:
                with contextlib.suppress(OSError, ValueError):
                    stream.close()


def _blocking_write(stream: IO[bytes], payload: bytes) -> None:
    """Write + flush a payload onto a raw pipe (runs in an executor thread)."""
    stream.write(payload)
    stream.flush()


def _blocking_readline(stream: IO[bytes], max_line_bytes: int) -> bytes:
    """Read one ``\\n``-terminated line from a raw pipe, BOUNDED (executor thread).

    Reads in chunks with a hard budget of ``max_line_bytes + 1`` bytes: a child
    that streams bytes with NO terminator can never force unbounded buffering before
    the over-bound check in :meth:`GatewayAdapterStdioTransport.read_frame` fires.
    The ``+ 1`` lets the caller's ``len(line) > max_line_bytes`` test distinguish an
    exactly-at-cap good line from an over-bound one — the one extra byte proves the
    line did not terminate within the bound. ``readline(remaining)`` returns at most
    ``remaining`` bytes, stopping early at a ``\\n`` if one appears within the span,
    so a well-formed in-bound line still returns in one read.

    Returns ``b""`` on EOF (the peer to ``StreamReader.readline``'s clean-EOF
    contract). Runs OFF the event loop so a slow / wedged child does not block it.
    """
    budget = max_line_bytes + 1
    chunks: list[bytes] = []
    collected = 0
    while collected < budget:
        chunk = stream.readline(budget - collected)
        if not chunk:
            # EOF before a terminator: return what we have (``b""`` if nothing).
            break
        chunks.append(chunk)
        collected += len(chunk)
        if chunk.endswith(_FRAME_TERMINATOR):
            # A complete in-bound line — stop (do not block waiting for more).
            break
    return b"".join(chunks)


__all__ = [
    "GatewayAdapterStdioTransport",
]
