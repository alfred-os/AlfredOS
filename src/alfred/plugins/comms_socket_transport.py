"""``CommsSocketTransport`` — a 0600 unix-socket comms wire for the foreground TUI.

ADR-0031. The daemon-spawned comms adapters (Discord, the reference plugin) reach
the host over an anonymous pipe to a launcher-exec'd child
(:class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport`). The foreground
TUI cannot: ``alfred chat`` is a separate, operator-owned process that must own the
operator's PTY, so the daemon can never spawn-and-own it. Instead the two
already-running peers rendezvous over a **named local socket**: the daemon binds +
accepts, the foreground ``alfred chat`` dials in, and the accepted connection IS the
wire.

**Same wire, different carrier.** The frames, the ADR-0025 line-delimited JSON-RPC
codec, the ``_MAX_COMMS_LINE_BYTES`` frame bound, the ``CommsProtocolError``
loud-failure discipline, and the four-awaitable :class:`_CommsTransportLike` shape
are all SHARED with :class:`CommsStdioTransport`. Only the byte-carrier changes from
a pipe-to-a-child to a 0600 owner-only unix socket between same-uid peers. This
transport is therefore a drop-in for the UNCHANGED
:class:`alfred.plugins.comms_runner.CommsPluginRunner` — the runner, the session,
the handshake, and the dispatch/ack path are reused byte-for-byte (ADR-0031
Decision 1).

**Thin, like its sibling.** No DLP, no secret substitution, no T3 tagging, no canary
scan — the comms trust boundary lives upstream in ``process_inbound_message`` +
``ScannedOutboundBody`` (ADR-0025). The socket's security duties are exactly two: a
frame-size bound + loud failure on a malformed wire (CLAUDE.md hard rule #7), and a
0600 owner-only local socket so the only peer that can connect is a same-uid process.

**``spawn()`` is a no-op.** The accepted connection is established by the listener
BEFORE the runner's handshake runs, so ``spawn()`` is an inert success — there is no
subprocess to launch (ADR-0031 Decision 2). ``send`` / ``read_frame`` drive the
accepted :class:`asyncio.StreamReader` / :class:`asyncio.StreamWriter`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import socket
import stat
import struct
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Final

import structlog

from alfred.i18n import t

# The frame bound + loud-failure type are SHARED across the comms wire (ADR-0031
# Decision 1) — the socket carries the identical ADR-0025 wire, so reuse the bound
# and the protocol-error class rather than forking a second, divergent framer. They
# live in the ``comms_wire`` leaf module (Spec A G2 / ADR-0032) so the seq/ack
# codec can import them too without a codec<->transport import cycle.
from alfred.plugins.comms_seq_codec import (
    SeqFrame,
    decode_seq_frame,
    encode_seq_frame,
)
from alfred.plugins.comms_wire import (
    _MAX_COMMS_LINE_BYTES,
    CommsProtocolError,
)

log = structlog.get_logger(__name__)

# The daemon runtime dir + permission discipline mirror the PID file
# (:mod:`alfred.cli.daemon._daemon_pidfile`): ~/.run/alfred at mode 0700, owner =
# current uid. The socket lives here so the local-IPC surface is the operator's own
# uid and nothing wider.
_SOCKET_MODE: Final[int] = 0o600
_RUNTIME_DIR_MODE: Final[int] = 0o700

# An ``adapter_id`` is interpolated straight into the socket FILENAME, so it must be
# a single path segment with no traversal potential: lowercase alnum plus ``_``/``-``.
# This forbids ``/`` (sub-path), ``.``/``..`` (escape), and the empty string. The id
# is host-controlled today (only ``"tui"``), so this guard is defence-in-depth that
# keeps the helper structurally incapable of constructing a path outside the 0700
# runtime dir even if a future caller threads an attacker-influenced value through.
_ADAPTER_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9_-]+$")


def _runtime_dir() -> Path:
    """Resolve ``~/.run/alfred`` at call time (honours a changed ``$HOME``)."""
    return Path.home() / ".run" / "alfred"


# The kernel ``struct ucred`` returned by ``SO_PEERCRED`` is three UNSIGNED ints
# ``{ pid_t pid; uid_t uid; gid_t gid; }``; ``"3I"`` matches it (uid is unsigned).
_UCRED_STRUCT: Final[str] = "3I"

# Perf (devex carry-forward): hoist the fixed struct width to a module constant so
# ``_resolve_peer_uid`` does not recompute ``struct.calcsize`` on every accept.
_UCRED_WIDTH: Final[int] = struct.calcsize(_UCRED_STRUCT)


def _resolve_peer_uid(sock: socket.socket | None) -> int | None:
    """Return the connected peer's uid, or ``None`` when unknowable.

    Linux answers via ``SO_PEERCRED`` (kernel-attested ``(pid, uid, gid)``). A
    platform without it (macOS dev hosts) returns ``None`` — the 0600 socket under
    the 0700 runtime dir is the same-uid enforcement-of-record there; ``SO_PEERCRED``
    is defense-in-depth, not the only line. NEVER raises: ``getsockopt`` may return
    fewer bytes than requested (a short read makes ``struct.unpack`` raise
    ``struct.error``), and a closed/non-AF_UNIX socket raises ``OSError`` — both
    degrade to ``None`` (accept on FS perms) rather than crashing the accept
    callback and wedging the listener.
    """
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        # devex-263-002: leave a breadcrumb on the no-SO_PEERCRED branch (a macOS
        # dev host) so the FS-perms-of-record degrade is distinguishable in a trace
        # from a short-read / getsockopt-fault degrade — the operator can tell the
        # peer-uid check was SKIPPED (platform), not ATTEMPTED-and-failed.
        log.debug(
            "comms.socket.peer_cred_unsupported",
            so_peercred_present=hasattr(socket, "SO_PEERCRED"),
            sock_present=sock is not None,
        )
        return None
    width = _UCRED_WIDTH
    try:
        # ``SO_PEERCRED`` is a Linux-only socket constant; the ``hasattr`` guard
        # above gates the access. pyright on a macOS dev host cannot see the
        # Linux-platform typeshed stub, so silence the attr-access there (mypy on
        # this host resolves it, hence ``unused-ignore`` keeps the Linux gate quiet).
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, width)  # type: ignore[attr-defined, unused-ignore]
        if len(creds) != width:
            return None
        # ``struct.unpack`` is typed ``tuple[Any, ...]``; the ``"3I"`` format
        # guarantees three ints, so coerce the uid to ``int`` for mypy --strict.
        _pid, uid, _gid = struct.unpack(_UCRED_STRUCT, creds)
    except (OSError, struct.error) as exc:
        # Degrade-open to the FS-perms-of-record (return None -> authorized). This
        # is benign for the enumerated cases (short read, closed/non-AF_UNIX socket),
        # but a security check that fails open should leave a breadcrumb so an
        # UNEXPECTED getsockopt fault on a SO_PEERCRED-advertising host is not
        # indistinguishable from the normal degrade path (review err-263-001).
        log.debug("comms.socket.peer_cred_unavailable", error=repr(exc))
        return None
    return int(uid)


def _peer_uid_authorized(*, reported_uid: int | None) -> bool:
    """True if the peer is the same uid as us, or unknowable (FS-perms-of-record).

    ``None`` (no ``SO_PEERCRED`` / short read) is authorized: the only peer that can
    ``connect`` a 0600 socket under a 0700 dir is the owner. A reported uid that
    mismatches ``os.getuid()`` is a genuine impostor (a same-uid race that re-bound
    or a wider-perm misconfig) and is refused.
    """
    return reported_uid is None or reported_uid == os.getuid()


def default_comms_socket_path(adapter_id: str) -> Path:
    """Return the adapter-keyed socket path (``~/.run/alfred/comms-<adapter_id>.sock``).

    Keyed by ``adapter_id`` so the path is self-documenting and a future per-adapter
    listener is a zero-cost path change (ADR-0031 Decision 3), even though this cut
    accepts exactly one connection. ``$HOME`` is resolved at call time (not import
    time) so the path tracks the daemon's environment.

    Validates ``adapter_id`` against :data:`_ADAPTER_ID_RE` (``^[a-z0-9_-]+$``) FIRST,
    so the helper can never interpolate a ``/`` / ``..`` / empty segment into the
    filename and escape the 0700 runtime dir — a bad id raises ``ValueError`` loudly
    rather than silently yielding a path outside ``~/.run/alfred``.
    """
    if not _ADAPTER_ID_RE.fullmatch(adapter_id):
        raise ValueError(
            f"comms adapter_id must match {_ADAPTER_ID_RE.pattern!r} "
            f"(no path separators, no traversal, non-empty): {adapter_id!r}"
        )
    return _runtime_dir() / f"comms-{adapter_id}.sock"


async def dial_comms_socket(adapter_id: str) -> CommsSocketTransport:
    """Dial the daemon's bound comms socket; return the peer-end transport.

    The connect-analog of :meth:`CommsSocketListener.accept` (ADR-0031 PR-2): the
    foreground ``alfred chat`` is a separate, already-running process, so it does
    not get its connection accepted — it *establishes* one by dialing the daemon's
    0600 owner-only socket. The returned :class:`CommsSocketTransport` is the SAME
    carrier-symmetric duplex the listener hands back — only establishment differs
    (connect vs accept); ``send`` / ``read_frame`` drive the dialed streams with the
    identical ADR-0025 codec.

    The dialed reader is pinned to :data:`_MAX_COMMS_LINE_BYTES` so the client
    enforces the IDENTICAL frame-size DoS bound the accept side pins
    (:meth:`CommsSocketListener.accept`), matching the stdio transport's guard.

    A daemon-absent / socket-missing dial raises LOUD: ``open_unix_connection``
    surfaces ``FileNotFoundError`` (the socket inode is gone) or
    ``ConnectionRefusedError`` (a stale inode with no listener) — never swallowed,
    so the caller (``_chat_main``) can map it to the daemon-required operator
    message (CLAUDE.md hard rule #7).
    """
    reader, writer = await asyncio.open_unix_connection(
        path=str(default_comms_socket_path(adapter_id)),
        limit=_MAX_COMMS_LINE_BYTES,
    )
    return CommsSocketTransport(adapter_id=adapter_id, reader=reader, writer=writer)


class CommsSocketTransport:
    """A line-delimited JSON-RPC duplex pipe over an accepted unix-socket connection.

    Constructed by :meth:`CommsSocketListener.accept` over the accepted
    ``(reader, writer)`` pair. Satisfies the runner's structural
    :class:`alfred.plugins.comms_runner._CommsTransportLike` seam: ``spawn`` is a
    no-op (the connection is already live), ``send`` / ``read_frame`` drive the
    accepted streams, ``close`` reaps the connection (idempotent).
    """

    def __init__(
        self,
        *,
        adapter_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        max_line_bytes: int = _MAX_COMMS_LINE_BYTES,
    ) -> None:
        self._adapter_id = adapter_id
        self._reader = reader
        self._writer = writer
        self._max_line_bytes = max_line_bytes
        self._closed = False
        # Spec A G2 (#237): out-of-band seq/ack framing, OFF by default. Flipped ON
        # (via enable_seq_ack) only when the lifecycle.start handshake negotiated
        # ``AlfredSeqAck/1`` on BOTH peers. When OFF the wire is byte-for-byte the
        # existing ADR-0025 plain frame. Like the stdio sibling, the transport
        # emits an ``a=0`` PLACEHOLDER ack and stores NO received-seq high-water
        # (the real contiguous ack is the G3 relay's concern — ADR-0032 Decision 3).
        self._seq_ack_enabled = False
        self._send_seq = 0
        # Spec A G3-2 (#237) C2 — REQUIRED on the socket carrier: a second writer
        # (the boot coroutine's lifecycle-send via ``CommsPluginRunner.send_notification``)
        # now races the pump's reentrant ``send_request``, so ``send`` serialises the
        # whole ``encode -> write -> drain -> seq-increment`` critical section under
        # this lock. A torn frame is worse than a delayed one, so the lock
        # intentionally spans ``drain``. The reader (:meth:`read_frame`) NEVER takes
        # this lock, so there is no reader/writer deadlock.
        self._send_lock = asyncio.Lock()

    def enable_seq_ack(self) -> None:
        """Turn the out-of-band seq/ack header ON (post-handshake, version-gated).

        Idempotent flip the runner calls once the ``lifecycle.start`` negotiation
        confirmed BOTH peers speak ``AlfredSeqAck/1``. Mirrors
        :meth:`CommsStdioTransport.enable_seq_ack` — only the carrier differs.
        """
        self._seq_ack_enabled = True

    async def spawn(self) -> None:
        """No-op: the accepted connection IS the wire (ADR-0031 Decision 2).

        A stdio transport's ``spawn`` execs a subprocess; the socket transport owns
        no subprocess — the peer is its own process and the connection was accepted
        before the runner's handshake. Kept as an inert awaitable so the runner's
        lifecycle (``spawn`` → handshake → pump) drives unchanged. The empty body is
        deliberate — the connection is the wire, so there is nothing to establish.
        """

    async def send(self, frame: Mapping[str, object]) -> None:
        """Write one ``json.dumps(frame) + "\\n"`` frame to the peer.

        Loud on a broken pipe (the peer died mid-conversation): the
        ``BrokenPipeError`` / ``ConnectionResetError`` propagates so the runner's
        crash arm routes an ``adapter.crashed`` and the breaker can trip (CLAUDE.md
        hard rule #7).
        """
        body = json.dumps(frame).encode()
        # Spec A G3-2 (#237) C2: the entire encode -> write -> drain -> seq-increment
        # critical section is serialised so a concurrent second writer (the boot
        # lifecycle-send) cannot interleave a frame or race ``_send_seq``.
        async with self._send_lock:
            if self._seq_ack_enabled:
                payload = encode_seq_frame(
                    body,
                    seq=self._send_seq,
                    # PLACEHOLDER (ADR-0032 Decision 3) — NOT a high-water; the G3 relay
                    # wires SeqDedupWindow.cumulative_ack() as the real ack source.
                    ack=0,
                    max_unit_bytes=self._max_line_bytes,
                )
                self._send_seq += 1
            else:
                payload = body + b"\n"
            try:
                self._writer.write(payload)
                await self._writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                log.warning("comms.socket.send_broken_pipe", adapter_id=self._adapter_id)
                raise

    async def read_frame(self) -> Mapping[str, object] | None:
        """Read one line-delimited frame; ``None`` on clean EOF.

        Returns the decoded JSON object, or ``None`` when the peer closed the
        connection cleanly (empty read). Raises :class:`CommsProtocolError` on an
        over-bound line, non-JSON bytes, or a non-object top-level JSON value — the
        SAME malformed-frame discipline as :meth:`CommsStdioTransport.read_frame` so
        the runner's existing malformed-frame arm handles it uniformly.
        """
        try:
            line = await self._reader.readline()
        except (ValueError, asyncio.LimitOverrunError) as exc:
            # The StreamReader limit (pinned at accept) tripped on an over-bound
            # line. Surface it as a protocol error, not a raw ValueError.
            log.warning("comms.socket.frame_too_large", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc
        if not line:
            # Clean EOF — the peer closed the connection. The runner ends the pump.
            return None
        if len(line) > self._max_line_bytes:
            # Belt-and-braces: a line at exactly the reader limit can slip through
            # readline() without raising; enforce the bound explicitly too.
            log.warning("comms.socket.frame_too_large", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            )
        if self._seq_ack_enabled:
            # Spec A G2 (#237): strip the out-of-band header; the inner payload
            # continues through the existing json.loads path unchanged. CONSUMES NO
            # seq/ack here (no dedup, no ack, no high-water — the G3 relay is the
            # consumer). ``decode_seq_frame`` is magic-gated, so a plain line from an
            # un-upgraded peer still decodes via the SeqFrame(seq=None, ...) fallback
            # (mixed-wire safety), and is fail-loud on a malformed header — surfacing
            # through the SAME arm as a malformed plain frame. Mirrors the stdio
            # sibling exactly; only the carrier differs.
            frame_unit: SeqFrame = decode_seq_frame(line, max_unit_bytes=self._max_line_bytes)
            line = frame_unit.payload
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("comms.socket.malformed_frame", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            ) from exc
        if not isinstance(decoded, dict):
            # A JSON-RPC frame is always a top-level object. A list / scalar is a
            # protocol violation, not a frame the dispatcher can route.
            log.warning("comms.socket.non_object_frame", adapter_id=self._adapter_id)
            raise CommsProtocolError(
                t("comms.transport.malformed_frame", adapter_id=self._adapter_id)
            )
        return decoded

    async def close(self) -> None:
        """Close the accepted connection; idempotent.

        Closes the writer (EOF to the peer) and waits for the close to flush. A
        ``BrokenPipeError`` / ``ConnectionResetError`` during the drain is suppressed
        — the peer is already gone, which is the exact state close is reaching for.
        A no-op on a second call (teardown paths double-close by design).
        """
        if self._closed:
            return
        self._closed = True
        if not self._writer.is_closing():
            self._writer.close()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            await self._writer.wait_closed()


class CommsSocketListener:
    """Binds the daemon's 0600 comms socket and accepts ONE peer connection.

    The daemon-side rendezvous for the foreground TUI (ADR-0031). :meth:`bind`
    creates ``~/.run/alfred/comms-<adapter_id>.sock`` (0600, owner-only, fresh each
    boot via unlink-stale-then-bind); :meth:`accept` awaits a single peer and returns
    the :class:`CommsSocketTransport` over the accepted connection; :meth:`aclose`
    reaps the listener + the socket file on EVERY exit path (mirrors
    :meth:`alfred.cli.daemon._commands._CommsBootGraph.aclose`).
    """

    def __init__(
        self,
        *,
        adapter_id: str,
        max_line_bytes: int = _MAX_COMMS_LINE_BYTES,
        on_peer_rejected: Callable[[int | None], Awaitable[None]] | None = None,
    ) -> None:
        self._adapter_id = adapter_id
        self._max_line_bytes = max_line_bytes
        self._path = default_comms_socket_path(adapter_id)
        self._sock: socket.socket | None = None
        self._server: asyncio.AbstractServer | None = None
        self._accepted: asyncio.Future[CommsSocketTransport] | None = None
        # Spec A G3-2 (#237) — arch-263-001 (closes the G3-1 deferral): a CALLBACK
        # (not a counter — security M-3) fired in ``_on_connect`` at the reject
        # point, passing the rejected peer's uid. The daemon supplies a callback
        # that writes the ``comms.socket.peer_uid_rejected`` AUDIT row (peer_uid +
        # expected_uid) via the audit writer it already holds. A counter would lose
        # the peer_uid and could miss a reject immediately followed by a legitimate
        # accept. A rejection is an EXPECTED adversarial event, so it does NOT refuse
        # the boot (that would be a self-inflicted DoS): loud audit row, boot
        # continues, the listener keeps waiting for a legitimate same-uid peer.
        self._on_peer_rejected = on_peer_rejected

    @property
    def path(self) -> Path:
        return self._path

    async def bind(self) -> None:
        """Create the 0600 owner-only socket under the 0700 runtime dir.

        Unlink-stale-then-bind: a crashed prior boot leaves the socket inode behind,
        and binding over it would raise ``EADDRINUSE`` — so a stale path is removed
        first (ADR-0031 Decision 3). The socket file mode is set to 0600 AFTER bind
        (a freshly-bound unix socket inherits the umask), so it is owner-only the
        instant the daemon advertises it; the only peer that can connect is a
        same-uid process.

        Guards against a double bind — a second call with a live socket is a
        programming error, raised loudly.
        """
        if self._sock is not None:
            raise RuntimeError(
                f"CommsSocketListener.bind() called twice for adapter {self._adapter_id!r}"
            )
        runtime_dir = self._path.parent
        runtime_dir.mkdir(mode=_RUNTIME_DIR_MODE, parents=True, exist_ok=True)
        # ``mkdir(mode=...)`` only applies at CREATION (and is umask-masked even
        # then); a pre-existing ``~/.run/alfred`` from a looser-umask boot keeps
        # its old perms, leaving the 0600 socket under a too-open dir. Tighten the
        # dir to 0700 UNCONDITIONALLY so the bind->chmod window's 0700 invariant
        # holds every boot (CLAUDE.md hard rule #7, fail-closed). The dir is
        # alfred-owned runtime state and its parent is the user's owner-only home,
        # so this chmod cannot be redirected through an attacker-controlled symlink.
        runtime_dir.chmod(_RUNTIME_DIR_MODE)
        self._unlink_stale()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(self._path))
            # A freshly-bound unix socket is created under the process umask; pin it
            # to 0600 explicitly so it is owner-only regardless of the umask.
            self._path.chmod(_SOCKET_MODE)
            sock.listen(1)
            # ``asyncio.start_unix_server(sock=...)`` puts the socket in non-blocking
            # mode itself when it adapts it in :meth:`accept`, so we do not set it
            # here (and avoid a bare boolean-positional call).
        except BaseException:
            sock.close()
            self._unlink_stale()
            raise
        self._sock = sock

    def _unlink_stale(self) -> None:
        """Remove a leftover socket/file at the path; a missing path is not an error.

        Only ever removes a path the listener owns (the adapter-keyed socket under
        the daemon's own 0700 runtime dir). A non-socket regular file from a prior
        crash is also removed — the daemon re-owns its own runtime path each boot.
        """
        with contextlib.suppress(FileNotFoundError):
            # ``lstat`` (not stat) so a symlink target is never followed.
            st = self._path.lstat()
            if stat.S_ISSOCK(st.st_mode) or stat.S_ISREG(st.st_mode):
                self._path.unlink()
            else:
                # A FIFO / device / symlink at our runtime path is anomalous — refuse
                # rather than blindly unlink something we do not recognise as ours.
                raise RuntimeError(
                    f"comms socket path {self._path} is not a socket or regular file: "
                    f"{stat.S_IFMT(st.st_mode):#o}"
                )

    async def accept(self) -> CommsSocketTransport:
        """Await ONE peer connection; return the transport over it.

        This cut accepts exactly one connection (ADR-0031 Decision 4) — the single
        foreground ``alfred chat``. The accepted ``StreamReader`` limit is pinned to
        :data:`_max_line_bytes` so an over-bound line fails fast at the reader rather
        than buffering unboundedly, matching the stdio transport's DoS guard.
        """
        if self._sock is None:
            raise RuntimeError(
                f"CommsSocketListener.accept() called before bind() for adapter "
                f"{self._adapter_id!r}"
            )
        if self._accepted is not None:
            # One-shot lifecycle (ADR-0031 Decision 4): a listener instance serves
            # EXACTLY one connection. A second ``accept()`` call would re-arm the
            # future and accept another client — a programming error, raised loudly
            # (distinct from the second *socket* dial-in that ``_on_connect`` closes).
            raise RuntimeError(
                f"CommsSocketListener.accept() called twice for adapter {self._adapter_id!r}"
            )
        loop = asyncio.get_running_loop()
        self._accepted = loop.create_future()

        async def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            assert self._accepted is not None
            if self._accepted.done():
                # This cut serves a single connection; a second dial-in is closed
                # immediately rather than racing the first (ADR-0031 Decision 4).
                writer.close()
                return
            # ``get_extra_info("socket")`` is the ACCEPTED CHILD socket (per-
            # connection), so SO_PEERCRED reads the CONNECTOR's creds. Never read
            # peer creds off ``self._sock`` (the listener) — that returns our own
            # uid and always passes, defeating the check.
            peer_uid = _resolve_peer_uid(writer.get_extra_info("socket"))
            if not _peer_uid_authorized(reported_uid=peer_uid):
                # A different-uid peer beat a legitimate dial-in to the socket
                # (stale-socket race / wider-perm misconfig). Refuse it loudly and
                # KEEP WAITING — do NOT resolve the future, so a legitimate same-uid
                # peer can still connect (CLAUDE.md hard rule #7: never ack-and-drop).
                log.warning(
                    "comms.socket.peer_uid_rejected",
                    adapter_id=self._adapter_id,
                    peer_uid=peer_uid,
                )
                # Fire the daemon's reject callback (the audit-row writer) at the
                # reject point, BEFORE closing the impostor's writer, so the loud
                # audit row records every reject (arch-263-001). Boot is NOT refused.
                if self._on_peer_rejected is not None:
                    try:
                        await self._on_peer_rejected(peer_uid)
                    except Exception as exc:
                        # The reject ITSELF is benign (keep waiting). But a FAILED
                        # audit-write of a security-boundary reject is hard-rule-#7
                        # territory — it must NOT be orphaned in this detached
                        # ``start_unix_server`` callback (asyncio would surface it
                        # only as an unretrieved-task-exception log). Escalate it to
                        # the supervised ``accept()`` awaiter so the pump task fails
                        # LOUD (an audited supervisor crash), making the callback's
                        # fail-loud contract true. ``CancelledError`` is a
                        # ``BaseException`` and propagates past this ``except``.
                        # The ``done()`` branch covers the rare race where a
                        # concurrent legit peer resolved the future during the audit
                        # await: re-raise so the broken audit still surfaces via
                        # asyncio's unretrieved-exception handler.
                        if self._accepted.done():  # pragma: no cover - concurrent-resolve race
                            writer.close()
                            raise
                        self._accepted.set_exception(exc)
                        writer.close()
                        return
                writer.close()
                return
            self._accepted.set_result(
                CommsSocketTransport(
                    adapter_id=self._adapter_id,
                    reader=reader,
                    writer=writer,
                    max_line_bytes=self._max_line_bytes,
                )
            )

        self._server = await asyncio.start_unix_server(
            _on_connect,
            sock=self._sock,
            limit=self._max_line_bytes,
        )
        return await self._accepted

    async def aclose(self) -> None:
        """Reap the listener + socket file on EVERY exit path; idempotent.

        Closes the asyncio server (stops accepting), closes the underlying socket,
        and unlinks the socket file so the next boot's unlink-stale path is a no-op
        and no stale inode lingers. Called on clean shutdown, a boot refusal, or a
        supervisor failure — mirrors :meth:`_CommsBootGraph.aclose`'s leak-discipline.
        A double close (teardown after a start failure) is safe.
        """
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            # The peer may already be gone, leaving the server's close/drain to
            # surface an ``OSError`` on the underlying socket or a ``RuntimeError``
            # from asyncio's server bookkeeping — the exact "already closing" states
            # this reap is reaching for. Suppress ONLY those; a broader ``Exception``
            # arm would swallow a genuine bug (CLAUDE.md hard rule #7).
            with contextlib.suppress(OSError, RuntimeError):
                await server.wait_closed()
        sock = self._sock
        self._sock = None
        if sock is not None:
            sock.close()
        # Remove the socket file last so a partially-bound listener (bind raised after
        # creating the inode) is still cleaned up. ``missing_ok`` keeps the second
        # close a no-op.
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()


__all__ = [
    "CommsProtocolError",
    "CommsSocketListener",
    "CommsSocketTransport",
    "default_comms_socket_path",
    "dial_comms_socket",
]
