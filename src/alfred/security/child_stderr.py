"""Continuous stderr drain for launcher-spawned children (#520).

``bin/alfred-plugin-launcher.sh`` reports every sandbox refusal on stderr — a bare
i18n key plus a ``supervisor.plugin.sandbox_refused`` JSON row. Two of the four
spawn sites piped that stream and never read it, so those refusals reached nobody:
no log line, no audit row, no operator message (CLAUDE.md hard rule #7).

Leaving the pipe unread costs more than diagnostics, and costs it *differently*
depending on the spawn API. Measured, 20MB of child stderr attempted:

    asyncio limit=64KB   ->   214/20000 KB  STALLED
    asyncio limit=10MB   -> 20000/20000 KB  ok
    raw Popen (gateway)  ->    64/20000 KB  STALLED

``subprocess.Popen`` has nothing polling the pipe, so the 64KB kernel buffer fills
and the child blocks in ``write()`` forever — no crash, no error, just a wedged
adapter. ``asyncio.create_subprocess_exec`` installs a transport that *actively
polls* the pipe into the ``StreamReader`` regardless of whether anyone reads, so
the child never blocks; instead the parent retains every byte the child ever wrote
(20MB written -> 20MB held), an unbounded leak in the daemon.

One continuous drain fixes both. Note it is deliberately NOT the exit-gated
one-shot read used by the quarantine child
(:meth:`alfred.security.quarantine_child_io._SubprocessChildIO._log_child_stderr`,
#251): that returns early unless ``poll()`` shows the child has exited, which is
right for a short-lived extraction child and useless for an adapter that must keep
running while it logs.

Refusal rows are ACCUMULATED here, not written here. Persisting them is ``async``
(:class:`alfred.security.sandbox_refusal_audit.SandboxRefusalRecorder`) and the
blocking driver runs on a thread that cannot await, so the spawn site drains
:attr:`ChildStderrPump.refusal_rows` on its failure arm — the same "record at the
drain, not at a spawn-time probe barrier" shape ADR-0051 §2 chose.
"""

from __future__ import annotations

import asyncio
import threading
import unicodedata
from typing import IO, Final

import structlog

from alfred.audit.launcher_refusal import SandboxRefusalRow, parse_launcher_refusal_rows

log = structlog.get_logger(__name__)

# Per-line cap for the emitted log field. Matches the quarantine drain's cap so a
# child's stderr renders identically whichever producer spawned it.
STDERR_LOG_CAP_BYTES: Final[int] = 4096
STDERR_TRUNCATION_MARKER: Final[str] = " …[truncated]"

# ``Cc`` (C0/C1 controls incl. \n \r \t \x1b / DEL) + ``Cf`` (format chars incl.
# bidi overrides / zero-width). Stripping both is what keeps an adversary-influenced
# stderr byte from forging a log line or display-spoofing an operator's terminal.
STRIPPED_UNICODE_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf"})

# Read granularity. Small enough that a chatty child is drained incrementally rather
# than in one large allocation; large enough not to syscall per line.
_READ_CHUNK_BYTES: Final[int] = 64 * 1024

# A single stderr "line" longer than this is discarded rather than buffered — the
# whole point of the drain is that a child cannot grow the parent without bound, and
# a child that never emits a newline must not defeat that.
_MAX_LINE_BYTES: Final[int] = 64 * 1024

# Refusals are emitted once, pre-``exec``, before the child image exists. Retaining a
# handful is sufficient and keeps a chatty (or hostile) child from growing this list.
_MAX_RETAINED_REFUSAL_ROWS: Final[int] = 16


def sanitize_child_stderr(raw: bytes, *, cap: int, truncated: bool = False) -> str | None:
    """De-fang child stderr into a single-line structured-log field (or ``None``).

    Every char in a stripped Unicode category is replaced with a space, whitespace
    runs are collapsed, and the result stripped — so the field is single-line
    searchable and injection-proof under both the JSON and console renderers.
    Returns ``None`` when nothing printable remains (no empty-field noise).
    Secret-shape masking happens DOWNSTREAM in the bootstrap structlog
    leaf-redactor once this lands as a log field.

    ``truncated`` is passed by a caller whose RAW read already hit a byte cap. It is
    load-bearing for multi-byte UTF-8: a byte-capped read can decode to FEWER than
    ``cap`` chars, so ``len(collapsed) > cap`` alone would silently drop the marker
    even though bytes were clipped.
    """
    text = raw.decode("utf-8", errors="replace")
    despaced = "".join(
        " " if unicodedata.category(ch) in STRIPPED_UNICODE_CATEGORIES else ch for ch in text
    )
    collapsed = " ".join(despaced.split())
    if not collapsed:
        return None
    if truncated or len(collapsed) > cap:
        return collapsed[:cap] + STDERR_TRUNCATION_MARKER
    return collapsed


class _LineAssembler:
    """Splits a byte stream into lines under a bounded partial-line buffer.

    A child that writes megabytes without a newline must not be able to grow the
    parent, so an over-long partial is dropped and its remaining tail discarded up
    to the next newline (rather than being re-emitted as a spurious short line).
    """

    def __init__(self, max_line_bytes: int) -> None:
        self._buf = bytearray()
        self._max = max_line_bytes
        self._discarding = False

    def feed(self, chunk: bytes) -> list[tuple[bytes, bool]]:
        """Return ``(line, clamped)`` pairs; ``clamped`` marks a line cut to the cap."""
        lines: list[tuple[bytes, bool]] = []
        self._buf.extend(chunk)
        while True:
            idx = self._buf.find(b"\n")
            if idx < 0:
                break
            clamped = idx > self._max
            line = bytes(self._buf[: min(idx, self._max)])
            del self._buf[: idx + 1]
            if self._discarding:
                self._discarding = False  # that newline closed the over-long line
                continue
            # An over-long line that IS newline-terminated inside this chunk never
            # reaches the size check below, so clamp on emit too. The clamp is
            # REPORTED rather than applied quietly: a truncation the operator cannot
            # see is a silent failure (hard rule #7), and the cap here can sit below
            # the log cap, where the sanitizer would not mark it on length alone.
            lines.append((line, clamped))
        if len(self._buf) > self._max:
            # The line ran past the cap WITHOUT a newline in this chunk. Emit the
            # head we have — clamped, therefore marked — rather than dropping it.
            #
            # Dropping was a SILENT failure, and the one this file's own comments
            # promise not to commit. It was also easy to hit, not exotic:
            # `_MAX_LINE_BYTES == _READ_CHUNK_BYTES`, so ANY line spanning more than
            # one read() with no embedded newline took this path, vanished whole, and
            # left no log line and no truncation marker. A refusal row or diagnostic
            # caught in such a run disappeared undetected.
            lines.append((bytes(self._buf[: self._max]), True))
            self._buf.clear()
            self._discarding = True
        return lines

    def flush(self) -> list[tuple[bytes, bool]]:
        """Return the unterminated tail at EOF (empty when it was over-long)."""
        tail = b"" if self._discarding else bytes(self._buf)
        self._buf.clear()
        self._discarding = False
        return [(tail, False)] if tail else []


class ChildStderrPump:
    """Drains a launcher-spawned child's stderr continuously, for its whole life.

    Best-effort and **never raises**: a diagnostic drain must not preempt the
    caller's contracted spawn error, so every failure is caught and surfaced loudly
    with an explicit ``error_class`` rather than silently swallowed (hard rule #7).
    """

    def __init__(
        self, *, plugin_id: str, event: str, max_line_bytes: int = _MAX_LINE_BYTES
    ) -> None:
        self._plugin_id = plugin_id
        self._event = event
        self._assembler = _LineAssembler(max_line_bytes)
        self._rows: list[SandboxRefusalRow] = []
        self._lock = threading.Lock()  # the blocking driver consumes off-loop
        self._task: asyncio.Task[None] | None = None
        self._thread: threading.Thread | None = None

    @property
    def refusal_rows(self) -> tuple[SandboxRefusalRow, ...]:
        """Launcher refusal rows seen so far, for the caller's failure arm."""
        with self._lock:
            return tuple(self._rows)

    def _consume(self, line: bytes, *, clamped: bool = False) -> None:
        """Handle one drained stderr line. Never raises.

        A recognised sandbox refusal is logged at WARNING and carries its closed-vocab
        ``reason``: that is the line an operator must not miss, and the whole point of
        #520. Everything else is the adapter's own chatter — forwarded at DEBUG, not
        info, because a healthy adapter logs continuously to this stream and a chatty
        one would otherwise dominate the daemon's log volume. Nothing is dropped
        silently either way (hard rule #7).
        """
        try:
            rows = parse_launcher_refusal_rows(line)
            for row in rows:
                with self._lock:
                    if len(self._rows) < _MAX_RETAINED_REFUSAL_ROWS:
                        self._rows.append(row)
            # `truncated` reports that the RAW bytes were already clipped before
            # this call — which is exactly what `clamped` means and nothing else.
            # Comparing `len(line)` (BYTES) against STDERR_LOG_CAP_BYTES (applied by
            # the sanitizer as a CHARACTER cap) forced a false truncation marker onto
            # CJK/emoji stderr that was never actually cut. The sanitizer already
            # makes the character-length decision correctly on the decoded string.
            text = sanitize_child_stderr(line, cap=STDERR_LOG_CAP_BYTES, truncated=clamped)
            if text is None:
                return
            if rows:
                for row in rows:
                    log.warning(
                        "security.child_stderr.sandbox_refused",
                        plugin_id=self._plugin_id,
                        reason=row.reason,
                        environment=row.environment,
                        host_os=row.host_os,
                        source_event=self._event,
                    )
            else:
                log.debug(self._event, plugin_id=self._plugin_id, child_stderr=text)
        except Exception as exc:  # loud, never silent (hard rule #7)
            log.warning(
                "security.child_stderr.consume_failed",
                plugin_id=self._plugin_id,
                error_class=type(exc).__name__,
            )

    def _consume_chunk(self, chunk: bytes) -> None:
        for line, clamped in self._assembler.feed(chunk):
            self._consume(line, clamped=clamped)

    def _consume_tail(self) -> None:
        for line, clamped in self._assembler.flush():
            self._consume(line, clamped=clamped)

    # --- drivers -------------------------------------------------------------

    def start(self, stream: asyncio.StreamReader) -> None:
        """Drain an ``asyncio`` child's stderr on a background task."""
        self._task = asyncio.create_task(
            self._pump_stream(stream), name=f"child-stderr-pump[{self._plugin_id}]"
        )

    async def _pump_stream(self, stream: asyncio.StreamReader) -> None:
        try:
            while True:
                chunk = await stream.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                self._consume_chunk(chunk)
            self._consume_tail()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # loud, never silent (hard rule #7)
            log.warning(
                "security.child_stderr.pump_failed",
                plugin_id=self._plugin_id,
                error_class=type(exc).__name__,
            )

    def start_blocking(self, stream: IO[bytes]) -> None:
        """Drain a synchronous ``Popen`` child's stderr on a daemon thread.

        A daemon thread, not ``loop.run_in_executor``: ``asyncio.run`` JOINS the
        default executor at teardown, so an executor-hosted reader blocked on a live
        child's pipe would hang interpreter shutdown. A daemon thread cannot.
        """
        self._thread = threading.Thread(
            target=self._pump_blocking,
            args=(stream,),
            daemon=True,
            name=f"child-stderr-pump[{self._plugin_id}]",
        )
        self._thread.start()

    def _pump_blocking(self, stream: IO[bytes]) -> None:
        try:
            while True:
                # ``read1`` returns as soon as ANY bytes are available; plain ``read(n)``
                # would block until n bytes or EOF, re-creating the stall being fixed.
                chunk = stream.read1(_READ_CHUNK_BYTES)  # type: ignore[attr-defined]
                if not chunk:
                    break
                self._consume_chunk(chunk)
            self._consume_tail()
        except Exception as exc:  # loud, never silent (hard rule #7)
            log.warning(
                "security.child_stderr.pump_failed",
                plugin_id=self._plugin_id,
                error_class=type(exc).__name__,
            )

    async def aclose(self) -> None:
        """Stop the drain. Idempotent; never raises.

        The blocking driver's thread is a daemon and ends at EOF on the child's
        stderr, which the child's death guarantees — so there is nothing to join and
        no way for it to outlive the interpreter.
        """
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass  # expected — we just cancelled it
        except Exception as exc:  # a genuine pump fault must be loud (hard rule #7)
            log.warning(
                "security.child_stderr.pump_failed",
                plugin_id=self._plugin_id,
                error_class=type(exc).__name__,
            )


__all__ = [
    "STDERR_LOG_CAP_BYTES",
    "STDERR_TRUNCATION_MARKER",
    "STRIPPED_UNICODE_CATEGORIES",
    "ChildStderrPump",
    "sanitize_child_stderr",
]
