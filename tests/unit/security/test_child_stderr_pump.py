"""``ChildStderrPump`` — the continuous launcher-child stderr drain (#520).

The drain exists so a launcher sandbox refusal reaches a log line and an audit row
instead of the floor (CLAUDE.md hard rule #7), and so an unread pipe cannot wedge a
raw-``Popen`` child or grow an asyncio parent without bound.

Assertions go through ``structlog.testing.capture_logs``: these events are emitted
via structlog, which does NOT land in pytest's ``caplog``, so a caplog-based
assertion here would be vacuous.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import structlog

from alfred.security.child_stderr import (
    STDERR_TRUNCATION_MARKER,
    ChildStderrPump,
    sanitize_child_stderr,
)


def _refusal_line(reason: str = "environment_not_set") -> bytes:
    return (
        json.dumps(
            {
                "event": "supervisor.plugin.sandbox_refused",
                "plugin_id": "alfred.discord",
                "policy_ref": "",
                "reason": reason,
                "environment": "production",
                "host_os": "linux",
            }
        ).encode()
        + b"\n"
    )


async def _feed(pump: ChildStderrPump, payload: bytes) -> None:
    """Drive the async driver over an in-memory stream to EOF."""
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    pump.start(reader)
    await asyncio.sleep(0)  # let the pump task run
    for _ in range(50):
        if reader.at_eof() and not reader._buffer:
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_sandbox_refusal_is_logged_loudly_with_its_reason() -> None:
    """THE #520 case: a refusal must not vanish. It is a WARNING carrying the reason."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, _refusal_line())

    refusals = [e for e in logs if e["event"] == "security.child_stderr.sandbox_refused"]
    assert len(refusals) == 1, f"expected exactly one refusal log line, got {logs}"
    assert refusals[0]["reason"] == "environment_not_set"
    assert refusals[0]["log_level"] == "warning"


@pytest.mark.asyncio
async def test_ordinary_chatter_is_forwarded_at_debug_not_info() -> None:
    """A healthy adapter logs continuously; that must not dominate the daemon's logs."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, b"just an ordinary adapter log line\n")

    forwarded = [e for e in logs if e["event"] == "gateway.adapter.child_stderr"]
    assert len(forwarded) == 1
    assert forwarded[0]["log_level"] == "debug"
    assert forwarded[0]["child_stderr"] == "just an ordinary adapter log line"


@pytest.mark.asyncio
async def test_an_overlong_line_is_discarded_not_buffered() -> None:
    """A child that never emits a newline must not be able to grow the parent."""
    pump = ChildStderrPump(
        plugin_id="alfred.discord", event="gateway.adapter.child_stderr", max_line_bytes=1024
    )
    with structlog.testing.capture_logs() as logs:
        # An over-long unterminated run, then a normal line: the head is REPORTED
        # clamped, its tail discarded up to the newline, and the next line arrives.
        await _feed(pump, b"y" * 8192 + b"\nkept\n")

    forwarded = [e for e in logs if e["event"] == "gateway.adapter.child_stderr"]
    texts = [e["child_stderr"] for e in forwarded]
    assert len(texts) == 2, texts
    # The giant line is clamped, not buffered whole and not silently dropped...
    assert texts[0].endswith(STDERR_TRUNCATION_MARKER), "a clamp must be VISIBLE, not silent"
    assert len(texts[0]) <= 1024 + len(STDERR_TRUNCATION_MARKER)
    # ...and the line after it still arrives intact.
    assert texts[1] == "kept"


def test_sanitizer_strips_control_and_format_chars() -> None:
    """Forged newlines / ANSI / bidi must not reach a log field or an operator's term."""
    raw = b"before\x1b[31m\nforged: level=error\x00\xe2\x80\xaeafter"
    out = sanitize_child_stderr(raw, cap=4096)
    assert out is not None
    assert "\n" not in out and "\x1b" not in out and "\x00" not in out
    assert "‮" not in out  # bidi override (Cf)
    assert "before" in out and "after" in out


def test_sanitizer_returns_none_when_nothing_printable_remains() -> None:
    assert sanitize_child_stderr(b"\x00\x01\x02", cap=4096) is None


def test_sanitizer_marks_truncation_from_the_raw_byte_cap() -> None:
    """Load-bearing for multi-byte UTF-8: a byte-capped read can decode to < cap chars."""
    out = sanitize_child_stderr("é".encode() * 10, cap=4096, truncated=True)
    assert out is not None
    assert out.endswith(STDERR_TRUNCATION_MARKER)


@pytest.mark.asyncio
async def test_aclose_is_idempotent_and_never_raises() -> None:
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    await pump.aclose()  # never started
    reader = asyncio.StreamReader()
    pump.start(reader)
    await pump.aclose()
    await pump.aclose()


@pytest.mark.asyncio
async def test_an_overlong_run_spanning_chunks_is_reported_not_dropped() -> None:
    """A flood with no newline must be REPORTED clamped, never silently dropped.

    This case previously asserted the opposite — that the run vanished — which
    encoded a silent failure as the contract. CodeRabbit caught it: the head was
    discarded with no log line and no truncation marker, and it was easy to reach
    rather than exotic, since `_MAX_LINE_BYTES == _READ_CHUNK_BYTES` means ANY line
    spanning more than one read with no embedded newline took that path. A refusal
    row caught in such a run disappeared undetected.

    The head is now emitted clamped (so it carries the truncation marker), the
    remainder is swallowed up to the closing newline so no spurious short line is
    forged from it, and the next real line still arrives intact.
    """
    pump = ChildStderrPump(
        plugin_id="alfred.discord", event="gateway.adapter.child_stderr", max_line_bytes=512
    )
    with structlog.testing.capture_logs() as logs:
        reader = asyncio.StreamReader()
        pump.start(reader)
        reader.feed_data(b"z" * 4096)  # no newline: exceeds the cap mid-stream
        await asyncio.sleep(0.05)
        reader.feed_data(b"tail-of-the-clamped-line\nrecovered\n")
        reader.feed_eof()
        await asyncio.sleep(0.1)
        await pump.aclose()

    texts = [e["child_stderr"] for e in logs if e["event"] == "gateway.adapter.child_stderr"]
    assert len(texts) == 2, texts
    assert texts[0].startswith("z"), "the head of the over-long run was not reported"
    assert texts[0].endswith(STDERR_TRUNCATION_MARKER), "a clamp must be VISIBLE"
    assert "tail-of-the-clamped-line" not in texts[0], (
        "the swallowed remainder was forged into the reported line"
    )
    assert texts[1] == "recovered", "the reader did not resync onto the next line"


@pytest.mark.asyncio
async def test_a_consume_failure_is_logged_loudly_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drain fault must surface with its error_class, never silently (hard rule #7)."""

    def _boom(_line: bytes) -> object:
        raise RuntimeError("parser exploded")

    monkeypatch.setattr("alfred.security.child_stderr.parse_launcher_refusal_rows", _boom)
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, b"anything\n")

    failures = [e for e in logs if e["event"] == "security.child_stderr.consume_failed"]
    assert len(failures) == 1
    assert failures[0]["error_class"] == "RuntimeError"
    assert failures[0]["log_level"] == "warning"


@pytest.mark.asyncio
async def test_a_stream_read_failure_is_logged_loudly_not_swallowed() -> None:
    """A torn pipe must not raise out of the pump and preempt the caller's error."""

    class _ExplodingReader:
        async def read(self, _n: int) -> bytes:
            raise OSError("pipe torn")

    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        pump.start(_ExplodingReader())  # type: ignore[arg-type]
        await asyncio.sleep(0.05)
        await pump.aclose()

    failures = [e for e in logs if e["event"] == "security.child_stderr.pump_failed"]
    assert len(failures) == 1
    assert failures[0]["error_class"] == "OSError"


def test_a_blocking_read_failure_is_logged_loudly_not_swallowed() -> None:
    """Same contract on the thread driver, which cannot propagate to the caller at all."""

    class _ExplodingStream:
        def read1(self, _n: int) -> bytes:
            raise OSError("pipe torn")

    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        pump.start_blocking(_ExplodingStream())  # type: ignore[arg-type]
        pump._thread.join(timeout=5)

    failures = [e for e in logs if e["event"] == "security.child_stderr.pump_failed"]
    assert len(failures) == 1
    assert failures[0]["error_class"] == "OSError"


@pytest.mark.asyncio
async def test_an_unprintable_line_emits_no_empty_field_noise() -> None:
    """Nothing printable left -> no log line at all, rather than an empty field."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, b"\x00\x01\x02\n")

    assert [e for e in logs if e["event"] == "gateway.adapter.child_stderr"] == []


@pytest.mark.asyncio
async def test_an_unterminated_final_line_is_still_drained_at_eof() -> None:
    """A child that dies mid-line must not lose that line — it may name the reason."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, b"died before the newline")

    texts = [e["child_stderr"] for e in logs if e["event"] == "gateway.adapter.child_stderr"]
    assert texts == ["died before the newline"]


@pytest.mark.asyncio
async def test_aclose_cancels_a_pump_blocked_on_read() -> None:
    """aclose must actually stop a live drain, not leave a task on a dead child."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    reader = asyncio.StreamReader()  # never fed, never EOF: the pump blocks in read()
    pump.start(reader)
    await asyncio.sleep(0.05)  # let it reach the blocking read
    task = pump._task
    assert task is not None and not task.done()

    await pump.aclose()

    assert task.cancelled(), "the pump task survived aclose()"


@pytest.mark.asyncio
async def test_multibyte_stderr_is_not_falsely_marked_truncated() -> None:
    """A line over the BYTE cap but under the CHARACTER cap was never cut.

    `truncated` reports that the raw bytes were already clipped. Comparing
    `len(line)` in BYTES against a constant the sanitizer applies as a CHARACTER
    cap stamped a truncation marker onto CJK/emoji stderr that was fully intact —
    a false loss report in a field an operator reads to diagnose a refusal.
    """
    # 3 bytes per char: over the 4096-BYTE cap, comfortably under it in CHARACTERS.
    line = ("世" * 2000).encode()
    assert len(line) > 4096 and len("世" * 2000) < 4096

    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, line + b"\n")

    texts = [e["child_stderr"] for e in logs if e["event"] == "gateway.adapter.child_stderr"]
    assert len(texts) == 1
    assert not texts[0].endswith(STDERR_TRUNCATION_MARKER), (
        "content that was never cut was reported as truncated"
    )
    assert len(texts[0]) == 2000


@pytest.mark.asyncio
async def test_aclose_logs_a_pump_fault_instead_of_swallowing_it() -> None:
    """A fault surfacing at close must be LOUD, not blanket-suppressed.

    `aclose` previously wrapped the await in
    `contextlib.suppress(asyncio.CancelledError, Exception)`, so a genuine pump
    fault that only surfaced when the task was reaped vanished — a silent failure
    in a security path (hard rule #7). It now distinguishes the CancelledError we
    caused (expected) from a real fault (logged with its `error_class`).
    """

    async def _explode() -> None:
        raise RuntimeError("pump died on reap")

    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    pump._task = asyncio.create_task(_explode())
    await asyncio.sleep(0.01)  # let it fail before we close

    with structlog.testing.capture_logs() as logs:
        await pump.aclose()  # must not raise

    failures = [e for e in logs if e["event"] == "security.child_stderr.pump_failed"]
    assert len(failures) == 1, f"the fault was swallowed: {logs}"
    assert failures[0]["error_class"] == "RuntimeError"


@pytest.mark.asyncio
async def test_a_refusal_is_reported_even_when_it_sanitizes_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The WARNING must not be gated on how the chatter happens to format.

    `_consume` returned early on `text is None`, so a refusal that parsed cleanly
    as a row but left nothing printable after Cc/Cf stripping was silently dropped
    — in the drain whose entire purpose is that refusals stop disappearing.

    The sanitizer is forced to return `None` rather than hoping a payload does it:
    a refusal row is valid JSON and therefore always printable, so the obvious
    payload could never reach the branch and the case would have passed with the
    early return restored. (It did — CodeRabbit caught exactly that.)
    """
    monkeypatch.setattr("alfred.security.child_stderr.sanitize_child_stderr", lambda *a, **k: None)
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    with structlog.testing.capture_logs() as logs:
        await _feed(pump, _refusal_line())

    refusals = [e for e in logs if e["event"] == "security.child_stderr.sandbox_refused"]
    assert len(refusals) == 1, f"the refusal was gated on formatting: {logs}"
    assert refusals[0]["reason"] == "environment_not_set"


@pytest.mark.asyncio
async def test_a_second_start_is_a_loud_programming_error() -> None:
    """Silently orphaning the first driver would leave it reading a dead stream."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    pump.start(asyncio.StreamReader())
    try:
        with pytest.raises(RuntimeError, match="already started"):
            pump.start(asyncio.StreamReader())
    finally:
        await pump.aclose()


def test_a_second_start_blocking_is_a_loud_programming_error() -> None:
    """Same contract on the thread driver."""

    class _Eof:
        def read1(self, _n: int = -1) -> bytes:
            return b""

    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    pump.start_blocking(_Eof())  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="already started"):
        pump.start_blocking(_Eof())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_drained_on_a_pump_that_never_started_is_a_no_op() -> None:
    """The close path calls this unconditionally, including on a failed spawn."""
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    await pump.drained()  # must not raise or hang
