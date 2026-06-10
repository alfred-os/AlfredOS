"""``crash_emitter`` emits ``adapter.crashed`` then exits (Task G3, #206).

A top-level uncaught exception in the adapter must (a) tell the host so its
supervisor breaker can trip, and (b) exit non-zero so the supervisor sees the
process die. The crash detail is scrubbed by the in-plugin DLP-lite (sec-2)
BEFORE it crosses stdio — a leaked secret in an exception string never leaves
the subprocess raw.

Behaviour pinned here:

1. A synthetic exception → one ``adapter.crashed`` frame written to the sink,
   flushed, then ``SystemExit(1)``.
2. ``detail`` is ``scrub_in_plugin(str(exc))`` truncated to ≤256 chars — a
   planted secret shape is redacted.
3. ``KeyboardInterrupt`` / ``SystemExit`` are operator shutdowns: NO crash
   notification, re-raised unchanged.
4. A broken-pipe write failure (host already gone) is swallowed; the emitter
   still exits 1.
5. Re-entry guard: a second crash during crash handling emits only one frame.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from plugins.alfred_discord.crash_emitter import CrashEmitter

_ADAPTER = "discord"


class _SyncSink:
    def __init__(self, *, raises: BaseException | None = None) -> None:
        self.frames: list[Mapping[str, object]] = []
        self._raises = raises

    def emit_sync(self, frame: Mapping[str, object]) -> None:
        if self._raises is not None:
            raise self._raises
        self.frames.append(frame)


def _emitter(sink: _SyncSink) -> CrashEmitter:
    return CrashEmitter(adapter_id=_ADAPTER, sink=sink)


def test_crash_emits_frame_then_exits() -> None:
    sink = _SyncSink()
    emitter = _emitter(sink)
    with pytest.raises(SystemExit) as excinfo:
        emitter.handle_crash(RuntimeError("boom"))
    assert excinfo.value.code == 1
    assert len(sink.frames) == 1
    frame = sink.frames[0]
    assert frame["method"] == "adapter.crashed"
    params = frame["params"]
    assert isinstance(params, Mapping)
    assert params["error_class"] == "RuntimeError"


def test_detail_is_dlp_scrubbed_and_bounded() -> None:
    sink = _SyncSink()
    emitter = _emitter(sink)
    planted = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    with pytest.raises(SystemExit):
        emitter.handle_crash(RuntimeError(f"leaked {planted} oops " + "x" * 400))
    params = sink.frames[0]["params"]
    assert isinstance(params, Mapping)
    detail = params["detail"]
    assert isinstance(detail, str)
    assert planted not in detail
    assert len(detail) <= 256


def test_keyboard_interrupt_not_treated_as_crash() -> None:
    sink = _SyncSink()
    emitter = _emitter(sink)
    with pytest.raises(KeyboardInterrupt):
        emitter.handle_crash(KeyboardInterrupt())
    assert sink.frames == []


def test_system_exit_passes_through() -> None:
    sink = _SyncSink()
    emitter = _emitter(sink)
    with pytest.raises(SystemExit):
        emitter.handle_crash(SystemExit(7))
    assert sink.frames == []


def test_broken_pipe_swallowed_still_exits() -> None:
    sink = _SyncSink(raises=BrokenPipeError("host gone"))
    emitter = _emitter(sink)
    with pytest.raises(SystemExit) as excinfo:
        emitter.handle_crash(RuntimeError("boom"))
    assert excinfo.value.code == 1


def test_re_entry_guard_emits_once() -> None:
    sink = _SyncSink()
    emitter = _emitter(sink)
    with pytest.raises(SystemExit):
        emitter.handle_crash(RuntimeError("first"))
    # A second crash after the guard latched emits nothing more and re-exits.
    with pytest.raises(SystemExit):
        emitter.handle_crash(RuntimeError("second"))
    assert len(sink.frames) == 1
