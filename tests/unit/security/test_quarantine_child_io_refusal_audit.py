"""The read_frame drain records launcher refusals (#433).

A refused launcher (``bin/alfred-plugin-launcher.sh``) exits BEFORE ``exec``ing
the quarantined child, so the child never produces a frame -> ``read_frame``
hits EOF -> ``_log_child_stderr(failure=True)`` drains the stderr carrying the
``sandbox_refused`` JSON row (the interception point empirically confirmed in
Task 0). This module drives that drain against a fake ``Popen`` (the
``_FakePopen`` convention from ``test_quarantine_child_io.py``) + a fake
:class:`alfred.security.sandbox_refusal_audit.SandboxRefusalRecorder`, never a
real bwrap subprocess.
"""

from __future__ import annotations

import pytest

from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _SubprocessChildIO,
)

_REFUSAL_ROW = (
    b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"alfred.quarantined-llm",'
    b'"reason":"sandbox_block_missing","environment":"development","host_os":"linux"}\n'
)


class _CapturingRecorder:
    """A ``SandboxRefusalRecorder`` double that just remembers what it was given."""

    def __init__(self) -> None:
        self.rows: list[SandboxRefusalRow] = []

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        self.rows.extend(rows)


def _exited_fake(stderr: bytes):
    # Reuse the existing _FakePopen convention (test_quarantine_child_io.py:106):
    # empty stdout_frames -> read_frame hits EOF; preset returncode so the drain's
    # ``poll() is not None`` gate fires; stderr carries the refusal JSON.
    from tests.unit.security.test_quarantine_child_io import _FakePopen

    fake = _FakePopen(stdout_frames=[], stderr_bytes=stderr)
    fake.returncode = 1  # launcher exited (refusal) — poll() returns non-None
    return fake


async def test_refusal_recorded_on_read_frame_eof() -> None:
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW), refusal_recorder=recorder)
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "sandbox_block_missing"


async def test_default_none_records_nothing() -> None:
    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW))  # no recorder
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    # no crash, unchanged behavior


async def test_record_failure_does_not_mask_refusal() -> None:
    """A recorder that raises must NOT mask the ``read_frame`` refusal error.

    Test-guidance override (the brief's ``caplog``-based version is a dead
    param — structlog events do not land in ``caplog.records`` in this repo,
    see ``test_quarantine_child_io.py:643-647``): use
    ``structlog.testing.capture_logs`` and assert BOTH that the primary
    ``QuarantineChildSpawnError`` still propagates AND that the guard logs
    ``refusal_record_failed`` loudly (CLAUDE.md hard rule #7 — no silent
    swallow of a security-audit failure).
    """
    import structlog.testing

    class _BoomRecorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
            raise RuntimeError("audit down")

    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW), refusal_recorder=_BoomRecorder())
    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(QuarantineChildSpawnError),  # the PRIMARY error still wins
    ):
        await io.read_frame()
    failed = [e for e in logs if e["event"] == "security.quarantine_child.refusal_record_failed"]
    assert len(failed) == 1  # loud, not silent
    assert failed[0]["error_class"] == "RuntimeError"


async def test_clean_teardown_records_nothing() -> None:
    # stderr with no sandbox_refused row (child ran) -> aclose drains -> no record.
    recorder = _CapturingRecorder()
    fake = _exited_fake(b"some benign child log line\n")
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.aclose()
    assert recorder.rows == []
