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


# ---------------------------------------------------------------------------
# sec-001/arch-001 (#433 follow-up): gate recording to the LAUNCHER-authored
# signal. A genuine refusal is read_frame EOF with NO frame EVER read (the
# launcher exited pre-exec, above). A crashed/wedged EXEC'D child is
# CHILD-authored stderr — a malicious child could otherwise forge a
# schema-valid sandbox_refused line and get an attributed audit row +
# fail_closed hookpoint dispatch out of it. Both cases below carry the exact
# same forged _REFUSAL_ROW in stderr but must record NOTHING.
# ---------------------------------------------------------------------------


def _exited_fake_with_frame(frame_body: bytes, stderr: bytes):
    # A real frame is read successfully ONCE (simulating a live, exec'd
    # quarantine child that produced at least one reply), then the buffer is
    # drained -> the NEXT read_frame call hits EOF mid-header. returncode is
    # preset so the drain's ``poll() is not None`` gate passes once we get
    # there (mirrors ``_exited_fake``).
    from tests.unit.security.test_quarantine_child_io import _FakePopen, _framed

    fake = _FakePopen(stdout_frames=[_framed(frame_body)], stderr_bytes=stderr)
    fake.returncode = 1
    return fake


async def test_post_frame_read_failure_not_recorded() -> None:
    """A crash AFTER a frame was read is CHILD-authored -- never recorded."""
    recorder = _CapturingRecorder()
    fake = _exited_fake_with_frame(b'{"jsonrpc":"2.0","result":{"ok":1}}', _REFUSAL_ROW)
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.read_frame()  # first read succeeds -> sets _frame_read = True
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()  # buffer now empty -> EOF mid-frame (a crash)
    assert recorder.rows == []


async def test_launcher_authored_eof_with_no_refusal_row_records_nothing() -> None:
    """The gate passes (failure=True, no prior frame) but stderr has NO refusal row.

    Branch-coverage fill for ``_record_launcher_refusals``'s ``if rows:``: the
    gate letting a genuine pre-exec EOF through does not itself guarantee the
    stderr parses to a row -- benign launcher stderr with nothing recognisable
    must still record nothing (distinct from the child-authored-suppression
    tests above, which never even reach ``_record_launcher_refusals``).
    """
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(
        _exited_fake(b"some benign launcher log line\n"), refusal_recorder=recorder
    )
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert recorder.rows == []


async def test_aclose_with_refusal_row_not_recorded() -> None:
    """aclose (failure=False) never records -- not the launcher-refusal signal.

    Even though stderr carries a schema-valid ``sandbox_refused`` row and no
    frame was ever read, a clean teardown is not itself the ``read_frame``
    EOF signal the gate keys on -- only the ``read_frame`` failure arm may
    attribute a row (see the drain's ``_log_child_stderr`` docstring).
    """
    recorder = _CapturingRecorder()
    fake = _exited_fake(_REFUSAL_ROW)
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.aclose()
    assert recorder.rows == []
