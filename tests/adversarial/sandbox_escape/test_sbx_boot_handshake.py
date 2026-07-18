"""Executable counterparts to sbx-2026-021..024 (#443 PR2 two-frame boot handshake).

PURE-UNIT (monkeypatched ``subprocess.Popen``, no bwrap, no docker) -- kept OUT of
``test_sbx_corpus_executable.py`` deliberately (te-005): that module mixes in
``@_bwrap_required``-marked tests, and a pure-unit test placed there risks an
ambient "bwrap absent" skip reading as a pass when it never ran (the #245
paper-only-gate pattern). This module carries no bwrap/docker skip marker at all,
so a missing bwrap on the runner (macOS dev, some CI legs) can never mask these
four assertions.

Reuses the SAME fakes + helpers the source-of-truth unit suites already use
(``_FakePopen`` / ``_boot_frames`` from ``test_quarantine_child_io.py``,
``_REFUSAL_ROW`` from ``test_quarantine_child_io_refusal_audit.py``, the
``_load()`` YAML loader from ``test_sbx_corpus_executable.py``) rather than a
second hardcoded copy -- the #428 lesson.
"""

from __future__ import annotations

import socket
import time
from typing import Any

import pytest
import structlog.testing

import alfred.security.quarantine_child.__main__ as child_main
import alfred.security.quarantine_child_io as qcio
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    spawn_quarantine_child_io,
)
from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor
from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor
from tests.adversarial.sandbox_escape.test_sbx_corpus_executable import _load
from tests.unit.security.test_quarantine_child_io import _boot_frames, _FakePopen
from tests.unit.security.test_quarantine_child_io_refusal_audit import _REFUSAL_ROW


def _patch_spawn_seam(monkeypatch: pytest.MonkeyPatch, fake: _FakePopen) -> None:
    """Patch the three seams every ``spawn_quarantine_child_io`` unit test patches.

    Mirrors ``test_quarantine_child_io.py``'s ``_spawn_capture`` fixture: the
    real ``os.pipe()`` / ``os.dup`` / ``os.close`` plumbing runs unpatched (it is
    hermetic against the pytest process's own fd table, per that fixture's
    established use), only the subprocess exec, the fd-3 key delivery, and the
    fd-3-onto-3 ``dup2`` are faked so no real bwrap/launcher process is ever spawned.
    """
    monkeypatch.setattr(qcio.subprocess, "Popen", lambda *_a, **_k: fake)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", lambda **_k: None)
    monkeypatch.setattr(qcio.os, "dup2", lambda _s, d, *_a, **_k: d)


class _CapturingRecorder:
    """A ``SandboxRefusalRecorder`` double that just remembers what it was given.

    Mirrors ``test_quarantine_child_io_refusal_audit.py``'s ``_CapturingRecorder``
    -- deriving "was a row recorded" from what the recorder actually received,
    never from re-reading the drain gate's own internal predicate
    (``domain_a_test_that_asks_the_code_if_the_code_is_right``).
    """

    def __init__(self) -> None:
        self.rows: list[SandboxRefusalRow] = []

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        self.rows.extend(rows)


class _SlowEofStdout:
    """A raw stdout stand-in that returns ZERO bytes (a real EOF) after a delay.

    Read inside ``read_frame``'s executor thread, so the delay never blocks the
    event loop. Simulates a launcher that is slow to reach its own conclusion
    (resolving environment / host-OS / manifest / sandbox-kind) before genuinely
    refusing (sbx-2026-023) -- distinct from a WEDGED child, which never reaches
    EOF at all and instead trips ``_READ_FRAME_TIMEOUT_S``.
    """

    def __init__(self, delay_s: float) -> None:
        self._delay_s = delay_s

    def read(self, _n: int) -> bytes:
        time.sleep(self._delay_s)
        return b""


# ---------------------------------------------------------------------------
# sbx-2026-021 -- THE core-001 regression oracle.
# ---------------------------------------------------------------------------


async def test_sbx_2026_021_boot_barrier_refusal_reaches_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine (slow-reason) launcher refusal refuses BOOT with a real dispatch.

    Modelled on the REAL-REGISTRY tests in ``test_sandbox_refusal_audit.py``
    (``test_record_real_dispatch_against_declared_hookpoint`` et al.) -- NOT that
    file's dominant ``_fake_invoke``-monkeypatch fixture. Calling the real
    ``declare_hookpoints()`` (the same function ``Supervisor.__init__``
    delegates to) against the real ``get_registry()`` singleton, then running
    ``SandboxRefusalAuditor.record`` UNPATCHED, means the assertion below on the
    ABSENCE of ``refusal_record_failed`` is what actually proves the
    ``fail_closed`` T0 hookpoint dispatch succeeded (arch-002 / te-003): a
    monkeypatched ``invoke`` would make that assertion pass even on a build
    where the hookpoint was never declared, certifying nothing.

    Non-vacuity: temporarily commenting out the
    ``await _await_boot_handshake(child_io, child_module=child_module)`` line
    in ``quarantine_child_io.spawn_quarantine_child_io`` makes this test FAIL
    (the ``pytest.raises(QuarantineChildSpawnError)`` context manager sees no
    exception -- the spawn returns the half-refused child instead of refusing
    boot) -- exactly the threat this entry names.
    """
    payload = _load("sbx-2026-021")
    assert payload.expected_outcome == "refused"
    assert payload.payload["pinned_reason"] == "sandbox_block_missing"

    declare_supervisor()  # real registry -- the same call Supervisor.__init__ makes at boot
    rows: list[dict[str, Any]] = []

    class _CapturingWriter:
        async def append_schema(self, **kwargs: Any) -> None:
            rows.append(kwargs)

    recorder = SandboxRefusalAuditor(audit_writer=_CapturingWriter())

    fake = _FakePopen(stdout_frames=[], stderr_bytes=_REFUSAL_ROW)
    fake.returncode = 1  # the launcher exited pre-exec -- poll() returns non-None
    _patch_spawn_seam(monkeypatch, fake)

    with structlog.testing.capture_logs() as logs, pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)

    assert len(rows) == 1, f"expected exactly one attributed row, got {rows!r}"
    assert rows[0]["subject"]["reason"] == "sandbox_block_missing"
    # THE core-001 assertion: the fail_closed dispatch actually FIRED -- it was
    # NOT swallowed as refusal_record_failed (exactly what an undeclared
    # hookpoint produces). A row-only assertion above passes straight through
    # a core-001 regression, because SandboxRefusalAuditor.record calls
    # append_schema BEFORE invoke() -- this is the load-bearing signal.
    failed = [e for e in logs if e["event"] == "security.quarantine_child.refusal_record_failed"]
    assert not failed, f"hookpoint dispatch was swallowed as refusal_record_failed: {failed!r}"


# ---------------------------------------------------------------------------
# sbx-2026-022 -- post-handshake forgery is inert.
# ---------------------------------------------------------------------------


async def test_sbx_2026_022_post_handshake_forgery_not_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that completed the boot handshake cannot forge a refusal row after.

    Spawns with stdout carrying exactly the two boot frames (the handshake
    completes cleanly -- ``spawn_quarantine_child_io`` returns successfully),
    then drives one further ``read_frame()`` call (mirroring the extract-RPC
    drain) that hits EOF against the now-exhausted stdout buffer while stderr
    carries a forged, schema-valid ``sandbox_refused`` row. "No row recorded"
    is derived from the CAPTURING recorder double, never from re-reading
    ``_child_wrote_stdout`` itself.
    """
    payload = _load("sbx-2026-022")
    assert payload.expected_outcome == "neutralized"

    recorder = _CapturingRecorder()
    fake = _FakePopen(stdout_frames=list(_boot_frames()), stderr_bytes=_REFUSAL_ROW)
    fake.returncode = 1  # the child has already exited by the time the drain runs
    _patch_spawn_seam(monkeypatch, fake)

    child_io = await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    # The boot handshake completed (both frames were read) -- _child_wrote_stdout
    # latched True on the FIRST byte, closing the drain gate for this child's life.
    with pytest.raises(QuarantineChildSpawnError):
        await child_io.read_frame()  # the forged row rides this crash's stderr
    assert recorder.rows == [], f"a post-handshake forged row was recorded: {recorder.rows!r}"


# ---------------------------------------------------------------------------
# sbx-2026-023 -- a delayed-but-genuine refusal still refuses boot.
# ---------------------------------------------------------------------------


async def test_sbx_2026_023_slow_refusal_still_refuses_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A launcher slow to reach its own EOF still refuses boot -- no clock in the gate.

    The delay is short (well under ``_READ_FRAME_TIMEOUT_S``) so the resulting
    failure is a genuine zero-byte ``_TruncatedFrameError`` (a real EOF), never
    a ``TimeoutError`` -- the two are attributed differently by the drain gate.
    """
    payload = _load("sbx-2026-023")
    assert payload.expected_outcome == "refused"
    delay_s = float(payload.payload["simulated_delay_seconds"])

    recorder = _CapturingRecorder()
    fake = _FakePopen(stdout_frames=[], stderr_bytes=_REFUSAL_ROW)
    fake.stdout = _SlowEofStdout(delay_s)  # type: ignore[assignment]
    fake.returncode = 1
    _patch_spawn_seam(monkeypatch, fake)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "sandbox_block_missing"


# ---------------------------------------------------------------------------
# sbx-2026-024 -- the child boot path performs no external IO (defence in depth).
# ---------------------------------------------------------------------------


def test_sbx_2026_024_child_boot_performs_no_external_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_build_provider`` never opens a socket -- defence-in-depth over ``--unshare-net``.

    Lightweight by design (payload note): the kernel-enforced containment is
    the shipped bwrap policy's ``--unshare-net``, asserted directly against the
    real policy bytes by sbx-2026-005. This entry catches a FUTURE regression
    at the Python level (e.g. a PR-S4-11c-2c real-client cutover that eagerly
    opens a connection at construction time) before it would ever reach that
    kernel boundary.
    """
    payload = _load("sbx-2026-024")
    assert payload.expected_outcome == "neutralized"
    assert payload.payload["expected_provider_type"] == "_DeterministicProvider"

    def _boom_socket(*_a: Any, **_k: Any) -> None:
        raise AssertionError("child boot path attempted to construct a socket")

    monkeypatch.setattr(socket, "socket", _boom_socket)
    provider = child_main._build_provider("sk-test-quarantine-key")
    assert isinstance(provider, child_main._DeterministicProvider)
