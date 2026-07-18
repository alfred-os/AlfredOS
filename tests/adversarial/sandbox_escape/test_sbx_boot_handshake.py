"""Executable counterparts to sbx-2026-021..024 (#443 PR2 two-frame boot handshake).

PURE-UNIT (monkeypatched ``subprocess.Popen``, no bwrap, no docker) -- kept OUT of
``test_sbx_corpus_executable.py`` deliberately (te-005): that module mixes in
``@_bwrap_required``-marked tests, and a pure-unit test placed there risks an
ambient "bwrap absent" skip reading as a pass when it never ran (the #245
paper-only-gate pattern). This module carries no bwrap/docker skip marker at all,
so a missing bwrap on the runner (macOS dev, some CI legs) can never mask these
four assertions.

Uses adversarial-LOCAL fakes (``_FakePopen`` / ``_boot_frames`` defined in THIS
module, not imported from a mutable unit-test helper) so a release-blocking
adversarial test never inherits behaviour from a unit suite that can change out
from under it (test-isolation, CR-3). It still reuses the ``_load()`` YAML loader
from ``test_sbx_corpus_executable.py`` and derives each fake refusal-row stderr
FROM the corpus YAML payload (``_corpus_refusal_row()``) so a payload change can
never leave these tests silently stale -- the #428 single-source-of-truth lesson.
The sbx-021 oracle drives a RealGate-backed ``make_allow_system_gate`` (not the
``make_permissive_fixture_gate`` shim) so a RealGate grant-policy regression stays
visible (CLAUDE.md hard rule #2, CR-4).
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
from alfred.hooks import HookRegistry, get_registry, set_registry
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    spawn_quarantine_child_io,
)
from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor
from alfred.supervisor.fd3_key_delivery import ProviderKeyDeliveryError
from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor
from tests.adversarial.payload_schema import AdversarialPayload
from tests.adversarial.sandbox_escape.test_sbx_corpus_executable import _load
from tests.helpers.gates import make_allow_system_gate

# --- adversarial-LOCAL subprocess doubles (CR-3: a release-blocking test imports no --------
# behaviour from a mutable unit-test helper; a minimal ``subprocess.Popen``-shaped shape) ---


def _boot_frames() -> list[bytes]:
    """The two frames a real child emits at boot (hello + ready), for a fake stdout (#443)."""
    return [HELLO_FRAME, READY_FRAME]


class _FakeStdout:
    """Raw-pipe stand-in: synchronous ``read(n)`` over a length-prefixed stream, ``b""`` at EOF."""

    def __init__(self, frames: list[bytes]) -> None:
        self._buf = bytearray(b"".join(frames))

    def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk


class _FakeStderr:
    """Raw-pipe stderr stand-in: ``read(n)`` over a byte buffer, plus an observable ``close()``."""

    def __init__(self, data: bytes = b"") -> None:
        self._buf = bytearray(data)
        self.closed = False

    def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakeStdin:
    """A no-op stdin pipe stand-in (the sbx tests only read)."""

    def write(self, data: bytes) -> None:
        pass

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class _FakePopen:
    """Minimal ``subprocess.Popen``-shaped double — adversarial-LOCAL (CR-3).

    The real spawn's ``Popen`` call is intercepted before any fork/exec, so this asserts
    purely on what the SEAM decided; it forks nothing. Copies only the shape these tests
    need (``stdin`` / ``stdout`` / ``stderr`` / ``poll`` / ``terminate`` / ``wait`` /
    ``returncode``) so it never inherits behaviour from the unit suite's ``_FakePopen``.
    """

    def __init__(self, stdout_frames: list[bytes], stderr_bytes: bytes = b"") -> None:
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(stdout_frames)
        self.stderr = _FakeStderr(stderr_bytes)
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1

    def wait(self) -> int:
        self.wait_calls += 1
        self.returncode = 0
        return 0


def _corpus_refusal_row(payload: AdversarialPayload, field: str) -> bytes:
    """The launcher-authored refusal row, sourced FROM the corpus YAML (single source of truth).

    Deriving the fake's stderr from the corpus payload (not a hardcoded copy imported from
    another test module) means a changed corpus row can never leave this executable test
    asserting against stale bytes while still reading green -- the #428 lesson. The launcher
    emits one JSON line terminated by a newline; the YAML folded scalar (``>-``) strips the
    trailing newline, so re-add exactly one to match the real launcher stderr shape (the
    parser ``splitlines()``s either way, so this is fidelity, not a parse requirement).
    """
    row = payload.payload[field]
    assert isinstance(row, str), f"corpus field {field!r} must carry the row as a string"
    return row.encode("utf-8") + b"\n"


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
    file's dominant ``_fake_invoke``-monkeypatch fixture. It swaps in a FRESH but
    REAL ``HookRegistry`` (the default singleton carries a fail-closed
    ``_DenyAllGate`` that would refuse the positive-dispatch subscriber below), calls
    the real ``declare_hookpoints()`` (the same function ``Supervisor.__init__``
    delegates to) on it, and runs ``SandboxRefusalAuditor.record`` UNPATCHED -- so the
    real, unpatched ``invoke`` resolves this registry. A monkeypatched ``invoke`` would
    make the dispatch assertions vacuous (they would pass even on a build where the
    hookpoint was never declared -- arch-002 / te-003), so it is deliberately avoided.

    The oracle proves dispatch on TWO independent signals: (a) the ABSENCE of
    ``refusal_record_failed`` (an undeclared hookpoint would log it), AND (b) a REAL
    registered T0 subscriber actually FIRED with the attributed reason. Signal (b) is
    the stronger oracle: a declared hookpoint with ZERO subscribers is a dispatch no-op
    that ALSO passes (a), so registering a subscriber and asserting it ran proves
    POSITIVE dispatch, not merely the absence of a failure.

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

    # A FRESH real registry with a RealGate-backed system-tier grant, swapped in for the
    # duration: the default singleton's _DenyAllGate would refuse the subscriber
    # registration, and declare_supervisor(registry) puts the supervisor hookpoints on
    # THIS registry (the same declaration Supervisor.__init__ delegates to). The
    # auditor's record() -> invoke() resolves this same registry via get_registry().
    #
    # CR-4 / CLAUDE.md hard rule #2: use the RealGate-backed make_allow_system_gate (an
    # EXPLICIT scoped grant), NOT the make_permissive_fixture_gate shim whose docstring
    # warns it is not RealGate-shaped ("a RealGate regression would be invisible"). The
    # grant is scoped to the SUBSCRIBER's attribution: HookRegistry.register consults
    # gate.check(plugin_id=hook_fn.__module__, ...), and the subscriber below is defined
    # in THIS module, so its plugin_id is __name__. A RealGate grant-policy regression
    # (wrong plugin_id / hookpoint matching) now surfaces here as a refused registration
    # -> an empty fired_reasons -> a red test, instead of being papered over by the shim.
    registry = HookRegistry(
        gate=make_allow_system_gate(
            plugin_id=__name__, hookpoint="supervisor.plugin.sandbox_refused"
        ),
        strict_declarations=True,
    )
    prior = get_registry()
    set_registry(registry)
    try:
        declare_supervisor(registry)

        # A REAL fixture T0 subscriber: proves POSITIVE dispatch (signal (b) above).
        fired_reasons: list[str] = []

        async def _sandbox_refused_subscriber(ctx: Any) -> None:
            # An implicit None return is the subscriber contract's "no change / proceed"
            # for a post-kind hook (the dispatcher keys off the None return).
            fired_reasons.append(ctx.input["reason"])

        registry.register(
            hook_fn=_sandbox_refused_subscriber,
            hookpoint="supervisor.plugin.sandbox_refused",
            kind="post",
            tier="system",
        )

        rows: list[dict[str, Any]] = []

        class _CapturingWriter:
            async def append_schema(self, **kwargs: Any) -> None:
                rows.append(kwargs)

        recorder = SandboxRefusalAuditor(
            audit_writer=_CapturingWriter(), host_os="linux", environment="development"
        )

        fake = _FakePopen(
            stdout_frames=[], stderr_bytes=_corpus_refusal_row(payload, "launcher_refusal_row")
        )
        fake.returncode = 1  # the launcher exited pre-exec -- poll() returns non-None
        _patch_spawn_seam(monkeypatch, fake)

        with structlog.testing.capture_logs() as logs, pytest.raises(QuarantineChildSpawnError):
            await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)

        assert len(rows) == 1, f"expected exactly one attributed row, got {rows!r}"
        assert rows[0]["subject"]["reason"] == payload.payload["pinned_reason"]
        # Signal (a) -- the fail_closed dispatch was NOT swallowed as
        # refusal_record_failed (exactly what an undeclared hookpoint produces). A
        # row-only assertion passes straight through a core-001 regression, because
        # SandboxRefusalAuditor.record calls append_schema BEFORE invoke().
        failed = [
            e for e in logs if e["event"] == "security.quarantine_child.refusal_record_failed"
        ]
        assert not failed, f"hookpoint dispatch was swallowed as refusal_record_failed: {failed!r}"
        # Signal (b) -- the load-bearing POSITIVE-dispatch proof: the real registered T0
        # subscriber RAN once with the attributed reason. Without this, the oracle only
        # proves "no dispatch error was logged", which a zero-subscriber hookpoint also
        # satisfies while dispatching to nobody.
        assert fired_reasons == [payload.payload["pinned_reason"]], (
            f"expected the T0 subscriber to fire once with the attributed reason, "
            f"got {fired_reasons!r}"
        )
    finally:
        set_registry(prior)


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
    fake = _FakePopen(
        stdout_frames=list(_boot_frames()),
        stderr_bytes=_corpus_refusal_row(payload, "forged_refusal_row"),
    )
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
    fake = _FakePopen(
        stdout_frames=[], stderr_bytes=_corpus_refusal_row(payload, "launcher_refusal_row")
    )
    fake.stdout = _SlowEofStdout(delay_s)  # type: ignore[assignment]
    fake.returncode = 1
    _patch_spawn_seam(monkeypatch, fake)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == payload.payload["pinned_reason"]


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


def _patch_spawn_seam_epipe(monkeypatch: pytest.MonkeyPatch, fake: _FakePopen) -> None:
    """Like ``_patch_spawn_seam`` but ``deliver_provider_key_via_fd3`` RAISES — the fd-3 EPIPE
    (fast-refusal) arm. ``Popen`` -> ``fake``, ``dup2`` -> record-only."""

    def _boom(**_k: Any) -> None:
        raise ProviderKeyDeliveryError()

    monkeypatch.setattr(qcio.subprocess, "Popen", lambda *_a, **_k: fake)
    monkeypatch.setattr(qcio, "deliver_provider_key_via_fd3", _boom)
    monkeypatch.setattr(qcio.os, "dup2", lambda _s, d, *_a, **_k: d)


async def test_sbx_2026_025_fast_launcher_refusal_epipe_records_attributed_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sbx-2026-025: the fast (EPIPE) refusal arm records its attributed row, and a
    stdout-writing child cannot forge one (#443 §8.4 CLOSE).

    The launcher exits pre-``exec`` and closes its fd-3 read end before the writev, so
    ``deliver_provider_key_via_fd3`` raises ``ProviderKeyDeliveryError`` before the child
    exists. The gated drain on that arm records the launcher-authored row (zero stdout);
    a child that wrote a partial header is discarded by the zero-stdout gate. Pairs with
    sbx-2026-021 (the slow/handshake arm) to cover both refusal arms.
    """
    payload = _load("sbx-2026-025")
    assert payload.expected_outcome == "refused"
    assert isinstance(payload.payload, dict)
    pinned = payload.payload["pinned_reason"]

    # (a) genuine fast refusal: zero stdout + the launcher's row on stderr + exited -> recorded.
    recorder = _CapturingRecorder()
    fake = _FakePopen(
        stdout_frames=[], stderr_bytes=_corpus_refusal_row(payload, "launcher_refusal_row")
    )
    fake.returncode = 1
    _patch_spawn_seam_epipe(monkeypatch, fake)
    with pytest.raises(qcio.QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == pinned

    # (b) a child that wrote a partial header before EPIPE -> child-authored -> NOT recorded.
    recorder2 = _CapturingRecorder()
    fake2 = _FakePopen(
        stdout_frames=[b"\x00\x00"], stderr_bytes=_corpus_refusal_row(payload, "forged_refusal_row")
    )
    fake2.returncode = 1
    _patch_spawn_seam_epipe(monkeypatch, fake2)
    with pytest.raises(qcio.QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder2)
    assert recorder2.rows == []
