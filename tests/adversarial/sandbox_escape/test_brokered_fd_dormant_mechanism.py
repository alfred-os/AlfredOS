"""Executable counterpart to sbx-2026-015 — the PR2a fd-broker mechanism ships dormant (#340).

#340 PR2a lands the SCM_RIGHTS reachability-broker (``control_fd_broker.py`` +
the opt-in ``control_fd`` parameter on ``spawn_quarantine_child_io``), but the
daemon's ONLY live/echo caller never opts in. This module proves that claim
rather than merely documenting it (fold-log L4 — every sbx payload gets an
EXECUTABLE test, not just a schema-valid YAML):

* :func:`test_payload_loads` — the corpus entry schema-validates and declares
  the expected containment.
* :func:`test_live_echo_spawn_passes_no_control_fd` — the dormancy proof: the
  default (``control_fd=False``) live spawn passes fd 3 only, never fd 4.
* :func:`test_control_channel_refuses_a_second_or_zero_fd` — the capability-
  envelope proof: the control channel accepts EXACTLY one SCM_RIGHTS fd per
  frame; a data-only (zero-fd) frame is a loud refusal, not a silent no-op.

[L-7] These are PURE UNIT tests (mocked ``Popen`` + a real ``socketpair``, no
bwrap, no real subprocess) and MUST NOT carry a ``@_bwrap_required`` (or any
other bwrap-skip) marker — that would skip them on ordinary CI and defeat the
whole point of registering their node-ids in the release-blocking gate (see
``.github/workflows/adversarial.yml``).
"""

from __future__ import annotations

import array
import contextlib
import os
import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

import alfred.security.quarantine_child_io as child_io_mod
from alfred.egress.control_fd_broker import ControlFdBrokerError, recv_passed_fd
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
from alfred.security.quarantine_child_io import spawn_quarantine_child_io
from tests.adversarial.payload_schema import AdversarialPayload
from tests.unit.security.test_quarantine_child_io import _FakeStdout

_DIR = Path(__file__).parent


def _load(payload_id: str) -> AdversarialPayload:
    path = next(_DIR.glob(f"{payload_id.replace('-', '_')}*.yaml"))
    return AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))


def test_payload_loads() -> None:
    """sbx-2026-015 schema-validates and declares the dormancy containment."""
    payload = _load("sbx-2026-015")
    assert payload.id == "sbx-2026-015"
    assert payload.category == "sandbox_escape"
    assert payload.expected_outcome == "refused"


class _FakePopen:
    """A ``subprocess.Popen`` stand-in — captures ``pass_fds``, forks nothing.

    Peer to ``tests/unit/security/test_quarantine_child_io.py``'s
    ``_FakePopen``: the real spawn's ``Popen`` call is intercepted before any
    fork/exec happens, so this test asserts purely on what the SEAM decided to
    pass through — never a real subprocess.
    """

    def __init__(self, argv: list[str], **kwargs: Any) -> None:
        self.argv = argv
        self.pass_fds = tuple(kwargs.get("pass_fds", ()))
        self.stdin = None
        # A real child emits hello+ready at boot; the quarantine spawn now CONSUMES
        # both frames inside the two-frame boot handshake (#443, Task 5 landed). This
        # dormancy-focused fake is pre-seeded so that handshake read is satisfied and
        # the spawn returns.
        self.stdout = _FakeStdout([HELLO_FRAME, READY_FRAME])
        self.stderr = None
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


@pytest.mark.asyncio
async def test_live_echo_spawn_passes_no_control_fd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dormancy proof: the default (``control_fd=False``) live spawn passes fd 3 ONLY.

    This is the load-bearing assertion behind sbx-2026-015: the daemon's
    live/echo caller never opts into ``control_fd=True`` (ADR-0050), so the
    fd-broker mechanism #340 PR2a ships is inert on the production path today
    — no fd 4 ever reaches the child.

    MONKEYPATCH DISCIPLINE mirrors ``test_quarantine_child_io.py``'s
    ``_spawn_capture`` fixture exactly: ``subprocess.Popen``,
    ``deliver_provider_key_via_fd3``, and ``os.dup2`` are all faked so the
    real spawn's synchronous ``os.dup2(read_fd, 3)`` clobber-window dance
    never touches this pytest runner's REAL fd 3 (faking ``dup2`` turns every
    call inside that window into a record-only no-op). ``os.pipe`` is wrapped
    (not replaced) — the real pipe machinery still runs, since exercising it
    is the whole point — but every fd it opens is tracked and
    best-effort-closed here, so this test leaks none regardless of which end
    the (faked) production path does or doesn't close itself.
    """
    captured: dict[str, Any] = {}
    opened_fds: list[int] = []

    def _fake_popen(argv: list[str], **kwargs: Any) -> _FakePopen:
        proc = _FakePopen(argv, **kwargs)
        captured["pass_fds"] = proc.pass_fds
        return proc

    def _fake_deliver(*, write_fd: int, key: str) -> None:
        """No real fd-3 delivery — this test only asserts on ``pass_fds``."""

    def _fake_dup2(src: int, dst: int, *args: Any, **kwargs: Any) -> int:
        """Record-only: never actually dup2 onto a live fd in this process."""
        return dst

    real_pipe = child_io_mod.os.pipe

    def _tracking_pipe() -> tuple[int, int]:
        r, w = real_pipe()
        opened_fds.extend((r, w))
        return r, w

    monkeypatch.setattr(child_io_mod.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", _fake_deliver)
    monkeypatch.setattr(child_io_mod.os, "dup2", _fake_dup2)
    monkeypatch.setattr(child_io_mod.os, "pipe", _tracking_pipe)

    try:
        await spawn_quarantine_child_io(provider_key="k")  # default: control_fd=False
        assert captured["pass_fds"] == (3,)  # dormant: no fd 4 on the live path
    finally:
        for fd in opened_fds:
            with contextlib.suppress(OSError):
                os.close(fd)


def test_control_channel_refuses_a_second_or_zero_fd() -> None:
    """Capability envelope: exactly one fd per frame — zero-fd OR multi-fd frames are refused.

    A compromised child cannot coax the broker's control channel into (a) accepting
    a no-fd frame (a silent socket-less return) or (b) smuggling a SECOND descriptor
    through a single frame: ``recv_passed_fd`` raises :class:`ControlFdBrokerError`
    in both cases.
    """
    # (a) zero-fd frame: data only, no SCM_RIGHTS ancillary.
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        parent.sendall(b"\x01")
        with pytest.raises(ControlFdBrokerError):
            recv_passed_fd(child)
    finally:
        parent.close()
        child.close()

    # (b) multi-fd frame: TWO SCM_RIGHTS descriptors in one frame. ``recv_passed_fd``
    # sizes its ancillary buffer for exactly one fd, so the kernel truncates
    # (``MSG_CTRUNC``) rather than admitting a second descriptor — a loud refusal.
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    donor_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    donor_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        two_fds = array.array("i", [donor_a.fileno(), donor_b.fileno()])
        parent.sendmsg([b"\x01"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, two_fds)])
        with pytest.raises(ControlFdBrokerError):
            recv_passed_fd(child)
    finally:
        parent.close()
        child.close()
        donor_a.close()
        donor_b.close()
