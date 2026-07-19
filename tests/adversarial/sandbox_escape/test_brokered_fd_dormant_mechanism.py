"""Executable counterpart to sbx-2026-015 — the fd-broker mechanism is LIVE-enforced (#340).

#340 PR2b golive wires the SCM_RIGHTS reachability-broker (``control_fd_broker.py``
+ the opt-in ``control_fd`` parameter on ``spawn_quarantine_child_io``) LIVE: the
daemon's production spawn (``comms_mcp/daemon_runtime.py``) now sets
``control_fd=True`` and brokers the child exactly one gateway socket over fd 4.
The PR2a dormancy this payload originally documented is retired; the file keeps
its historical ``_dormant`` name. This module proves the LIVE-enforced containment
rather than merely documenting it (fold-log L4 — every sbx payload gets an
EXECUTABLE test, not just a schema-valid YAML):

* :func:`test_payload_loads` — the corpus entry schema-validates and declares
  the expected containment.
* :func:`test_live_echo_spawn_passes_no_control_fd` — the opt-in-discipline proof:
  a spawn that does NOT opt in (``control_fd=False``, the default) is passed fd 3
  only, so no egress fd is ever granted by accident — only the golive caller's
  explicit ``control_fd=True`` crosses fd 4.
* :func:`test_control_channel_refuses_a_second_or_zero_fd` — the capability-
  envelope proof: the control channel accepts EXACTLY one SCM_RIGHTS fd per
  frame; a data-only (zero-fd) or multi-fd frame is a loud refusal, not a silent
  no-op, so a compromised child cannot smuggle a second socket even with the
  broker live.
* :func:`test_live_brokered_child_net_stays_unshared` — the sole-egress proof: the
  shipped quarantined-LLM Linux policy ``--unshare-net``'s the child, so the single
  brokered fd is its only egress and a direct outbound is kernel-refused.

[L-7] The first three are PURE UNIT tests (mocked ``Popen`` + a real
``socketpair``, no bwrap, no real subprocess) and MUST NOT carry a
``@_bwrap_required`` (or any other bwrap-skip) marker — that would skip them on
ordinary CI and defeat the whole point of registering their node-ids in the
release-blocking gate (see ``.github/workflows/adversarial.yml``). The
net-unshared proof reads the shipped policy TOML (no bwrap) and likewise always
runs.
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
from alfred.plugins.sandbox_policy import read_policy_toml
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
from alfred.security.quarantine_child_io import spawn_quarantine_child_io
from tests.adversarial.payload_schema import AdversarialPayload

_DIR = Path(__file__).parent
_QUARANTINED_LINUX_POLICY = (
    Path(__file__).resolve().parents[3]
    / "config"
    / "sandbox"
    / "quarantined-llm.linux.bwrap.policy"
)


class _FakeStdout:
    """Raw-pipe stand-in: synchronous ``read(n)`` over a length-prefixed stream, ``b""`` at EOF.

    Adversarial-LOCAL double (CR-3): a release-blocking test imports no behaviour from a
    mutable unit-test helper. Mirrors the shape ``_blocking_read_exactly`` drives (returns at
    most ``n`` bytes per call, EOF when drained).
    """

    def __init__(self, frames: list[bytes]) -> None:
        self._buf = bytearray(b"".join(frames))

    def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk


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
    """Opt-in-discipline proof: a spawn that does NOT opt in passes fd 3 ONLY.

    Now that the golive caller wires the broker live (``control_fd=True`` in
    ``daemon_runtime.py``, ADR-0052), the load-bearing residual property is that
    the mechanism stays OPT-IN: a spawn that leaves ``control_fd`` at its default
    ``False`` (this test) is passed fd 3 only — no egress fd is ever granted by
    accident. A fd 4 reaches the child ONLY when a caller explicitly opts in, so
    the brokered egress channel can never appear on the wire unintentionally.

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
        assert captured["pass_fds"] == (3,)  # opt-in discipline: no fd 4 without an explicit opt-in
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


def test_live_brokered_child_net_stays_unshared() -> None:
    """Sole-egress proof: the child's net namespace is empty, so the brokered fd is its ONLY egress.

    The golive spawn hands the child exactly one pre-connected gateway socket over
    the control fd; the SHIPPED quarantined-LLM Linux policy ``--unshare-net``'s the
    child into an EMPTY network namespace, so it cannot open any OTHER outbound
    connection — a direct connect is refused at the kernel. Together with the
    exactly-one-fd capability envelope
    (:func:`test_control_channel_refuses_a_second_or_zero_fd`) this is what makes
    "egress ONLY via the brokered fd" true under the now-live broker. Mirrors
    ``test_sbx_2026_005_outbound_network_egress_contained`` — a dropped ``net`` from
    ``unshare`` would silently re-open the child's egress outside the broker.
    """
    payload = _load("sbx-2026-015")
    assert payload.expected_outcome == "refused"
    policy = read_policy_toml(_QUARANTINED_LINUX_POLICY.read_text())
    assert "net" in policy.unshare, (
        "quarantined-LLM policy no longer unshares net — sbx-2026-015 asserts the "
        "golive child's ONLY egress is the single brokered fd (--unshare-net); a "
        "dropped 'net' silently re-opens direct egress outside the broker"
    )
