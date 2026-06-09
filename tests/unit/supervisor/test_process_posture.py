"""Supervisor-side process posture (PR-S4-6 Component E, spec §7.5).

``disable_core_dumps`` sets ``RLIMIT_CORE`` to ``(0, 0)`` so a core dump of
the Supervisor — which briefly holds the provider key in memory — cannot leak
it to disk. ``try_mlockall`` is a Linux best-effort wrapper that pins the
Supervisor's pages out of swap; its failure (missing ``CAP_IPC_LOCK`` in a
container) is loud (audit row at the caller) but non-fatal.
"""

from __future__ import annotations

import contextlib
import resource
import sys
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from alfred.supervisor.process_posture import (
    MlockResult,
    disable_core_dumps,
    try_mlockall,
)


@pytest.fixture(autouse=True)
def _restore_rlimit_core() -> Iterator[None]:
    # Save + restore RLIMIT_CORE so mutating it here does not leak across
    # pytest workers / other tests in the same process.
    before = resource.getrlimit(resource.RLIMIT_CORE)
    try:
        yield
    finally:
        # A hard-limit lower bound may forbid restoring; best-effort.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CORE, before)


def test_disable_core_dumps_sets_zero() -> None:
    disable_core_dumps()
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


def test_disable_core_dumps_idempotent() -> None:
    disable_core_dumps()
    disable_core_dumps()
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


def test_try_mlockall_does_not_raise() -> None:
    # On CI runners without CAP_IPC_LOCK this MUST NOT raise.
    result = try_mlockall()
    assert isinstance(result, MlockResult)
    assert result.kind in {"success", "unavailable"}


def test_try_mlockall_non_linux_is_unavailable() -> None:
    with patch.object(sys, "platform", "darwin"):
        result = try_mlockall()
    assert result.kind == "unavailable"
    assert "non-linux" in result.errno_string.lower()


def test_try_mlockall_success_path() -> None:
    # Simulate a successful libc.mlockall (rc == 0) on linux.
    fake_libc = _FakeLibc(rc=0)
    with (
        patch.object(sys, "platform", "linux"),
        patch("alfred.supervisor.process_posture.ctypes.CDLL", return_value=fake_libc),
    ):
        result = try_mlockall()
    assert result.kind == "success"


def test_try_mlockall_nonzero_rc_is_unavailable() -> None:
    fake_libc = _FakeLibc(rc=-1)
    with (
        patch.object(sys, "platform", "linux"),
        patch("alfred.supervisor.process_posture.ctypes.CDLL", return_value=fake_libc),
        patch("alfred.supervisor.process_posture.ctypes.get_errno", return_value=1),
    ):
        result = try_mlockall()
    assert result.kind == "unavailable"
    assert result.errno_string  # carries a translated strerror


def test_try_mlockall_oserror_is_unavailable() -> None:
    with (
        patch.object(sys, "platform", "linux"),
        patch(
            "alfred.supervisor.process_posture.ctypes.CDLL",
            side_effect=OSError("libc.so.6 not found"),
        ),
    ):
        result = try_mlockall()
    assert result.kind == "unavailable"
    assert "libc.so.6" in result.errno_string


class _FakeLibc:
    """Minimal stand-in for ``ctypes.CDLL('libc.so.6')`` exposing mlockall."""

    def __init__(self, rc: int) -> None:
        self._rc = rc

    def mlockall(self, flags: int) -> int:
        return self._rc
