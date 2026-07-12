"""Verify the launcher policy-resolving probe (#174, flipped by PR-S4-6).

PR-S4-1 shipped a stub whose self-test returned ``_STUB_SIGNATURE`` so
production refused to boot on the unverified launcher (sec-004). PR-S4-6
FLIPS ``_launcher_self_test_impl`` to actually shell out to
``bin/alfred-plugin-launcher.sh --self-test``; the real launcher returns the
policy-resolving signature, so a prod deploy on it now boots.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_probes import (
    _POLICY_RESOLVING_SIGNATURE,
    _STUB_SIGNATURE,
    _launcher_self_test_impl,
    probe_launcher_policy_resolving,
)
from alfred.cli.daemon._failures import LauncherNotPolicyResolvingFailure


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: exec of the .sh launcher script via asyncio.create_subprocess_exec "
    "(no POSIX shebang interpreter on Windows; falls back to the stub signature)",
)
async def test_real_launcher_self_test_returns_policy_resolving() -> None:
    """PR-S4-6: the real launcher --self-test returns the resolving signature."""
    assert await _launcher_self_test_impl() == _POLICY_RESOLVING_SIGNATURE


@pytest.mark.asyncio
async def test_probe_passes_in_development() -> None:
    """The real policy-resolving launcher passes the dev probe."""
    result = await probe_launcher_policy_resolving(environment="development")
    assert result is None


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: exec of the .sh launcher script via asyncio.create_subprocess_exec "
    "(no POSIX shebang interpreter on Windows; falls back to the stub signature)",
)
async def test_probe_passes_in_production_with_real_launcher() -> None:
    """PR-S4-6 flip: the real policy-resolving launcher boots in production.

    No monkeypatch — exercises the SHIPPED launcher's --self-test. This is the
    arch-001 closure: once PR-S4-6 ships the real self-test, prod boot
    succeeds (the stub-era refusal is gone).
    """
    result = await probe_launcher_policy_resolving(environment="production")
    assert result is None


@pytest.mark.asyncio
async def test_probe_passes_in_production_when_signature_resolving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine policy-resolving signature passes even in production."""

    async def _resolving() -> str:
        return _POLICY_RESOLVING_SIGNATURE

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _resolving,
    )
    result = await probe_launcher_policy_resolving(environment="production")
    assert result is None


@pytest.mark.asyncio
async def test_probe_refuses_arbitrary_signature_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec-004: any non-resolving signature refuses the boot in production."""

    async def _other() -> str:
        return "some-other-signature"

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _other,
    )
    result = await probe_launcher_policy_resolving(environment="production")
    assert isinstance(result, LauncherNotPolicyResolvingFailure)
    assert result.probe_response == "some-other-signature"


@pytest.mark.asyncio
async def test_probe_tolerates_arbitrary_signature_in_development(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside production, a non-resolving signature is tolerated (dev)."""

    async def _other() -> str:
        return "some-other-signature"

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._launcher_self_test_impl",
        _other,
    )
    result = await probe_launcher_policy_resolving(environment="development")
    assert result is None


@pytest.mark.asyncio
async def test_self_test_missing_launcher_returns_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An un-runnable launcher (OSError) yields the STUB signature — fail
    closed: a broken launcher must not impersonate a resolving one."""
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._LAUNCHER_PATH",
        Path("/nonexistent/alfred-plugin-launcher.sh"),
    )
    assert await _launcher_self_test_impl() == _STUB_SIGNATURE


@pytest.mark.asyncio
async def test_self_test_nonzero_exit_returns_stub(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A launcher that exits non-zero on --self-test yields the STUB
    signature (fail closed)."""
    fake = tmp_path / "fake-launcher.sh"
    fake.write_text("#!/bin/sh\nexit 3\n")
    fake.chmod(0o755)
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._LAUNCHER_PATH",
        fake,
    )
    assert await _launcher_self_test_impl() == _STUB_SIGNATURE


@pytest.mark.asyncio
async def test_self_test_hang_times_out_to_stub(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """err (CR PR #229 finding-2): a launcher whose --self-test HANGS must NOT
    stall boot forever. The probe bounds the subprocess with a short timeout; on
    expiry it kills the process group and returns the STUB signature so
    production refuses the boot loudly (fail closed) rather than hanging.

    The fake launcher sleeps far longer than the (overridden, tiny) timeout. The
    call must return the stub signature within the timeout window, not block.
    """
    fake = tmp_path / "hang-launcher.sh"
    fake.write_text("#!/bin/sh\nsleep 30\n")
    fake.chmod(0o755)
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._LAUNCHER_PATH",
        fake,
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._SELF_TEST_TIMEOUT_S",
        0.5,
    )
    # asyncio.timeout would also catch a regression where the impl itself never
    # returns; 5s is comfortably above the 0.5s self-test timeout.
    async with asyncio.timeout(5):
        result = await _launcher_self_test_impl()
    assert result == _STUB_SIGNATURE


@pytest.mark.asyncio
async def test_self_test_hang_does_not_orphan_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The timeout path kills the spawned process group — no orphaned child of
    the hung self-test survives the probe."""
    marker = tmp_path / "still_alive.marker"
    # The child writes the marker only if it survives past the timeout window.
    fake = tmp_path / "hang-launcher.sh"
    fake.write_text(f"#!/bin/sh\nsleep 2\ntouch {marker}\n")
    fake.chmod(0o755)
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._LAUNCHER_PATH",
        fake,
    )
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._SELF_TEST_TIMEOUT_S",
        0.3,
    )
    result = await _launcher_self_test_impl()
    assert result == _STUB_SIGNATURE
    # Wait past when the child WOULD have touched the marker had it survived.
    await asyncio.sleep(2.5)
    assert not marker.exists(), "self-test child survived the timeout — it was not killed"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.killpg (process groups)",
)
def test_kill_process_group_falls_back_to_pid_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    """If ``os.killpg`` raises (group lookup races a just-exited leader), the
    per-pid ``proc.kill()`` fallback fires so the process is still reaped."""
    from unittest.mock import MagicMock

    from alfred.cli.daemon._daemon_probes import _kill_process_group

    def _boom(*_args: object) -> None:
        raise ProcessLookupError

    monkeypatch.setattr("alfred.cli.daemon._daemon_probes.os.killpg", _boom)
    proc = MagicMock()
    proc.pid = 4242
    _kill_process_group(proc)
    proc.kill.assert_called_once()
