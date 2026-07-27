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

from alfred.cli._launcher_spawn import launcher_path
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
async def test_real_launcher_self_test_returns_policy_resolving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PR-S4-6: the real launcher --self-test returns the resolving signature.

    #521: the environment is now supplied explicitly. The self-test resolves it (it is the
    launcher's first real check), so leaving it unset made this test pass for the wrong
    reason — it asserted "resolving" on a launcher that would refuse every spawn.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    assert await _launcher_self_test_impl() == _POLICY_RESOLVING_SIGNATURE


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: exec of the .sh launcher script via asyncio.create_subprocess_exec",
)
async def test_probe_refuses_in_production_when_launcher_cannot_resolve_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#521: a launcher that cannot resolve the environment must NOT pass the boot probe.

    Before #521 ``--self-test`` returned the resolving signature without ever attempting the
    resolution, so this probe reported green on a launcher that would refuse EVERY spawn —
    the #514 paper-gate shape. The refusal names the fault in ``probe_response`` rather than
    collapsing into the generic stub signature, so the operator learns WHY.
    """
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_ETC_ENV_FILE", "/nonexistent/alfred-environment")

    result = await probe_launcher_policy_resolving(environment="production")

    assert isinstance(result, LauncherNotPolicyResolvingFailure)
    assert result.probe_response == "environment-unresolved"


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: exec of the .sh launcher script via asyncio.create_subprocess_exec",
)
async def test_probe_still_tolerates_unresolvable_environment_outside_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#521 must not regress dev convenience: non-production still boots.

    The sec-004 posture is unchanged — only production refuses on a non-resolving signature.
    Pinned so a future tightening of #521 is a deliberate decision, not a side effect.
    """
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_ETC_ENV_FILE", "/nonexistent/alfred-environment")

    assert await probe_launcher_policy_resolving(environment="development") is None


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
async def test_probe_passes_in_production_with_real_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PR-S4-6 flip: the real policy-resolving launcher boots in production.

    Exercises the SHIPPED launcher's --self-test. This is the arch-001 closure: once
    PR-S4-6 ships the real self-test, prod boot succeeds (the stub-era refusal is gone).

    #521: the environment is supplied explicitly. Without it the shipped self-test now
    reports ``environment-unresolved`` — correctly, since such a launcher would refuse every
    spawn — so this test previously asserted prod boot on a launcher that could not work.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
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
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", "/nonexistent/alfred-plugin-launcher.sh")
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
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake))
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
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake))
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
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake))
    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes._SELF_TEST_TIMEOUT_S",
        0.3,
    )
    result = await _launcher_self_test_impl()
    assert result == _STUB_SIGNATURE
    # Wait past when the child WOULD have touched the marker had it survived.
    await asyncio.sleep(2.5)
    assert not marker.exists(), "self-test child survived the timeout — it was not killed"


@pytest.mark.asyncio
async def test_probe_launcher_uses_repo_root_default_when_no_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#500: the ACTUAL fix — with no ``ALFRED_PLUGIN_LAUNCHER``, the probe
    resolves the launcher under ``repo_root()/bin`` (not the old wrong
    ``parents[4]`` const, which pointed one directory too shallow). Pin
    ``ALFRED_REPO_ROOT`` so the default is deterministic, and assert the probe
    itself execs THAT path — not just that ``launcher_path()`` computes it.
    """
    monkeypatch.delenv("ALFRED_PLUGIN_LAUNCHER", raising=False)
    monkeypatch.setenv("ALFRED_REPO_ROOT", "/app")
    assert launcher_path() == str(Path("/app") / "bin" / "alfred-plugin-launcher.sh")

    captured: dict[str, object] = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (_POLICY_RESOLVING_SIGNATURE.encode(), b"")

    async def _fake_exec(*args: object, **kwargs: object) -> _FakeProc:
        captured["argv0"] = args[0]
        return _FakeProc()

    monkeypatch.setattr(
        "alfred.cli.daemon._daemon_probes.asyncio.create_subprocess_exec",
        _fake_exec,
    )

    result = await _launcher_self_test_impl()

    assert captured["argv0"] == str(Path("/app") / "bin" / "alfred-plugin-launcher.sh")
    assert result == _POLICY_RESOLVING_SIGNATURE


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: execs a #!/bin/sh launcher script (Windows cannot exec a .sh directly).",
)
@pytest.mark.asyncio
async def test_launcher_self_test_honours_env_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``ALFRED_PLUGIN_LAUNCHER`` overrides the default, end to end.

    Pins the override at both layers: ``launcher_path()`` resolves it (the
    seam the daemon probe and the launcher-spawn seam now share), AND the
    probe's real subprocess exec drives THIS launcher, not the in-tree
    default.
    """
    fake = tmp_path / "my-launcher.sh"
    fake.write_text(f'#!/bin/sh\necho "{_POLICY_RESOLVING_SIGNATURE}"\n')
    fake.chmod(0o755)
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake))

    assert launcher_path() == str(fake)
    assert await _launcher_self_test_impl() == _POLICY_RESOLVING_SIGNATURE


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
