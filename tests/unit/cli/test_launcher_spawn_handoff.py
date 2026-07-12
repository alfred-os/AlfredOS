"""Hand-off outcome model for :mod:`alfred.cli._launcher_spawn` (PR-S4-10 F3, #206).

The launcher-spawn seam serves two shapes of caller:

* ``alfred chat`` (boot) — a launcher still alive after the probe window has
  handed off a live, long-running session; the command BLOCKS on it (the
  foreground TUI runs to completion; the relay runs until SIGTERM).

* Readiness probe (``block_on_handoff=False``) — originally the now-retired
  ``alfred discord verify`` subcommand (deleted in #309, Spec B G6-7-8; Discord
  is gateway-hosted since that flag-day). A launcher still alive after the
  window is HEALTHY, but a healthy long-running relay would never exit, so
  blocking on it hangs the probe forever (the F3 bug). The probe shape must
  instead observe the hand-off, TERMINATE the child, and report OK.

:func:`spawn_plugin_via_launcher` distinguishes the two via a new
:data:`LaunchResult.HANDED_OFF` outcome, surfaced only when the caller opts out
of blocking (``block_on_handoff=False``); it then terminates the child so the
probe returns promptly instead of hanging.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from alfred.cli import _launcher_spawn
from alfred.cli._launcher_spawn import (
    LaunchResult,
    PluginLaunchSpec,
    spawn_plugin_via_launcher,
)


def _sleep_launcher(tmp_path: Path, seconds: float) -> Path:
    """A launcher stand-in that stays alive ``seconds`` then exits 0.

    Ignores its positional args (plugin_id / executable / -m / module) and just
    sleeps — modelling a healthy long-running plugin that survives the probe
    window and would otherwise block ``proc.wait()`` forever.
    """
    script = tmp_path / "sleep-launcher.sh"
    script.write_text(f"#!/usr/bin/env bash\nexec sleep {seconds}\n")
    script.chmod(0o755)
    return script


def _spec() -> PluginLaunchSpec:
    return PluginLaunchSpec(
        plugin_id="alfred_x",
        manifest_path=Path("/opt/alfred/manifest.toml"),
        module="x.server",
        adapter_id="x-instance",
        import_roots=(),
        inherit_stdio=False,
        sandbox_kind="full",
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: bash-shebang launcher stand-in + chmod 0o755 exec",
)
async def test_alive_past_probe_without_blocking_returns_handed_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A child alive past the probe -> HANDED_OFF (not a hang) when not blocking.

    This was the ``alfred discord verify`` path (retired in #309 — Discord is
    gateway-hosted): the healthy relay survives the probe window; with
    ``block_on_handoff=False`` the seam reports HANDED_OFF and terminates the
    child rather than awaiting an exit that never comes.
    """
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(_sleep_launcher(tmp_path, 30)))
    monkeypatch.setattr(_launcher_spawn, "LAUNCHER_PROBE_TIMEOUT_S", 0.2)

    outcome = await spawn_plugin_via_launcher(_spec(), block_on_handoff=False)

    assert outcome.result is LaunchResult.HANDED_OFF


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: bash-shebang launcher stand-in + chmod 0o755 exec",
)
async def test_handed_off_terminates_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HANDED_OFF path leaves no surviving child (verify must not leak relays)."""
    captured: dict[str, object] = {}
    real_exec = _launcher_spawn.asyncio.create_subprocess_exec

    async def _spy(*args: object, **kwargs: object) -> object:
        proc = await real_exec(*args, **kwargs)
        captured["proc"] = proc
        return proc

    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(_sleep_launcher(tmp_path, 30)))
    monkeypatch.setattr(_launcher_spawn, "LAUNCHER_PROBE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(_launcher_spawn.asyncio, "create_subprocess_exec", _spy)

    outcome = await spawn_plugin_via_launcher(_spec(), block_on_handoff=False)
    assert outcome.result is LaunchResult.HANDED_OFF

    proc = captured["proc"]
    # The seam terminated the child; its returncode is now set (not None).
    assert proc.returncode is not None  # type: ignore[attr-defined]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: bash-shebang launcher stand-in + chmod 0o755 exec",
)
async def test_blocking_caller_waits_for_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chat/boot default blocks past the probe and reports COMPLETED on exit.

    A short-lived sleep models a session that ends cleanly after hand-off; the
    blocking caller (``block_on_handoff=True``, the default) waits for it and
    sees COMPLETED, never HANDED_OFF.
    """
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(_sleep_launcher(tmp_path, 0.4)))
    monkeypatch.setattr(_launcher_spawn, "LAUNCHER_PROBE_TIMEOUT_S", 0.2)

    outcome = await spawn_plugin_via_launcher(_spec())

    assert outcome.result is LaunchResult.COMPLETED
    assert outcome.returncode == 0


async def test_failure_within_probe_is_failed_regardless_of_blocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-zero exit inside the probe window is FAILED even when not blocking."""
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", "/usr/bin/false")

    outcome = await spawn_plugin_via_launcher(_spec(), block_on_handoff=False)

    assert outcome.result is LaunchResult.FAILED
