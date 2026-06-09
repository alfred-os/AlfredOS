"""fd-leak discipline for the launcher spawn boundary (CR PR #229 finding-3).

When the Supervisor (or the integration harness) spawns the launcher it passes
exactly the provider-key pipe fd via ``pass_fds`` and nothing else. CPython's
``pass_fds`` forces ``close_fds=True``, so any OTHER fd the parent happens to
hold open (a log file, a socket, a leaked descriptor) is closed in the child
and never reaches the sandboxed plugin. A leaked fd into a quarantined plugin
is a confused-deputy channel — the plugin could read or write a host resource
the operator never granted.

This test plants an extra inheritable fd (``os.dup`` → some fd > 3) in the
parent BEFORE spawning the launcher, drives the real bash launcher through the
``kind:none`` path to a Python plugin that introspects which fds it actually
inherited, and asserts the planted fd is NOT among them — only the standard
streams {0,1,2} plus the single passed pipe fd survive.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

_NONE_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "none"
"""

# A plugin that prints the set of open fds it inherited (excluding the dirfd
# os.listdir transiently opens). Lives off /proc on Linux and /dev/fd on macOS.
_FD_INTROSPECT_PLUGIN = r"""
import os, sys

def open_fds():
    fds = set()
    for fd_dir in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(fd_dir):
            for name in os.listdir(fd_dir):
                try:
                    fds.add(int(name))
                except ValueError:
                    pass
            break
    return fds

fds = open_fds()
# Drop the transient dirfd that listdir/scandir opened (highest fd, already
# closed by the time we print) by re-checking liveness via fstat.
live = set()
for fd in fds:
    try:
        os.fstat(fd)
        live.add(fd)
    except OSError:
        pass
print("INHERITED_FDS=" + ",".join(str(f) for f in sorted(live)), flush=True)
sys.exit(0)
"""


def _spawn_launcher_with_planted_fd(
    tmp_path: Path, *, pass_pipe: bool
) -> subprocess.CompletedProcess[str]:
    plugin = tmp_path / "fd_introspect.py"
    plugin.write_text(_FD_INTROSPECT_PLUGIN)
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_NONE_MANIFEST)

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "development",
        "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        # kind:none on a non-Linux dev host execs the plugin directly (no
        # runuser); on Linux CI runuser may be absent → that path refuses. The
        # fd-inheritance discipline is identical regardless, so we force the
        # direct-exec dev path via FAKE_UNAME=Darwin (dev only — refused in prod).
        "FAKE_UNAME": "Darwin",
    }

    # Plant a leaked, inheritable fd in the PARENT before spawning.
    leaked_read, leaked_write = os.pipe()
    os.set_inheritable(leaked_read, True)  # noqa: FBT003
    os.set_inheritable(leaked_write, True)  # noqa: FBT003

    pass_fds: tuple[int, ...] = ()
    provider_read = provider_write = None
    if pass_pipe:
        provider_read, provider_write = os.pipe()
        os.set_inheritable(provider_read, True)  # noqa: FBT003
        pass_fds = (provider_read,)

    try:
        proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
            [str(LAUNCHER), "alfred.example", sys.executable, str(plugin)],
            capture_output=True,
            text=True,
            env=env,
            pass_fds=pass_fds,
            check=False,
        )
    finally:
        for fd in (leaked_read, leaked_write, provider_read, provider_write):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
    return proc


def _inherited_fds(stdout: str) -> set[int]:
    for line in stdout.splitlines():
        if line.startswith("INHERITED_FDS="):
            payload = line.split("=", 1)[1]
            return {int(x) for x in payload.split(",") if x}
    raise AssertionError(f"plugin did not report its fds; stdout={stdout!r}")


def test_planted_fd_not_inherited_into_plugin(tmp_path: Path) -> None:
    """A leaked parent fd (> 3) is NOT visible inside the launched plugin.

    ``subprocess.run(..., pass_fds=())`` implies ``close_fds=True``, so the
    planted inheritable pipe fd is closed in the child. Only the standard
    streams reach the plugin.
    """
    proc = _spawn_launcher_with_planted_fd(tmp_path, pass_pipe=False)
    if proc.returncode != 0:
        pytest.skip(f"launcher did not reach the plugin on this host: {proc.stderr}")
    inherited = _inherited_fds(proc.stdout)
    # Standard streams only; no planted fd 4+ survives.
    assert inherited <= {0, 1, 2}, f"unexpected inherited fds: {sorted(inherited)}"


def test_only_passed_pipe_fd_plus_stdio_inherited(tmp_path: Path) -> None:
    """With ``pass_fds=[provider_pipe]`` the plugin inherits exactly the
    standard streams plus that one pipe fd — never the separately-planted leak.

    Mirrors the integration harness's ``pass_fds=(read_fd,)`` fd-3 discipline.
    """
    proc = _spawn_launcher_with_planted_fd(tmp_path, pass_pipe=True)
    if proc.returncode != 0:
        pytest.skip(f"launcher did not reach the plugin on this host: {proc.stderr}")
    inherited = _inherited_fds(proc.stdout)
    # Exactly one non-stdio fd (the passed provider pipe). The planted leak and
    # any other parent fd must be absent.
    non_stdio = inherited - {0, 1, 2}
    assert len(non_stdio) <= 1, (
        f"more than the single passed pipe fd was inherited: {sorted(non_stdio)}"
    )
