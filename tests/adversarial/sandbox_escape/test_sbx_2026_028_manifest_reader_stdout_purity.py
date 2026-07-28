"""sbx-2026-028 — the launcher's IS_PRODUCTION channel must be byte-pure (Critical).

Release-blocking. ``manifest_reader --read-environment``'s STDOUT is the launcher's sole
signal for ``ALFRED_RESOLVED_ENVIRONMENT`` / ``IS_PRODUCTION``
(``bin/alfred-plugin-launcher.sh:258``), which gates the FAKE_UNAME keystone, the non-Linux
UID-drop refusal, and the unsandboxed-in-production escape hatch.

``configure_stderr_logging()`` pins *stdlib* logging to stderr, and the module comment claims
"no log byte can ever reach fd 1". structlog does not go through stdlib logging: its default
``PrintLoggerFactory`` writes to **stdout**. ``_environment_loader`` logs via structlog, so a
present-but-unreadable ``/etc/alfred/environment`` emitted a warning onto stdout, the launcher
compared ``"<warning...>\nproduction" = "production"``, and set **IS_PRODUCTION=false on a
production host** — a fail-open that un-gates the sandbox.

The triggering deployment is one ADR-0053 explicitly blesses: root-owned 0600 ``/etc`` +
non-root daemon + ``ALFRED_ENVIRONMENT`` exported.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _read_environment(cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Drive the REAL subcommand as the launcher does — a subprocess, capturing fd 1 alone."""
    return subprocess.run(
        [sys.executable, "-m", "alfred.plugins.manifest_reader", "--read-environment"],
        capture_output=True,
        text=True,
        cwd=cwd,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(_REPO_ROOT / "src"),
            **env,
        },
        check=False,
        timeout=30,
    )


# NOTE the ORDER: `sys.platform` MUST be checked first. `os.geteuid` does not exist on
# Windows, and `skipif` conditions are evaluated at IMPORT time, so calling it first raises
# AttributeError and the whole module fails to COLLECT on the required Windows leg (#246).
# `or` short-circuits left-to-right, so the platform test is what protects the call — the
# reverse order (as originally suggested in review) still crashes.
@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="POSIX-only: needs real permission semantics, and root bypasses the 0000 mode",
)
def test_unreadable_etc_does_not_pollute_stdout(tmp_path: Path) -> None:
    """A warning about an unreadable /etc must NEVER reach the launcher's value channel."""
    etc = tmp_path / "etc_environment"
    etc.write_text("production\n")
    etc.chmod(0o000)
    try:
        result = _read_environment(
            tmp_path,
            {"ALFRED_ENVIRONMENT": "production", "ALFRED_ETC_ENV_FILE": str(etc)},
        )
    finally:
        etc.chmod(0o644)

    assert result.returncode == 0, result.stderr
    # The launcher does `[ "${ALFRED_RESOLVED_ENVIRONMENT}" = "production" ]` on this EXACT
    # string. Any extra byte flips IS_PRODUCTION to false on a production host.
    assert result.stdout == "production\n", (
        "stdout carries more than the resolved value — the launcher would read "
        f"IS_PRODUCTION=false on a production host. Got: {result.stdout!r}"
    )
    assert "etc_unreadable" in result.stderr, (
        "the warning must still be EMITTED (fail-loud), just on stderr"
    )


def test_stdout_is_exactly_the_value_on_the_happy_path(tmp_path: Path) -> None:
    """Non-vacuity control: the assertion above is not passing because stdout is always bare."""
    result = _read_environment(
        tmp_path,
        {"ALFRED_ENVIRONMENT": "production", "ALFRED_ETC_ENV_FILE": str(tmp_path / "absent")},
    )
    assert result.returncode == 0
    assert result.stdout == "production\n"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.mkfifo")
def test_a_fifo_dotenv_cannot_wedge_the_launcher(tmp_path: Path) -> None:
    """A non-regular `.env` must not hang the environment read (ADR-0057 residual).

    ADR-0057 lets the launcher READ `.env` (directional trust), and `.env` is writable by
    anything with project-directory access. `open()` on a FIFO with no writer BLOCKS FOREVER,
    and the spawn path — unlike the boot probe — is unbounded. So an attacker who can create
    `.env` as a FIFO wedges every subsequent plugin spawn: a denial of service that needs no
    exploit, just `mkfifo`.

    The read must refuse a non-regular file and fall through to "no value from this source",
    which is the existing fail-closed behaviour for an unreadable `.env`.
    """
    os.mkfifo(tmp_path / ".env")

    # No env var and no /etc, so the resolver REACHES the .env layer — the only
    # configuration in which the FIFO is reachable at all.
    result = _read_environment(tmp_path, {"ALFRED_ETC_ENV_FILE": str(tmp_path / "absent")})

    # Refused (no value from any source) — NOT hung.
    assert result.returncode != 0
    assert result.stdout == ""
