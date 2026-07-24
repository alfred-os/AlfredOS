"""Real-execution regression test for the post-bind Discord probe advisory.

#469 Blocker 2 CodeRabbit finding 2: after ``alfred user bind --platform discord``, the
setup script used to advise running ``alfred gateway adapters --wait-ready discord``
whenever a Discord token merely existed in ``.env`` — even under an explicit
``ALFRED_GATEWAY_HOSTED_ADAPTERS=[]`` opt-out, where Discord is deliberately NOT
gateway-hosted and that probe would never succeed. ``discord_probe_advisory`` (sliced
out of ``bin/alfred-setup.sh``, same technique ``test_setup_script_env_seed.py`` uses
for ``seed_hosted_adapters``) now bases the advisory on the EFFECTIVE hosted-adapter
set read back from ``.env`` (post ``seed_hosted_adapters``), not merely token presence.

No Docker, no testcontainers — just ``bash``, already a hard prerequisite of this
repo's dev/CI environment.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled invocations of `bash` from the unit suite. Every argv is a literal
# authored in this module; nothing crosses an untrusted boundary.
import subprocess
from pathlib import Path

from tests._setup_script_helpers import slice_shell_function

_SETUP_SH = Path("bin/alfred-setup.sh")
_READ_ENV_VAR_START = "read_env_var() {"
_WARN_START = 'warn() { printf "WARNING: %s\\n" "$1" >&2; }'
_ADVISORY_START = "discord_probe_advisory() {"


def _advisory_script() -> str:
    """Slice ``discord_probe_advisory`` + its ``read_env_var``/``warn`` dependencies.

    Anchored on all three functions' declaration lines so a moved/renamed helper — or a
    moved/renamed callee — raises loudly here instead of silently running a stale copy
    (mirrors ``test_setup_script_env_seed.py``'s ``_seed_hosted_adapters_script``).
    """
    return (
        slice_shell_function(_SETUP_SH, _WARN_START)
        + "\n"
        + slice_shell_function(_SETUP_SH, _READ_ENV_VAR_START)
        + "\n"
        + slice_shell_function(_SETUP_SH, _ADVISORY_START)
    )


def _run_advisory(env_path: Path) -> subprocess.CompletedProcess[str]:
    """Run the real ``discord_probe_advisory`` function against ``env_path`` as ``.env``.

    ``cwd=env_path.parent`` so the function's literal (unparameterised) ``.env`` resolves
    to the caller-supplied temp file, exactly as the real script does when invoked from
    the repo root.
    """
    script = "set -euo pipefail\n" + _advisory_script() + "\ndiscord_probe_advisory\n"
    return subprocess.run(
        ["bash", "-c", script],
        cwd=env_path.parent,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        check=False,
        timeout=30,
    )


def test_advisory_markers_still_match_the_script() -> None:
    """Guard the guard — a silently-empty slice would make every test below vacuous."""
    script = _advisory_script()
    assert "read_env_var() {" in script
    assert "warn() {" in script
    assert "discord_probe_advisory() {" in script
    assert "--wait-ready discord" in script


def test_hosted_adapter_present_prints_the_probe(tmp_path: Path) -> None:
    """Discord IS in the effective hosted set -> advertise the readiness probe."""
    env_path = tmp_path / ".env"
    env_path.write_text(
        'ALFRED_DISCORD_BOT_TOKEN=real-token\nALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]\n'
    )
    result = _run_advisory(env_path)
    assert result.returncode == 0, (
        f"advisory failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "alfred gateway adapters --wait-ready discord" in result.stdout


def test_explicit_opt_out_suppresses_the_probe(tmp_path: Path) -> None:
    """CodeRabbit finding 2: a token present + an explicit ``=[]`` opt-out must NOT advise
    probing an adapter that will never run — the old token-only check did exactly that.
    """
    env_path = tmp_path / ".env"
    env_path.write_text("ALFRED_DISCORD_BOT_TOKEN=real-token\nALFRED_GATEWAY_HOSTED_ADAPTERS=[]\n")
    result = _run_advisory(env_path)
    assert result.returncode == 0, (
        f"advisory failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "--wait-ready discord" not in result.stdout, (
        f"advised probing a non-hosted adapter:\nstdout: {result.stdout!r}"
    )
    assert "not in ALFRED_GATEWAY_HOSTED_ADAPTERS" in result.stderr, (
        f"expected an explanatory warning on stderr, got:\nstderr: {result.stderr!r}"
    )


def test_token_absent_warns_to_set_the_token(tmp_path: Path) -> None:
    """No token at all -> the original point-at-both-remedies warning, unchanged behaviour."""
    env_path = tmp_path / ".env"
    env_path.write_text("# ALFRED_DISCORD_BOT_TOKEN=\n")
    result = _run_advisory(env_path)
    assert result.returncode == 0, (
        f"advisory failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "--wait-ready discord" not in result.stdout
    assert "ALFRED_DISCORD_BOT_TOKEN is unset" in result.stderr
