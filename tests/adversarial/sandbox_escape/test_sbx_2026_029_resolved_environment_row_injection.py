"""sbx-2026-029 — the launcher must not interpolate an unvalidated environment (High).

Release-blocking. The residual of sbx-2026-028 (#524): 028 stopped structlog polluting
``manifest_reader``'s fd 1; it did NOT fix the interpolation that made the leak dangerous.

``bin/alfred-plugin-launcher.sh`` assigns ``ALFRED_RESOLVED_ENVIRONMENT`` from the helper's
captured stdout and interpolates it RAW into every ``supervisor.plugin.sandbox_refused`` JSON
row. Both neighbouring fields in those same templates are guarded precisely because they
reach them — ``PLUGIN_ID`` at entry (CR on PR #140) and ``POLICY_REF`` in #437 — each
refusing with a launcher-authored sentinel rather than echoing tainted bytes. This value had
neither.

sbx-2026-028 is the proof the "the helper only ever prints development|production|test"
expectation can break: a structlog warning reached fd 1 and the captured value became a
multi-line string, which was then interpolated into the row and split it across lines.

The helper is replaced with a stub rather than provoked into misbehaving: this case is about
the LAUNCHER's own gate, which must hold whatever the helper does. That is the whole point of
defence in depth at the last fail-closed gate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

_PLUGIN_ID = "alfred.probe"

# A payload that closes the JSON string, forges a second field, and splits the row across
# lines — exactly the shape sbx-2026-028's leak produced accidentally.
_INJECTION = 'production","host_os":"forged\n{"event":"forged.row","plugin_id":"evil'


def _fake_helper(tmp_path: Path, stdout_payload: str) -> Path:
    """A stand-in for `python3 -m alfred.plugins.manifest_reader` on PATH.

    The launcher invokes the helper as `python3 -m ...`, so shadowing `python3` is what
    lets this case drive the launcher's own handling of a hostile value without needing
    the real helper to misbehave.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / "python3"
    shim.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        "  *--read-environment*)\n"
        f"    printf '%s' '{stdout_payload}'\n"
        "    exit 0 ;;\n"
        "esac\n"
        f'exec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return bindir


def _run_launcher(tmp_path: Path, stdout_payload: str) -> subprocess.CompletedProcess[str]:
    bindir = _fake_helper(tmp_path, stdout_payload)
    # S603: argv is entirely repo-local and fixed — the launcher path, a literal
    # plugin id and /bin/true. The hostile input is the SHIMMED HELPER's stdout,
    # which is what this case exists to drive, not the command line.
    return subprocess.run(  # noqa: S603
        [str(_LAUNCHER), _PLUGIN_ID, "/bin/true"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={
            "PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(tmp_path / "manifest.toml"),
        },
        check=False,
        timeout=60,
    )


def _json_rows(stderr: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in stderr.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: the launcher is a shell script")
def test_an_injected_environment_never_reaches_an_audit_row(tmp_path: Path) -> None:
    """THE case: a hostile environment value must not forge or split an audit row.

    Asserts the payload's bytes are absent from every emitted row AND that no forged
    event appears — checking only for a refusal would pass while the tainted value
    still rode into the row that reported it.
    """
    result = _run_launcher(tmp_path, _INJECTION)

    assert result.returncode != 0, "an unrecognised environment must be a fail-closed refusal"

    rows = _json_rows(result.stderr)
    assert rows, f"the refusal emitted no audit row at all: {result.stderr!r}"
    assert not any(r.get("event") == "forged.row" for r in rows), (
        f"the injected payload forged a second audit row: {result.stderr!r}"
    )
    for row in rows:
        for key, value in row.items():
            assert "forged" not in str(value), f"tainted bytes reached audit field {key!r}: {row!r}"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: the launcher is a shell script")
def test_the_refusal_names_the_unrecognised_environment_reason(tmp_path: Path) -> None:
    """The refusal must be diagnosable, and use the closed-vocabulary reason."""
    result = _run_launcher(tmp_path, "definitely-not-an-environment")

    assert result.returncode != 0
    rows = _json_rows(result.stderr)
    reasons = {r.get("reason") for r in rows}
    assert "environment_unrecognised" in reasons, (
        f"expected the closed-vocab environment_unrecognised reason, got {reasons!r}"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: the launcher is a shell script")
@pytest.mark.parametrize("environment", ["development", "production", "test"])
def test_every_recognised_environment_is_still_accepted(tmp_path: Path, environment: str) -> None:
    """The vacuity floor: the guard must not refuse the values it exists to allow.

    Without this, refusing EVERYTHING would satisfy the cases above.
    """
    result = _run_launcher(tmp_path, environment)

    rows = _json_rows(result.stderr)
    assert not any(r.get("reason") == "environment_unrecognised" for r in rows), (
        f"the guard refused the legitimate environment {environment!r}: {result.stderr!r}"
    )
