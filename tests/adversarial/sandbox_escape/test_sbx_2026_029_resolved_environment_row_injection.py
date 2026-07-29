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

# `/bin/true` does not exist on macOS (it is `/usr/bin/true`), and the launcher's
# argv must be a real binary for a legitimate environment to reach its exec at all.
# The interpreter is absolute, so the PATH shim below cannot shadow it.
_TRUE_ARGV = (sys.executable, "-c", "")

# Minimal but REAL manifest. Without one the launcher refuses every environment with
# `manifest_unreadable` before reaching the sandbox stage — which is exactly why the
# original acceptance case proved nothing (see its docstring).
_MANIFEST = """alfred.manifest_version = 1

[plugin]
id = "alfred.probe"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

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


def _run_launcher(
    tmp_path: Path, stdout_payload: str, *, with_manifest: bool = False
) -> subprocess.CompletedProcess[str]:
    bindir = _fake_helper(tmp_path, stdout_payload)
    if with_manifest:
        (tmp_path / "manifest.toml").write_text(_MANIFEST, encoding="utf-8")
    # S603: argv is entirely repo-local and fixed — the launcher path, a literal
    # plugin id and /bin/true. The hostile input is the SHIMMED HELPER's stdout,
    # which is what this case exists to drive, not the command line.
    return subprocess.run(  # noqa: S603
        [str(_LAUNCHER), _PLUGIN_ID, *_TRUE_ARGV],
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

    Asserts the EXACT launcher-authored row, not merely the absence of the payload's
    bytes. A weaker "no `forged` anywhere" form passes if a regression substitutes
    some other non-forged value — `production`, say — for the required `unset`
    sentinel, which would be a fail-OPEN carrying an attacker-influenced value into
    the signed audit log. It also pins the row COUNT, so an extra malformed
    JSON-prefixed line cannot slip past.
    """
    result = _run_launcher(tmp_path, _INJECTION)

    assert result.returncode != 0, "an unrecognised environment must be a fail-closed refusal"

    rows = _json_rows(result.stderr)
    assert rows == [
        {
            "event": "supervisor.plugin.sandbox_refused",
            "plugin_id": _PLUGIN_ID,
            "reason": "environment_unrecognised",
            "environment": "unset",
            "host_os": "unknown",
        }
    ], f"expected exactly the launcher-authored refusal row, got {rows!r}"

    # Belt and braces on the raw stream: the payload tried to SPLIT the row, so a
    # forged fragment could exist as a line the JSON parser above skipped.
    assert "forged" not in result.stderr, (
        f"tainted bytes reached the stderr stream: {result.stderr!r}"
    )


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
@pytest.mark.parametrize("environment", ["development", "test"])
def test_a_recognised_environment_completes_the_launch(tmp_path: Path, environment: str) -> None:
    """The vacuity floor, and it has to be a real one.

    Asserting merely "no `environment_unrecognised` row" was worthless: EVERY value
    failed earlier with `manifest_unreadable` and never reached the sandbox stage at
    all, so the case passed without the guard ever having accepted anything. A zero
    exit is the direct acceptance assertion — the launcher ran the argv.

    `production` is excluded because it legitimately refuses on a non-Linux host
    (`uid_separation_unavailable`, the #486 keystone) and on a non-root Linux host
    (`runuser_unavailable`); it gets its own case below, which asserts acceptance
    through the audit row instead.
    """
    result = _run_launcher(tmp_path, environment, with_manifest=True)

    assert result.returncode == 0, (
        f"the launcher refused the legitimate environment {environment!r} instead of "
        f"running its argv: rc={result.returncode} stderr={result.stderr!r}"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: the launcher is a shell script")
def test_production_is_accepted_and_propagated_even_when_the_host_refuses(
    tmp_path: Path,
) -> None:
    """`production` must be ACCEPTED by the environment gate on every host.

    It may still be refused downstream — that is the point of the #486 keystone — so
    a zero exit is not portable here. Acceptance is proved instead by the refusal row
    carrying the real `production` value: a value the gate had rejected could never
    reach that field, which is hard-coded to the `unset` sentinel on the refusal path.
    """
    result = _run_launcher(tmp_path, "production", with_manifest=True)

    rows = _json_rows(result.stderr)
    assert not any(r.get("reason") == "environment_unrecognised" for r in rows), (
        f"the gate refused the legitimate `production` value: {result.stderr!r}"
    )
    if result.returncode != 0:
        assert any(r.get("environment") == "production" for r in rows), (
            "a downstream refusal did not carry the accepted environment, so this "
            f"case cannot prove the gate accepted it: {rows!r}"
        )
