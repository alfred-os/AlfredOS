"""Behaviour-level test for ``bin/alfred-setup.sh``'s .env credential gate.

UAT drove a stock first run — `cp .env.example .env && bin/alfred-setup.sh` — and the
script exited 1 on the DeepSeek `sk-...` placeholder shipped in `.env.example` itself.
The quarantine-key warning, added precisely because a keyless stack now REFUSE-BOOTS,
sat further down the script and was therefore UNREACHABLE on the one run it existed for.
The operator fixed the DeepSeek key, re-ran, and only then met the second required key.

A source-text assertion cannot catch that: both checks were present in the file the whole
time. Only ORDER made one dead. So this test runs the real block under `bash` and asserts
on what an operator actually sees.

It also pins the compose-precedence correction. The old text told an operator whose key
was exported in the shell but absent from `.env` that "docker compose reads .env, so the
stack will still refuse to boot". That is false — compose gives the shell environment
precedence over `.env`, so that stack boots. Verified directly::

    $ cat .env                       # FOO=from_dotenv
    $ FOO=from_shell docker compose config | grep FOO
          FOO: from_shell

Telling an operator their working setup is broken costs more than saying nothing.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled `bash` invocations from the integration suite. Every argv is a literal
# authored in this module; nothing crosses an untrusted boundary.
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

_ROOT = Path(__file__).resolve().parents[2]
_SETUP_SH = _ROOT / "bin" / "alfred-setup.sh"
_ENV_EXAMPLE = _ROOT / ".env.example"

_BLOCK_START = 'step "Validating .env credentials"'
_BLOCK_END = 'echo ".env credentials OK."'


def _credential_gate_block() -> str:
    """Slice the credential gate out of the real script, with the helpers it needs.

    Anchored on the section markers so a moved/renamed block fails loud here rather than
    silently running a stale copy. The helper prelude (`warn` / `step` / `read_env_var`)
    is sliced from the script too, not retyped, so the test can never drift from the
    definitions the script actually uses.
    """
    content = _SETUP_SH.read_text()
    prelude_start = content.index("step() {")
    prelude_end = content.index(_BLOCK_START)
    block_end = content.index(_BLOCK_END) + len(_BLOCK_END)
    prelude = content[prelude_start:prelude_end]
    # Drop everything in the prelude that needs docker/jq — we want the pure helpers.
    prelude = prelude[: prelude.index('step "Checking prerequisites"')]
    body = content[content.index(_BLOCK_START) : block_end]
    return "set -euo pipefail\n" + prelude + body


def _run_gate(
    tmp_path: Path, env_text: str, extra_env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    """Run the sliced credential gate in ``tmp_path`` against ``env_text`` as ``.env``."""
    (tmp_path / ".env").write_text(env_text)
    script = tmp_path / "gate.sh"
    script.write_text(_credential_gate_block())
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        # Start from a clean slate so a real key in the developer's own shell cannot
        # leak in and flip the shell-precedence branch under test.
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **(extra_env or {})},
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_the_slice_markers_still_match_the_script() -> None:
    """Guard the guard — a silently-empty slice would make every test below vacuous."""
    block = _credential_gate_block()
    assert "ALFRED_DEEPSEEK_API_KEY" in block
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in block
    assert "read_env_var" in block


def test_stock_first_run_reports_both_missing_credentials(tmp_path: Path) -> None:
    """The exact UAT scenario: `.env.example` copied verbatim.

    Both problems must appear in ONE report. Before the fix the run died on the DeepSeek
    placeholder and never mentioned the quarantine key at all.
    """
    code, _out, err = _run_gate(tmp_path, _ENV_EXAMPLE.read_text())

    assert code == 1, "a stock .env.example copy must not pass the credential gate"
    assert "ALFRED_DEEPSEEK_API_KEY" in err
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in err, (
        "the quarantine-key problem is STILL unreachable on a stock first run — this is "
        "the exact ordering bug the gate was restructured to fix"
    )
    assert "sk-..." in err, "the DeepSeek problem must name the placeholder it found"


def test_the_stock_report_is_actionable(tmp_path: Path) -> None:
    """Each problem states what to do next, and the run says what state it left behind."""
    _code, _out, err = _run_gate(tmp_path, _ENV_EXAMPLE.read_text())
    assert "platform.deepseek.com" in err
    assert "refuse to boot" in err.lower()
    assert "Nothing was changed" in err, (
        "a setup script that exits must tell the operator what state they are in"
    )


def test_only_the_quarantine_key_missing_is_reported_alone(tmp_path: Path) -> None:
    """A second-run operator who fixed DeepSeek sees only what is still wrong."""
    code, _out, err = _run_gate(
        tmp_path, "ALFRED_DEEPSEEK_API_KEY=sk-real\nALFRED_QUARANTINE_PROVIDER_API_KEY=\n"
    )
    assert code == 1
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in err
    assert "ALFRED_DEEPSEEK_API_KEY" not in err


def test_both_keys_present_passes(tmp_path: Path) -> None:
    """The happy path is quiet and exits 0."""
    code, out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\nALFRED_QUARANTINE_PROVIDER_API_KEY=sk-quar\n",
    )
    assert code == 0, err
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY is configured in .env." in out
    assert ".env credentials OK." in out


def test_shell_only_quarantine_key_is_not_reported_as_a_boot_failure(tmp_path: Path) -> None:
    """The item-2 correction: shell-set + .env-absent BOOTS. Do not claim otherwise.

    docker compose gives the shell environment precedence over `.env`, so this operator's
    stack starts. The old warning asserted it "will still refuse to boot".
    """
    code, out, err = _run_gate(
        tmp_path,
        "ALFRED_DEEPSEEK_API_KEY=sk-real\n",
        extra_env={"ALFRED_QUARANTINE_PROVIDER_API_KEY": "sk-from-shell"},
    )
    combined = out + err

    assert code == 0, f"a shell-exported key must not fail the gate: {combined!r}"
    assert "refuse to boot" not in combined.lower(), (
        "the gate still tells an operator whose stack boots fine that it will not boot"
    )
    # The real caveat — durability across terminals — is still worth saying.
    assert "precedence" in combined
    assert "durable" in combined


def test_empty_env_file_reports_both(tmp_path: Path) -> None:
    """An operator who wrote their own `.env` from scratch gets the same complete report."""
    code, _out, err = _run_gate(tmp_path, "")
    assert code == 1
    assert "ALFRED_DEEPSEEK_API_KEY" in err
    assert "ALFRED_QUARANTINE_PROVIDER_API_KEY" in err
