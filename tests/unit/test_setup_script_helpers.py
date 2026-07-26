"""Structural-safety tests for ``tests._setup_script_helpers.slice_shell_function``.

#470 CR (Major): the earlier ``content.index("\\n}\\n")`` slice could truncate at a nested
brace group or a ``}`` line inside a heredoc. These pin the heredoc-aware brace-depth scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests._setup_script_helpers import slice_shell_function, slice_shell_step


def _script(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "setup.sh"
    p.write_text(body)
    return p


def test_slices_a_simple_top_level_function(tmp_path: Path) -> None:
    s = _script(tmp_path, "a() { :; }\nfoo() {\n  echo hi\n}\nb() { :; }\n")
    assert slice_shell_function(s, "foo() {") == "foo() {\n  echo hi\n}\n"


def test_nested_brace_group_is_not_a_premature_close(tmp_path: Path) -> None:
    s = _script(
        tmp_path,
        "foo() {\n  if x; then\n    { echo a; }\n  fi\n  echo end\n}\nb() { :; }\n",
    )
    out = slice_shell_function(s, "foo() {")
    assert "echo end" in out
    assert out.count("{") == out.count("}")
    assert out.rstrip().endswith("}")


def test_heredoc_brace_line_is_not_a_premature_close(tmp_path: Path) -> None:
    # A `}` alone on a line INSIDE a heredoc must not end the slice early.
    s = _script(
        tmp_path,
        "foo() {\n  cat <<EOF\n}\nliteral text\nEOF\n  echo real_end\n}\nb() { :; }\n",
    )
    out = slice_shell_function(s, "foo() {")
    assert "echo real_end" in out
    assert out.rstrip().endswith("}")


def test_missing_anchor_raises(tmp_path: Path) -> None:
    s = _script(tmp_path, "foo() { :; }\n")
    with pytest.raises(ValueError, match="declaration line"):
        slice_shell_function(s, "nope() {")


def test_the_real_openssl_missing_message_is_sliced_whole() -> None:
    # The actual function this helper exists to slice — heredoc body included in full.
    func = slice_shell_function(Path("bin/alfred-setup.sh"), "openssl_missing_message() {")
    assert func.startswith("openssl_missing_message() {")
    assert func.rstrip().endswith("}")
    assert "apt-get install" in func  # heredoc content is present, not truncated


def test_slice_step_returns_block_up_to_next_step(tmp_path: Path) -> None:
    s = _script(
        tmp_path,
        'step "First"\necho one\nadd_config_problem "x"\nstep "Second"\necho two\n',
    )
    out = slice_shell_step(s, "First")
    assert out == 'step "First"\necho one\nadd_config_problem "x"\n'
    assert "Second" not in out


def test_slice_step_runs_to_eof_when_last(tmp_path: Path) -> None:
    s = _script(tmp_path, 'step "Only"\necho done\n')
    assert slice_shell_step(s, "Only") == 'step "Only"\necho done\n'


def test_slice_step_ignores_the_step_function_definition(tmp_path: Path) -> None:
    # `step() { ... }` is the function def, not a `step "Title"` call — must not anchor on it.
    s = _script(tmp_path, 'step() {\n  echo "$1"\n}\nstep "Real"\necho body\n')
    assert slice_shell_step(s, "Real") == 'step "Real"\necho body\n'


def test_slice_step_missing_raises(tmp_path: Path) -> None:
    s = _script(tmp_path, 'step "Present"\necho hi\n')
    with pytest.raises(ValueError, match="Absent"):
        slice_shell_step(s, "Absent")


def test_the_real_credential_gate_step_is_sliced_whole() -> None:
    block = slice_shell_step(Path("bin/alfred-setup.sh"), "Validating .env credentials")
    assert block.startswith('step "Validating .env credentials"')
    assert "config_problems" in block
    assert "ALFRED_DEEPSEEK_API_KEY" in block and "ALFRED_QUARANTINE_PROVIDER_API_KEY" in block
    # Bounded: it must not run past the gate into the next step.
    assert "Loading the bwrap userns AppArmor profile" not in block
