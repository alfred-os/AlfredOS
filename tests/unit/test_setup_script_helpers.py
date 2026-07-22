"""Structural-safety tests for ``tests._setup_script_helpers.slice_shell_function``.

#470 CR (Major): the earlier ``content.index("\\n}\\n")`` slice could truncate at a nested
brace group or a ``}`` line inside a heredoc. These pin the heredoc-aware brace-depth scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests._setup_script_helpers import slice_shell_function


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
