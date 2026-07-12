"""Unit coverage for ``interpreter_sandbox_roots`` (the bwrap interpreter-bind walk).

The integration/adversarial suites that consume this helper are bwrap-gated
(Linux + CI only), so the symlink-chain walk would otherwise have NO coverage on a
dev box. These pure tests construct fake symlink layouts so the chain logic — the
uv minor-version alias hop in particular — is exercised without bwrap.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests._sandbox_interp import interpreter_sandbox_roots


def test_includes_prefix_base_prefix_and_realpath_root() -> None:
    """The real interpreter's prefix, base_prefix, and realpath root are always bound."""
    roots = interpreter_sandbox_roots()
    assert sys.prefix in roots
    assert sys.base_prefix in roots
    assert str(Path(sys.executable).resolve().parents[1]) in roots
    assert all(isinstance(r, str) for r in roots)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: symlink semantics for the bwrap sandbox root walk (#246 review)",
)
def test_walks_the_uv_minor_alias_symlink_hop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A venv whose bin/python traverses a MINOR-version alias dir binds the alias too.

    Reproduces the uv >=0.x layout that broke CI:
        .venv/bin/python -> <uv>/cpython-3.14-X/bin/python3   (the MINOR alias hop)
        <uv>/cpython-3.14-X  -> <uv>/cpython-3.14.6-X         (the patch dir / realpath)
    The alias dir is neither sys.prefix nor sys.base_prefix, so a base_prefix-only
    bind would leave it un-bound and bwrap's execvp through the symlink would fail.
    """
    uv = tmp_path / "uv-python"
    patch_dir = uv / "cpython-3.14.6-X"
    (patch_dir / "bin").mkdir(parents=True)
    (patch_dir / "bin" / "python3").write_text("#!/bin/true\n")
    alias_dir = uv / "cpython-3.14-X"
    alias_dir.symlink_to(patch_dir)  # the minor-version alias dir is a symlink
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / "python"
    venv_python.symlink_to(alias_dir / "bin" / "python3")  # via the ALIAS path

    monkeypatch.setattr(sys, "executable", str(venv_python))
    roots = interpreter_sandbox_roots()

    # The alias dir (the hop that base_prefix alone misses) is bound.
    assert str(alias_dir) in roots, f"alias hop not bound: {sorted(roots)}"
    # The realpath patch dir is bound too (covered by the realpath-root entry).
    assert str(patch_dir) in roots


def test_terminates_on_a_symlink_cycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A pathological symlink cycle does not hang the walk (the ``seen`` guard)."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.symlink_to(b)
    b.symlink_to(a)
    monkeypatch.setattr(sys, "executable", str(a))
    # Must return (not loop forever); the cycle members contribute their parents.
    roots = interpreter_sandbox_roots()
    assert isinstance(roots, set)


def test_terminates_on_a_relative_dotdot_cycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative ``..`` symlink that re-aliases itself must not slip the guard.

    ``d/link -> ../d/link`` revisits the same node under a DIFFERENT raw string
    (``d/../d/link``) each hop. The lexically-normalized ``seen`` key (+ the hard
    depth bound) must still terminate the walk (CodeRabbit).
    """
    d = tmp_path / "d"
    d.mkdir()
    link = d / "link"
    link.symlink_to(Path("..") / "d" / "link")  # relative, contains ``..``, self-aliasing
    monkeypatch.setattr(sys, "executable", str(link))
    roots = interpreter_sandbox_roots()  # must RETURN (no hang)
    assert isinstance(roots, set)


def test_non_symlink_executable_yields_just_the_static_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain (non-symlink) interpreter adds no chain hops beyond the static roots."""
    real = tmp_path / "py" / "bin" / "python3"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/true\n")
    monkeypatch.setattr(sys, "executable", str(real))
    roots = interpreter_sandbox_roots()
    # The realpath-root entry is the interpreter install root.
    assert str(tmp_path / "py") in roots
