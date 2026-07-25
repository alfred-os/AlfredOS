"""Unit tests for the single repo-root resolver (#500)."""

from __future__ import annotations

from pathlib import Path

from alfred._repo_root import _CONTAINER_ROOT, _resolve, repo_root


def test_env_override_wins(monkeypatch) -> None:
    monkeypatch.setenv("ALFRED_REPO_ROOT", "/opt/somewhere")
    assert repo_root() == Path("/opt/somewhere")


def test_resolve_env_value_wins_over_source() -> None:
    assert _resolve("/deploy/root", Path("/x/y/z/_repo_root.py")) == Path("/deploy/root")


def test_resolve_blank_env_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "src" / "alfred").mkdir(parents=True)
    (tmp_path / "plugins").mkdir()
    module_path = tmp_path / "src" / "alfred" / "_repo_root.py"
    assert _resolve("   ", module_path) == tmp_path


def test_resolve_source_tree_when_marker_present(tmp_path: Path) -> None:
    (tmp_path / "src" / "alfred").mkdir(parents=True)
    (tmp_path / "plugins").mkdir()  # the marker
    module_path = tmp_path / "src" / "alfred" / "_repo_root.py"
    assert _resolve(None, module_path) == tmp_path


def test_resolve_container_fallback_when_no_marker(tmp_path: Path) -> None:
    (tmp_path / "lib" / "site-packages").mkdir(parents=True)
    module_path = tmp_path / "lib" / "site-packages" / "_repo_root.py"
    assert _resolve(None, module_path) == _CONTAINER_ROOT


def test_repo_root_finds_worktree_plugins_dir(monkeypatch) -> None:
    monkeypatch.delenv("ALFRED_REPO_ROOT", raising=False)
    root = repo_root()
    assert (root / "plugins").is_dir()
