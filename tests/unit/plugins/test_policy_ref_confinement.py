"""policy_ref path-confinement (PR-S4-6 Component G — sec-2 BLOCKER keystone).

The launcher resolves a manifest's per-OS ``policy_ref`` into a policy file it
reads. An attacker who can plant a manifest must not be able to point
``policy_ref`` outside the sandbox-policy root (``../../etc/passwd``, an
absolute path, or a symlink escaping the root). ``manifest_reader`` enforces
this BEFORE the file is ever read, refusing with
``reason="policy_ref_escapes_root"`` (the shipped audit vocab) and a non-zero
exit.

These tests exercise the in-process ``resolve_policy_ref`` boundary so every
refusal branch is measured for the 100% trust-boundary floor; the launcher
shells out to the same code via ``--policy-to-bwrap-flags --policy-ref``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.plugins.manifest_reader import (
    PolicyRefEscapesRoot,
    resolve_policy_ref,
)


def _make_root(tmp_path: Path) -> Path:
    root = tmp_path / "config" / "sandbox"
    root.mkdir(parents=True)
    return root


def test_clean_relative_ref_resolves(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    policy = root / "foo.linux.bwrap.policy"
    policy.write_text("keep_fds = [3]\n")
    resolved = resolve_policy_ref("config/sandbox/foo.linux.bwrap.policy", install_root=tmp_path)
    assert resolved == policy.resolve()


def test_parent_traversal_refused(tmp_path: Path) -> None:
    _make_root(tmp_path)
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("config/sandbox/../../etc/passwd", install_root=tmp_path)


def test_absolute_path_outside_root_refused(tmp_path: Path) -> None:
    _make_root(tmp_path)
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("/etc/passwd", install_root=tmp_path)


def test_dotdot_component_refused_even_if_lands_inside(tmp_path: Path) -> None:
    # Defence in depth: ANY ``..`` component is refused, even one that would
    # resolve back inside the root — a launderable shape we don't tolerate.
    root = _make_root(tmp_path)
    (root / "foo.linux.bwrap.policy").write_text("keep_fds = [3]\n")
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("config/sandbox/sub/../foo.linux.bwrap.policy", install_root=tmp_path)


def test_symlink_escaping_root_refused(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    outside = tmp_path / "outside.policy"
    outside.write_text("keep_fds = [3]\n")
    link = root / "evil.linux.bwrap.policy"
    link.symlink_to(outside)
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("config/sandbox/evil.linux.bwrap.policy", install_root=tmp_path)


def test_symlink_inside_root_allowed(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    real = root / "real.linux.bwrap.policy"
    real.write_text("keep_fds = [3]\n")
    link = root / "alias.linux.bwrap.policy"
    link.symlink_to(real)
    resolved = resolve_policy_ref("config/sandbox/alias.linux.bwrap.policy", install_root=tmp_path)
    assert resolved == real.resolve()


def test_ref_pointing_at_root_dir_itself_refused(tmp_path: Path) -> None:
    _make_root(tmp_path)
    with pytest.raises(PolicyRefEscapesRoot):
        # A ref that resolves to the root directory (not a file under it) is
        # not a policy file — refuse rather than try to read a directory.
        resolve_policy_ref("config/sandbox", install_root=tmp_path)


def test_custom_policy_dir_override(tmp_path: Path) -> None:
    # ALFRED_SANDBOX_POLICY_DIR may relocate the root; confinement follows it.
    custom = tmp_path / "custom-policies"
    custom.mkdir()
    policy = custom / "foo.policy"
    policy.write_text("keep_fds = [3]\n")
    resolved = resolve_policy_ref("foo.policy", install_root=tmp_path, policy_dir=custom)
    assert resolved == policy.resolve()


def test_custom_policy_dir_traversal_refused(tmp_path: Path) -> None:
    custom = tmp_path / "custom-policies"
    custom.mkdir()
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("../escape", install_root=tmp_path, policy_dir=custom)


def test_missing_file_refused(tmp_path: Path) -> None:
    # A clean ref whose file simply does not exist: strict resolve() raises
    # OSError → refused (the launcher never reads an unresolvable ref).
    _make_root(tmp_path)
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("config/sandbox/absent.policy", install_root=tmp_path)


def test_ref_resolving_to_subdir_refused(tmp_path: Path) -> None:
    # A ref under the root that resolves to a DIRECTORY (not a file) is not a
    # policy file — refuse (hits the is_file() guard, distinct from the
    # root-dir-itself and parent-traversal guards).
    root = _make_root(tmp_path)
    (root / "subdir").mkdir()
    with pytest.raises(PolicyRefEscapesRoot):
        resolve_policy_ref("config/sandbox/subdir", install_root=tmp_path)
