"""TOCTOU-safe session-file load (sec-2 closure).

``load_session_file`` opens the PARENT directory first, fstat-validates
it (refuse if group/other-accessible or not owned by euid), then
``openat(parent_fd, "session", O_RDONLY | O_NOFOLLOW)`` and fstat-
validates the file (mode 0600, owner uid/gid). This refuses both
symlink swaps (``O_NOFOLLOW``) and rename-into-dir attacks that
``O_NOFOLLOW`` alone misses.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr

from alfred.identity.operator_session import (
    OperatorSessionBadFileMode,
    OperatorSessionBadFileOwner,
    OperatorSessionFile,
    OperatorSessionMalformed,
    OperatorSessionMissing,
    OperatorSessionParentDirInsecure,
    _serialize_to_file_bytes,
    load_session_file,
    write_session_file,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX mode/owner semantics; Windows operators use the WSL2 path.",
)


def _session() -> OperatorSessionFile:
    issued = datetime(2026, 6, 8, tzinfo=UTC)
    return OperatorSessionFile(
        schema_version=1,
        user_id=1,
        token=SecretStr("tok"),
        issued_at=issued,
        expires_at=issued + timedelta(hours=12),
        host="h",
        machine_id_hash="c" * 64,
    )


def _write_secure(tmp_path: Path, body: bytes, *, mode: int = 0o600) -> Path:
    """Write tmp_path/.config/alfred/session with a 0700 parent dir."""
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True, exist_ok=True)
    parent.chmod(0o700)
    path = parent / "session"
    path.write_bytes(body)
    path.chmod(mode)
    return path


def test_happy_path_returns_parsed_session(tmp_path: Path) -> None:
    path = _write_secure(tmp_path, _serialize_to_file_bytes(_session()))
    assert load_session_file(path) == _session()


def test_missing_file_refused(tmp_path: Path) -> None:
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    with pytest.raises(OperatorSessionMissing):
        load_session_file(parent / "session")


def test_bad_file_mode_refused(tmp_path: Path) -> None:
    path = _write_secure(tmp_path, _serialize_to_file_bytes(_session()), mode=0o644)
    with pytest.raises(OperatorSessionBadFileMode):
        load_session_file(path)


def test_symlink_refused_at_open(tmp_path: Path) -> None:
    target = tmp_path / "attacker"
    target.write_bytes(_serialize_to_file_bytes(_session()))
    target.chmod(0o600)
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    link = parent / "session"
    link.symlink_to(target)
    with pytest.raises(OperatorSessionBadFileMode):
        load_session_file(link)


def test_insecure_parent_dir_refused(tmp_path: Path) -> None:
    path = _write_secure(tmp_path, _serialize_to_file_bytes(_session()))
    # Broaden the parent dir to group/other-accessible.
    path.parent.chmod(0o755)
    with pytest.raises(OperatorSessionParentDirInsecure):
        load_session_file(path)


def test_malformed_json_refused(tmp_path: Path) -> None:
    path = _write_secure(tmp_path, b"{not valid json")
    with pytest.raises(OperatorSessionMalformed):
        load_session_file(path)


def test_extra_field_refused(tmp_path: Path) -> None:
    body = _serialize_to_file_bytes(_session()).replace(b"}", b', "x": 1}', 1)
    path = _write_secure(tmp_path, body)
    with pytest.raises(OperatorSessionMalformed):
        load_session_file(path)


def test_write_round_trips_through_load(tmp_path: Path) -> None:
    """write_session_file produces a file load_session_file accepts."""
    path = tmp_path / ".config" / "alfred" / "session"
    write_session_file(path, _session())
    assert (path.stat().st_mode & 0o777) == 0o600
    assert load_session_file(path) == _session()


def test_write_refuses_insecure_existing_parent(tmp_path: Path) -> None:
    """An existing parent dir broader than 0700 is refused before write."""
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    with pytest.raises(OperatorSessionParentDirInsecure):
        write_session_file(parent / "session", _session())


def test_missing_parent_dir_refused(tmp_path: Path) -> None:
    """A path whose parent dir does not exist refuses with Missing."""
    with pytest.raises(OperatorSessionMissing):
        load_session_file(tmp_path / "nope" / "session")


def test_oversize_file_refused(tmp_path: Path) -> None:
    path = _write_secure(tmp_path, b"x" * (64 * 1024 + 1))
    with pytest.raises(OperatorSessionMalformed, match="exceeds"):
        load_session_file(path)


@pytest.mark.skipif(
    os.getuid() == 0,
    reason="root bypasses mode/owner checks; the test asserts a non-root refusal.",
)
def test_parent_dir_not_owned_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A parent dir owned by a different euid refuses with ParentDirNotOwned."""
    from alfred.identity.operator_session import OperatorSessionParentDirNotOwned

    path = _write_secure(tmp_path, _serialize_to_file_bytes(_session()))
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(OperatorSessionParentDirNotOwned):
        load_session_file(path)


@pytest.mark.skipif(
    os.getuid() == 0,
    reason="root bypasses mode/owner checks; the test asserts a non-root refusal.",
)
def test_bad_file_owner_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A uid mismatch on the file fstat refuses with BadFileOwner.

    We cannot chown to another uid without privilege, so we monkeypatch
    ``os.getuid`` to report a different uid than the file actually has —
    exercising the same comparison branch the real attack would hit.
    """
    path = _write_secure(tmp_path, _serialize_to_file_bytes(_session()))
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    with pytest.raises(OperatorSessionBadFileOwner):
        load_session_file(path)
