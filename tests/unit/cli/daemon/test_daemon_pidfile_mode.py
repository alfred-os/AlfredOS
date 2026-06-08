"""PID file is mode 0600 + owner-current-user; refuses foreign-owned (#174)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_pidfile import (
    DaemonPidFileError,
    PidFileInfo,
    load_pidfile,
    write_pidfile,
)


def test_write_pidfile_creates_0600(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    write_pidfile(
        path=pf,
        pid=12345,
        boot_id="abc-def",
        started_at="2026-06-07T00:00:00+00:00",
    )
    st = pf.stat()
    assert st.st_mode & 0o777 == 0o600
    assert st.st_uid == os.getuid()


def test_write_pidfile_overwrites_existing_and_leaves_no_temp(tmp_path: Path) -> None:
    """A second write replaces the target (rename) and leaves no .tmp behind.

    The ``O_EXCL`` guards the UNIQUE temp inode, not the target, so an
    existing pidfile is replaced cleanly. The unique-suffix temp must not
    linger in the directory.
    """
    pf = tmp_path / "daemon.pid"
    write_pidfile(path=pf, pid=1, boot_id="first", started_at="t1")
    write_pidfile(path=pf, pid=2, boot_id="second", started_at="t2")
    assert load_pidfile(pf).boot_id == "second"
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == [], f"orphaned temp files: {leftovers}"


def test_write_pidfile_cleans_up_temp_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure mid-write removes the unique temp — no orphaned inode.

    sec write-validation: an exception after the ``O_EXCL`` open must not
    leave a partial temp the next write could trip over.
    """
    import alfred.cli.daemon._daemon_pidfile as mod

    pf = tmp_path / "daemon.pid"

    def _boom(_fd: int, _data: bytes) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(mod.os, "write", _boom)
    with pytest.raises(OSError, match="disk full"):
        write_pidfile(path=pf, pid=1, boot_id="x", started_at="t")
    assert not pf.exists()
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == [], f"orphaned temp files: {leftovers}"


def test_load_pidfile_roundtrips(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    write_pidfile(path=pf, pid=4242, boot_id="boot-x", started_at="2026-06-07T00:00:00+00:00")
    info = load_pidfile(pf)
    assert isinstance(info, PidFileInfo)
    assert info.pid == 4242
    assert info.boot_id == "boot-x"
    assert info.started_at == "2026-06-07T00:00:00+00:00"
    assert info.hostname


def test_load_pidfile_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(DaemonPidFileError):
        load_pidfile(tmp_path / "absent.pid")


def test_load_pidfile_refuses_bad_mode(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    pf.write_text(
        '{"pid":1,"boot_id":"x","started_at":"now","hostname":"h"}',
        encoding="utf-8",
    )
    pf.chmod(0o644)  # world-readable — refuse
    with pytest.raises(DaemonPidFileError):
        load_pidfile(pf)


def test_load_pidfile_refuses_malformed_json(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    pf.write_text("not-json", encoding="utf-8")
    pf.chmod(0o600)
    with pytest.raises(DaemonPidFileError):
        load_pidfile(pf)


def test_load_pidfile_refuses_foreign_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pf = tmp_path / "daemon.pid"
    pf.write_text(
        json.dumps({"pid": 1, "boot_id": "x", "started_at": "now", "hostname": "h"}),
        encoding="utf-8",
    )
    pf.chmod(0o600)

    real_fstat = os.fstat

    def _fake_fstat(fd: int) -> os.stat_result:
        s = real_fstat(fd)
        fields = list(s)
        fields[4] = 99999  # st_uid → a uid that is not ours
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", _fake_fstat)
    with pytest.raises(DaemonPidFileError):
        load_pidfile(pf)


def test_load_pidfile_refuses_non_regular_file(tmp_path: Path) -> None:
    """CR #3: a FIFO (or any non-regular file) at the path is refused.

    A planted non-regular file (FIFO / device / socket) could block forever
    on ``read`` or feed garbage. After the O_NOFOLLOW open + fstat we assert
    the opened fd is a REGULAR file and refuse otherwise.
    """
    fifo = tmp_path / "daemon.pid"
    os.mkfifo(fifo, mode=0o600)
    with pytest.raises(DaemonPidFileError):
        load_pidfile(fifo)


def test_load_pidfile_refuses_non_positive_pid(tmp_path: Path) -> None:
    """CR #4: a pidfile payload with pid <= 0 is malformed and refused.

    A ``0`` / negative pid would make ``os.kill(pid, 0)`` signal a process
    group or fail confusingly, so the loader rejects it as malformed.
    """
    for bad_pid in (0, -1):
        pf = tmp_path / f"daemon-{bad_pid}.pid"
        pf.write_text(
            json.dumps({"pid": bad_pid, "boot_id": "x", "started_at": "now", "hostname": "h"}),
            encoding="utf-8",
        )
        pf.chmod(0o600)
        with pytest.raises(DaemonPidFileError):
            load_pidfile(pf)
