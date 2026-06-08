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
