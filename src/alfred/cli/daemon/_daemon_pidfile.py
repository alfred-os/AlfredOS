"""PID file discipline for the daemon CLI (#174 PR-S4-1).

File at ``~/.run/alfred/daemon.pid`` (mode 0600, owner = current uid).
JSON contents: ``{"pid": int, "boot_id": str, "started_at": str (ISO8601),
"hostname": str}``.

Validation discipline mirrors the operator-session loader (open-then-fstat
to close the TOCTOU window):

1. ``open(path, O_RDONLY | O_NOFOLLOW)`` — refuse symlinks.
2. ``fstat(fd)`` — validate ``st_mode == 0600`` AND ``st_uid == getuid()``.
3. Only then read contents.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_PIDFILE_DEFAULT_DIR: Final[Path] = Path.home() / ".run" / "alfred"
_PIDFILE_NAME: Final[str] = "daemon.pid"
_PIDFILE_READ_LIMIT: Final[int] = 4096


class DaemonPidFileError(Exception):
    """Raised on a malformed / foreign-owned / mode-wrong / missing PID file."""


@dataclass(frozen=True, slots=True)
class PidFileInfo:
    """Parsed PID-file contents."""

    pid: int
    boot_id: str
    started_at: str
    hostname: str


def default_pidfile_path() -> Path:
    """Return the default PID-file path (``~/.run/alfred/daemon.pid``)."""
    return _PIDFILE_DEFAULT_DIR / _PIDFILE_NAME


def write_pidfile(
    path: Path,
    *,
    pid: int,
    boot_id: str,
    started_at: str,
) -> None:
    """Write the PID file atomically with mode 0600.

    Creates parent directories if missing (they too are mode 0700). The
    write goes to a unique temp file then renames, and the mode is set on
    the fd via the ``os.open`` mode argument so the file is never
    world-readable even momentarily.

    sec (security LOW, write-validation): the temp file is opened with
    ``O_EXCL`` and a per-write unique suffix (PID + random token) so the
    write NEVER reuses a pre-existing inode. Mirrors the read side's
    open-then-validate discipline: an attacker-planted ``.tmp`` (same uid,
    e.g. a compromised sibling process) is refused with ``FileExistsError``
    rather than truncated-and-reused — we only ever write a file we created.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "pid": pid,
            "boot_id": boot_id,
            "started_at": started_at,
            "hostname": socket.gethostname(),
        }
    )
    unique = f"{os.getpid()}.{secrets.token_hex(8)}"
    tmp = path.with_name(f"{path.name}.{unique}.tmp")
    fd = os.open(
        str(tmp),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(fd, payload.encode("utf-8"))
        os.close(fd)
        tmp.rename(path)
    except BaseException:
        # Never leave a partial / orphaned temp behind on any failure path.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def load_pidfile(path: Path) -> PidFileInfo:
    """Open + fstat-validate + read the PID file.

    Raises:
        DaemonPidFileError: on missing file, bad mode, foreign owner, or
            malformed JSON.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise DaemonPidFileError(f"pidfile_missing:{path}") from exc
    try:
        st = os.fstat(fd)
        if st.st_mode & 0o777 != 0o600:
            raise DaemonPidFileError(f"bad_file_mode:{oct(st.st_mode)}")
        if st.st_uid != os.getuid():
            raise DaemonPidFileError(f"bad_file_owner:{st.st_uid}")
        raw = os.read(fd, _PIDFILE_READ_LIMIT)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DaemonPidFileError("malformed_json") from exc
    try:
        return PidFileInfo(
            pid=int(data["pid"]),
            boot_id=str(data["boot_id"]),
            started_at=str(data["started_at"]),
            hostname=str(data["hostname"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DaemonPidFileError("malformed_json") from exc


def is_pid_alive(pid: int) -> bool:
    """Best-effort liveness check via ``kill(pid, 0)``.

    Returns ``True`` if the process exists and we have permission to signal
    it; ``False`` on ``ProcessLookupError``. ``PermissionError`` is treated
    as "alive but not ours" — for daemon status that is a "running" answer.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another uid
    return True


def delete_pidfile(path: Path) -> None:
    """Remove the PID file; a missing file is not an error."""
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
