"""Daemon per-adapter status snapshot — model, builder, and file IO (G6-2b-2c / #288).

The ``alfred status`` / ``alfred daemon status`` CLI does NOT dial the daemon (it
reads Settings / the pidfile only), and there is no daemon RPC service. So the
daemon SERIALISES its in-process per-adapter status (the AdapterStatusObserver's
``latest`` map) + crash-incident summary (the CrashIncidentReconciler) to a 0600
JSON file under the runtime dir, tied to the daemon ``boot_id``, and the CLI reads
it. This is the sanctioned "relocate the render in-daemon" option from the 2b-2b
snapshot-reachability decision (NO new socket RPC — YAGNI).

NO secret / raw error text crosses the file: only non-sensitive operational
metadata (adapter_id, state, occurred_at, incarnation, incident COUNT + the latest
incident's seq/source/id). The raw crash ``detail`` lives only in the signed audit
log. SEC-02 carry-forward: ``crash_signal_source == "both"`` is a diagnostic hint,
NOT authenticated corroboration — render it as informational only.

File discipline MIRRORS ``_daemon_pidfile.py`` exactly: O_EXCL temp + rename write
at mode 0600, O_NOFOLLOW + O_NONBLOCK + fstat (regular-file + mode + owner)
validate on read.

Anti-stale is NOT anti-forgery (sec-MEDIUM-3, correction #12). The CLI cross-checks
the snapshot's ``boot_id`` against the live pidfile to reject a STALE snapshot left
by a PRIOR daemon incarnation. ``boot_id`` is NON-secret: a same-uid process —
already INSIDE the daemon trust domain — could forge a snapshot carrying the
current ``boot_id``. We deliberately add NO HMAC: it would only defend against an
attacker who has already defeated the trust boundary, and would impose a
secret-on-disk obligation this slice rightly avoids. The signed audit log is the
authoritative record; this snapshot is best-effort operator convenience.

Runtime-dir ownership (sec-MEDIUM-2, correction #16a): the pidfile is written FIRST
in ``_start_async`` and OWNS the ``~/.run/alfred`` dir creation at mode 0700. This
module relies on its OWN per-file 0600 + owner ``fstat`` on read; neither module
tightens an already-loose pre-existing dir.

Cross-version file contract (sec-LOW-6, correction #16e): a schema change is
self-healing only AFTER the new daemon rewrites the file. An OLD CLI reading a
NEWER file that carries an unknown ``extra`` field is rejected by ``extra="forbid"``
-> ``malformed_snapshot`` -> the render skips the adapter section, which is
acceptable best-effort degradation (no stale lie, no crash).

NOTE (arch-H1, correction #1): ``default_status_snapshot_path`` resolves
``Path.home()`` at CALL time (mirroring ``comms_socket_transport._runtime_dir``) so
a test that monkeypatches ``$HOME`` sees the redirect. The pidfile, socket
transport, and this module each derive ``~/.run/alfred`` INDEPENDENTLY today; a
single shared ``runtime_dir()`` resolver is the ideal but is a cross-package
refactor — known drift for a follow-up.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

# "unknown" = an adapter the reconciler has seen (a crash incident) but for which
# the observer holds no accepted gateway state yet (e.g. a child-only crash before
# any accepted ``up``).
RenderedAdapterState = Literal["up", "down", "crashed", "breaker_open", "unknown"]
CrashSignalSource = Literal["gateway", "child", "both"]

_SNAPSHOT_NAME: Final[str] = "daemon-status.json"
# sec-LOW-5 (correction #16c): a real snapshot is <4 KiB; bound the read toward the
# pidfile's 4 KiB so a planted huge file cannot OOM the CLI. 64 KiB leaves slack
# for many adapters while staying a tight cap.
_SNAPSHOT_READ_LIMIT: Final[int] = 64 * 1024


class DaemonStatusSnapshotFileError(Exception):
    """Raised on a missing / malformed / mode-wrong / foreign-owned snapshot file."""


class LatestCrashSummary(BaseModel):
    """The most recent correlated crash incident for one adapter (non-secret summary)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_restart_seq: int = Field(ge=0)
    crash_signal_source: CrashSignalSource
    crash_incident_id: str = Field(min_length=1)


class AdapterStatusLine(BaseModel):
    """One adapter's render line: state + why-not-up summary (no secret/raw detail)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter_id: str = Field(min_length=1)
    state: RenderedAdapterState
    occurred_at: str | None = None  # ISO8601 of the latest accepted gateway transition
    current_incarnation: int = Field(default=0, ge=0)
    crash_incident_count: int = Field(default=0, ge=0)
    latest_crash: LatestCrashSummary | None = None


class DaemonStatusSnapshot(BaseModel):
    """The full per-adapter status snapshot the daemon publishes for the CLI."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    boot_id: str = Field(min_length=1)
    written_at: str  # ISO8601
    adapters: dict[str, AdapterStatusLine] = Field(default_factory=dict)


def build_daemon_status_snapshot(
    *,
    boot_id: str,
    written_at: datetime,
    observer: AdapterStatusObserver,
    reconciler: CrashIncidentReconciler,
) -> DaemonStatusSnapshot:
    """Fold the observer's per-adapter state + the reconciler's incidents into a snapshot.

    Pure: reads the two in-process surfaces, invents no state, leaks no secret.
    """
    latest = observer.all_latest()
    adapter_ids = set(latest) | set(reconciler.adapter_ids())
    lines: dict[str, AdapterStatusLine] = {}
    # correction #6 (arch-L2): ``sorted(adapter_ids)`` fixes the dict insertion
    # order, which makes the serialised ``adapters`` dict STABLE across refreshes.
    # That stability is LOAD-BEARING for the publisher's write-if-changed
    # content-key comparison — without it, an unchanged set of adapters could
    # serialise in a different order and trigger a spurious rewrite.
    for adapter_id in sorted(adapter_ids):
        snap = latest.get(adapter_id)
        incidents = reconciler.incidents(adapter_id)
        latest_crash = (
            LatestCrashSummary(
                host_restart_seq=incidents[-1].host_restart_seq,
                crash_signal_source=incidents[-1].crash_signal_source,
                crash_incident_id=incidents[-1].crash_incident_id,
            )
            if incidents
            else None
        )
        lines[adapter_id] = AdapterStatusLine(
            adapter_id=adapter_id,
            state=snap.state if snap is not None else "unknown",
            occurred_at=snap.occurred_at.isoformat() if snap is not None else None,
            current_incarnation=reconciler.current_incarnation(adapter_id),
            crash_incident_count=len(incidents),
            latest_crash=latest_crash,
        )
    return DaemonStatusSnapshot(boot_id=boot_id, written_at=written_at.isoformat(), adapters=lines)


def default_status_snapshot_path() -> Path:
    """Return the default snapshot path (``~/.run/alfred/daemon-status.json``).

    Resolves ``Path.home()`` at CALL time (arch-H1, correction #1) so a test that
    monkeypatches ``$HOME`` sees the redirect — mirrors
    ``comms_socket_transport._runtime_dir``.
    """
    return Path.home() / ".run" / "alfred" / _SNAPSHOT_NAME


def write_status_snapshot(path: Path, snapshot: DaemonStatusSnapshot) -> None:
    """Atomically write the snapshot JSON at mode 0600 (mirrors ``write_pidfile``)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = snapshot.model_dump_json().encode("utf-8")
    unique = f"{os.getpid()}.{secrets.token_hex(8)}"
    tmp = path.with_name(f"{path.name}.{unique}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, payload)
        os.close(fd)
        tmp.rename(path)
    except BaseException:
        # Never leave a partial / orphaned temp behind on any failure path.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def load_status_snapshot(path: Path) -> DaemonStatusSnapshot:
    """Open + fstat-validate + parse the snapshot (mirrors ``load_pidfile`` discipline)."""
    try:
        # O_NONBLOCK is load-bearing: a same-uid attacker who plants a FIFO at the
        # path would otherwise hang the CLI open() forever before fstat runs. With
        # O_NONBLOCK the open returns immediately and fstat then rejects the FIFO as
        # non-regular below. O_NOFOLLOW refuses a symlink target.
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as exc:
        raise DaemonStatusSnapshotFileError(f"snapshot_missing:{path}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise DaemonStatusSnapshotFileError(f"not_a_regular_file:{oct(st.st_mode)}")
        if st.st_mode & 0o777 != 0o600:
            raise DaemonStatusSnapshotFileError(f"bad_file_mode:{oct(st.st_mode)}")
        if st.st_uid != os.getuid():
            raise DaemonStatusSnapshotFileError(f"bad_file_owner:{st.st_uid}")
        raw = os.read(fd, _SNAPSHOT_READ_LIMIT)
    finally:
        os.close(fd)
    try:
        return DaemonStatusSnapshot.model_validate(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        # A truncated oversized file (read capped at _SNAPSHOT_READ_LIMIT) fails the
        # JSON parse here too -> the SAME malformed branch.
        raise DaemonStatusSnapshotFileError("malformed_snapshot") from exc


def delete_status_snapshot(path: Path) -> None:
    """Remove the snapshot file; a missing file is not an error."""
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


__all__ = [
    "AdapterStatusLine",
    "DaemonStatusSnapshot",
    "DaemonStatusSnapshotFileError",
    "LatestCrashSummary",
    "build_daemon_status_snapshot",
    "default_status_snapshot_path",
    "delete_status_snapshot",
    "load_status_snapshot",
    "write_status_snapshot",
]
