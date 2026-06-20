# G6-2b-2c — Daemon Status Snapshot + `alfred daemon status` Adapter Render Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the daemon's in-process per-adapter status + crash-incident data (the `AdapterStatusObserver.latest()` snapshot and the `CrashIncidentReconciler` incidents from G6-2b-2a/2b-2b) reachable from the CLI, so an operator running `alfred daemon status` can see each adapter's state and *why* it is not `up` — closing the 2b-2b-deferred "snapshot reachability" seam.

**Architecture:** The `alfred status` / `alfred daemon status` CLI commands do **not** dial the daemon (they read Settings / the pidfile only — verified), and there is **no daemon RPC service** today (the comms socket is a one-shot TUI-bound wire). Rather than build a new trust-sensitive socket RPC, 2b-2c takes the sanctioned "relocate the render in-daemon" option from the 2b-2b decision: the daemon periodically serialises a **non-secret status snapshot** to a `0600` JSON file under the runtime dir (`~/.run/alfred/daemon-status.json`), written with the exact O_EXCL-temp+rename / O_NOFOLLOW / fstat-validate discipline the pidfile already uses, tied to the daemon's `boot_id`, and reaped on every shutdown path. `alfred daemon status` loads the file, cross-checks its `boot_id` against the live pidfile (stale → ignored), and renders the per-adapter lines via `t()`. The observer/reconciler stay pure (a periodic publisher *polls* them — their G6-2b constructor signatures are NOT re-touched); the publisher is a supervised task reaped like the socket listeners. No new wire, no RPC, no secret on the wire (YAGNI; `alfred status` / `alfred gateway adapters` can reuse the loader + render helper in G6-4/G6-5).

**Tech Stack:** Python 3.12+, Pydantic v2 (frozen wire/view models), asyncio (a periodic publisher task), structlog, pytest + pytest-asyncio. All new logic is pure host/core-side and runs in-process on the required NON-ROOT gate (no bwrap, no launcher).

---

## Context the implementer must hold

Read these before starting. Findings are verified against `main` (`e7f5d850`, with G6-2b-2b merged).

- **The CLI is non-dialing today.** `status()` (`src/alfred/cli/main.py:175-215`) reads Settings + `SecretBroker` only; `status_daemon()` (`src/alfred/cli/daemon/_commands.py:2299-2328`) reads the pidfile only via `load_pidfile`. Neither reaches the in-daemon `AdapterStatusObserver` / `CrashIncidentReconciler`. This slice extends **`alfred daemon status`** (the daemon-runtime view that already reads runtime files) — NOT the global `alfred status` (which is the Settings/provider overview and should stay daemon-free). The eventual `alfred gateway adapters` (G6-5) reuses the loader + render helper this slice builds.
- **The data lives in `_CommsBootGraph`** (`src/alfred/cli/daemon/_commands.py:564-660`), a `frozen=True, slots=True` dataclass built once in `_build_comms_boot_graph` (guarded behind `if settings.comms_enabled_adapters`) and held for the daemon process lifetime in `_start_async`. It exposes `status_observer: AdapterStatusObserver` and `crash_incident_reconciler: CrashIncidentReconciler`. The graph is FROZEN — do **not** add the publisher to it; own the publisher in the boot loop alongside the socket listeners (Task 5).
- **The read surfaces today are per-id only.** `AdapterStatusObserver.latest(adapter_id) -> AdapterStatusSnapshot | None` (`adapter_status_observer.py:179-181`; `AdapterStatusSnapshot(adapter_id, state: AdapterState, occurred_at: datetime)` at lines 119-126; `AdapterState = Literal["up","down","crashed","breaker_open"]`). `CrashIncidentReconciler.incidents(adapter_id) -> tuple[CrashIncidentView, ...]` (`crash_incident_reconciler.py:155-168`; `CrashIncidentView(adapter_id, host_restart_seq, crash_incident_id, crash_signal_source)`). Neither enumerates its adapters — Task 1 adds additive enumeration read surfaces; it touches NO existing behaviour.
- **The pidfile module is the discipline to mirror EXACTLY** (`src/alfred/cli/daemon/_daemon_pidfile.py`): `write_pidfile` uses `mkdir(mode=0o700)`, a per-write unique temp (`PID + secrets.token_hex`), `os.open(... O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)`, write, `rename`, and cleans the temp on any failure. `load_pidfile` uses `os.open(... O_RDONLY|O_NOFOLLOW|O_NONBLOCK)`, `fstat` → `S_ISREG` + `mode & 0o777 == 0o600` + `st_uid == getuid()` BEFORE reading, then JSON-parses. `delete_pidfile` suppresses `FileNotFoundError`. The snapshot writer/loader reuse this discipline verbatim (Task 3). `PidFileInfo` carries `boot_id` — the snapshot cross-checks against it.
- **The boot loop owns supervised tasks + reaps on every exit path.** `_start_async` (`_commands.py:1801-2250`) writes the pidfile (~L2087), spawns adapters + socket listeners (held in a list, reaped ~L2238-2247), and `await wait_for_shutdown(...)` then drains in a `finally`. The publisher task is started after the comms graph is built and cancelled+awaited+file-deleted in that same drain finally (Task 5). This codebase is strict about reaping — mirror it.
- **i18n is mandatory** for every new operator-facing line (`t()` + a catalog entry in `locale/.../alfred.po` + compiled `.mo`). The status templates already use `t()` (e.g. `daemon.status.template`). Audit: a read-only status render writes NO audit row (convention — pure read, no side effect). The snapshot WRITE is daemon-internal observability, NOT a security boundary: a write failure logs a structured WARNING (loud, never silent) but does **not** crash the daemon (status display is best-effort) — this is the observability fail-loud-but-non-fatal stance, distinct from the hard-rule-#7 security paths which DO escalate.
- **No secret crosses the file.** The snapshot carries only non-sensitive operational metadata: `adapter_id`, `state`, `occurred_at`, `current_incarnation`, the per-adapter incident COUNT, and the LATEST incident's `host_restart_seq` / `crash_signal_source` / `crash_incident_id` (a uuid). NO `detail` / `detail_redacted` / `error_class` — the human-readable "why" is the state + incident summary, not the raw error text (which lives only in the signed audit log). This keeps the snapshot a T0 daemon-internal artefact with no DLP obligation.

### SEC-02 carry-forward (from 2b-2b)
`crash_signal_source == "both"` is a diagnostic hint, NOT authenticated corroboration (the in-child `CrashedNotification` has no anti-forgery binding). The render must therefore present the source label as informational (e.g. "last crash: gateway+child") and MUST NOT imply it is a verified/authenticated fact. Carry a one-line note in the render helper + docs.

---

## File structure

**Created:**

- `src/alfred/cli/daemon/_daemon_status_snapshot.py` — the snapshot **model** (`DaemonStatusSnapshot` + `AdapterStatusLine` frozen Pydantic), the pure **builder** `build_daemon_status_snapshot(...)`, and the file **writer/loader/deleter** (`write_status_snapshot` / `load_status_snapshot` / `delete_status_snapshot` / `default_status_snapshot_path`) mirroring `_daemon_pidfile.py`'s discipline.
- `src/alfred/cli/daemon/_daemon_status_publisher.py` — `DaemonStatusSnapshotPublisher` (the periodic, write-if-changed async task that polls the observer + reconciler and writes the file; `start()` / `aclose()`).
- `tests/unit/cli/daemon/test_daemon_status_snapshot.py` — model + builder + writer/loader unit suite.
- `tests/unit/cli/daemon/test_daemon_status_publisher.py` — publisher refresh + write-if-changed + reap suite.
- `tests/unit/cli/daemon/test_status_daemon_render.py` — the `alfred daemon status` adapter-section render (boot_id match / stale / missing).

**Modified:**

- `src/alfred/comms_mcp/adapter_status_observer.py` — add `all_latest() -> Mapping[str, AdapterStatusSnapshot]` (additive read surface; returns a copy/`MappingProxyType`).
- `src/alfred/comms_mcp/crash_incident_reconciler.py` — add `adapter_ids() -> tuple[str, ...]` and `current_incarnation(adapter_id) -> int` (additive read surfaces).
- `src/alfred/cli/daemon/_commands.py` — construct + start the publisher after `_build_comms_boot_graph`; cancel+await+delete-file in the drain `finally`; extend `status_daemon()` to load + boot_id-cross-check + render the adapter section.
- `locale/<locales>/LC_MESSAGES/alfred.po` (+ compiled `.mo`) — new render catalog keys.
- `docs/subsystems/comms.md` — update the crash-dedup/snapshot subsection: the 2b-2c seam now EXISTS (snapshot file, not an RPC).
- `src/alfred/comms_mcp/crash_incident_reconciler.py` module docstring — flip the "2b-2c must choose a seam" note to "2b-2c shipped the daemon-status snapshot file (no RPC) — see `_daemon_status_snapshot.py`".
- `.github/workflows/ci.yml` — IF `cli/daemon` has a per-file coverage gate, register the two new files (Task 9 verifies; the pidfile module is the precedent to check).

**CI gate note (verify in Task 9):** check whether `src/alfred/cli/daemon/_daemon_pidfile.py` is named in any per-file 100%-coverage gate in `ci.yml`. If `cli/daemon` files are gated, register the two new modules the same way (the two-part `hashFiles` guard + `--include` list pattern from 2b-2b). If `cli/daemon` has NO per-file gate, the new files are covered by the overall suite gate only — note that in the task, do not invent a new gate.

---

## Task 1: Additive enumeration read surfaces on the observer + reconciler

**Files:**
- Modify: `src/alfred/comms_mcp/adapter_status_observer.py` (after `latest`, ~line 181)
- Modify: `src/alfred/comms_mcp/crash_incident_reconciler.py` (after `incidents`, ~line 168)
- Test: `tests/unit/comms_mcp/test_adapter_status_observer.py`, `tests/unit/comms_mcp/test_crash_incident_reconciler.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/comms_mcp/test_crash_incident_reconciler.py`:

```python
def test_adapter_ids_and_current_incarnation_enumerate_state() -> None:
    reconciler = CrashIncidentReconciler()
    assert reconciler.adapter_ids() == ()
    assert reconciler.current_incarnation("discord") == 0  # unseen -> 0, no state invented
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=2)
    reconciler.observe_gateway_crash(adapter_id="telegram", host_restart_seq=0)
    assert set(reconciler.adapter_ids()) == {"discord", "telegram"}
    assert reconciler.current_incarnation("discord") == 2
    # current_incarnation never invents state for an unseen adapter (read-only).
    assert reconciler.adapter_ids() == reconciler.adapter_ids()  # stable tuple
```

Add to `tests/unit/comms_mcp/test_adapter_status_observer.py` (reuse its `_RecordingAuditWriter`/`_EPOCH`/`_NOW` helpers — read the file first):

```python
async def test_all_latest_enumerates_every_observed_adapter() -> None:
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

    observer = AdapterStatusObserver(
        audit=_RecordingAuditWriter(), expected_epoch=lambda: _EPOCH, now=lambda: _NOW,
        reconciler=CrashIncidentReconciler(),
    )
    assert dict(observer.all_latest()) == {}
    await observer.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0})
    snap = observer.all_latest()
    assert set(snap) == {"discord"}
    assert snap["discord"].state == "up"
    # The returned mapping is a read-only view (mutating it must not corrupt the observer).
    with pytest.raises(TypeError):
        snap["discord"] = snap["discord"]  # type: ignore[index]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py::test_adapter_ids_and_current_incarnation_enumerate_state tests/unit/comms_mcp/test_adapter_status_observer.py::test_all_latest_enumerates_every_observed_adapter -v`
Expected: FAIL — `adapter_ids` / `current_incarnation` / `all_latest` do not exist.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/adapter_status_observer.py`, add `from types import MappingProxyType` and `from collections.abc import Mapping` (if not already imported), then after `latest`:

```python
    def all_latest(self) -> Mapping[str, AdapterStatusSnapshot]:
        """A read-only view of the latest accepted status for EVERY observed adapter.

        The in-process read surface for the daemon-status snapshot publisher
        (G6-2b-2c / #288). A ``MappingProxyType`` so a consumer cannot mutate the
        observer's internal map.
        """
        return MappingProxyType(self._latest)
```

In `src/alfred/comms_mcp/crash_incident_reconciler.py`, after `incidents`:

```python
    def adapter_ids(self) -> tuple[str, ...]:
        """Every adapter the reconciler has observed (in-process read for 2b-2c)."""
        return tuple(self._adapters)

    def current_incarnation(self, adapter_id: str) -> int:
        """The latest incarnation seen for ``adapter_id`` (0 if unseen; never invents state)."""
        state = self._adapters.get(adapter_id)
        return 0 if state is None else state.current_incarnation
```

Add `adapter_ids` / `current_incarnation` are pure reads; `current_incarnation` uses `.get` so it does NOT create an `_AdapterState` (no state-invention on read).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py tests/unit/comms_mcp/test_adapter_status_observer.py -v`
Expected: PASS (all, including pre-existing).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/adapter_status_observer.py src/alfred/comms_mcp/crash_incident_reconciler.py tests/unit/comms_mcp/test_adapter_status_observer.py tests/unit/comms_mcp/test_crash_incident_reconciler.py
git commit -m "feat(comms): additive enumeration read surfaces for the status snapshot (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: The snapshot model + pure builder

**Files:**
- Create: `src/alfred/cli/daemon/_daemon_status_snapshot.py`
- Test: `tests/unit/cli/daemon/test_daemon_status_snapshot.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/daemon/test_daemon_status_snapshot.py`:

```python
"""DaemonStatusSnapshot model + builder (G6-2b-2c / #288)."""

from __future__ import annotations

from datetime import UTC, datetime

from alfred.cli.daemon._daemon_status_snapshot import (
    DaemonStatusSnapshot,
    build_daemon_status_snapshot,
)
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)
_EPOCH = "0" * 32


async def _observer_with(reconciler: CrashIncidentReconciler) -> AdapterStatusObserver:
    class _Audit:
        async def append_schema(self, **_: object) -> None: ...

    return AdapterStatusObserver(
        audit=_Audit(), expected_epoch=lambda: _EPOCH, now=lambda: _NOW, reconciler=reconciler
    )


async def test_builder_folds_state_and_incident_summary_per_adapter() -> None:
    reconciler = CrashIncidentReconciler()
    observer = await _observer_with(reconciler)
    await observer.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 1})
    await observer.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "RuntimeError", "detail": "boom", "host_restart_seq": 1},
    )
    snap = build_daemon_status_snapshot(
        boot_id="boot-xyz", written_at=_NOW, observer=observer, reconciler=reconciler
    )
    assert snap.boot_id == "boot-xyz"
    line = snap.adapters["discord"]
    assert line.state == "crashed"
    assert line.current_incarnation == 1
    assert line.crash_incident_count == 1
    assert line.latest_crash is not None
    assert line.latest_crash.crash_signal_source == "gateway"
    assert line.latest_crash.host_restart_seq == 1
    # NO secret/raw-detail fields exist on the model (json round-trips clean).
    dumped = snap.model_dump_json()
    assert "boom" not in dumped and "RuntimeError" not in dumped


async def test_builder_unions_observer_and_reconciler_adapters() -> None:
    reconciler = CrashIncidentReconciler()
    observer = await _observer_with(reconciler)
    # An adapter known only to the reconciler (child-only crash, no gateway state yet).
    reconciler.observe_child_crash(adapter_id="telegram")
    await observer.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0})
    snap = build_daemon_status_snapshot(
        boot_id="b", written_at=_NOW, observer=observer, reconciler=reconciler
    )
    assert set(snap.adapters) == {"discord", "telegram"}
    # telegram has crash incidents but no observed gateway state -> state is "unknown".
    assert snap.adapters["telegram"].state == "unknown"
    assert snap.adapters["telegram"].crash_incident_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_status_snapshot.py -v`
Expected: FAIL — `ModuleNotFoundError: alfred.cli.daemon._daemon_status_snapshot`.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/cli/daemon/_daemon_status_snapshot.py` (model + builder portion; the file IO lands in Task 3):

```python
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
at mode 0600, O_NOFOLLOW + fstat (regular-file + mode + owner) validate on read.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

# "unknown" = an adapter the reconciler has seen (a crash incident) but for which the
# observer holds no accepted gateway state yet (e.g. a child-only crash before any up).
RenderedAdapterState = Literal["up", "down", "crashed", "breaker_open", "unknown"]
CrashSignalSource = Literal["gateway", "child", "both"]


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
    return DaemonStatusSnapshot(
        boot_id=boot_id, written_at=written_at.isoformat(), adapters=lines
    )


__all__ = [
    "AdapterStatusLine",
    "DaemonStatusSnapshot",
    "LatestCrashSummary",
    "build_daemon_status_snapshot",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_status_snapshot.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_daemon_status_snapshot.py tests/unit/cli/daemon/test_daemon_status_snapshot.py
git commit -m "feat(daemon): per-adapter status snapshot model + pure builder (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Snapshot file writer / loader / deleter (mirror the pidfile discipline)

**Files:**
- Modify: `src/alfred/cli/daemon/_daemon_status_snapshot.py` (add the file IO)
- Test: `tests/unit/cli/daemon/test_daemon_status_snapshot.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/cli/daemon/test_daemon_status_snapshot.py`:

```python
import os
import stat
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_status_snapshot import (
    DaemonStatusSnapshotFileError,
    delete_status_snapshot,
    load_status_snapshot,
    write_status_snapshot,
)


def _snap(tmp_path: Path) -> DaemonStatusSnapshot:
    return DaemonStatusSnapshot(boot_id="b1", written_at="2026-06-20T00:00:00+00:00", adapters={})


def test_write_then_load_round_trips_at_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap(tmp_path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    loaded = load_status_snapshot(path)
    assert loaded.boot_id == "b1"


def test_load_refuses_a_world_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap(tmp_path))
    os.chmod(path, 0o644)
    with pytest.raises(DaemonStatusSnapshotFileError):
        load_status_snapshot(path)


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(DaemonStatusSnapshotFileError):
        load_status_snapshot(tmp_path / "nope.json")


def test_delete_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap(tmp_path))
    delete_status_snapshot(path)
    delete_status_snapshot(path)  # missing file is not an error
    assert not path.exists()


def test_write_is_atomic_no_temp_left_behind(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap(tmp_path))
    assert [p.name for p in tmp_path.iterdir()] == ["daemon-status.json"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_status_snapshot.py -k "round_trips or refuses or missing or delete or atomic" -v`
Expected: FAIL — the writer/loader symbols don't exist.

- [ ] **Step 3: Write minimal implementation**

Add to `src/alfred/cli/daemon/_daemon_status_snapshot.py` (imports at top: `import contextlib, json, os, secrets, stat` and `from pathlib import Path`):

```python
_SNAPSHOT_DEFAULT_DIR: Final[Path] = Path.home() / ".run" / "alfred"
_SNAPSHOT_NAME: Final[str] = "daemon-status.json"
_SNAPSHOT_READ_LIMIT: Final[int] = 256 * 1024  # generous; bounded so a planted huge file can't OOM the CLI


class DaemonStatusSnapshotFileError(Exception):
    """Raised on a missing / malformed / mode-wrong / foreign-owned snapshot file."""


def default_status_snapshot_path() -> Path:
    """Return the default snapshot path (``~/.run/alfred/daemon-status.json``)."""
    return _SNAPSHOT_DEFAULT_DIR / _SNAPSHOT_NAME


def write_status_snapshot(path: Path, snapshot: DaemonStatusSnapshot) -> None:
    """Atomically write the snapshot JSON at mode 0600 (mirrors write_pidfile)."""
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
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def load_status_snapshot(path: Path) -> DaemonStatusSnapshot:
    """Open + fstat-validate + parse the snapshot (mirrors load_pidfile discipline)."""
    try:
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
        raise DaemonStatusSnapshotFileError("malformed_snapshot") from exc


def delete_status_snapshot(path: Path) -> None:
    """Remove the snapshot file; a missing file is not an error."""
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
```

Add the four new symbols to `__all__`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_status_snapshot.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_daemon_status_snapshot.py tests/unit/cli/daemon/test_daemon_status_snapshot.py
git commit -m "feat(daemon): 0600 atomic status-snapshot writer/loader (mirrors pidfile) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: The periodic snapshot publisher (write-if-changed)

**Files:**
- Create: `src/alfred/cli/daemon/_daemon_status_publisher.py`
- Test: `tests/unit/cli/daemon/test_daemon_status_publisher.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/daemon/test_daemon_status_publisher.py`:

```python
"""DaemonStatusSnapshotPublisher — periodic write-if-changed (G6-2b-2c / #288)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_status_publisher import DaemonStatusSnapshotPublisher
from alfred.cli.daemon._daemon_status_snapshot import load_status_snapshot
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

pytestmark = pytest.mark.asyncio

_EPOCH = "0" * 32
_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)


class _Audit:
    async def append_schema(self, **_: object) -> None: ...


def _publisher(path: Path, observer: AdapterStatusObserver, reconciler: CrashIncidentReconciler):
    return DaemonStatusSnapshotPublisher(
        path=path, boot_id="boot-1", observer=observer, reconciler=reconciler,
        now=lambda: _NOW, interval_seconds=0.01,
    )


async def test_refresh_once_writes_current_state(tmp_path: Path) -> None:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(audit=_Audit(), expected_epoch=lambda: _EPOCH, now=lambda: _NOW, reconciler=reconciler)
    await observer.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0})
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    await pub.refresh_once()
    loaded = load_status_snapshot(path)
    assert loaded.adapters["discord"].state == "up"


async def test_refresh_skips_write_when_unchanged(tmp_path: Path) -> None:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(audit=_Audit(), expected_epoch=lambda: _EPOCH, now=lambda: _NOW, reconciler=reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    await pub.refresh_once()
    first_mtime = path.stat().st_mtime_ns
    await pub.refresh_once()  # nothing changed -> no rewrite
    assert path.stat().st_mtime_ns == first_mtime


async def test_aclose_cancels_task_and_deletes_file(tmp_path: Path) -> None:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(audit=_Audit(), expected_epoch=lambda: _EPOCH, now=lambda: _NOW, reconciler=reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    pub.start()
    await pub.refresh_once()
    assert path.exists()
    await pub.aclose()
    assert not path.exists()  # reaped like the pidfile


async def test_write_failure_is_loud_but_non_fatal(tmp_path: Path, caplog) -> None:
    # A snapshot write failure must NOT crash the daemon (observability is best-effort)
    # but must be logged loudly (never silent).
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(audit=_Audit(), expected_epoch=lambda: _EPOCH, now=lambda: _NOW, reconciler=reconciler)
    # Point at a path whose parent is a file -> mkdir/open fails.
    bad_parent = tmp_path / "afile"
    bad_parent.write_text("x")
    pub = _publisher(bad_parent / "daemon-status.json", observer, reconciler)
    await pub.refresh_once()  # must not raise
```

(Use `structlog.testing.capture_logs()` for the loud-warning assertion if the suite prefers it — match the codebase pattern in `test_comms_runner.py`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_status_publisher.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/cli/daemon/_daemon_status_publisher.py`:

```python
"""Periodic daemon status-snapshot publisher (G6-2b-2c / #288).

A supervised async task that polls the in-process AdapterStatusObserver +
CrashIncidentReconciler, builds a DaemonStatusSnapshot, and writes it to the 0600
runtime-dir file IF the serialised content changed since the last write. The
observer/reconciler stay pure (their G6-2b constructor signatures are NOT
re-touched) — the publisher reads their additive enumeration surfaces.

Lifecycle MIRRORS the daemon's other supervised resources (socket listeners): the
boot loop calls ``start()`` after the comms graph is built and ``aclose()`` in the
drain ``finally`` on EVERY exit path (cancel + await + delete the file, so a dead
daemon leaves no stale snapshot — the boot_id cross-check is the belt; this is the
braces).

A write failure is observability-best-effort: logged LOUD (structured warning,
never silent) but NON-fatal — a status-display hiccup must not crash the daemon.
This is distinct from the hard-rule-#7 security paths, which escalate.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Final

import structlog

from alfred.cli.daemon._daemon_status_snapshot import (
    DaemonStatusSnapshot,
    build_daemon_status_snapshot,
    delete_status_snapshot,
    write_status_snapshot,
)
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_log = structlog.get_logger(__name__)
_DEFAULT_INTERVAL_SECONDS: Final[float] = 2.0


class DaemonStatusSnapshotPublisher:
    """Periodically publish the per-adapter status snapshot to the runtime-dir file."""

    def __init__(
        self,
        *,
        path: Path,
        boot_id: str,
        observer: AdapterStatusObserver,
        reconciler: CrashIncidentReconciler,
        now: Callable[[], datetime],
        interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        self._path = path
        self._boot_id = boot_id
        self._observer = observer
        self._reconciler = reconciler
        self._now = now
        self._interval = interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._last_json: str | None = None

    def _build(self) -> DaemonStatusSnapshot:
        return build_daemon_status_snapshot(
            boot_id=self._boot_id,
            written_at=self._now(),
            observer=self._observer,
            reconciler=self._reconciler,
        )

    async def refresh_once(self) -> None:
        """Build + write the snapshot IF its content changed. Loud-but-non-fatal on error."""
        snapshot = self._build()
        # Compare on content EXCLUDING written_at (the timestamp always changes; we
        # only rewrite on a real state change to avoid churn).
        content_key = snapshot.model_copy(update={"written_at": ""}).model_dump_json()
        if content_key == self._last_json:
            return
        try:
            write_status_snapshot(self._path, snapshot)
            self._last_json = content_key
        except OSError as exc:
            _log.warning("daemon_status_snapshot_write_failed", path=str(self._path), error=str(exc))

    def start(self) -> None:
        """Start the periodic refresh task (idempotent)."""
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="daemon-status-publisher")

    async def _run(self) -> None:
        try:
            while True:
                await self.refresh_once()
                await asyncio.sleep(self._interval)
        except asyncio.CancelledError:
            raise

    async def aclose(self) -> None:
        """Cancel + await the task and delete the snapshot file (reaped like the pidfile)."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        delete_status_snapshot(self._path)


__all__ = ["DaemonStatusSnapshotPublisher"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_status_publisher.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_daemon_status_publisher.py tests/unit/cli/daemon/test_daemon_status_publisher.py
git commit -m "feat(daemon): periodic write-if-changed status-snapshot publisher (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Wire the publisher into the daemon boot loop (start + reap on every exit path)

**Files:**
- Modify: `src/alfred/cli/daemon/_commands.py` (`_start_async` — construct + start after the comms graph build; cancel+await+delete in the drain `finally`)
- Test: `tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py` (or the boot-loop test file — verify which drives `_start_async`)

- [ ] **Step 1: Write the failing test**

Read the boot-loop test that drives `_start_async` via `CliRunner` (the one used in `test_comms_boot_graph_status_observer.py`). Add a test that boots the daemon with a comms adapter enabled, asserts the snapshot file exists + parses + carries the boot_id during run, and is DELETED after shutdown. Sketch (adapt to the file's real boot harness + fixtures — `host_restart_seq`/epoch/etc.):

```python
async def test_daemon_publishes_and_reaps_status_snapshot(...) -> None:
    # ... boot the daemon with one comms adapter enabled (reuse the file's helper) ...
    # During run: the snapshot file exists, parses, and its boot_id matches the pidfile.
    from alfred.cli.daemon._daemon_status_snapshot import (
        default_status_snapshot_path, load_status_snapshot,
    )
    snap = load_status_snapshot(default_status_snapshot_path())
    assert snap.boot_id == <the booted boot_id>
    # ... trigger shutdown ...
    # After drain: the snapshot file is reaped (like the pidfile).
    assert not default_status_snapshot_path().exists()
```

If the existing boot harness can't easily assert mid-run, assert instead that `_start_async` constructs a `DaemonStatusSnapshotPublisher` and that the drain path calls its `aclose()` (spy/patch `DaemonStatusSnapshotPublisher` and assert `start()` + `aclose()` were called). Pick whichever matches the file's established style; prefer the real-file assertion if the harness supports a tmp `$HOME`.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py -k snapshot -v`
Expected: FAIL — no publisher wired.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/cli/daemon/_commands.py`:

1. Import: `from alfred.cli.daemon._daemon_status_publisher import DaemonStatusSnapshotPublisher` and `from alfred.cli.daemon._daemon_status_snapshot import default_status_snapshot_path`.
2. In `_start_async`, AFTER `comms_graph` is built (the `if settings.comms_enabled_adapters:` block) and the boot_id is known, construct and start:

```python
        status_publisher: DaemonStatusSnapshotPublisher | None = None
        if comms_graph is not None:
            status_publisher = DaemonStatusSnapshotPublisher(
                path=default_status_snapshot_path(),
                boot_id=boot_id,
                observer=comms_graph.status_observer,
                reconciler=comms_graph.crash_incident_reconciler,
                now=lambda: datetime.now(UTC),
            )
            status_publisher.start()
```

3. In the drain `finally` (where the pidfile + socket listeners are reaped), add — isolated so its failure cannot mask other reaps (mirror the existing per-resource reap isolation):

```python
            if status_publisher is not None:
                with contextlib.suppress(Exception):
                    await status_publisher.aclose()
```

(Match the EXACT shape of the surrounding reap blocks — if they log on failure rather than suppress, do the same. The publisher's own `aclose` already suppresses `CancelledError` + missing-file; the outer guard is belt-and-braces consistent with the other reaps.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py
git commit -m "feat(daemon): publish + reap the status snapshot in the boot loop (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Render the adapter section in `alfred daemon status`

**Files:**
- Modify: `src/alfred/cli/daemon/_commands.py` (`status_daemon`, ~2299-2328)
- Test: `tests/unit/cli/daemon/test_status_daemon_render.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/daemon/test_status_daemon_render.py` (use Typer's `CliRunner`; set `$HOME` to a tmp dir so the pidfile + snapshot resolve there; write a pidfile + matching/mismatched snapshot by hand):

```python
"""alfred daemon status — per-adapter snapshot render (G6-2b-2c / #288)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon._daemon_pidfile import default_pidfile_path, write_pidfile
from alfred.cli.daemon._daemon_status_snapshot import (
    AdapterStatusLine,
    DaemonStatusSnapshot,
    default_status_snapshot_path,
    write_status_snapshot,
)


def _write_live_pidfile(boot_id: str) -> None:
    import os
    write_pidfile(default_pidfile_path(), pid=os.getpid(), boot_id=boot_id, started_at="2026-06-20T00:00:00+00:00")


def test_status_renders_adapter_lines_when_boot_id_matches(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_live_pidfile("boot-A")
    write_status_snapshot(
        default_status_snapshot_path(),
        DaemonStatusSnapshot(
            boot_id="boot-A", written_at="2026-06-20T00:00:01+00:00",
            adapters={"discord": AdapterStatusLine(adapter_id="discord", state="crashed", current_incarnation=1, crash_incident_count=2)},
        ),
    )
    from alfred.cli.daemon import daemon_app  # the Typer sub-app (verify import path)
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0
    assert "discord" in result.stdout
    assert "crashed" in result.stdout


def test_status_ignores_snapshot_with_mismatched_boot_id(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_live_pidfile("boot-A")
    write_status_snapshot(
        default_status_snapshot_path(),
        DaemonStatusSnapshot(boot_id="STALE", written_at="x", adapters={"discord": AdapterStatusLine(adapter_id="discord", state="up")}),
    )
    from alfred.cli.daemon import daemon_app
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0
    # stale snapshot ignored -> no adapter section
    assert "discord" not in result.stdout


def test_status_without_snapshot_still_renders_pidfile_subset(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_live_pidfile("boot-A")
    from alfred.cli.daemon import daemon_app
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0  # no snapshot file -> back-compat, just the pidfile subset
```

(Verify the Typer app import path + command name — it may be `daemon_app` with command `status`, or invoked through the root `app` as `["daemon", "status"]`. Match the existing daemon CLI tests.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_status_daemon_render.py -v`
Expected: FAIL — `status_daemon` renders no adapter section.

- [ ] **Step 3: Write minimal implementation**

Extend `status_daemon()` in `_commands.py` — after the existing `daemon.status.template` echo, add the adapter section:

```python
    # G6-2b-2c (#288): render the per-adapter status snapshot the daemon publishes.
    # Read-only, best-effort: a missing / malformed / boot_id-mismatched snapshot is
    # silently skipped (back-compat with a daemon that predates the snapshot / has no
    # comms adapters). The boot_id cross-check rejects a stale snapshot left by a prior
    # daemon incarnation (the file is reaped on clean shutdown; this guards a crash).
    try:
        snapshot = load_status_snapshot(default_status_snapshot_path())
    except DaemonStatusSnapshotFileError:
        return
    if snapshot.boot_id != info.boot_id:
        return
    if not snapshot.adapters:
        typer.echo(t("daemon.status.adapters_none"))
        return
    typer.echo(t("daemon.status.adapters_header"))
    for adapter_id in sorted(snapshot.adapters):
        line = snapshot.adapters[adapter_id]
        # SEC-02: crash_signal_source is a diagnostic hint, not authenticated corroboration.
        latest = (
            t(
                "daemon.status.adapter_latest_crash",
                seq=line.latest_crash.host_restart_seq,
                source=line.latest_crash.crash_signal_source,
            )
            if line.latest_crash is not None
            else ""
        )
        typer.echo(
            t(
                "daemon.status.adapter_line",
                adapter_id=line.adapter_id,
                state=line.state,
                incarnation=line.current_incarnation,
                crashes=line.crash_incident_count,
                latest_crash=latest,
            )
        )
```

Add imports: `from alfred.cli.daemon._daemon_status_snapshot import DaemonStatusSnapshotFileError, default_status_snapshot_path, load_status_snapshot`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_status_daemon_render.py -v` (fails until Task 7 adds the catalog keys — run again after Task 7).
Expected: PASS once catalog keys exist (Task 7).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_status_daemon_render.py
git commit -m "feat(daemon): alfred daemon status renders the per-adapter snapshot (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: i18n catalog entries for the new render strings

**Files:**
- Modify: `locale/<each-locale>/LC_MESSAGES/alfred.po` (+ recompile `.mo`)
- Test: the i18n catalog-drift gate (`pybabel ... --check`) + Task 6's render tests

- [ ] **Step 1: Identify the catalog + extraction flow**

Read how prior slices added keys (grep for `daemon.status.template` across `locale/`). Find the source-language `.po` (e.g. `locale/en/LC_MESSAGES/alfred.po`) and any non-English catalogs that must stay in sync. Note the project's compile step (`pybabel compile` / a make target).

- [ ] **Step 2: Add the new message ids**

Add these msgids (with sensible English defaults) to the source catalog (and a placeholder/identical entry to other locales so `pybabel update --check` does not flag drift):

- `daemon.status.adapters_header` → `"Adapters:"`
- `daemon.status.adapters_none` → `"Adapters: none reported"`
- `daemon.status.adapter_line` → `"  {adapter_id}: {state} (incarnation {incarnation}, {crashes} crash incident(s)){latest_crash}"`
- `daemon.status.adapter_latest_crash` → `" — last crash seq {seq}, signal {source}"`

**Critical (i18n memory rule):** NEVER run `pybabel update --omit-header` (it strips the required header block → fuzzy/skip). Use the project's established update/compile commands. After editing the `.po`, recompile the `.mo` and run the drift check.

- [ ] **Step 3: Recompile + verify no drift**

Run the project's catalog compile + check (e.g. `uv run pybabel compile ...` / the make target) and confirm `pybabel update --check` (the CI gate) passes.

- [ ] **Step 4: Run the render tests**

Run: `uv run pytest tests/unit/cli/daemon/test_status_daemon_render.py -v`
Expected: PASS (keys now resolve).

- [ ] **Step 5: Commit**

```bash
git add locale/
git commit -m "i18n: catalog keys for the daemon status adapter render (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 8: Docs — flip the 2b-2c seam decision to "shipped"

**Files:**
- Modify: `docs/subsystems/comms.md` (the crash-dedup + status-snapshot subsection)
- Modify: `src/alfred/comms_mcp/crash_incident_reconciler.py` (module docstring's 2b-2c note)

- [ ] **Step 1 (no test — docs): update the docstring**

In `crash_incident_reconciler.py`, change the module docstring's "2b-2c must choose either a daemon query seam OR relocate the render in-daemon" paragraph to record that **2b-2c shipped the in-daemon snapshot file** (`alfred.cli.daemon._daemon_status_snapshot` — a 0600 boot_id-tied JSON the daemon publishes and `alfred daemon status` reads; NO socket RPC was built — YAGNI). Keep the `incidents()` read-surface reference.

- [ ] **Step 2: update the subsystem doc**

In `docs/subsystems/comms.md`, update the "Crash de-dup + status snapshot" subsection: the operator now sees per-adapter state + crash summary via `alfred daemon status`, backed by `~/.run/alfred/daemon-status.json` (0600, boot_id-tied, reaped on shutdown, non-secret). Note the SEC-02 caveat (`both` is a diagnostic hint, not authenticated). Note `alfred status` / `alfred gateway adapters` can reuse the loader + render helper in G6-4/G6-5. Docs stay English (no `t()`).

- [ ] **Step 3: markdownlint**

Confirm the edited markdown passes the repo's markdownlint config (the `.markdownlint-cli2.jsonc` rules — MD013/MD028/MD036 are disabled; blockquotes + long lines are fine).

- [ ] **Step 4: Commit**

```bash
git add docs/subsystems/comms.md src/alfred/comms_mcp/crash_incident_reconciler.py
git commit -m "docs(comms): record the shipped 2b-2c status-snapshot seam (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 9: CI coverage-gate registration + full-suite verification

**Files:**
- Modify: `.github/workflows/ci.yml` (IF `cli/daemon` files are per-file-gated — verify)
- Verify: full `tests/unit` quality bar

- [ ] **Step 1: Determine whether `cli/daemon` is per-file-gated**

Read `.github/workflows/ci.yml`. Grep for `_daemon_pidfile.py` (or any `cli/daemon/` path) in a per-file `--include` / `hashFiles` coverage gate. IF such a gate exists, the two new modules (`_daemon_status_snapshot.py`, `_daemon_status_publisher.py`) belong in it (mirror the two-part pattern). IF NO `cli/daemon` per-file gate exists, do NOT invent one — the overall-suite coverage gate covers them; note this in the commit body.

- [ ] **Step 2: Register the new files if gated**

If gated, add both modules to the `--include` list AND the `hashFiles(...)` guard in the relevant job.

- [ ] **Step 3: Run the FULL unit suite under coverage**

Run: `uv run coverage run --branch -m pytest tests/unit` then `uv run coverage report --include="src/alfred/cli/daemon/_daemon_status_snapshot.py,src/alfred/cli/daemon/_daemon_status_publisher.py,src/alfred/comms_mcp/adapter_status_observer.py,src/alfred/comms_mcp/crash_incident_reconciler.py" --show-missing`
Expected: 100% on the two new modules; no regression below the existing bar on the two touched comms_mcp files (they are in the comms_mcp 100% gate — keep them at 100%). Run the WHOLE `tests/unit` (a subset under-counts shared-file coverage — this bit a prior slice).

- [ ] **Step 4: Full quality bar**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && PYRIGHT_PYTHON_FORCE_VERSION=latest uv run pyright src/ && uv run pytest tests/unit -q`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: coverage gate for the daemon status-snapshot modules (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-Review

**1. Spec coverage:**
- "new operator-facing states surfaced human-readably in `alfred status`" (spec §line 127) → Task 6 renders state + crash summary in `alfred daemon status` (the daemon-runtime view; `alfred status`/`alfred gateway adapters` reuse deferred to G6-4/G6-5, noted). ✔
- 2b-2b deferred "snapshot reachability — 2b-2c owns the query seam" → Tasks 2-6 build the in-daemon snapshot + CLI render (the sanctioned "relocate render in-daemon" option; NO RPC — YAGNI). ✔
- Trust/secret discipline (0600, O_NOFOLLOW/fstat, no secret on file, boot_id-tied, reaped) → Tasks 3-5. ✔
- SEC-02 carry-forward (`both` not authenticated) → render + docs note (Tasks 6, 8). ✔
- Fail-loud-but-non-fatal on write failure → Task 4. ✔
- i18n on every new line → Task 7. ✔
- Coverage + full-suite gate → Task 9. ✔
- Observer/reconciler signatures NOT re-touched (only additive reads) → Task 1. ✔

**2. Placeholder scan:** Every code step shows real code. The "verify the Typer import path / boot harness" notes in Tasks 5-6 are real verification instructions (grep the existing daemon CLI tests), not code placeholders.

**3. Type consistency:** `DaemonStatusSnapshot` / `AdapterStatusLine` / `LatestCrashSummary` / `build_daemon_status_snapshot` / `write_status_snapshot` / `load_status_snapshot` / `delete_status_snapshot` / `default_status_snapshot_path` / `DaemonStatusSnapshotFileError` / `DaemonStatusSnapshotPublisher` (`.refresh_once` / `.start` / `.aclose`) / `all_latest` / `adapter_ids` / `current_incarnation` — names identical across Tasks 1-9.

---

## Scope-boundary (OUT — deferred)

- **`alfred status` (global) + `alfred gateway adapters` render** reusing the loader/helper → G6-4 (metrics) / G6-5 (flag-day + the `alfred gateway adapters` command + CLAUDE.md row).
- **Per-adapter Prometheus metrics** (`gateway_adapter_*` series) → G6-4.
- **A live daemon query RPC / socket control plane** → not planned (YAGNI; the snapshot file is the sanctioned seam). Revisit only if a real-time (sub-2s) consumer appears.
- **Real credential spawn** → G6-3. **Ingress gate / leg scheduler / ReplayBuffer** → G6-4. **Discord flag-day** → G6-5. **Adversarial corpus** → G6-6.

---

## Plan-review corrections (MUST apply — architect + security + test-engineer, 2026-06-20)

All three reviewers returned **APPROVE-WITH-CHANGES** and unanimously validated the snapshot-file design (NOT an RPC; correctly a non-corpus, T0-internal observability slice). Apply these — they OVERRIDE conflicting earlier task text.

### Load-bearing correctness/safety (MUST)

1. **[arch-H1] Resolve the runtime dir at CALL time, not import time.** Do NOT use a module-level `_SNAPSHOT_DEFAULT_DIR: Final = Path.home() / ...` (import-frozen → breaks the `monkeypatch.setenv("HOME", ...)` test harness in Tasks 5-6, a latent test-correctness bug). Make `default_status_snapshot_path()` resolve `Path.home()` (or the runtime dir) **at call time**, mirroring `comms_socket_transport._runtime_dir()` (which resolves at call time precisely for this). Keep only `_SNAPSHOT_NAME` as a module `Final`. (Reusing a single shared `runtime_dir()` resolver across pidfile/socket/snapshot is the ideal but is a cross-package refactor → out of scope; do call-time resolution here + a one-line comment noting the three independent derivations as known drift for a follow-up.)

2. **[sec-MEDIUM-4 + test-H2/T4] Make the publisher self-healing (the #1 security ask).** In `refresh_once`: move the `_build()` + `content_key` computation INSIDE the try, and widen the catch from `except OSError` to `except Exception as exc` (still log-and-continue, NEVER fatal — observability is best-effort). In `_run`: wrap the loop body so a single bad `refresh_once` logs and continues rather than silently killing the supervised task (a silently-dead publisher misleads an operator worse than no snapshot). The test (`test_write_failure_is_loud_but_non_fatal`) MUST assert the loud warning is emitted via `structlog.testing.capture_logs()` (`assert any(e["event"] == "daemon_status_snapshot_write_failed" for e in logs)`), not merely "does not raise". Reconcile the docstring's "never crash" claim with the widened catch.

3. **[arch-H2] Do NOT blanket-`suppress(Exception)` the publisher reap in the boot loop (Task 5).** It is the safety-net for stale state. Match the EXACT shape of the SIBLING reap blocks (socket listeners / pidfile) in the drain `finally` — if they log on unexpected failure, do the same; do not silently swallow a reap failure. `delete_status_snapshot` already suppresses only `FileNotFoundError` (correct); the outer guard must log-not-blanket-suppress.

4. **[sec-MEDIUM-1 + test-C3/T8] Lock the field-set + de-tautologise.** Add a STRUCTURAL test asserting the exact field-name set of `AdapterStatusLine`, `LatestCrashSummary`, and `DaemonStatusSnapshot` (e.g. `assert set(AdapterStatusLine.model_fields) == {...}`) so a future field addition fails CI and forces reviewer justification (the no-secret guarantee must be enforced by an exact-field-set lock, not only `extra="forbid"` + a two-word substring check). Also replace the tautological `reconciler.adapter_ids() == reconciler.adapter_ids()` (Task 1) with an assertion against a sorted literal (`assert sorted(reconciler.adapter_ids()) == ["discord", "telegram"]`).

### Write-if-changed test honesty (MUST — the slice's most regression-prone logic)

5. **[test-C1/T1] Prove the REWRITE-on-real-change.** Add a publisher test: `refresh_once()` → capture content → drive a REAL adapter-state change (`observer.observe("gateway.adapter.crashed", {...})`) → `refresh_once()` again → assert the file content changed AND `load_status_snapshot(path).adapters["discord"].state == "crashed"`. (The planned tests only prove the skip-on-unchanged half — a `_last_json` that never updates would false-green.)

6. **[test-C2/T2] Prove the `written_at`-excluded content-key both directions.** (a) With an ADVANCING clock and unchanged adapter state → two refreshes must NOT rewrite (timestamp-only diff suppressed). (b) With a CONSTANT clock and a real state change → must rewrite (same-second real change not falsely suppressed). Add a one-line comment in `build_daemon_status_snapshot` that the `sorted(adapter_ids)` insertion order is **load-bearing for the publisher's change-detection** (arch-L2).

7. **[test-H1/T3] The boot-loop reap test MUST assert the REAL file is deleted via the REAL drain path** (tmp `$HOME`): during run the file exists+parses+boot_id matches; after triggering shutdown, the drain `finally` ran `aclose()` and the file is gone. The "spy that aclose() was called" fallback is a false-green — demote it to last-resort ONLY if the boot harness genuinely cannot run the drain.

8. **[test-H3/T5] Pin "latest crash" semantics.** `build_daemon_status_snapshot` uses `incidents[-1]` (OrderedDict insertion order = most-recently-OPENED incarnation). Add a builder test with TWO incidents at distinct incarnations (seq 0, then `note_incarnation`+crash at seq 2) asserting `latest_crash.host_restart_seq == 2` and `crash_incident_count == 2` — pins the chosen definition.

9. **[test-H4/T6] Render skips a malformed/oversized PRESENT snapshot.** Add: (a) a loader unit test asserting `load_status_snapshot` raises `DaemonStatusSnapshotFileError("malformed_snapshot")` on garbage bytes at mode 0600; (b) a render test where the file is present + correct-mode but malformed JSON → `alfred daemon status` exits 0 with no adapter section (exercises the `except DaemonStatusSnapshotFileError: return` back-compat branch). Note the oversized case truncates at the read limit → JSON-parse-fails → same malformed branch.

### Branch-coverage gaps for the 100% gate (MUST — see correction 14)

10. **[test-M1] Add the uncovered-branch tests:** (T7) builder `latest_crash is None` branch — an adapter with observer `up` state and ZERO incidents → `latest_crash is None`, `crash_incident_count == 0`, `state == "up"`; (T9) writer temp-cleanup on POST-open failure — monkeypatch `Path.rename` to raise after `os.open` succeeds → assert the `.tmp` is removed, the target untouched, exception propagates (hits `except BaseException`); (T10) `start()` idempotency — call twice, assert one task; (T11) `aclose()` on a never-started publisher — construct, `refresh_once()` (no `start()`), `aclose()` → no raise + file deleted.

### i18n / vocabulary (MUST)

11. **[arch-M3 + sec-LOW-3 + test-M4/T12] The rendered state token bypasses `t()` today — fix it.** The plan interpolates the raw enum `state=line.state` into the i18n template (hardcoded-English-to-an-operator's-eyes — HARD i18n rule #1). Map EACH state to its own catalog key (`daemon.status.state.up` → "up", `.down`, `.crashed`, `.breaker_open`, `.unknown`) and render the localized token. Add `"unknown"` to the glossary/`comms.md` state enumeration with its precise meaning ("the reconciler saw a crash incident but the observer holds no accepted gateway state for the adapter yet"). For the latest-crash line, reword toward diagnostic-origin framing ("last crash: incarnation {seq}, reported by {source}") so `both` does not read as authenticated double-confirmation (SEC-02). Add a render test (T12) with a populated `LatestCrashSummary` (source `both`) asserting the seq+source render via the catalog key.

### Documentation / honesty (MUST)

12. **[sec-MEDIUM-3] Document anti-stale ≠ anti-forgery.** In `_daemon_status_snapshot.py` docstring AND `docs/subsystems/comms.md`: the `boot_id` cross-check rejects a STALE snapshot from a prior incarnation; it is NOT an authenticity guarantee (`boot_id` is non-secret; a same-uid process — already inside the daemon trust domain — could forge a current-`boot_id` snapshot). The signed audit log is authoritative; this snapshot is best-effort operator convenience. Do NOT add an HMAC (it would defend against an attacker who has already defeated the trust boundary, and add a secret-on-disk obligation this slice rightly avoids).

13. **[arch-M2] Add an ADR-0036 annotation (Task 8).** ADR-0036 §line 208-209 already NAMES "the `alfred status` snapshot" but never says how it's materialised. Add a one-paragraph annotation recording: 2b-2c materialised the snapshot as a 0600 boot_id-tied runtime-dir JSON (NO RPC — YAGNI); SEC-02 + the anti-stale-not-anti-forgery caveat apply; the loader/builder/render helper (transport-agnostic) is reused by `alfred status`/`alfred gateway adapters` in G6-4/G6-5. No NEW ADR needed (no PRD §5 invariant, datastore, or wire-protocol change).

### CI gate (MUST — escalated by test reviewer)

14. **[test-L1] ADD a dedicated `cli/daemon` per-file 100% coverage gate** for `_daemon_status_snapshot.py` + `_daemon_status_publisher.py`. Verified: `ci.yml` has NO `cli/daemon` per-file gate today (the `_daemon_pidfile.py` mention at ~ci.yml:592 is a comment, not a gate). These two modules do trust-sensitive file IO (O_NOFOLLOW/fstat/mode-validate) — exactly the discipline `quarantine_transport.py` / the pidfile precedent warrant a dedicated gate for. Add a new per-file gate in the `coverage-gates` job (both the `hashFiles` guard AND the `--include` list, the two-part pattern) rather than relying on the overall-suite gate (which can hide a regression if other files over-cover). This makes Task 9 "ADD the gate", not "verify if one exists".

### Scope honesty + minor (SHOULD)

15. **[arch-M1] Reword Self-Review/Scope** to stop presenting `alfred daemon status` as SATISFYING spec §127 — the spec's named surfaces (`alfred status` / `alfred gateway adapters`) remain OWED to G6-4/G6-5; 2b-2c lands the data substrate + render helper and proves it via `alfred daemon status`. Confirm `alfred gateway adapters` is G6-5-owned (arch-L1) so this slice's loader/render contract is actually consumed, not stranded.

16. **[sec-MEDIUM-2 + sec-MEDIUM-5 + sec-LOW-2/5/6] Smaller items:** (a) state the runtime-dir 0700 assumption explicitly — the pidfile (written first in `_start_async`, ~L2087) owns dir creation/ownership; the snapshot relies on its OWN 0600+owner fstat and neither module tightens an already-loose existing dir; (b) correct the stale "up carries no seq" prose — `AdapterUpNotification.host_restart_seq` EXISTS on merged main and the observer already advances `current_incarnation` on `up` (the Task-1 test stubs are already correct; only the prose is stale); (c) tighten `_SNAPSHOT_READ_LIMIT` from 256 KiB toward the pidfile's bound (use `64 * 1024` — a real snapshot is <4 KiB); (d) bound the write-failure warning's `error=` field (log `error=str(exc)` for `OSError` is path/errno-bounded; with the widened `except Exception` prefer `error=type(exc).__name__` + a bounded message, or rely on the structlog redactor); (e) document the cross-version file contract (a schema change is self-healing only after the new daemon rewrites the file — an old CLI reading a newer file's `extra` field is rejected by `extra="forbid"` → skipped, which is acceptable best-effort).
