# G6-2b-2c (RPC) — Daemon Control-Plane Query + `alfred daemon status` Live Render Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This plan is LOCAL-ONLY — do NOT `git add` it.** Plan docs are markdownlint-gated in CI and (per established convention) are kept out of the merge. Commit only code/docs/tests.

**Goal:** Make the daemon's live in-process per-adapter status (the `AdapterStatusObserver.latest()` map) + crash-incident summary (`CrashIncidentReconciler`) reachable from the CLI over a **request/response control socket**, so `alfred daemon status` answers from a single live source of truth — no snapshot file, no staleness, no boot_id cross-check, no reap-of-stale-state. This is the principled replacement for the withdrawn file-snapshot approach (PR #299) and the channel the upcoming G6-5 `alfred gateway adapters --wait-ready` will reuse.

**Architecture:** The daemon binds a dedicated **control socket** (`~/.run/alfred/control.sock`, 0600 under the 0700 runtime dir) and serves a small **request/response JSON-RPC** over it: a CLI dials, sends one request frame (`{"method": "status.query", "id": ...}`), the daemon authenticates the peer (`SO_PEERCRED` + the same degrade-open-to-FS-perms discipline the comms socket uses), routes to a method handler that builds the response **live** from the in-process observer + reconciler, writes one response frame, and closes. Unlike the comms socket (ADR-0031: one-shot accept, bidirectional notification *pump*, TUI-bound), the control socket is **multi-connection, request/response, stateless-per-connection** — a true control plane. The security primitives (peer-uid resolution/auth, call-time `runtime_dir`, owner-only bind, the frame-size bound + loud-failure codec) are EXTRACTED into a shared `alfred.plugins._local_socket` module and reused by BOTH the comms socket (mechanical migration, test-guarded) and the new control socket — so we reuse audited security code instead of copy-pasting it (this also retires the "three independent `~/.run/alfred` derivations" drift). The observer/reconciler stay pure (additive enumeration read surfaces only — their G6-2b constructor signatures are untouched).

**Tech Stack:** Python 3.12+, asyncio (`start_unix_server` + `open_unix_connection`), Pydantic v2 (frozen request/response models), structlog, pytest + pytest-asyncio. Pure host/core-side; runs on the required NON-ROOT gate (unix sockets between same-uid peers, no bwrap, no launcher).

---

## Context the implementer must hold

Read these before starting. Verified against `main` (`e7f5d850`, G6-2b-2b merged; the file-snapshot PR #299 was CLOSED — none of its `_daemon_status_snapshot.py` / `_daemon_status_publisher.py` exists on main).

- **The CLI is non-dialing today; there is NO daemon RPC/control service.** `status()` (`src/alfred/cli/main.py:175-215`) reads Settings + broker; `status_daemon()` (`src/alfred/cli/daemon/_commands.py:2299-2328`) reads the pidfile only. The only socket the daemon runs is the per-adapter comms wire (`comms_socket_transport.py`), which is a **one-shot accept, bidirectional notification pump** bound to a single TUI peer — NOT a request/response query service. This slice adds the first daemon control plane.
- **Reusable, already-audited security primitives** live in `src/alfred/plugins/comms_socket_transport.py` — read them; Task 1 extracts them:
  - `_resolve_peer_uid(sock) -> int | None` (`:101-144`) — `SO_PEERCRED`, NEVER raises, returns `None` on a no-`SO_PEERCRED` host (macOS dev) or short read; logs a breadcrumb on each degrade branch.
  - `_peer_uid_authorized(*, reported_uid) -> bool` (`:147-155`) — `None` (unknowable) OR `== os.getuid()` is authorized; a mismatch is a refused impostor.
  - `_runtime_dir() -> Path` (`:87-89`) — resolves `~/.run/alfred` **at call time** (honours a changed `$HOME` — load-bearing for tests).
  - `_assert_dial_path_owned(path)` (`:179-207`) — pre-dial `lstat` (NOT stat) backstop: refuse anything that is not an `S_ISSOCK` inode owned by `getuid()`; the only owner enforcement on a no-`SO_PEERCRED` host.
  - The bind discipline (`CommsSocketListener.bind`, `:569-611`): `mkdir(mode=0o700)` + **unconditional** `chmod(0o700)` on the dir (a pre-existing looser dir is tightened every boot) + unlink-stale-then-bind + `chmod(0o600)` on the socket AFTER bind + `listen()`.
  - `_unlink_stale` (`:613-631`): `lstat` + only unlink an `S_ISSOCK`/`S_ISREG` we own; refuse a FIFO/device/symlink at our path.
  - The frame bound + loud-failure codec: `_MAX_COMMS_LINE_BYTES` + `CommsProtocolError` + `CommsPeerAuthError` from `alfred.plugins.comms_wire`.
- **The data surfaces** (built once in `_CommsBootGraph`, `_commands.py:564-625`, held for the daemon process lifetime): `status_observer: AdapterStatusObserver`, `crash_incident_reconciler: CrashIncidentReconciler`. Today neither enumerates its adapters — Task 2 adds additive enumeration reads (these touch NO existing behaviour): `AdapterStatusObserver.latest(id) -> AdapterStatusSnapshot | None` (`adapter_status_observer.py:179`; `AdapterStatusSnapshot(adapter_id, state: AdapterState, occurred_at)` at `:119-126`; `AdapterState = Literal["up","down","crashed","breaker_open"]`); `CrashIncidentReconciler.incidents(id) -> tuple[CrashIncidentView,...]` (`crash_incident_reconciler.py:155`; `CrashIncidentView(adapter_id, host_restart_seq, crash_incident_id, crash_signal_source)`); internal `_adapters: dict[str, _AdapterState]` with `current_incarnation`.
- **The boot loop owns + reaps supervised resources** (`_start_async`, `_commands.py:1801-2250`): pidfile written ~L2087, socket listeners held in a list + reaped in the drain `finally` ~L2238-2247. The control server is bound after the comms graph is built and its serve task + socket are reaped in that same `finally` on EVERY exit path. The `_CommsBootGraph` is `frozen=True, slots=True` — own the control server in the boot loop, NOT the graph.
- **`alfred chat` already dials a daemon socket** (`dial_comms_socket`, `comms_socket_transport.py:210-270`) — the control-client `query_daemon_control` mirrors its two-layer auth (pre-dial `lstat` owner backstop + post-connect `SO_PEERCRED`) but does request/response, not a pump.
- **i18n is mandatory** for every operator-facing render string (`t()` + catalog entry). The render reuses the per-state catalog-key approach (`daemon.status.state.{up,down,crashed,breaker_open,unknown}`) so the state token is localized, not raw-interpolated. **Commit type for catalog commits must be a pure-alpha allowed type with `i18n` as the SCOPE — `feat(i18n):` / `chore(i18n):`, NEVER `i18n:`** (the commit-format validator's `^[a-z]+` rejects the digits in `i18n` as a type). Audit: a read-only status query writes NO audit row (convention — pure read). A **peer-auth rejection** on the control socket IS audited (mirrors the comms socket's `comms.socket.peer_uid_rejected` reject-callback) — a refused different-uid dial is a loud security event.
- **No secret/T3 on the wire.** The response carries only non-sensitive operational metadata (adapter_id, state, occurred_at, current_incarnation, crash incident count + the latest incident's seq/source/id). NO raw `detail`/`error_class`. The response model uses `extra="forbid"` and an exact-field-set lock test (carry-forward from the #299 review).

### Why request/response live, not a file (the design decision this slice embodies)

A live query has ONE source of truth (the in-process observer/reconciler), read at query time — so there is no staleness window, no periodic publisher, no reap-of-stale-file, and no `boot_id` "anti-stale-not-anti-forgery" caveat (the daemon answering the socket IS, by construction, the live daemon; `SO_PEERCRED` + the 0600 socket are the authenticity guarantee the file's non-secret `boot_id` could never be). The control channel also generalises: the G6-5 `alfred gateway adapters --wait-ready <adapter>` command (spec §line 124, with a 0/1/2/3 exit-code contract) is a live-ness consumer that a ≤2s-stale file serves poorly but a live query serves naturally — it reuses this exact channel + method router.

---

## File structure

**Created:**

- `src/alfred/plugins/_local_socket.py` — the shared local-socket security primitives extracted from `comms_socket_transport.py`: `runtime_dir()`, `resolve_peer_uid()`, `peer_uid_authorized()`, `assert_path_owned()`, plus `bind_owner_only_unix_socket(path) -> socket.socket` (the mkdir-0700 + chmod + unlink-stale + bind + chmod-0600 + listen discipline) and `unlink_stale_socket(path)`. Public (no leading underscore on the functions) since two modules import them.
- `src/alfred/cli/daemon/_daemon_control_protocol.py` — the frozen request/response Pydantic models: `ControlRequest(method: str, id: str, params: dict)`, `ControlResponse(id, result | error)`, and the `status.query` result model `DaemonStatusResult` + `AdapterStatusLine` + `LatestCrashSummary` (the live response shape — NO `boot_id`/`written_at`; it is inherently live). Plus the pure live builder `build_daemon_status_result(*, observer, reconciler) -> DaemonStatusResult`.
- `src/alfred/cli/daemon/_daemon_control_server.py` — `DaemonControlServer`: binds the control socket via `_local_socket.bind_owner_only_unix_socket`, serves request/response per connection (auth → read one request → route via a method map → write one response → close), with a `on_peer_rejected` audit callback; `start()` / `aclose()` (reap server + socket file, every exit path).
- `src/alfred/cli/daemon/_daemon_control_client.py` — `query_daemon_control(method, params=...) -> ControlResponse`: dial + pre-dial `assert_path_owned` + post-connect `SO_PEERCRED` + send one request + read one response (bounded) + close; raises `DaemonControlUnavailableError` (daemon absent) / `DaemonControlAuthError` (peer mismatch) / `DaemonControlProtocolError` (malformed/over-bound).
- Tests: `tests/unit/plugins/test_local_socket.py`, `tests/unit/cli/daemon/test_daemon_control_protocol.py`, `test_daemon_control_server.py`, `test_daemon_control_client.py`, `test_daemon_control_roundtrip.py` (server+client over a real socket), `test_status_daemon_render.py` (the render).

**Modified:**

- `src/alfred/plugins/comms_socket_transport.py` — replace the now-extracted private helpers (`_resolve_peer_uid`/`_peer_uid_authorized`/`_runtime_dir`/the bind body/`_unlink_stale`) with imports from `_local_socket` (mechanical; the existing comms socket tests guard the behaviour). Keep `_assert_dial_path_owned`/`default_comms_socket_path` as thin wrappers over the shared `assert_path_owned`/`runtime_dir` if their call sites are convenient.
- `src/alfred/comms_mcp/adapter_status_observer.py` — add `all_latest() -> Mapping[str, AdapterStatusSnapshot]` (MappingProxyType).
- `src/alfred/comms_mcp/crash_incident_reconciler.py` — add `adapter_ids() -> tuple[str, ...]` and `current_incarnation(adapter_id) -> int` (`.get`, no state-invention).
- `src/alfred/cli/daemon/_commands.py` — bind + start the control server after `_build_comms_boot_graph` (guard on comms enabled); reap in the drain `finally`; extend `status_daemon()` to dial the control socket, render the live result (daemon-absent → the existing not-running message; per-adapter lines via `t()`).
- `locale/en/LC_MESSAGES/alfred.po` (+ compiled `.mo`) — render catalog keys.
- `docs/subsystems/comms.md` — document the control plane (the live query seam) replacing the snapshot-reachability TODO.
- `src/alfred/comms_mcp/crash_incident_reconciler.py` module docstring — flip "2b-2c owns the query seam" to "2b-2c shipped the daemon control-plane query RPC (`_daemon_control_*`)".
- `docs/adr/0038-daemon-control-socket.md` — NEW ADR (see Task 8): the daemon control plane is a genuine new architectural surface (a request/response IPC the CLI uses to introspect the live daemon) — it warrants its own ADR, cross-referenced from ADR-0031 (comms socket sibling) and ADR-0036.
- `.github/workflows/ci.yml` — per-file 100% coverage gate for the new trust-sensitive modules (`_local_socket.py`, `_daemon_control_server.py`, `_daemon_control_client.py`, `_daemon_control_protocol.py`).

---

## Task 1: Extract shared local-socket security primitives

**Files:**

- Create: `src/alfred/plugins/_local_socket.py`
- Modify: `src/alfred/plugins/comms_socket_transport.py` (import from the new module)
- Test: `tests/unit/plugins/test_local_socket.py` (+ the existing `tests/unit/plugins/test_comms_socket_transport.py` must still pass unchanged — the migration is behaviour-preserving)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_local_socket.py` exercising the extracted primitives as a public API:

```python
"""Shared local-socket security primitives (G6-2b-2c RPC / #288)."""

from __future__ import annotations

import os
import socket
import stat
from pathlib import Path

import pytest

from alfred.plugins._local_socket import (
    assert_path_owned,
    bind_owner_only_unix_socket,
    peer_uid_authorized,
    runtime_dir,
)


def test_runtime_dir_resolves_home_at_call_time(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert runtime_dir() == tmp_path / ".run" / "alfred"


def test_peer_uid_authorized_rules() -> None:
    assert peer_uid_authorized(reported_uid=None) is True       # unknowable -> FS-perms-of-record
    assert peer_uid_authorized(reported_uid=os.getuid()) is True
    assert peer_uid_authorized(reported_uid=os.getuid() + 1) is False


def test_bind_creates_0600_socket_under_0700_dir(tmp_path: Path) -> None:
    path = tmp_path / "run" / "control.sock"
    sock = bind_owner_only_unix_socket(path)
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    finally:
        sock.close()


def test_bind_unlinks_a_stale_socket(tmp_path: Path) -> None:
    path = tmp_path / "run" / "control.sock"
    bind_owner_only_unix_socket(path).close()  # leaves a stale inode
    sock = bind_owner_only_unix_socket(path)   # must unlink-then-rebind, not EADDRINUSE
    sock.close()


def test_assert_path_owned_refuses_non_socket(tmp_path: Path) -> None:
    f = tmp_path / "notasock"
    f.write_text("x")
    with pytest.raises(Exception):  # CommsPeerAuthError-family
        assert_path_owned(f)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_local_socket.py -v`
Expected: FAIL — `ModuleNotFoundError: alfred.plugins._local_socket`.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/plugins/_local_socket.py` by MOVING (not copying) the bodies of `_runtime_dir`, `_resolve_peer_uid`, `_peer_uid_authorized`, the bind discipline, and `_unlink_stale` out of `comms_socket_transport.py`, as public functions:

```python
"""Shared 0600-unix-socket security primitives for AlfredOS local IPC.

Extracted from comms_socket_transport.py (ADR-0031) so the comms wire AND the
daemon control socket (G6-2b-2c / ADR-0038) reuse ONE audited implementation of
peer-uid auth, owner-only bind, and call-time runtime-dir resolution — rather than
two divergent copies (the drift the #299 architect review flagged). The security
contract is unchanged from ADR-0031: a 0600 socket under a 0700 runtime dir whose
parent is the operator's owner-only home, plus SO_PEERCRED defense-in-depth that
degrades OPEN to the FS-perms-of-record on a no-SO_PEERCRED host (macOS dev).
"""

from __future__ import annotations

import contextlib
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Final

import structlog

from alfred.i18n import t
from alfred.plugins.comms_wire import CommsPeerAuthError

log = structlog.get_logger(__name__)

_RUNTIME_DIR_MODE: Final[int] = 0o700
_SOCKET_MODE: Final[int] = 0o600
_UCRED_STRUCT: Final[str] = "3I"
_UCRED_WIDTH: Final[int] = struct.calcsize(_UCRED_STRUCT)


def runtime_dir() -> Path:
    """Resolve ``~/.run/alfred`` at call time (honours a changed ``$HOME``)."""
    return Path.home() / ".run" / "alfred"


def resolve_peer_uid(sock: socket.socket | None) -> int | None:
    # ... MOVE the verbatim body of comms_socket_transport._resolve_peer_uid here ...


def peer_uid_authorized(*, reported_uid: int | None) -> bool:
    # ... MOVE the verbatim body of comms_socket_transport._peer_uid_authorized here ...


def unlink_stale_socket(path: Path) -> None:
    # ... MOVE the verbatim body of CommsSocketListener._unlink_stale (path-parameterised) ...


def bind_owner_only_unix_socket(path: Path, *, backlog: int = 16) -> socket.socket:
    """mkdir-0700 + unconditional dir-chmod + unlink-stale + bind + chmod-0600 + listen.

    Returns the bound, listening socket. Mirrors CommsSocketListener.bind's discipline
    verbatim (the security comments there are load-bearing — carry them). ``backlog``
    is >1 here (the control plane is multi-connection, unlike the comms wire's listen(1)).
    """
    runtime_parent = path.parent
    runtime_parent.mkdir(mode=_RUNTIME_DIR_MODE, parents=True, exist_ok=True)
    runtime_parent.chmod(_RUNTIME_DIR_MODE)  # unconditional: tighten a pre-existing looser dir
    unlink_stale_socket(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
        path.chmod(_SOCKET_MODE)
        sock.listen(backlog)
    except BaseException:
        sock.close()
        unlink_stale_socket(path)
        raise
    return sock


def assert_path_owned(path: Path) -> None:
    """Pre-dial lstat backstop: refuse anything not an S_ISSOCK inode we own (raises CommsPeerAuthError)."""
    # ... MOVE the verbatim body of comms_socket_transport._assert_dial_path_owned ...
```

Then in `comms_socket_transport.py`, DELETE the moved bodies and re-point internal callers at the shared functions (e.g. `_runtime_dir = runtime_dir` alias or direct import; `_resolve_peer_uid`/`_peer_uid_authorized` imported; `_assert_dial_path_owned` becomes a call to `assert_path_owned`; `CommsSocketListener.bind` keeps its method but its body either calls `bind_owner_only_unix_socket(self._path, backlog=1)` or keeps its `listen(1)` specifics — preserve the one-shot `listen(1)` semantics). The migration MUST keep `tests/unit/plugins/test_comms_socket_transport.py` green unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/plugins/test_local_socket.py tests/unit/plugins/test_comms_socket_transport.py -v`
Expected: PASS (new + ALL pre-existing comms socket tests — the migration is behaviour-preserving).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/plugins/_local_socket.py src/alfred/plugins/comms_socket_transport.py tests/unit/plugins/test_local_socket.py
git commit -m "refactor(comms): extract shared local-socket security primitives (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Additive enumeration read surfaces + the live result model & builder

**Files:**

- Modify: `src/alfred/comms_mcp/adapter_status_observer.py` (add `all_latest`), `src/alfred/comms_mcp/crash_incident_reconciler.py` (add `adapter_ids`, `current_incarnation`)
- Create: `src/alfred/cli/daemon/_daemon_control_protocol.py` (models + builder)
- Test: `tests/unit/comms_mcp/test_adapter_status_observer.py`, `test_crash_incident_reconciler.py`, `tests/unit/cli/daemon/test_daemon_control_protocol.py`

- [ ] **Step 1: Write the failing tests**

(Reuse the #299-reviewed shapes.) Observer: `all_latest()` returns a `MappingProxyType` of every observed adapter (immutable view; `pytest.raises(TypeError)` on item-set). Reconciler: `adapter_ids()` returns a tuple of observed ids (assert against a SORTED LITERAL, not `x == x`); `current_incarnation(id)` returns the latest seq seen (0 if unseen; uses `.get`, invents no state). Protocol: `build_daemon_status_result(observer=..., reconciler=...)` folds state + crash summary per adapter into `DaemonStatusResult`; an exact-field-set lock test on `AdapterStatusLine` + `LatestCrashSummary` + `DaemonStatusResult`; a round-trip JSON test asserting raw crash text (`"boom"`, `"RuntimeError"`) NEVER appears; the `state == "unknown"` union branch (an adapter in the reconciler but not the observer); the `latest_crash is None` branch (observer state, no incidents); latest-crash = `incidents[-1]` with TWO incarnations asserting the higher seq. (These mirror the #299 builder tests — `DaemonStatusResult` is the #299 `DaemonStatusSnapshot` MINUS `boot_id`/`written_at`, which were file-staleness artifacts a live response does not need.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_observer.py tests/unit/comms_mcp/test_crash_incident_reconciler.py tests/unit/cli/daemon/test_daemon_control_protocol.py -v`
Expected: FAIL — methods/module absent.

- [ ] **Step 3: Write minimal implementation**

Observer `all_latest` (add `from types import MappingProxyType`):

```python
    def all_latest(self) -> Mapping[str, AdapterStatusSnapshot]:
        """Read-only view of the latest accepted status for EVERY observed adapter (#288)."""
        return MappingProxyType(self._latest)
```

Reconciler:

```python
    def adapter_ids(self) -> tuple[str, ...]:
        """Every adapter the reconciler has observed (in-process read for 2b-2c)."""
        return tuple(self._adapters)

    def current_incarnation(self, adapter_id: str) -> int:
        """Latest incarnation seen for ``adapter_id`` (0 if unseen; .get -> no state-invention)."""
        state = self._adapters.get(adapter_id)
        return 0 if state is None else state.current_incarnation
```

Create `_daemon_control_protocol.py` with the request/response envelope + the `status.query` result model + builder:

```python
"""Daemon control-plane request/response models + the status.query builder (#288, ADR-0038).

The CONTROL plane is request/response (vs the comms wire's notification pump): a CLI
sends one ControlRequest, the daemon answers one ControlResponse, the connection
closes. The status.query result is built LIVE from the in-process observer +
reconciler at query time — no snapshot, no staleness, no boot_id (the daemon that
answers the 0600 SO_PEERCRED socket IS, by construction, the live daemon).

NO secret/T3 on the wire: the result carries only non-sensitive operational metadata
(adapter_id, state, occurred_at, current_incarnation, incident count + the latest
incident's seq/source/id). NO raw detail/error_class — those live only in the signed
audit log. The exact field set is locked by a structural test (#299 carry-forward).
SEC-02 carry-forward: crash_signal_source == "both" is a diagnostic hint, NOT
authenticated corroboration — rendered as informational origin only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

RenderedAdapterState = Literal["up", "down", "crashed", "breaker_open", "unknown"]
CrashSignalSource = Literal["gateway", "child", "both"]

CONTROL_PROTOCOL_VERSION: Final[str] = "AlfredDaemonControl/1"
STATUS_QUERY_METHOD: Final[str] = "status.query"


class ControlRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    version: str = Field(default=CONTROL_PROTOCOL_VERSION, min_length=1)
    id: str = Field(min_length=1)
    method: str = Field(min_length=1)
    params: dict[str, object] = Field(default_factory=dict)


class LatestCrashSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    host_restart_seq: int = Field(ge=0)
    crash_signal_source: CrashSignalSource
    crash_incident_id: str = Field(min_length=1)


class AdapterStatusLine(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    adapter_id: str = Field(min_length=1)
    state: RenderedAdapterState
    occurred_at: str | None = None
    current_incarnation: int = Field(default=0, ge=0)
    crash_incident_count: int = Field(default=0, ge=0)
    latest_crash: LatestCrashSummary | None = None


class DaemonStatusResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    adapters: dict[str, AdapterStatusLine] = Field(default_factory=dict)


class ControlResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(min_length=1)
    result: dict[str, object] | None = None
    error: str | None = None


def build_daemon_status_result(
    *, observer: AdapterStatusObserver, reconciler: CrashIncidentReconciler
) -> DaemonStatusResult:
    """Fold live observer state + reconciler incidents into the status result (pure, no secret)."""
    latest = observer.all_latest()
    adapter_ids = sorted(set(latest) | set(reconciler.adapter_ids()))
    lines: dict[str, AdapterStatusLine] = {}
    for adapter_id in adapter_ids:
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
    return DaemonStatusResult(adapters=lines)
```

(Add `from typing import Final` for the constants.)

- [ ] **Step 4: Run tests to verify they pass**

Run the three test files; Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/adapter_status_observer.py src/alfred/comms_mcp/crash_incident_reconciler.py src/alfred/cli/daemon/_daemon_control_protocol.py tests/unit/comms_mcp/test_adapter_status_observer.py tests/unit/comms_mcp/test_crash_incident_reconciler.py tests/unit/cli/daemon/test_daemon_control_protocol.py
git commit -m "feat(daemon): control-plane request/response models + live status builder (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: The control server (bind + serve request/response + method router)

**Files:**

- Create: `src/alfred/cli/daemon/_daemon_control_server.py`
- Test: `tests/unit/cli/daemon/test_daemon_control_server.py`

- [ ] **Step 1: Write the failing test**

Tests (pytest-asyncio): bind creates a 0600 socket under the 0700 dir; a connected peer that sends `{"version","id","method":"status.query","params":{}}` gets a `ControlResponse` whose `result` parses to `DaemonStatusResult`; an UNKNOWN method gets a `ControlResponse` with `error` set (not a crash, not a silent drop); an over-bound request line fails LOUD (`CommsProtocolError`-family, connection closed, server keeps serving); a malformed (non-JSON / schema-invalid) request yields an `error` response, server stays up; a peer-uid mismatch (simulate via a patched `resolve_peer_uid`) is refused + the `on_peer_rejected` audit callback fires + the connection is closed + the server keeps serving (never wedges); `aclose()` cancels the serve task and deletes the socket file. Drive the server by connecting a raw `asyncio.open_unix_connection` client in-test.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_control_server.py -v`
Expected: FAIL — module absent.

- [ ] **Step 3: Write minimal implementation**

Create `_daemon_control_server.py`:

```python
"""Daemon control-plane server: request/response over a 0600 control socket (#288, ADR-0038).

Multi-connection request/response (one request -> one response -> close per
connection), in contrast to the comms wire's one-shot bidirectional pump
(ADR-0031). Reuses the shared local-socket security primitives (peer-uid auth,
owner-only bind) so the control plane does not fork a second copy of the socket
security code. Serving is resilient: a malformed/over-bound/unknown-method request
on one connection is answered (or loud-closed) WITHOUT wedging the server — the
accept loop keeps serving other clients (a control-plane outage would blind the
operator worse than a single bad request).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Final

import structlog

from alfred.cli.daemon._daemon_control_protocol import (
    STATUS_QUERY_METHOD,
    ControlRequest,
    ControlResponse,
    DaemonStatusResult,
    build_daemon_status_result,
)
from alfred.plugins._local_socket import (
    bind_owner_only_unix_socket,
    peer_uid_authorized,
    resolve_peer_uid,
    runtime_dir,
)
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsProtocolError

log = structlog.get_logger(__name__)
_CONTROL_SOCKET_NAME: Final[str] = "control.sock"

# A method handler reads the parsed request, returns the result dict (or raises).
_Handler = Callable[[ControlRequest], Mapping[str, object]]


def default_control_socket_path() -> Path:
    """``~/.run/alfred/control.sock`` (call-time $HOME)."""
    return runtime_dir() / _CONTROL_SOCKET_NAME


class DaemonControlServer:
    def __init__(
        self,
        *,
        observer: object,
        reconciler: object,
        path: Path | None = None,
        on_peer_rejected: Callable[[int | None], Awaitable[None]] | None = None,
        max_line_bytes: int = _MAX_COMMS_LINE_BYTES,
    ) -> None:
        self._observer = observer
        self._reconciler = reconciler
        self._path = path if path is not None else default_control_socket_path()
        self._on_peer_rejected = on_peer_rejected
        self._max_line_bytes = max_line_bytes
        self._server: asyncio.AbstractServer | None = None
        # The method router — extensible (G6-5 adds gateway.adapters / --wait-ready).
        self._handlers: dict[str, _Handler] = {STATUS_QUERY_METHOD: self._handle_status_query}

    def _handle_status_query(self, _request: ControlRequest) -> Mapping[str, object]:
        result: DaemonStatusResult = build_daemon_status_result(
            observer=self._observer, reconciler=self._reconciler  # type: ignore[arg-type]
        )
        return result.model_dump()

    async def start(self) -> None:
        sock = bind_owner_only_unix_socket(self._path)
        self._server = await asyncio.start_unix_server(
            self._on_connect, sock=sock, limit=self._max_line_bytes
        )

    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer_uid = resolve_peer_uid(writer.get_extra_info("socket"))
            if not peer_uid_authorized(reported_uid=peer_uid):
                log.warning("daemon.control.peer_uid_rejected", peer_uid=peer_uid)
                if self._on_peer_rejected is not None:
                    await self._on_peer_rejected(peer_uid)
                return
            await self._serve_one(reader, writer)
        except CommsProtocolError as exc:
            log.warning("daemon.control.request_over_bound", error=str(exc))
        except Exception as exc:  # resilient: one bad connection never wedges the server
            log.warning("daemon.control.connection_failed", error=type(exc).__name__)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        raw = await reader.readline()
        if not raw:
            return
        if len(raw) > self._max_line_bytes:
            raise CommsProtocolError("control request exceeds frame bound")
        response = self._route(raw)
        writer.write(json.dumps(response.model_dump()).encode() + b"\n")
        await writer.drain()

    def _route(self, raw: bytes) -> ControlResponse:
        try:
            request = ControlRequest.model_validate_json(raw)
        except ValueError as exc:
            return ControlResponse(id="?", error=f"malformed_request:{type(exc).__name__}")
        handler = self._handlers.get(request.method)
        if handler is None:
            return ControlResponse(id=request.id, error=f"unknown_method:{request.method}")
        try:
            return ControlResponse(id=request.id, result=dict(handler(request)))
        except Exception as exc:  # a handler fault answers an error, never crashes the server
            log.warning("daemon.control.handler_failed", method=request.method, error=type(exc).__name__)
            return ControlResponse(id=request.id, error=f"handler_error:{type(exc).__name__}")

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()


__all__ = ["DaemonControlServer", "default_control_socket_path"]
```

Type the `observer`/`reconciler` params concretely (`AdapterStatusObserver`/`CrashIncidentReconciler`) under `TYPE_CHECKING` to drop the `type: ignore`.

- [ ] **Step 4: Run test to verify it passes** — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_daemon_control_server.py tests/unit/cli/daemon/test_daemon_control_server.py
git commit -m "feat(daemon): control-plane server (request/response + method router) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: The control client

**Files:**

- Create: `src/alfred/cli/daemon/_daemon_control_client.py`
- Test: `tests/unit/cli/daemon/test_daemon_control_client.py`, `test_daemon_control_roundtrip.py`

- [ ] **Step 1: Write the failing tests**

Client unit: dialing a non-existent socket raises `DaemonControlUnavailableError` (daemon absent — the operator-facing "not running" path); a dialed path that is not a socket-we-own raises `DaemonControlAuthError` (reuse `assert_path_owned`); a post-connect peer-uid mismatch (patched) raises `DaemonControlAuthError`; an over-bound / malformed response raises `DaemonControlProtocolError`. Round-trip (`test_daemon_control_roundtrip.py`): start a real `DaemonControlServer` over a tmp socket with a fake observer+reconciler holding one crashed adapter, call `query_daemon_control(STATUS_QUERY_METHOD, path=...)`, assert the parsed `DaemonStatusResult` carries the adapter with `state == "crashed"`. This is the genuine end-to-end proof the channel works.

- [ ] **Step 2: Run tests to verify they fail** — Expected: FAIL (module absent).

- [ ] **Step 3: Write minimal implementation**

Create `_daemon_control_client.py` mirroring `dial_comms_socket`'s two-layer auth but request/response:

```python
"""Daemon control-plane client: dial + one request + one response (#288, ADR-0038)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Final

import structlog

from alfred.cli.daemon._daemon_control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    ControlRequest,
    ControlResponse,
)
from alfred.cli.daemon._daemon_control_server import default_control_socket_path
from alfred.plugins._local_socket import assert_path_owned, peer_uid_authorized, resolve_peer_uid
from alfred.plugins.comms_wire import CommsPeerAuthError, CommsProtocolError, _MAX_COMMS_LINE_BYTES

log = structlog.get_logger(__name__)


class DaemonControlUnavailableError(Exception):
    """The daemon control socket is absent / unconnectable (daemon not running)."""


class DaemonControlAuthError(Exception):
    """The dialed socket is not owned by us / the peer uid mismatched."""


class DaemonControlProtocolError(Exception):
    """The response was malformed / over-bound."""


async def query_daemon_control(
    method: str, *, params: dict[str, object] | None = None, path: Path | None = None, request_id: str = "1"
) -> ControlResponse:
    sock_path = path if path is not None else default_control_socket_path()
    try:
        assert_path_owned(sock_path)
    except FileNotFoundError as exc:
        raise DaemonControlUnavailableError(str(sock_path)) from exc
    except CommsPeerAuthError as exc:
        raise DaemonControlAuthError(str(exc)) from exc
    try:
        reader, writer = await asyncio.open_unix_connection(path=str(sock_path), limit=_MAX_COMMS_LINE_BYTES)
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raise DaemonControlUnavailableError(str(sock_path)) from exc
    try:
        peer_uid = resolve_peer_uid(writer.get_extra_info("socket"))
        if not peer_uid_authorized(reported_uid=peer_uid):
            raise DaemonControlAuthError(f"peer_uid={peer_uid}")
        request = ControlRequest(version=CONTROL_PROTOCOL_VERSION, id=request_id, method=method, params=params or {})
        writer.write(request.model_dump_json().encode() + b"\n")
        await writer.drain()
        raw = await reader.readline()
        if not raw or len(raw) > _MAX_COMMS_LINE_BYTES:
            raise DaemonControlProtocolError("empty or over-bound control response")
        try:
            return ControlResponse.model_validate_json(raw)
        except ValueError as exc:
            raise DaemonControlProtocolError(f"malformed control response: {type(exc).__name__}") from exc
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
```

(Add `import contextlib`.)

- [ ] **Step 4: Run tests to verify they pass** — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_daemon_control_client.py tests/unit/cli/daemon/test_daemon_control_client.py tests/unit/cli/daemon/test_daemon_control_roundtrip.py
git commit -m "feat(daemon): control-plane client + end-to-end roundtrip (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Wire the control server into the daemon boot loop (start + reap)

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (`_start_async`)
- Test: `tests/unit/cli/daemon/test_daemon_control_boot.py`

- [ ] **Step 1: Write the failing test**

Boot the daemon (the existing `CliRunner` boot harness) with a comms adapter enabled; mid-run, dial the control socket via `query_daemon_control(STATUS_QUERY_METHOD)` and assert a `DaemonStatusResult` comes back (the fake harness has no live frames, so `adapters` is legitimately empty — the proof is the REAL socket answered, not the content). After shutdown, assert the control socket file is gone (reaped via the real drain `finally`) and a dial raises `DaemonControlUnavailableError`. Mirror the #299 boot-test discipline: REAL socket + REAL drain, NOT a spy.

- [ ] **Step 2: Run test to verify it fails** — Expected: FAIL (no server wired).

- [ ] **Step 3: Write minimal implementation**

In `_start_async`, after `comms_graph` is built and the `on_peer_rejected` audit callback is available (reuse the comms socket's `comms.socket.peer_uid_rejected`-style audit writer — emit a `daemon.control.peer_uid_rejected` row), construct + start the server; reap in the drain `finally` with the SAME shape as the sibling reaps:

```python
        control_server: DaemonControlServer | None = None
        if comms_graph is not None:
            control_server = DaemonControlServer(
                observer=comms_graph.status_observer,
                reconciler=comms_graph.crash_incident_reconciler,
                on_peer_rejected=_make_control_reject_auditor(audit_writer, boot_id),
            )
            await control_server.start()
```

```python
            if control_server is not None:
                with contextlib.suppress(Exception):
                    await control_server.aclose()
```

Add the reject auditor (a small factory returning an async callback that writes a `daemon.control.peer_uid_rejected` audit row — reuse the audit field-set pattern of `comms.socket.peer_uid_rejected`; add the field-set if one doesn't already fit). Declare `control_server` BEFORE the supervisor `try` so the `finally` can never `NameError` (the architect's hoist note from #299).

- [ ] **Step 4: Run test to verify it passes** — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_daemon_control_boot.py
git commit -m "feat(daemon): bind + reap the control server in the boot loop (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: `alfred daemon status` dials the control socket + renders live

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (`status_daemon`)
- Test: `tests/unit/cli/daemon/test_status_daemon_render.py`

- [ ] **Step 1: Write the failing test**

Render tests (CliRunner, tmp `$HOME`): with a daemon control server running (start one in-test over the default path) holding a fake observer/reconciler with a crashed adapter → `alfred daemon status` prints the adapter line (state via the localized catalog key) + the latest-crash diagnostic line (`reported by {source}`); with NO daemon (no socket) → the existing not-running message, exit 0; a populated `LatestCrashSummary(source="both")` renders the SEC-02 informational line. (`asyncio.run` the query inside the sync Typer command.)

- [ ] **Step 2: Run test to verify it fails** — Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Extend `status_daemon()` — after the pidfile subset render, dial the control socket and render the live result:

```python
    # G6-2b-2c (#288, ADR-0038): query the live daemon control plane for per-adapter
    # status. Read-only, best-effort: a daemon-absent dial is the not-running path; a
    # protocol/auth fault degrades to "no adapter section" (the signed audit log is
    # authoritative). The response is LIVE (no snapshot/staleness/boot_id).
    try:
        response = asyncio.run(query_daemon_control(STATUS_QUERY_METHOD))
    except DaemonControlUnavailableError:
        return  # pidfile subset already rendered; daemon control not reachable
    if response.error is not None or response.result is None:
        return
    result = DaemonStatusResult.model_validate(response.result)
    if not result.adapters:
        typer.echo(t("daemon.status.adapters_none"))
        return
    typer.echo(t("daemon.status.adapters_header"))
    for adapter_id in sorted(result.adapters):
        line = result.adapters[adapter_id]
        latest = (
            t("daemon.status.adapter_latest_crash", seq=line.latest_crash.host_restart_seq, source=line.latest_crash.crash_signal_source)
            if line.latest_crash is not None else ""
        )
        typer.echo(
            t("daemon.status.adapter_line", adapter_id=line.adapter_id,
              state=t(_ADAPTER_STATE_KEYS[line.state]), incarnation=line.current_incarnation,
              crashes=line.crash_incident_count, latest_crash=latest)
        )
```

Add `_ADAPTER_STATE_KEYS: Mapping[str, str]` mapping each `RenderedAdapterState` → its `daemon.status.state.*` key (render-layer concern, lives in `_commands.py`). Add imports.

- [ ] **Step 4: Run test to verify it passes** — Expected: PASS (after Task 7's catalog keys).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_status_daemon_render.py
git commit -m "feat(daemon): alfred daemon status renders the live control-plane query (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: i18n catalog entries

**Files:**

- Modify: `locale/en/LC_MESSAGES/alfred.po` (+ compiled `.mo`); reserve dynamically-dereferenced state keys in `src/alfred/i18n/_spec_b_reserve.py`; add to `SLICE_4_KEYS` in `tests/unit/test_catalog_slice_4_keys.py`

- [ ] **Step 1-2:** Add msgids: `daemon.status.adapters_header` ("Adapters:"), `daemon.status.adapters_none` ("Adapters: none reported"), `daemon.status.adapter_line` ("  {adapter_id}: {state} (incarnation {incarnation}, {crashes} crash incident(s)){latest_crash}"), `daemon.status.adapter_latest_crash` (" — last crash: incarnation {seq}, reported by {source}"), and the 5 per-state keys `daemon.status.state.{up,down,crashed,breaker_open,unknown}`. Reserve the 5 state keys in `_spec_b_reserve.py` (dict-dereferenced — pybabel can't see the literal at the call site). Add all 9 to `SLICE_4_KEYS` (the reverse-drift scan owns the `daemon.` prefix). **NEVER `pybabel update --omit-header`** — use the project's plain update/compile commands; keep `#:` location refs so the drift gate passes.

- [ ] **Step 3:** Recompile `.mo`, run the catalog-drift check (`pybabel ... --check`) — PASS.

- [ ] **Step 4:** Re-run `tests/unit/cli/daemon/test_status_daemon_render.py` — PASS.

- [ ] **Step 5: Commit**

```bash
git add locale/ src/alfred/i18n/_spec_b_reserve.py tests/unit/test_catalog_slice_4_keys.py
git commit -m "feat(i18n): catalog keys for the daemon status control-plane render (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

(NOTE the commit type: `feat(i18n)` — NOT `i18n:`. The commit-format validator rejects `i18n` as a type.)

---

## Task 8: ADR-0038 + docs

**Files:**

- Create: `docs/adr/0038-daemon-control-socket.md`
- Modify: `docs/subsystems/comms.md`, `src/alfred/comms_mcp/crash_incident_reconciler.py` (docstring)

- [ ] **Step 1: Write ADR-0038.** Context: the daemon holds live per-adapter status the CLI must read; the comms socket (ADR-0031) is a one-shot bidirectional pump, not a query service; no control plane exists. Decision: a dedicated request/response control socket (`~/.run/alfred/control.sock`, 0600, reusing the ADR-0031 peer-auth + bind discipline via the shared `_local_socket` module), with a method router (`status.query` now; `gateway.adapters` / `--wait-ready` in G6-5). Consequences: live single-source-of-truth (no snapshot/staleness/boot_id); a new same-uid local IPC surface (auth = SO_PEERCRED + 0600 + owner-only bind; a refused different-uid dial is audited); read-only queries are not audited. Alternatives considered + rejected: the file-snapshot (PR #299 — staleness, reap-of-stale-state, boot_id is anti-stale-not-anti-forgery, throwaway when --wait-ready lands); reusing the comms socket (wrong shape — pump, not query; TUI-bound). Cross-reference ADR-0031 (sibling carrier) + ADR-0036 (which names "the alfred status snapshot").

- [ ] **Step 2: `docs/subsystems/comms.md`** — document the control plane (the live query seam): `alfred daemon status` dials `~/.run/alfred/control.sock`, the daemon answers `status.query` live from the observer + reconciler; SEC-02 (`both` = diagnostic hint, not authenticated); the channel is the G6-5 `--wait-ready` substrate. Flip the reconciler module docstring's "2b-2c owns the query seam" to "2b-2c shipped the daemon control-plane RPC".

- [ ] **Step 3: markdownlint** the two docs + the ADR (`.markdownlint-cli2.jsonc` rules — blank line before every list, blanks around headings; MD013/MD028/MD036 are disabled). Run `npx markdownlint-cli2@0.14.0` on the changed docs and confirm zero violations IN THOSE FILES.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0038-daemon-control-socket.md docs/subsystems/comms.md src/alfred/comms_mcp/crash_incident_reconciler.py
git commit -m "docs(adr): ADR-0038 daemon control socket + comms.md control-plane seam (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 9: CI coverage gate + full-suite verification

**Files:**

- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1:** Add a per-file 100% line+branch coverage gate (in the `coverage-gates` job — the required one) for the trust-sensitive new modules: `src/alfred/plugins/_local_socket.py`, `src/alfred/cli/daemon/_daemon_control_server.py`, `src/alfred/cli/daemon/_daemon_control_client.py`, `src/alfred/cli/daemon/_daemon_control_protocol.py`. Use the two-part pattern (the `&& hashFiles(...) != ''` guard AND the `--include` list), mirroring the comms_mcp/gateway gates. `_local_socket.py` is a security primitive → it belongs in a 100% gate.

- [ ] **Step 2:** Run the FULL unit suite under coverage (a subset under-counts shared files): `uv run coverage run --branch -m pytest tests/unit` then `uv run coverage report --include="src/alfred/plugins/_local_socket.py,src/alfred/cli/daemon/_daemon_control_server.py,src/alfred/cli/daemon/_daemon_control_client.py,src/alfred/cli/daemon/_daemon_control_protocol.py,src/alfred/comms_mcp/adapter_status_observer.py,src/alfred/comms_mcp/crash_incident_reconciler.py" --show-missing`. Require 100% on the new modules; keep the two comms_mcp files at 100% (they're in the comms_mcp gate).

- [ ] **Step 3:** Full quality bar: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && PYRIGHT_PYTHON_FORCE_VERSION=latest uv run pyright src/ && uv run pytest tests/unit -q`. Plus the i18n catalog-drift check. All green.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: 100% coverage gate for the daemon control-plane modules (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-Review

**1. Spec coverage:** Live per-adapter status reachable from the CLI (the 2b-2b-deferred seam) → Tasks 2-6 (control plane). The G6-5 `--wait-ready` substrate → the method router (Task 3) + the channel is reusable. `alfred status` (global) / `alfred gateway adapters` render → still OWED to G6-4/G6-5 (this slice lands the channel + `alfred daemon status` proof). ✔

**2. Placeholder scan:** Novel/load-bearing code (server, client, protocol, shared primitives) is shown concretely; "MOVE the verbatim body" in Task 1 is a precise extraction instruction, not a placeholder.

**3. Type consistency:** `ControlRequest`/`ControlResponse`/`DaemonStatusResult`/`AdapterStatusLine`/`LatestCrashSummary`/`build_daemon_status_result`/`DaemonControlServer`/`query_daemon_control`/`default_control_socket_path`/`STATUS_QUERY_METHOD`/`runtime_dir`/`resolve_peer_uid`/`peer_uid_authorized`/`assert_path_owned`/`bind_owner_only_unix_socket`/`all_latest`/`adapter_ids`/`current_incarnation` — consistent across tasks.

---

## Scope-boundary (OUT — deferred)

- **`alfred status` (global) + `alfred gateway adapters --wait-ready`** → G6-4/G6-5 (both reuse this channel + method router).
- **Migrating the comms socket's OTHER internals** (the transport/listener bodies beyond the extracted primitives) → not needed; Task 1 extracts only the shared security primitives.
- **Real-credential spawn** → G6-3. **Ingress gate / leg scheduler / ReplayBuffer** → G6-4. **Discord flag-day** → G6-5. **Adversarial corpus** (incl. a forged-control-dial case) → G6-6.

---

## Plan-review corrections (MUST apply — architect + security + test-engineer, 2026-06-20)

All three returned **APPROVE-WITH-CHANGES** and validated the control-socket architecture (dedicated request/response socket, shared-primitive extraction, live-query-over-file). Apply these — they OVERRIDE conflicting earlier task text.

### Blocking correctness/security (MUST)

1. **[arch-C1] ADR number collision — APPLIED: the daemon control socket is ADR-0038, NOT 0037.** `docs/adr/0037-production-quarantine-sandbox-boundary.md` already holds the 0037 slot, so the shipped ADR is `docs/adr/0038-daemon-control-socket.md`; every reference in this plan, the module docstring tags, comms.md, and the reconciler docstring uses 0038.

2. **[sec-HIGH-1] Per-connection exchange TIMEOUT (the #1 security ask).** The plan's `_serve_one` does `await reader.readline()` with NO timeout; `start_unix_server` spawns one unbounded task per connection. A same-uid peer that connects and never sends a newline holds a serve task + fd forever (slow-loris; the comms socket is immune because it's one-shot `listen(1)`, the control plane is multi-connection). Wrap the whole authenticate→read→respond exchange in `asyncio.timeout(_CONTROL_EXCHANGE_TIMEOUT_S)` (5s — generous for localhost same-uid). On timeout: close, `log.warning("daemon.control.request_timed_out")`, keep serving. **Test:** a peer that connects + never writes is dropped after the deadline AND the server still answers a subsequent well-formed dial.

3. **[sec-HIGH-2] Bounded concurrency cap.** Add an `asyncio.Semaphore` (16–32) gating live serve tasks; past the ceiling, close the connection immediately (don't queue unboundedly). `backlog` does NOT bound this (it bounds only the kernel accept queue). **Test:** a flood past the ceiling is refused/closed without unbounded task growth.

4. **[sec-LOW-1 + test-M2] Failed `on_peer_rejected` audit-write must ESCALATE, not be swallowed.** The plan's `_on_connect` calls `await self._on_peer_rejected(peer_uid)` inside the broad `except Exception` that logs `connection_failed` — that swallows a FAILED audit-write of a security reject (hard rule #7 violation). Mirror the comms socket's escalation (`comms_socket_transport.py:683-704`): a reject-audit-write failure must surface loud (re-raise past the connection-resilience guard, or a dedicated `log.error` + escalation), NOT fold into the generic resilient-connection swallow. The connection-resilience `except Exception` covers handler/parse faults; the audit-write-failure of a security event is the one thing that must stay loud. **Test:** a reject whose audit callback raises → assert it surfaces (not silently swallowed) and is distinguishable from a normal resilient-connection continue.

5. **[sec-HIGH-4 + test-M3] Client error-mapping + `assert_path_owned` contract.** `assert_path_owned(missing)` MUST raise `FileNotFoundError` (bare `path.lstat()`, NOT wrapped) so the client maps missing-socket → `DaemonControlUnavailableError`. Add the `open_unix_connection` `ConnectionRefusedError` → `DaemonControlUnavailableError` arm (stale inode we own, no listener) — distinct from the missing-path arm. **Tests:** missing socket → Unavailable (via `assert_path_owned`); stale-inode-no-listener → Unavailable (via connect); both covered.

6. **[arch-H3] Make `_Handler` ASYNC now + document `--wait-ready` shape.** Type `_Handler = Callable[[ControlRequest], Awaitable[Mapping[str, object]]]` so G6-5's blocking readiness handler doesn't re-type the seam. In ADR-0038 Consequences, pick + document the `--wait-ready` forward shape: **client-side poll loop over repeated `status.query`** (keeps the server stateless; the exit-code contract lives in the client) — RECOMMENDED — vs a long-lived-connection handler that awaits an observer transition. Decide here, don't discover in G6-5.

7. **[arch-M1] Dedicated `DAEMON_CONTROL_PEER_REJECTED_FIELDS` audit schema (NO `adapter_id`).** The control plane is daemon-global, not adapter-keyed — do NOT reuse `COMMS_SOCKET_PEER_REJECTED_FIELDS` (its `adapter_id` key has no value here). Define a new field-set `{peer_uid, expected_uid, occurred_at}` + `result="refused"`; state where it lives.

8. **[sec-MEDIUM-4 + test-L4] Bound + lock the wire envelope.** Add `max_length` to `ControlRequest.method` AND `id` (a peer-controlled `method` is reflected in the error response — bound it). Extend the exact-field-set lock test to `ControlRequest` + `ControlResponse`; assert `ControlResponse.error` carries ONLY enumerated non-sensitive tokens (method name + `type(exc).__name__`, NEVER `str(exc)`). Add a test that a request with an unexpected top-level key is rejected (proves `extra="forbid"` is load-bearing).

### Extraction-migration safety (MUST)

9. **[arch-H1] Re-export the frame bound publicly from `_local_socket.py`** (`MAX_LOCAL_SOCKET_LINE_BYTES = _MAX_COMMS_LINE_BYTES`) so the new daemon modules depend on the shared module's public surface, not `comms_wire`'s underscore name.

10. **[arch-H2a + test-H1] `CommsSocketListener.bind` DELEGATES to `bind_owner_only_unix_socket(self._path, backlog=1)`** (one bind implementation, one 100%-gated test set; preserves one-shot `listen(1)` via the `backlog` param). NOT a divergent re-implementation.

11. **[arch-H2b] Preserve import compatibility.** `comms_socket_transport.__all__` exports `_peer_uid_authorized`/`_resolve_peer_uid`; there are external importers (the daemon reject path, tests). Grep first: `grep -rn "_resolve_peer_uid\|_peer_uid_authorized\|_assert_dial_path_owned\|_runtime_dir" src/ tests/`, then either keep thin re-export aliases in `comms_socket_transport` OR update every call site. `test_comms_socket_transport.py` MUST stay green UNCHANGED.

12. **[sec-MEDIUM-1 + test-H1] `test_local_socket.py` must DIRECTLY assert the load-bearing security branches** (don't rely on listener-mediated coverage post-extraction): (a) `assert_path_owned` refuses a symlink (lstat-not-stat) and a non-owned socket; (b) both degrade-open breadcrumb logs (`peer_cred_unsupported` / `peer_cred_unavailable`) fire on the `None`/no-SO_PEERCRED branch; (c) `bind_owner_only_unix_socket` unconditionally tightens a pre-existing **0755** parent to 0700; (d) the bind `except BaseException` cleanup unlinks the partial inode on a post-open failure (monkeypatch `Path.chmod` to raise); (e) `unlink_stale_socket` refuses a FIFO (`os.mkfifo` → raises, FIFO survives).

13. **[sec-MEDIUM-1 + Task-1] Decide the shared-module log-event-name consciously** — keep `comms.socket.*` (accept the slight misnomer for the control socket), rename to `local_socket.*` (changes existing log/alert queries), or parameterize the prefix. Document the choice in Task 1; don't let the extraction silently relabel/orphan the breadcrumbs. RECOMMEND: parameterize (each caller passes its prefix) so comms keeps `comms.socket.*` and control uses `daemon.control.*`.

### Test honesty (MUST)

14. **[test-C1] "latest crash" semantics.** `incidents[-1]` is the most-recently-OPENED incarnation (OrderedDict insertion order), NOT necessarily the highest seq — an out-of-order (stale) crash arrival breaks the "higher seq wins" assumption. DECIDE: either `max(incidents, key=host_restart_seq)` (+ a test feeding out-of-seq arrival asserting the higher seq) OR keep insertion-order + document it + test the insertion-order result on out-of-seq arrival. Pin whichever; don't leave it an untested guess.

15. **[test-H2] `test_server_serves_second_connection_after_bad_first`** — parametrized over {malformed JSON, over-bound, unknown-method, peer-reject}: after a bad first connection, a second connection returns a parseable `DaemonStatusResult`. This is THE load-bearing multi-connection-resilience property (assert a real second roundtrip, not "server object not closed").

16. **[test-H3] Assert error-response CONTENT + echoed id** (not "no raise"): unknown-method → `error` startswith `unknown_method:`, `result is None`, `id` echoes request; malformed → `error` startswith `malformed_request:`, `id == UNKNOWN_REQUEST_ID`; over-bound → PIN that the server raises BEFORE writing (no response frame) so the client sees EOF → `DaemonControlProtocolError("empty…")` — assert the silent-close contract explicitly.

17. **[test-M4] Split the client `if not raw or len(raw) > bound`** into two independent tests (empty-read AND over-bound-response, the latter via a stub server emitting an over-bound line) + the malformed-response `ValueError` arm (stub server emits non-JSON). With `--branch`, the `or` short-circuits otherwise.

18. **[test-M5] Failure-mode roundtrip against the REAL server:** unknown-method roundtrip → real server answers `error` startswith `unknown_method`. Note the peer-reject roundtrip stays at the UNIT layer (you can't present a foreign uid to a real same-uid server without patching `resolve_peer_uid` in the server module).

19. **[test-M6] Post-control-start boot-failure reap test:** inject a boot failure AFTER the control server starts but before/at serving; assert the control socket file is STILL unlinked by the drain `finally` (the "EVERY exit path" reap, not just clean shutdown). Guards a regression that moves the `control_server` declaration back inside the supervisor `try`.

20. **[test-L2] The `bind` tests MUST use the short-`$HOME` `runtime_dir` fixture, NOT raw `tmp_path`** (AF_UNIX paths have a ~108-byte limit; pytest `tmp_path` on macOS overflows it → a mac-only flake). Mirror the existing `test_comms_socket_transport.py` fixture (its file has the load-bearing comment).

21. **[test-L5] Render test asserts the LOCALIZED state token** (`t("daemon.status.state.crashed")` value), not the raw `"crashed"` literal — else a regression bypassing `t()` passes.

### ADR-0038 content (MUST)

22. **[sec-HIGH-3 + arch-M2 + sec-MEDIUM-2/5] ADR-0038 must record, on the control plane's OWN terms:** (a) degrade-open auth is acceptable ONLY because the plane is read-only + non-sensitive + FS-perms-of-record on no-SO_PEERCRED hosts — and any future MUTATING method or sensitive-field method RE-OPENS the auth decision (likely fail-closed + step-up); (b) read-only query writes no audit row, peer-reject IS audited (security-ratified); (c) the bind→chmod TOCTOU window is unchanged from ADR-0031 and closed by the 0700 parent; (d) any future `params`-consuming method validates `params` into a per-method frozen model, never reads the raw dict. Plus name the `UNKNOWN_REQUEST_ID = "?"` sentinel (arch-M4) in the protocol module + client-handles-it. The ADR body goes through `alfred-reviewer` before merge (architect's don't-approve-your-own-design rule).

### Contract framing (from the maintainer discussion)

23. **Frame the protocol module as "the daemon/gateway introspection contract v1"** — the method schema + Pydantic request/response models are the transport-agnostic, long-lived asset a FUTURE remote management plane (dashboards/ops) will front over authenticated HTTP (see `docs/ARCHITECTURE.md` D1). The local CLI fronts it over the unix socket now. Document this reuse intent in the protocol module docstring + ADR-0038 so the contract is designed for it (no transport coupling in the models). The management-plane transport (gateway vs core vs sibling) is an explicitly DEFERRED decision (ARCHITECTURE.md D1) — do NOT build any remote/HTTP surface in this slice.

### Commit/doc hygiene (from the #299 CI failures)

24. **i18n commit type:** use `feat(i18n):` / `chore(i18n):` — NEVER `i18n:` (the commit-format validator's `^[a-z]+` rejects the digits in `i18n` as a type). **Do NOT `git add` this plan doc** (plan docs are markdownlint-gated + kept local). Run `npx markdownlint-cli2@0.14.0` on any committed `.md` (ADR-0038, comms.md) before committing — blank line before every list, blanks around headings.
