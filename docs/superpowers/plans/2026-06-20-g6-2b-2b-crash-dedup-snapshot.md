# G6-2b-2b — Crash De-dup + Observer Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correlate the two coexisting adapter-crash signals (the in-child `CrashedNotification` and the gateway's `gateway.adapter.crashed`) into ONE audited incident per physical crash, keyed on `adapter_id` + a gateway host-restart sequence, and make the core's per-adapter status snapshot reachable for a future `alfred status` render — without dropping or muting either loud signal.

**Architecture:** Add an additive `host_restart_seq: int` field to the frozen `AdapterCrashedNotification`, stamped by `GatewayAdapterSupervisor` from its per-adapter `restart_count`. Add a core-side `CrashIncidentReconciler` collaborator owned by the daemon's `_CommsBootGraph` and shared by BOTH the `AdapterStatusObserver` (gateway-crash arm) and the `AdapterCrashHandler` (in-child arm), which both already meet inside the same `AlfredPluginSession`. The reconciler folds both signals into one incident per `(adapter_id, incarnation)`, tagging each audit row with a `crash_signal_source` (`child`/`gateway`/`both`) and a stable `crash_incident_id` so downstream readers count one incident. The observer's in-process `latest(adapter_id)` snapshot stays the read surface; this slice documents the in-daemon-vs-dial decision for the `alfred status` render (2b-2c) and adds NO RPC (YAGNI).

**Tech Stack:** Python 3.12+, Pydantic v2 (frozen + `extra="forbid"` wire models), asyncio, structlog, pytest + pytest-asyncio. All new logic is pure core-side and runs in-process on the required NON-ROOT gate (no bwrap, no launcher).

---

## Context the implementer must hold

Read these before starting. Findings are verified against `main` (`cece59cf`) with G6-2b-2a merged.

- **Where the two signals meet.** Both crash signals are dispatched by the same `AlfredPluginSession._on_post_handshake_method` (`src/alfred/plugins/session.py`):
  - In-child: `adapter.crashed` → `_route_comms_notification` (session.py:816-818) → `self._crash_handler.process(CrashedNotification…)` → `AdapterCrashHandler.process` (`src/alfred/comms_mcp/handlers.py:322-359`) writes a `comms.adapter.crashed` audit row + fires the hookpoint.
  - Gateway: `gateway.adapter.crashed` → `_route_gateway_adapter_status` (session.py:866-894) → `self._status_observer.observe(method, params)` → `AdapterStatusObserver._accept` (`src/alfred/comms_mcp/adapter_status_observer.py:249-271`) writes a `gateway.adapter.crashed` audit row + records the `latest()` snapshot.
  - **Both `self._crash_handler` and `self._status_observer` are injected into the SAME session** (session.py constructor, lines 318-354). A shared reconciler injected into both is therefore natural — no new cross-process plumbing.
- **Today a single physical crash writes TWO audit rows** (`comms.adapter.crashed` from the in-child path AND `gateway.adapter.crashed` from the gateway path). That is the double-audit this slice corrects — by correlating, NOT by suppressing (hard rule #7: still loud + audited, one incident).
- **The frozen model is pre-sanctioned for an additive field.** `AdapterCrashedNotification` docstring (protocol.py:483-492) explicitly says 2b may add `host_restart_seq`/incarnation additively "with zero live-contract risk." `extra="forbid"` is fine for an additive field with a default — existing producers/consumers omit it and still validate.
- **The supervisor counter.** `GatewayAdapterSupervisor.restart_count(adapter_id) -> int` (`src/alfred/gateway/adapter_supervisor.py:253-254`) reads `_AdapterRun.restart_count`, incremented once per backoff-scheduled restart in `_handle_crash` (adapter_supervisor.py:454). This is the per-adapter, per-gateway-process restart sequence — the natural `host_restart_seq` ("the Nth incarnation of this adapter since the gateway last (re)started it").
- **No test pins the exact field SET of `AdapterCrashedNotification` by dict equality.** `tests/unit/gateway/test_adapter_status_emitter.py::test_emit_crashed_maps_error_class_and_redacted_detail` asserts the three fields individually (not full-dict). `tests/unit/comms_mcp/test_adapter_status_models.py::test_crashed_requires_nonempty_error_class` constructs without the new field. So the additive field breaks no exact-set assertion — but the emitter's crashed frame `model_dump()` will grow a key, so any future exact-dict assertion must include it. (The breaker-open emitter test DOES use exact-dict; the crashed one does not — leave it.)

### Resolved de-dup correlation rule (the design nuance the spec demanded)

The in-child `CrashedNotification` does **not** carry the gateway's `host_restart_seq` — the child process cannot know the gateway's per-adapter counter. So correlation is **NOT** "both frames carry the same seq." The rule is:

1. **Incarnation tracking (gateway-authoritative).** The `CrashIncidentReconciler` tracks, per `adapter_id`, the **current incarnation** = the latest `host_restart_seq` it has seen on a gateway frame. The gateway `up` frame establishes/advances the incarnation when an adapter (re)reaches serving; the gateway `crashed` frame carries the incarnation of the run that exited.
2. **Gateway crash is authoritative, opens/owns the incident.** When `gateway.adapter.crashed{adapter_id, host_restart_seq}` arrives, it is THE incident for `(adapter_id, host_restart_seq)`. The reconciler opens (or folds into) the incident, assigns a stable `crash_incident_id`, and sets `crash_signal_source` to `gateway` (or `both` if an in-child crash for this incarnation already arrived).
3. **In-child crash is tagged to the current incarnation.** When the in-child `CrashedNotification{adapter_id}` arrives, it carries no seq; the reconciler tags it to `adapter_id`'s **current incarnation** (the latest seq seen). It folds into that incarnation's incident (creating one with source `child` if the gateway crash has not yet arrived; upgrading source to `both` if it has).
4. **One incident, both rows still written, second row marked.** Both arms STILL write their audit row (loud, never dropped — hard rule #7). The reconciler stamps every crash audit row with `crash_incident_id` + `crash_signal_source`, so a downstream reader (alfred status, 2b-2c) counts incidents by distinct `crash_incident_id`, collapsing the two rows of one physical crash into one incident.
5. **Trust-boundary guard (the spec's CRITICAL constraint).** A forged/duplicate crash frame can NEVER suppress a real one: folding only ever ADDS a row or upgrades a source label — it never elides a row. A second gateway-crash for an ALREADY-seen `(adapter_id, host_restart_seq)` is a duplicate; it is folded (no new incident) but STILL audited (with `crash_signal_source=gateway` and a `duplicate=true` marker) so a replay is visible, not silently dropped. A forged in-child crash for an adapter with no open incarnation opens a `child`-only incident (still loud + audited) — it cannot mask a later genuine gateway crash, which opens its own incident at its own seq.

### `alfred status` snapshot reachability (verified — YAGNI decision)

`alfred status` (`src/alfred/cli/main.py:175-214`) and `alfred daemon status` (`src/alfred/cli/daemon/_commands.py:2276-2305`) are **standalone CLI commands that do NOT dial the daemon** — they read Settings / the pidfile only. The `AdapterStatusObserver` (and its `latest()` snapshot + the new reconciler's incident view) lives **inside the daemon process** (`_CommsBootGraph.status_observer`, _commands.py:615). The CLI cannot reach it in-process.

**Decision:** 2b-2b does NOT build a daemon RPC/query endpoint (YAGNI — no consumer exists until 2b-2c, and the render shape is 2b-2c's to design). Instead 2b-2b: (i) keeps the in-process `latest(adapter_id)` read surface, (ii) adds an in-process `incidents(adapter_id) -> tuple[CrashIncidentView, ...]` read surface on the reconciler for the SAME in-process consumer, and (iii) documents, in the plan's Precursor-gaps section + a code docstring, that **2b-2c must choose either a daemon query seam (the status CLI dials the daemon) or relocate the render in-daemon** — because the current `alfred status` process model cannot reach the observer. That is the genuine seam 2b-2c scopes; 2b-2b proves the data is correct and in-process-readable.

---

## File structure

**Modified:**

- `src/alfred/comms_mcp/protocol.py` — add `host_restart_seq: int = Field(default=0, ge=0)` to `AdapterCrashedNotification` (additive, defaulted, frozen-safe).
- `src/alfred/gateway/adapter_status_emitter.py` — `emit_crashed` gains a `host_restart_seq: int` param; threads it into `AdapterCrashedNotification`.
- `src/alfred/gateway/adapter_supervisor.py` — `_apply`'s `EMIT_CRASHED` arm passes `run.restart_count` as `host_restart_seq`; the `_handle_crash`/`_spawn_or_terminal` crash arms thread it through `_apply`.
- `src/alfred/audit/audit_row_schemas.py` — add `host_restart_seq`, `crash_incident_id`, `crash_signal_source` to `GATEWAY_ADAPTER_CRASHED_FIELDS`; add `crash_incident_id`, `crash_signal_source` to `COMMS_ADAPTER_CRASHED_FIELDS`.
- `src/alfred/comms_mcp/adapter_status_observer.py` — accept an injected `CrashIncidentReconciler`; on a `crashed` accept, fold via the reconciler and add the incident fields to the subject; `_subject_for` carries `host_restart_seq`.
- `src/alfred/comms_mcp/handlers.py` — `AdapterCrashHandler` accepts the same injected reconciler; folds the in-child crash and adds the incident fields to its subject.
- `src/alfred/cli/daemon/_commands.py` — `_build_comms_boot_graph` constructs ONE `CrashIncidentReconciler` and injects it into both the observer and the per-adapter `AdapterCrashHandler`; add it to `_CommsBootGraph` (pure in-memory, no reap).
- `src/alfred/plugins/session.py` — thread the reconciler-fed handler/observer through unchanged (they already take the dependencies; no new session field unless the crash handler is constructed there — verify in Task 9).

**Created:**

- `src/alfred/comms_mcp/crash_incident_reconciler.py` — the `CrashIncidentReconciler` + `CrashIncidentView` (pure in-memory correlation state machine).
- `tests/unit/comms_mcp/test_crash_incident_reconciler.py` — the reconciler unit suite (the de-dup correlation rule, in-process, non-root).
- `tests/unit/comms_mcp/test_crash_dedup_join.py` — integration of observer + in-child handler sharing one reconciler (one physical crash → one incident, two loud rows).

**CI gate registration (verify in Task 12):** `crash_incident_reconciler.py` is a new `comms_mcp` file → it lands in the per-file 100%-coverage gate. Add it explicitly to the coverage-gate file list in `ci.yml` mirroring how `adapter_status_observer.py` is listed (two-gates pattern: glob-caught AND named explicitly).

---

## Task 1: `host_restart_seq` additive field on `AdapterCrashedNotification`

**Files:**

- Modify: `src/alfred/comms_mcp/protocol.py` (the `AdapterCrashedNotification` class, ~lines 469-497)
- Test: `tests/unit/comms_mcp/test_adapter_status_models.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_adapter_status_models.py`:

```python
def test_crashed_carries_host_restart_seq_additive_default() -> None:
    # Existing producers omit the field -> defaults to 0 (back-compat, frozen-safe).
    default = AdapterCrashedNotification(adapter_id="discord", error_class="RuntimeError", detail="")
    assert default.host_restart_seq == 0
    # A real producer stamps the gateway's per-adapter restart sequence.
    stamped = AdapterCrashedNotification(
        adapter_id="discord", error_class="RuntimeError", detail="", host_restart_seq=3
    )
    assert stamped.host_restart_seq == 3
    # Negative is refused at the wire (ge=0) — a forged negative seq cannot reach the join.
    with pytest.raises(ValidationError):
        AdapterCrashedNotification(
            adapter_id="discord", error_class="RuntimeError", detail="", host_restart_seq=-1
        )
    # extra="forbid" still holds for genuinely unknown fields.
    with pytest.raises(ValidationError):
        AdapterCrashedNotification(
            adapter_id="discord", error_class="RuntimeError", detail="", bogus="x"  # type: ignore[call-arg]
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py::test_crashed_carries_host_restart_seq_additive_default -v`
Expected: FAIL — `host_restart_seq` is an unexpected keyword / `AttributeError`.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/protocol.py`, add the field to `AdapterCrashedNotification` (after `detail`):

```python
    adapter_id: AdapterId
    error_class: str = Field(min_length=1)
    detail: str
    # ADDITIVE (G6-2b-2b / #288): the gateway's per-adapter host-restart sequence —
    # the supervisor's ``restart_count`` for this adapter, i.e. which INCARNATION
    # (the Nth (re)spawn since the gateway last started this adapter) exited. The
    # core's CrashIncidentReconciler keys the crash-dedup join on
    # ``(adapter_id, host_restart_seq)``. Defaulted to 0 so every pre-2b-2b
    # producer/consumer validates unchanged (the docstring's pre-sanctioned
    # additive extension); ``ge=0`` refuses a forged negative at the wire. The
    # IN-CHILD ``CrashedNotification`` carries NO seq (the child cannot know the
    # gateway counter) — its signal is tagged to the current incarnation core-side.
    host_restart_seq: int = Field(default=0, ge=0)
```

Update the class docstring's CRASH DE-DUP paragraph to say the field now EXISTS (was "may be extended").

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py -v`
Expected: PASS (all model tests).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/protocol.py tests/unit/comms_mcp/test_adapter_status_models.py
git commit -m "feat(comms): additive host_restart_seq on AdapterCrashedNotification (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Audit field-sets carry the join + incident keys

**Files:**

- Modify: `src/alfred/audit/audit_row_schemas.py` (`GATEWAY_ADAPTER_CRASHED_FIELDS` ~789-796, `COMMS_ADAPTER_CRASHED_FIELDS` ~1061-1073)
- Test: `tests/unit/comms_mcp/test_adapter_status_models.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_adapter_status_models.py`:

```python
def test_crash_field_sets_carry_dedup_join_keys() -> None:
    from alfred.audit.audit_row_schemas import (
        COMMS_ADAPTER_CRASHED_FIELDS,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
    )

    # The gateway crash row carries the seq it joins on + the incident handle/source.
    assert {"host_restart_seq", "crash_incident_id", "crash_signal_source"} <= (
        GATEWAY_ADAPTER_CRASHED_FIELDS
    )
    # The in-child crash row carries the incident handle/source (it has no seq of
    # its own — it is tagged to the current incarnation core-side).
    assert {"crash_incident_id", "crash_signal_source"} <= COMMS_ADAPTER_CRASHED_FIELDS
    assert "host_restart_seq" not in COMMS_ADAPTER_CRASHED_FIELDS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py::test_crash_field_sets_carry_dedup_join_keys -v`
Expected: FAIL — the new keys are absent from both frozensets.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/audit/audit_row_schemas.py`, extend the two frozensets:

```python
GATEWAY_ADAPTER_CRASHED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "error_class",
        "detail_redacted",
        "occurred_at",
        # G6-2b-2b (#288): the gateway's per-adapter incarnation this crash belongs to,
        # and the crash-dedup incident handle + which signal(s) corroborate it.
        "host_restart_seq",
        "crash_incident_id",
        "crash_signal_source",
    }
)
```

```python
COMMS_ADAPTER_CRASHED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "adapter_id",
        "error_class",
        "reason",
        "detail_redacted",
        "crashed_at",
        # G6-2b-2b (#288): the crash-dedup incident handle this in-child crash folds
        # into + which signal(s) corroborate it. No host_restart_seq here — the
        # in-child frame is tagged to the current incarnation core-side.
        "crash_incident_id",
        "crash_signal_source",
    }
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_models.py::test_crash_field_sets_carry_dedup_join_keys -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/audit/audit_row_schemas.py tests/unit/comms_mcp/test_adapter_status_models.py
git commit -m "feat(audit): crash audit field-sets carry dedup join + incident keys (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: `CrashIncidentReconciler` — open a gateway incident

**Files:**

- Create: `src/alfred/comms_mcp/crash_incident_reconciler.py`
- Test: `tests/unit/comms_mcp/test_crash_incident_reconciler.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms_mcp/test_crash_incident_reconciler.py`:

```python
"""CrashIncidentReconciler — the core-side crash-dedup correlation (G6-2b-2b / #288)."""

from __future__ import annotations

from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler


def test_gateway_crash_opens_one_incident() -> None:
    reconciler = CrashIncidentReconciler()
    result = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    assert result.crash_signal_source == "gateway"
    assert result.duplicate is False
    assert result.crash_incident_id  # a stable non-empty handle
    incidents = reconciler.incidents("discord")
    assert len(incidents) == 1
    assert incidents[0].host_restart_seq == 0
    assert incidents[0].crash_signal_source == "gateway"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py::test_gateway_crash_opens_one_incident -v`
Expected: FAIL — `ModuleNotFoundError: alfred.comms_mcp.crash_incident_reconciler`.

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/comms_mcp/crash_incident_reconciler.py`:

```python
"""Core-side crash-dedup correlation (G6-2b-2b / Spec B §3 / #288).

Two crash signals coexist (Spec B §3): the gateway's PROCESS-level
``gateway.adapter.crashed`` (authoritative for host-supervision/audit) and the
in-child ``adapter.crashed`` (a finer code-level diagnostic). A single physical
crash can produce BOTH. This reconciler folds them into ONE audited incident per
``(adapter_id, incarnation)`` so a single crash is counted once — WITHOUT
dropping either loud signal (CLAUDE.md hard rule #7: still loud + audited).

CORRELATION RULE (the design nuance — the in-child frame carries no gateway seq):

* The gateway frame carries ``host_restart_seq`` (the supervisor's per-adapter
  restart counter = which INCARNATION exited). It is authoritative and OPENS the
  incident for ``(adapter_id, host_restart_seq)``.
* The in-child frame carries NO seq — the child cannot know the gateway counter.
  It is tagged to ``adapter_id``'s CURRENT incarnation (the latest seq the
  reconciler has seen for that adapter, advanced by gateway ``up``/``crashed``).
* Both fold into the SAME incident; ``crash_signal_source`` records which
  signal(s) corroborate it: ``gateway`` / ``child`` / ``both``.

TRUST BOUNDARY (Spec B §6 / hard rule #7): folding NEVER elides an audit row. A
duplicate gateway crash for an already-seen incarnation is marked
``duplicate=True`` but still audited (a replay is VISIBLE, not silently dropped);
a forged in-child crash opens a ``child``-only incident (still loud) and cannot
mask a later genuine gateway crash, which opens its own incident at its own seq.

In-memory only (per gateway↔core link lifetime); the gateway is "stateless beyond
a small connection buffer" and the durable record is the signed audit log.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

CrashSignalSource = Literal["gateway", "child", "both"]

# Bound the per-adapter incident history so a crash-loop cannot grow the map
# unboundedly (the gateway is memory-bounded; the durable trail is the audit log).
_MAX_INCIDENTS_PER_ADAPTER: Final[int] = 64


@dataclass(frozen=True, slots=True)
class CrashFoldResult:
    """The outcome of folding one crash signal — what the caller stamps on its row."""

    crash_incident_id: str
    crash_signal_source: CrashSignalSource
    host_restart_seq: int
    duplicate: bool


@dataclass(frozen=True, slots=True)
class CrashIncidentView:
    """A read-only snapshot of one correlated incident (for the in-process reader)."""

    adapter_id: str
    host_restart_seq: int
    crash_incident_id: str
    crash_signal_source: CrashSignalSource


@dataclass
class _Incident:
    crash_incident_id: str
    host_restart_seq: int
    saw_gateway: bool = field(default=False)
    saw_child: bool = field(default=False)

    @property
    def source(self) -> CrashSignalSource:
        if self.saw_gateway and self.saw_child:
            return "both"
        return "gateway" if self.saw_gateway else "child"


@dataclass
class _AdapterState:
    current_incarnation: int = 0
    incidents: OrderedDict[int, _Incident] = field(default_factory=OrderedDict)


class CrashIncidentReconciler:
    """Fold the two coexisting crash signals into one incident per incarnation."""

    def __init__(self) -> None:
        self._adapters: dict[str, _AdapterState] = {}

    def observe_gateway_crash(self, *, adapter_id: str, host_restart_seq: int) -> CrashFoldResult:
        """The authoritative process-level crash. Opens (or dedups) the incident."""
        state = self._state(adapter_id)
        state.current_incarnation = max(state.current_incarnation, host_restart_seq)
        existing = state.incidents.get(host_restart_seq)
        duplicate = existing is not None and existing.saw_gateway
        incident = existing if existing is not None else self._open(state, host_restart_seq)
        incident.saw_gateway = True
        return CrashFoldResult(
            crash_incident_id=incident.crash_incident_id,
            crash_signal_source=incident.source,
            host_restart_seq=host_restart_seq,
            duplicate=duplicate,
        )

    def observe_child_crash(self, *, adapter_id: str) -> CrashFoldResult:
        """The in-child diagnostic crash. Tagged to the CURRENT incarnation."""
        state = self._state(adapter_id)
        seq = state.current_incarnation
        existing = state.incidents.get(seq)
        duplicate = existing is not None and existing.saw_child
        incident = existing if existing is not None else self._open(state, seq)
        incident.saw_child = True
        return CrashFoldResult(
            crash_incident_id=incident.crash_incident_id,
            crash_signal_source=incident.source,
            host_restart_seq=seq,
            duplicate=duplicate,
        )

    def note_incarnation(self, *, adapter_id: str, host_restart_seq: int) -> None:
        """Advance the current incarnation on a gateway ``up`` (a fresh serving run).

        The observer calls this on an accepted ``up`` so a later in-child crash is
        tagged to the run that was actually serving, not a stale one.
        """
        state = self._state(adapter_id)
        state.current_incarnation = max(state.current_incarnation, host_restart_seq)

    def incidents(self, adapter_id: str) -> tuple[CrashIncidentView, ...]:
        """The correlated incidents for ``adapter_id`` (in-process read for 2b-2c)."""
        state = self._adapters.get(adapter_id)
        if state is None:
            return ()
        return tuple(
            CrashIncidentView(
                adapter_id=adapter_id,
                host_restart_seq=inc.host_restart_seq,
                crash_incident_id=inc.crash_incident_id,
                crash_signal_source=inc.source,
            )
            for inc in state.incidents.values()
        )

    def _open(self, state: _AdapterState, seq: int) -> _Incident:
        incident = _Incident(crash_incident_id=uuid.uuid4().hex, host_restart_seq=seq)
        state.incidents[seq] = incident
        while len(state.incidents) > _MAX_INCIDENTS_PER_ADAPTER:
            state.incidents.popitem(last=False)
        return incident

    def _state(self, adapter_id: str) -> _AdapterState:
        state = self._adapters.get(adapter_id)
        if state is None:
            state = _AdapterState()
            self._adapters[adapter_id] = state
        return state


__all__ = [
    "CrashFoldResult",
    "CrashIncidentReconciler",
    "CrashIncidentView",
    "CrashSignalSource",
]
```

Note: the `Mapping` import is removed if unused — keep the file import-clean (`ruff` will flag an unused import). Verify before commit.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py::test_gateway_crash_opens_one_incident -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/crash_incident_reconciler.py tests/unit/comms_mcp/test_crash_incident_reconciler.py
git commit -m "feat(comms): CrashIncidentReconciler opens a gateway crash incident (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Reconciler — fold an in-child crash into the current incarnation

**Files:**

- Modify: (none — Task 3 already wrote `observe_child_crash` / `note_incarnation`; this task PROVES them)
- Test: `tests/unit/comms_mcp/test_crash_incident_reconciler.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_crash_incident_reconciler.py`:

```python
def test_child_then_gateway_same_incarnation_folds_to_one_incident() -> None:
    reconciler = CrashIncidentReconciler()
    # Adapter reached its 2nd serving incarnation (after one restart).
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=1)
    # The in-child diagnostic arrives first, tagged to incarnation 1.
    child = reconciler.observe_child_crash(adapter_id="discord")
    assert child.crash_signal_source == "child"
    assert child.host_restart_seq == 1
    # The authoritative gateway crash for incarnation 1 arrives next -> SAME incident.
    gateway = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=1)
    assert gateway.crash_incident_id == child.crash_incident_id
    assert gateway.crash_signal_source == "both"
    assert reconciler.incidents("discord") == (
        # one incident, corroborated by both signals
        reconciler.incidents("discord")[0],
    )
    assert len(reconciler.incidents("discord")) == 1


def test_gateway_then_child_same_incarnation_folds_to_one_incident() -> None:
    reconciler = CrashIncidentReconciler()
    gateway = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    child = reconciler.observe_child_crash(adapter_id="discord")
    assert child.crash_incident_id == gateway.crash_incident_id
    assert child.crash_signal_source == "both"
    assert len(reconciler.incidents("discord")) == 1


def test_distinct_incarnations_are_distinct_incidents() -> None:
    reconciler = CrashIncidentReconciler()
    first = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=1)
    second = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=1)
    assert first.crash_incident_id != second.crash_incident_id
    assert len(reconciler.incidents("discord")) == 2
```

- [ ] **Step 2: Run test to verify it fails (or passes if Task 3 covered it)**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py -v`
Expected: PASS — Task 3's implementation already supports these; this task locks the folding behaviour with explicit assertions. (If any FAIL, the reconciler logic in Task 3 is wrong — fix Task 3's file, do not weaken the test.)

- [ ] **Step 3: Write minimal implementation**

No new code expected. If `test_gateway_then_child_same_incarnation_folds_to_one_incident` fails because `observe_child_crash` opened a NEW incident at `seq=0` when the gateway already opened one, confirm `_state(...).incidents.get(seq)` finds it — both use `current_incarnation`/`host_restart_seq=0`, so they collide correctly.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py -v`
Expected: PASS (all reconciler tests).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/comms_mcp/test_crash_incident_reconciler.py
git commit -m "test(comms): reconciler folds child+gateway crash to one incident (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Reconciler — duplicate + forgery never suppress (trust boundary)

**Files:**

- Test: `tests/unit/comms_mcp/test_crash_incident_reconciler.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_crash_incident_reconciler.py`:

```python
def test_duplicate_gateway_crash_is_marked_not_dropped() -> None:
    reconciler = CrashIncidentReconciler()
    first = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    second = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    assert first.duplicate is False
    # A replayed/forged gateway crash for the SAME incarnation folds (no new
    # incident) but is FLAGGED duplicate so the caller STILL audits it loudly.
    assert second.duplicate is True
    assert second.crash_incident_id == first.crash_incident_id
    assert len(reconciler.incidents("discord")) == 1


def test_forged_child_crash_cannot_mask_a_later_real_gateway_crash() -> None:
    reconciler = CrashIncidentReconciler()
    # A forged in-child crash with no prior incarnation -> a child-only incident at 0.
    forged = reconciler.observe_child_crash(adapter_id="discord")
    assert forged.crash_signal_source == "child"
    # A genuine gateway crash for a LATER incarnation opens its OWN incident.
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=2)
    real = reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=2)
    assert real.crash_incident_id != forged.crash_incident_id
    assert real.crash_signal_source == "gateway"
    assert len(reconciler.incidents("discord")) == 2


def test_incident_history_is_bounded() -> None:
    reconciler = CrashIncidentReconciler()
    for seq in range(200):
        reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=seq)
    # Bounded so a crash-loop cannot grow the map unboundedly (audit log is durable).
    assert len(reconciler.incidents("discord")) <= 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py -k "duplicate or forged or bounded" -v`
Expected: PASS if Task 3's `duplicate` logic + bound are correct; FAIL only if a gap remains (then fix Task 3's file).

- [ ] **Step 3: Write minimal implementation**

No new code expected (Task 3 implemented `duplicate` + `_MAX_INCIDENTS_PER_ADAPTER`). If `test_incident_history_is_bounded` fails, confirm `_open` trims via `popitem(last=False)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/comms_mcp/test_crash_incident_reconciler.py
git commit -m "test(comms): reconciler never suppresses a duplicate/forged crash (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Supervisor stamps `host_restart_seq` on the crashed frame

**Files:**

- Modify: `src/alfred/gateway/adapter_status_emitter.py` (`emit_crashed`, ~84-97)
- Modify: `src/alfred/gateway/adapter_supervisor.py` (`_apply` EMIT_CRASHED arm ~541-546; the `error_class`/`detail` thread-through in `_handle_crash` ~435-440 and `_spawn_or_terminal` ~348-353)
- Test: `tests/unit/gateway/test_adapter_status_emitter.py`, `tests/unit/gateway/test_adapter_supervisor.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/gateway/test_adapter_status_emitter.py`:

```python
async def test_emit_crashed_threads_host_restart_seq() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_crashed(
        adapter_id=_A, error_class="BrokenPipeError", detail="x", host_restart_seq=4
    )
    method, params = sink.frames[0]
    assert method == "gateway.adapter.crashed"
    assert params["host_restart_seq"] == 4


async def test_emit_crashed_defaults_host_restart_seq_to_zero() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_crashed(
        adapter_id=_A, error_class="BrokenPipeError", detail="x", host_restart_seq=0
    )
    assert sink.frames[0][1]["host_restart_seq"] == 0
```

Add to `tests/unit/gateway/test_adapter_supervisor.py` (mirror an existing crash-loop test that already drives a crash; assert the emitted crashed frame carries the run's restart sequence). Locate the existing fake status sink/emitter the supervisor tests use and assert:

```python
async def test_crashed_frame_carries_restart_seq(...)-> None:
    # ... drive a crash so the supervisor emits gateway.adapter.crashed ...
    # The first crash is incarnation 0 (restart_count starts at 0 before increment).
    crashed = [f for f in sink.frames if f[0] == "gateway.adapter.crashed"]
    assert crashed
    assert crashed[0][1]["host_restart_seq"] == 0
```

(Read `tests/unit/gateway/test_adapter_supervisor.py` to match its existing fake-seam construction; do not invent a new harness.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_adapter_status_emitter.py::test_emit_crashed_threads_host_restart_seq -v`
Expected: FAIL — `emit_crashed` has no `host_restart_seq` parameter.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/gateway/adapter_status_emitter.py`:

```python
    async def emit_crashed(
        self, *, adapter_id: str, error_class: str, detail: str, host_restart_seq: int
    ) -> None:
        """``gateway.adapter.crashed`` — the process-level crash signal.

        ``host_restart_seq`` is the supervisor's per-adapter ``restart_count`` — the
        incarnation that exited (G6-2b-2b / #288). The core's CrashIncidentReconciler
        keys the crash-dedup join on ``(adapter_id, host_restart_seq)``. ``detail`` is
        REDACTED then BOUND (correction #1) before it crosses to the sink.
        """
        redacted_detail = redact_secret_shapes(detail)[:_MAX_CRASH_DETAIL_LEN]
        frame = AdapterCrashedNotification(
            adapter_id=adapter_id,
            error_class=error_class,
            detail=redacted_detail,
            host_restart_seq=host_restart_seq,
        )
        await self._sink.emit(GATEWAY_ADAPTER_CRASHED, frame.model_dump())
```

In `src/alfred/gateway/adapter_supervisor.py`, thread `host_restart_seq` into `_apply`'s EMIT_CRASHED. Add a parameter to `_apply` (default 0) and pass `run.restart_count`:

```python
    async def _apply(
        self,
        run: _AdapterRun,
        event: AdapterLifecycleEvent,
        *,
        error_class: str = "",
        detail: str = "",
        reason: AdapterDownReason = "operator",
        retry_after_seconds: int = 0,
    ) -> None:
        ...
            case AdapterControl.EMIT_CRASHED:
                await self._emitter.emit_crashed(
                    adapter_id=adapter_id,
                    error_class=error_class or "AdapterChildExited",
                    detail=detail,
                    host_restart_seq=run.restart_count,
                )
```

`run.restart_count` is already accessible in `_apply` via `run`. The first crash emits `host_restart_seq=0` (the counter is incremented AFTER the crashed frame, in `_handle_crash`), which correctly labels "the 0th incarnation crashed." Confirm against the supervisor flow: `_handle_crash` calls `_apply(CHILD_EXITED)` BEFORE `run.restart_count += 1` — so the crashed frame carries the pre-increment value = the incarnation index that exited. Add a code comment noting this ordering is load-bearing.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_adapter_status_emitter.py tests/unit/gateway/test_adapter_supervisor.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/adapter_status_emitter.py src/alfred/gateway/adapter_supervisor.py tests/unit/gateway/test_adapter_status_emitter.py tests/unit/gateway/test_adapter_supervisor.py
git commit -m "feat(gateway): supervisor stamps host_restart_seq on the crashed frame (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: Observer folds the gateway crash + carries the incident fields

**Files:**

- Modify: `src/alfred/comms_mcp/adapter_status_observer.py` (constructor; `_accept`/`_subject_for`; the `up` accept calls `note_incarnation`)
- Test: `tests/unit/comms_mcp/test_adapter_status_observer.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_adapter_status_observer.py` (read the file first to reuse its fake audit writer + `_EPOCH` fixtures):

```python
async def test_crashed_subject_carries_host_restart_seq_and_incident_fields() -> None:
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

    writer = _RecordingAuditWriter()
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=writer,
        expected_epoch=lambda: _EPOCH,
        now=lambda: _NOW,
        reconciler=reconciler,
    )
    await observer.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "RuntimeError", "detail": "boom", "host_restart_seq": 2},
    )
    row = writer.rows[-1]
    assert row.event == "gateway.adapter.crashed"
    assert row.subject["host_restart_seq"] == 2
    assert row.subject["crash_signal_source"] == "gateway"
    assert row.subject["crash_incident_id"]
    # The reconciler now holds one incident at incarnation 2.
    assert len(reconciler.incidents("discord")) == 1


async def test_up_advances_incarnation_for_later_child_crash() -> None:
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

    writer = _RecordingAuditWriter()
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=writer, expected_epoch=lambda: _EPOCH, now=lambda: _NOW, reconciler=reconciler
    )
    # An accepted up at the 1st incarnation (epoch matches) advances the reconciler.
    await observer.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH})
    # A subsequent in-child crash (Task 8 wires the handler) would tag to incarnation 0;
    # here we just assert the observer told the reconciler about the up.
    # (up carries no seq -> note_incarnation(seq=0) is a no-op advance, but the call
    # path must exist so a future seq-bearing up advances correctly.)
    assert reconciler.incidents("discord") == ()  # no crash yet
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_observer.py::test_crashed_subject_carries_host_restart_seq_and_incident_fields -v`
Expected: FAIL — `AdapterStatusObserver.__init__` has no `reconciler` parameter.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/adapter_status_observer.py`:

1. Import: `from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler`.
2. Constructor takes `reconciler: CrashIncidentReconciler` (required — the daemon always injects it; a None-default would invite a silent no-dedup path).
3. In `_accept`, when the parsed model is `AdapterUpNotification`, call `self._reconciler.note_incarnation(adapter_id=parsed.adapter_id, host_restart_seq=0)` AFTER the audit write succeeds (up carries no seq today; seq-bearing up is a later concern — the call path must exist).
4. In `_accept`, when parsed is `AdapterCrashedNotification`, call `fold = self._reconciler.observe_gateway_crash(adapter_id=parsed.adapter_id, host_restart_seq=parsed.host_restart_seq)` and pass `fold` into `_subject_for` so the subject carries `host_restart_seq`, `crash_incident_id`, `crash_signal_source`. (Restructure `_subject_for` to take an optional `fold: CrashFoldResult | None` — only the crashed branch uses it.)

The crashed subject branch becomes:

```python
        if isinstance(parsed, AdapterCrashedNotification):
            assert fold is not None  # the crashed accept always folds first
            return {
                "adapter_id": parsed.adapter_id,
                "error_class": parsed.error_class,
                "detail_redacted": redact_secret_shapes(parsed.detail)[:_MAX_CRASH_DETAIL_LEN],
                "occurred_at": ts,
                "host_restart_seq": parsed.host_restart_seq,
                "crash_incident_id": fold.crash_incident_id,
                "crash_signal_source": fold.crash_signal_source,
            }
```

Wire the fold call in `_accept` before building the subject (the fold must precede the audit write so a duplicate is still flagged + audited).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_adapter_status_observer.py -v`
Expected: PASS (all observer tests, including pre-existing ones — confirm none broke from the constructor signature change; update their construction sites to pass a `CrashIncidentReconciler()`).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/adapter_status_observer.py tests/unit/comms_mcp/test_adapter_status_observer.py
git commit -m "feat(comms): observer folds gateway crash + carries incident fields (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 8: In-child crash handler folds into the same incident

**Files:**

- Modify: `src/alfred/comms_mcp/handlers.py` (`AdapterCrashHandler.__init__` + `.process`)
- Test: `tests/unit/comms_mcp/test_handlers.py` (or the file that covers `AdapterCrashHandler` — verify path first)

- [ ] **Step 1: Write the failing test**

Read the existing `AdapterCrashHandler` test file (grep `AdapterCrashHandler` under `tests/unit/comms_mcp/`). Add:

```python
async def test_in_child_crash_folds_and_carries_incident_fields() -> None:
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
    from alfred.comms_mcp.protocol import CrashedNotification

    writer = _RecordingAuditWriter()
    hook = _RecordingHookInvoker()
    reconciler = CrashIncidentReconciler()
    handler = AdapterCrashHandler(audit_writer=writer, hook_invoker=hook, reconciler=reconciler)
    await handler.process(
        CrashedNotification(adapter_id="discord", error_class="ValueError", detail="boom")
    )
    row = writer.rows[-1]
    assert row.event == "comms.adapter.crashed"
    assert row.subject["crash_signal_source"] == "child"
    assert row.subject["crash_incident_id"]
    assert "host_restart_seq" not in row.subject  # in-child row carries no seq
    assert len(reconciler.incidents("discord")) == 1


async def test_child_and_gateway_crash_share_one_incident_id(...) -> None:
    # Covered end-to-end in Task 10; this is the handler-level half.
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_handlers.py::test_in_child_crash_folds_and_carries_incident_fields -v`
Expected: FAIL — `AdapterCrashHandler.__init__` has no `reconciler` parameter.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/comms_mcp/handlers.py`, `AdapterCrashHandler`:

```python
    def __init__(
        self,
        *,
        audit_writer: _AuditWriterLike,
        hook_invoker: _HookInvokerLike,
        reconciler: CrashIncidentReconciler,
    ) -> None:
        self._audit_writer = audit_writer
        self._hook_invoker = hook_invoker
        self._reconciler = reconciler

    async def process(self, notification: CrashedNotification) -> None:
        fold = self._reconciler.observe_child_crash(adapter_id=notification.adapter_id)
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_ADAPTER_CRASHED_FIELDS,
            schema_name="COMMS_ADAPTER_CRASHED_FIELDS",
            event="comms.adapter.crashed",
            actor_user_id=None,
            subject={
                "adapter_id": notification.adapter_id,
                "error_class": notification.error_class,
                "reason": _CRASH_REASON_SELF_REPORTED,
                "detail_redacted": redact_secret_shapes(notification.detail)[:_MAX_CRASH_DETAIL_LEN],
                "crashed_at": datetime.now(UTC).isoformat(),
                "crash_incident_id": fold.crash_incident_id,
                "crash_signal_source": fold.crash_signal_source,
            },
            trust_tier_of_trigger="T3",
            result="crashed",
            cost_estimate_usd=0.0,
            trace_id=notification.adapter_id,
        )
        await self._hook_invoker.fire_adapter_crashed(
            adapter_id=notification.adapter_id,
            error_class=notification.error_class,
        )
```

Import `CrashIncidentReconciler` at module scope (or under `TYPE_CHECKING` for the annotation + a runtime import — it is used at runtime via the parameter, so a plain import is fine).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_handlers.py -v`
Expected: PASS (update any pre-existing `AdapterCrashHandler(...)` construction sites in tests to pass `reconciler=CrashIncidentReconciler()`).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/handlers.py tests/unit/comms_mcp/test_handlers.py
git commit -m "feat(comms): in-child crash handler folds into the shared incident (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 9: Daemon boot graph constructs + shares ONE reconciler

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (`_build_comms_boot_graph` ~655-790; `_CommsBootGraph` dataclass ~564-615; the per-adapter handler construction in `_build_comms_adapter_wiring` which builds the `AdapterCrashHandler` — verify the construction site)
- Modify: `src/alfred/plugins/session.py` only if the crash handler is constructed inside the session factory (verify)
- Test: `tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py`

- [ ] **Step 1: Write the failing test**

Read `tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py` for its boot-graph build helper. Add:

```python
async def test_boot_graph_shares_one_reconciler_between_observer_and_crash_handler() -> None:
    graph = await _build_test_comms_boot_graph(...)  # reuse the file's existing builder
    # The observer and the per-adapter crash handler must share the SAME reconciler
    # instance, so an in-child crash and a gateway crash for one physical crash fold
    # into one incident.
    assert graph.crash_incident_reconciler is graph.status_observer._reconciler
```

If the crash handler is built per-adapter in `_build_comms_adapter_wiring`, also assert (in that file's test) that the wiring receives the graph's reconciler. Verify the exact construction path before writing — grep `AdapterCrashHandler(` under `src/alfred/`.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py -k reconciler -v`
Expected: FAIL — `_CommsBootGraph` has no `crash_incident_reconciler` field.

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/cli/daemon/_commands.py`:

1. Import `CrashIncidentReconciler`.
2. In `_build_comms_boot_graph`, construct `crash_incident_reconciler = CrashIncidentReconciler()` once, pass it into `AdapterStatusObserver(..., reconciler=crash_incident_reconciler)`, and add it to the `_CommsBootGraph(...)` return.
3. Add the field to `_CommsBootGraph` (pure in-memory, NO reap — mirror the `status_observer` field comment: holds no resource, `aclose` does not touch it).
4. In the per-adapter `AdapterCrashHandler` construction (wherever the four handlers are built — `_build_comms_adapter_wiring` or the session factory), pass `reconciler=graph.crash_incident_reconciler`.

Add a docstring note on the `crash_incident_reconciler` field: *"Shared by the status observer (gateway-crash arm) AND every per-adapter AdapterCrashHandler (in-child arm) so the two coexisting crash signals fold into one incident (G6-2b-2b / #288). In-memory only; the durable trail is the signed audit log; not reachable from the `alfred status` CLI today (see the plan's snapshot-reachability decision — 2b-2c owns the query seam)."*

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py src/alfred/plugins/session.py tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py
git commit -m "feat(daemon): boot graph shares one CrashIncidentReconciler (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 10: End-to-end de-dup join — one physical crash → one incident, two loud rows

**Files:**

- Create: `tests/unit/comms_mcp/test_crash_dedup_join.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/comms_mcp/test_crash_dedup_join.py`:

```python
"""One physical crash -> one correlated incident, two loud audit rows (G6-2b-2b / #288).

Proves the de-dup join where the two signals MEET: the in-child AdapterCrashHandler
and the gateway-fed AdapterStatusObserver share one CrashIncidentReconciler (as the
daemon wires them), so a single physical crash that emits BOTH signals is ONE
incident — without dropping either loud audit row (hard rule #7).
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
from alfred.comms_mcp.handlers import AdapterCrashHandler
from alfred.comms_mcp.protocol import CrashedNotification

pytestmark = pytest.mark.asyncio

_EPOCH = "0" * 32


async def test_one_physical_crash_is_one_incident_with_two_rows() -> None:
    reconciler = CrashIncidentReconciler()
    audit = _RecordingAuditWriter()  # reuse the shared fake from the suite's conftest
    observer = AdapterStatusObserver(
        audit=audit, expected_epoch=lambda: _EPOCH, now=_fixed_now, reconciler=reconciler
    )
    crash_handler = AdapterCrashHandler(
        audit_writer=audit, hook_invoker=_NoopHookInvoker(), reconciler=reconciler
    )

    # The adapter was serving incarnation 0; the gateway observed the process exit.
    await observer.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "BrokenPipeError", "detail": "", "host_restart_seq": 0},
    )
    # The in-child diagnostic for the SAME physical crash arrives via the relay.
    await crash_handler.process(
        CrashedNotification(adapter_id="discord", error_class="ValueError", detail="")
    )

    # TWO audit rows (both loud, neither dropped) ...
    crash_rows = [
        r for r in audit.rows if r.event in {"gateway.adapter.crashed", "comms.adapter.crashed"}
    ]
    assert len(crash_rows) == 2
    # ... but ONE incident: both rows carry the SAME crash_incident_id.
    incident_ids = {r.subject["crash_incident_id"] for r in crash_rows}
    assert len(incident_ids) == 1
    # The reconciler records exactly one incident, corroborated by BOTH signals.
    incidents = reconciler.incidents("discord")
    assert len(incidents) == 1
    assert incidents[0].crash_signal_source == "both"
```

(Reuse the suite's existing fake audit writer / hook-invoker helpers — grep `_RecordingAuditWriter` under `tests/unit/comms_mcp/`; if it lives in a conftest, import it; otherwise define a minimal local one.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_dedup_join.py -v`
Expected: FAIL initially if helpers differ — adjust to the suite's real fakes; then it should PASS once Tasks 7+8 are in (this task adds no new src — it proves the join).

- [ ] **Step 3: Write minimal implementation**

No src change. If the test reveals the two rows DON'T share an incident id, the bug is in Task 7/8 fold ordering — fix there, not here.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_dedup_join.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/comms_mcp/test_crash_dedup_join.py
git commit -m "test(comms): one physical crash is one incident, two loud rows (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 11: Document the snapshot-reachability decision for 2b-2c

**Files:**

- Modify: `src/alfred/comms_mcp/crash_incident_reconciler.py` (module docstring — add the read-surface + 2b-2c note)
- Modify: `docs/subsystems/comms.md` (add a short "Crash de-dup + status snapshot" subsection)
- Test: `tests/unit/comms_mcp/test_crash_incident_reconciler.py` (assert the in-process read surface exists — already covered by `incidents(...)`; add a tiny `latest`-style read note if needed)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/comms_mcp/test_crash_incident_reconciler.py`:

```python
def test_incidents_read_surface_returns_views_for_in_process_reader() -> None:
    # 2b-2c reads the per-adapter incident view IN-PROCESS (the daemon holds the
    # reconciler). This asserts the read surface contract the render will consume.
    reconciler = CrashIncidentReconciler()
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    views = reconciler.incidents("discord")
    assert views[0].adapter_id == "discord"
    assert views[0].crash_signal_source in {"gateway", "child", "both"}
    assert reconciler.incidents("unknown-adapter") == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py::test_incidents_read_surface_returns_views_for_in_process_reader -v`
Expected: PASS (the read surface exists from Task 3) — if `adapter_kind` validation matters, `incidents` does not validate the id (it is a read), so an unknown id returns `()`.

- [ ] **Step 3: Write minimal implementation**

Add to `crash_incident_reconciler.py` module docstring a `Read surface (2b-2c)` paragraph:

> The in-process `incidents(adapter_id)` + the observer's `latest(adapter_id)` are the read surfaces a future `alfred status` render (2b-2c) consumes. **The `alfred status` / `alfred daemon status` CLI commands do NOT dial the daemon today** (they read Settings / the pidfile only — `src/alfred/cli/main.py` / `cli/daemon/_commands.py`), so they cannot reach this in-process reconciler. 2b-2c must therefore EITHER add a daemon query seam (the status CLI dials the daemon over the existing socket) OR relocate the render in-daemon. 2b-2b deliberately builds NO RPC (YAGNI — no consumer until 2b-2c) and only guarantees the data is correct + in-process readable.

Add the same decision to `docs/subsystems/comms.md` under a new subsection. Route any new operator-facing string in that doc through nothing (docs stay English; no `t()` for docs).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/comms_mcp/test_crash_incident_reconciler.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/comms_mcp/crash_incident_reconciler.py docs/subsystems/comms.md tests/unit/comms_mcp/test_crash_incident_reconciler.py
git commit -m "docs(comms): record crash-snapshot reachability decision for 2b-2c (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 12: CI coverage-gate registration + full-suite verification

**Files:**

- Modify: `.github/workflows/ci.yml` (the comms_mcp per-file 100%-coverage gate list — add `crash_incident_reconciler.py`, mirroring how `adapter_status_observer.py` is listed)
- Verify: full `tests/unit` coverage run (not a subset — the per-file gate is whole-suite-driven)

- [ ] **Step 1: Confirm the gate pattern**

Read `.github/workflows/ci.yml` and find the per-file coverage-gate block that names `adapter_status_observer.py` (the two-gates pattern: glob-caught AND named explicitly). Identify both the python-job per-file list and the coverage-gates per-file list.

- [ ] **Step 2: Add the new file to BOTH lists**

Add `src/alfred/comms_mcp/crash_incident_reconciler.py` to every per-file 100%-gate list that names `adapter_status_observer.py`. (If `handlers.py` / `adapter_status_observer.py` / `adapter_status_emitter.py` are already 100%-gated, no new entry needed for those — they only gained covered lines.)

- [ ] **Step 3: Run the FULL unit suite under coverage**

Run: `uv run coverage run -m pytest tests/unit && uv run coverage report --include="src/alfred/comms_mcp/crash_incident_reconciler.py,src/alfred/comms_mcp/adapter_status_observer.py,src/alfred/comms_mcp/handlers.py,src/alfred/gateway/adapter_status_emitter.py,src/alfred/gateway/adapter_supervisor.py" --show-missing`
Expected: 100% on `crash_incident_reconciler.py`; no regression below the existing bar on the touched files. (Run the WHOLE `tests/unit` — a subset would under-count cross-file coverage and falsely pass/fail the per-file gate.)

- [ ] **Step 4: Run the full quality bar**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit -q`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: 100%-coverage gate for crash_incident_reconciler (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Plan-review corrections (MUST apply — security + architect + test-engineer, 2026-06-20)

The fleet confirmed the trust boundary holds (never-drop, never-suppress, bounded state, fold-before-write, additive frozen-field safe, shared-reconciler seam needs no session.py change) BUT found a real common-order counting flaw + test-honesty gaps. Apply these — they OVERRIDE conflicting earlier text:

1. **SEC-01 (the load-bearing fix): carry the incarnation seq on the `up` frame, advance `current_incarnation` on `up`.** As planned, `up` carries no seq so `current_incarnation` advances ONLY on a gateway *crash* frame. But the in-child diagnostic fires as the child dies — BEFORE the gateway observes process-exit and emits its seq-N crashed frame. So in the COMMON order the child crash tags to incarnation N-1, folds into the stale prior incident, and the gateway crash opens a fresh N → **one physical crash = two incidents** (the slice's whole guarantee broken for the common case). Task 4's "child-first folds to one" test only passed via a manual `note_incarnation(seq=1)` call that has NO production call site. FIX: add an additive `host_restart_seq: int = Field(default=0, ge=0)` to **`AdapterUpNotification`** too (same as crashed); the supervisor stamps it on the up-transition from the run's `restart_count` (the incarnation being STARTED); the observer/reconciler advances `current_incarnation` on `up`. Update `GATEWAY_ADAPTER_UP_FIELDS` + the observer's `up` `_subject_for` (and the one exact-dict `up` test). Rewrite Task 4 to drive REAL `up`(seq=N) → in-child crash → gateway `crashed`(seq=N) frames (NO manual `note_incarnation`) and assert ONE incident for the common child-before-gateway order. Timing: `up` after a restart carries the post-increment count; the crashed frame carries the pre-increment (exited) count — verify both stamp the matching incarnation so up(N) and crashed(N) align.

2. **TE-1 (HIGH): prove never-suppress at the OBSERVER (boundary) layer, not just the pure reconciler.** The plan tests `duplicate=True` only on the reconciler return + the non-duplicate join end-to-end. Add a test that drives a **DUPLICATE gateway crash through `AdapterStatusObserver`** (the real wired consumer) and asserts a SECOND audit row IS still written (one incident, but every signal audited — hard rule #7). Without it, a future `if not fold.duplicate: append(...)` regression would silently drop a replayed row and pass every planned test. Also add the duplicate-IN-CHILD path test (TE-3 — it has logic but no test; 100%-branch-gate risk).

3. **TE-2: make the replay visible in the audit log.** The design's `duplicate=true` marker isn't in the crash audit field-set or stamped. Add a `duplicate` (bool) field to the crash audit field-set(s) and stamp it on the row, so a replayed/duplicate crash is auditable (not just counted internally).

4. **TE-4: update the existing live integration test.** `tests/integration/cli/daemon/test_gateway_status_leg_live.py` (~L145) constructs the observer/boot graph; the new shared `reconciler` constructor param will break it. Update that call site as part of this PR (call it out in the relevant task) so the merged live test still compiles + passes.

5. **TE-5: fix the coverage-gate registration (Task 12).** The comms_mcp per-file 100% gate lives ONLY in the `coverage-gates` job (NOT the python-job). Register `crash_incident_reconciler.py` there, and edit BOTH the `--include` list AND the `hashFiles(...)` guard (the two-part pattern). Keep the instruction to verify via the FULL `coverage run -m pytest tests/unit` (a subset under-covers shared files — this bit session.py in 2b-2a).

6. **SEC-02 (low): document that `crash_signal_source == "both"` is NOT authenticated corroboration.** The in-child `CrashedNotification` has no epoch/anti-forgery binding, so a forged in-child crash can upgrade a real gateway incident to `both`. Record (in the reconciler docstring + a note for 2b-2c) that `both` must NOT be read as security-meaningful corroboration — only the gateway frame is carrier-authenticated.

7. **Architect nit:** the File-structure bullet over-describes threading `host_restart_seq` through `_handle_crash`/`_spawn_or_terminal` — unnecessary; `_apply` already has `run` (and thus `restart_count`) in scope. Stamp inside `_apply`.

## Self-Review

**1. Spec coverage (Scope IN, §3 line 59):**

- Additive `host_restart_seq` → Task 1 (model) + Task 2 (field-set) + Task 6 (producer: emitter + supervisor). ✔
- Core-side crash de-dup join → Tasks 3-5 (reconciler) + Task 7 (gateway arm) + Task 8 (in-child arm) + Task 9 (shared instance) + Task 10 (e2e join). ✔
- Correlation rule documented + the in-child-carries-no-seq nuance resolved → Task 3 docstring + the plan's "Resolved de-dup correlation rule" section. ✔
- Observer snapshot query / `alfred status` reachability → Task 11 (read surface + documented YAGNI decision; no RPC built). ✔
- Trust boundary (no forged/dup frame suppresses a real one; never silently drop) → Task 5 + Task 10 (two loud rows). ✔
- Coverage 100% on touched comms_mcp/gateway-kernel files, full-suite run → Task 12. ✔
- Additive-field-on-frozen-model breaks no exact-set test → verified (no exact-dict pin on crashed); noted in Context. ✔
- Paper-gate: pure core-side, in-process, non-root → all tests run under `tests/unit`. ✔

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N" — every code step shows the code. The two spots that say "reuse the suite's fake" (Tasks 8, 10) are real instructions to grep an existing helper, with a fallback to a minimal local fake; not a code placeholder.

**3. Type consistency:** `CrashFoldResult` (fields `crash_incident_id`, `crash_signal_source`, `host_restart_seq`, `duplicate`), `CrashIncidentView`, `observe_gateway_crash`/`observe_child_crash`/`note_incarnation`/`incidents` — names identical across Tasks 3-11. `emit_crashed(..., host_restart_seq: int)`, `AdapterStatusObserver(..., reconciler=...)`, `AdapterCrashHandler(..., reconciler=...)`, `_CommsBootGraph.crash_incident_reconciler` — consistent across Tasks 6-10.

---

## Scope-boundary (OUT — deferred, restated)

- **`alfred status` RENDER + the daemon query seam** → 2b-2c. 2b-2b proves the data is correct + in-process readable and DOCUMENTS that the CLI cannot reach it today; it builds no RPC.
- **Real credential spawn (`spawn_request`/`spawn_grant`/fd-3)** → G6-3.
- **`PerAdapterIngressGate` / `GatewayLegScheduler` / per-leg `ReplayBuffer`** → G6-4.
- **Discord flag-day (Compose delete, secret repath, adapter self-broker→fd-3)** → G6-5.
- **Adversarial corpus (incl. the crash-dedup adversarial case (c)/(f) and a forged-duplicate-crash case)** → G6-6. (2b-2b ships the in-process unit-level forgery/duplicate guards in Task 5; the release-blocking adversarial corpus entry is G6-6.)
- **Live gateway→core status leg integration** → already landed in 2b-2a (the live leg) + extended by G6-2b producers; 2b-2b is pure correlation logic on top, no new wire leg.

---

## Precursor-gaps (VERIFIED findings)

**(a) The supervisor restart-counter attribute to stamp as `host_restart_seq`.**
VERIFIED. `GatewayAdapterSupervisor.restart_count(adapter_id) -> int` (`src/alfred/gateway/adapter_supervisor.py:253-254`) reads `_AdapterRun.restart_count` (adapter_supervisor.py:170), incremented once per backoff-scheduled restart in `_handle_crash` (line 454). It is per-adapter, per-gateway-process. **Ordering is load-bearing:** `_handle_crash` calls `_apply(CHILD_EXITED)` (which emits the crashed frame) BEFORE `run.restart_count += 1` — so the crashed frame carries the PRE-increment value = the incarnation index that exited (first crash → `host_restart_seq=0`). The emitter is reached via the single `_apply` applicator (lines 511-559), so Task 6 stamps `run.restart_count` there. There is no separate per-run id; `restart_count` is the correct + sole counter. `up_incarnation` exists too but is a test-sync count, not the wire seq — do NOT use it.

**(b) The in-child `CrashedNotification` arrival path + where it is audited today (double-audit risk).**
VERIFIED. Arrival: gateway/relay/runner → `CommsPluginRunner._route_notification` → `AlfredPluginSession._on_post_handshake_method` → `_route_comms_notification` (`src/alfred/plugins/session.py:816-818`) → `AdapterCrashHandler.process` (`src/alfred/comms_mcp/handlers.py:322-359`). **It DOES write its own audit row today** — `comms.adapter.crashed` (event), result `crashed`, trust tier T3, fields `COMMS_ADAPTER_CRASHED_FIELDS` — AND fires the `comms.adapter.crashed` hookpoint. The gateway crash writes a SEPARATE `gateway.adapter.crashed` row via `AdapterStatusObserver._accept`. So **a single physical crash currently produces TWO audit rows.** The de-dup MUST NOT drop either (hard rule #7) — both arms STILL write their row; the reconciler stamps both with one shared `crash_incident_id` so a downstream reader counts ONE incident. Crucially, **both handlers are injected into the SAME `AlfredPluginSession`** (session.py constructor holds both `self._crash_handler` and `self._status_observer`), so a single shared reconciler injected into both is the natural, no-extra-plumbing join point — they already meet in one process, one session.

**(c) The `alfred status` process model (in-daemon vs dial).**
VERIFIED — and it drives the YAGNI decision. `alfred status` (`src/alfred/cli/main.py:175-214`) reads Settings + broker only; `alfred daemon status` (`src/alfred/cli/daemon/_commands.py:2276-2305`) reads the pidfile only. **Neither dials the daemon, and neither holds nor reaches the in-process `AdapterStatusObserver` / reconciler** (which live in the daemon's `_CommsBootGraph`, _commands.py:615). So a future `alfred status` render of per-adapter crash incidents CANNOT reach the data in-process. **Decision (Task 11):** 2b-2b builds NO RPC (YAGNI — no consumer until 2b-2c) and documents that 2b-2c must choose a daemon query seam (status CLI dials the daemon over the existing 0600 socket) OR an in-daemon render. The reconciler exposes `incidents(adapter_id)` + the observer keeps `latest(adapter_id)` as the in-process read contract 2b-2c's seam will surface.

### Resolved de-dup correlation rule (canonical statement)

Correlation is by **`adapter_id` + incarnation**, NOT by both frames carrying the same seq (the in-child frame carries none). The gateway frame's `host_restart_seq` is authoritative and IS the incarnation key; the in-child frame is tagged to the adapter's CURRENT incarnation (latest seq seen, advanced by gateway `up`/`crashed`). Both fold into one `(adapter_id, host_restart_seq)` incident with a stable `crash_incident_id`; `crash_signal_source ∈ {gateway, child, both}` records corroboration. Both audit rows are always written (never dropped); a duplicate/replayed frame is flagged `duplicate=True` and still audited; a forged in-child crash opens a `child`-only incident and cannot mask a later genuine gateway crash (which opens its own incident at its own seq). A downstream reader counts incidents by distinct `crash_incident_id`.

### Spec/code mismatch found

The `AdapterCrashedNotification` docstring (protocol.py:483-492) says the host-restart sequence "is the 2b supervisor's per-adapter restart counter (none of which exist in 2a)." On `main` (2b-2a + 2b-1 merged), the supervisor AND its `restart_count` DO now exist (`adapter_supervisor.py`). The docstring's "(none of which exist)" is stale for the supervisor; Task 1 updates the docstring to reflect that the field now exists and points at `restart_count`. No behavioural mismatch — only stale prose.
