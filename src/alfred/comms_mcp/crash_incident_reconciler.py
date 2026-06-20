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
  SEC-01: the gateway ``up`` frame ADVANCES the current incarnation (via
  :meth:`note_incarnation`) so a child crash that fires as the child dies —
  BEFORE the gateway observes process-exit and emits its seq-bearing ``crashed``
  frame — is tagged to the run that was actually serving, not a stale prior one.
* Both fold into the SAME incident; ``crash_signal_source`` records which
  signal(s) corroborate it: ``gateway`` / ``child`` / ``both``.

TRUST BOUNDARY (Spec B §6 / hard rule #7): folding NEVER elides an audit row. A
duplicate gateway crash for an already-seen incarnation is marked
``duplicate=True`` but still audited (a replay is VISIBLE, not silently dropped);
a forged in-child crash opens a ``child``-only incident (still loud) and cannot
mask a later genuine gateway crash, which opens its own incident at its own seq.

SEC-02 (corroboration is NOT authenticated): ``crash_signal_source == "both"``
records only that two SIGNALS arrived for one incarnation — it is NOT a security
attestation. The in-child ``CrashedNotification`` has NO epoch / anti-forgery
binding (only the gateway frame is carrier-authenticated — the live leg's 0600 +
SO_PEERCRED + per-boot-epoch envelope), so a forged in-child crash can upgrade a
real gateway incident to ``both``. Downstream readers (2b-2c) MUST NOT treat
``both`` as security-meaningful corroboration — it is a diagnostic-coverage hint
only.

Read surface (2b-2c): the in-process :meth:`incidents` (per-adapter incident
views) + the observer's ``latest(adapter_id)`` snapshot are the read surfaces a
future ``alfred status`` render (2b-2c) consumes. **The ``alfred status`` /
``alfred daemon status`` CLI commands do NOT dial the daemon today** (they read
Settings / the pidfile only — ``src/alfred/cli/main.py`` /
``cli/daemon/_commands.py``), so they cannot reach this in-process reconciler.
2b-2c must therefore EITHER add a daemon query seam (the status CLI dials the
daemon over the existing 0600 socket) OR relocate the render in-daemon. 2b-2b
deliberately builds NO RPC (YAGNI — no consumer until 2b-2c) and only guarantees
the data is correct + in-process readable.

In-memory only (per gateway<->core link lifetime); the gateway is "stateless
beyond a small connection buffer" and the durable record is the signed audit log.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
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
        tagged to the run that was actually serving, not a stale one (SEC-01). It
        only ever ADVANCES (``max``) — a stale/lower seq cannot rewind the join.
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
