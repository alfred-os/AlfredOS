"""Daemon control-plane request/response models + the status.query builder (#288, ADR-0038).

**Introspection contract v1 (correction 23).** This module is the transport-agnostic,
long-lived asset: the method schema + frozen Pydantic request/response models a FUTURE
remote management plane (dashboards / ops) will front over an authenticated HTTP
transport (see ``docs/ARCHITECTURE.md`` D1 — the management-plane transport is an
explicitly DEFERRED decision). The LOCAL CLI fronts these over a 0600 unix socket TODAY.
There is NO transport coupling in the models — they are pure data — so the same contract
serves both. This slice builds ONLY the local unix-socket front; no remote/HTTP surface.

The CONTROL plane is request/response (vs the comms wire's notification pump): a CLI
sends one ``ControlRequest``, the daemon answers one ``ControlResponse``, the connection
closes. The ``status.query`` result is built LIVE from the in-process observer +
reconciler at query time — no snapshot, no staleness, no ``boot_id`` (the daemon that
answers the 0600 + ``SO_PEERCRED`` socket IS, by construction, the live daemon).

NO secret/T3 on the wire: the result carries only non-sensitive operational metadata
(adapter_id, state, occurred_at, current_incarnation, incident count + the latest
incident's seq/source/id). NO raw ``detail`` / ``error_class`` — those live only in the
signed audit log. The exact field set is locked by structural tests (#299 carry-forward),
and ``ControlResponse.error`` carries ONLY enumerated non-sensitive tokens (a method name
+ ``type(exc).__name__``), NEVER ``str(exc)`` (sec-MEDIUM-4).

SEC-02 carry-forward: ``crash_signal_source == "both"`` is a diagnostic-coverage hint,
NOT authenticated corroboration — rendered as informational origin only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

RenderedAdapterState = Literal["up", "down", "crashed", "breaker_open", "unknown"]
CrashSignalSource = Literal["gateway", "child", "both"]

CONTROL_PROTOCOL_VERSION: Final[str] = "AlfredDaemonControl/1"
STATUS_QUERY_METHOD: Final[str] = "status.query"

# The control request ``id`` echoes back on the response (correlation) and ``method``
# is reflected into the error token — both are peer-controlled, so bound them. These
# are generous for the closed-vocab values they carry; the frame-size bound is the
# DoS line, these are the reflection line (sec-MEDIUM-4).
_MAX_METHOD_LEN: Final[int] = 256
_MAX_REQUEST_ID_LEN: Final[int] = 128

# The sentinel id echoed when the request could not be parsed (its ``id`` is unknown)
# — named so the server + client agree on it (arch-M4).
UNKNOWN_REQUEST_ID: Final[str] = "?"


class ControlRequest(BaseModel):
    """One control-plane request frame (CLI -> daemon)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    version: str = Field(default=CONTROL_PROTOCOL_VERSION, min_length=1, max_length=64)
    id: str = Field(min_length=1, max_length=_MAX_REQUEST_ID_LEN)
    method: str = Field(min_length=1, max_length=_MAX_METHOD_LEN)
    params: dict[str, object] = Field(default_factory=dict)


class LatestCrashSummary(BaseModel):
    """The most recent crash incident for one adapter (non-sensitive metadata only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    host_restart_seq: int = Field(ge=0)
    crash_signal_source: CrashSignalSource
    crash_incident_id: str = Field(min_length=1)


class AdapterStatusLine(BaseModel):
    """The live per-adapter status line in a ``status.query`` result."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    adapter_id: str = Field(min_length=1)
    state: RenderedAdapterState
    occurred_at: str | None = None
    current_incarnation: int = Field(default=0, ge=0)
    crash_incident_count: int = Field(default=0, ge=0)
    latest_crash: LatestCrashSummary | None = None


class DaemonStatusResult(BaseModel):
    """The ``status.query`` result: the live per-adapter status map."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    adapters: dict[str, AdapterStatusLine] = Field(default_factory=dict)


class ControlResponse(BaseModel):
    """One control-plane response frame (daemon -> CLI).

    Exactly one of ``result`` / ``error`` is populated. ``error`` is a short
    closed-vocab token (``<reason>:<method>`` or ``<reason>:<exc-type-name>``) — NEVER
    ``str(exc)`` (no exception message ever reaches the wire — sec-MEDIUM-4).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(min_length=1, max_length=_MAX_REQUEST_ID_LEN)
    result: dict[str, object] | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _exactly_one_of_result_or_error(self) -> ControlResponse:
        """Enforce the documented XOR: exactly one of ``result`` / ``error`` is set.

        The model is the long-lived introspection contract a future remote management
        plane fronts (correction 23): a response that carries BOTH (an ambiguous
        success-and-error) or NEITHER (an empty non-answer) is malformed and must fail
        loud at construction, not silently slip onto the wire.
        """
        if (self.result is None) == (self.error is None):
            raise ValueError("ControlResponse requires exactly one of result / error")
        return self


def build_daemon_status_result(
    *, observer: AdapterStatusObserver, reconciler: CrashIncidentReconciler
) -> DaemonStatusResult:
    """Fold live observer state + reconciler incidents into the status result (pure, no secret).

    The full adapter set is the UNION of the observer's recorded snapshots and the
    reconciler's observed adapters — so an adapter that crashed before the observer
    recorded any snapshot still surfaces (as ``unknown``). The latest crash is the
    HIGHEST host_restart_seq incident (correction test-C1) — NOT insertion order — so
    an out-of-seq (stale) crash arrival cannot mislabel the latest incarnation.
    """
    latest = observer.all_latest()
    adapter_ids = sorted(set(latest) | set(reconciler.adapter_ids()))
    lines: dict[str, AdapterStatusLine] = {}
    for adapter_id in adapter_ids:
        snap = latest.get(adapter_id)
        incidents = reconciler.incidents(adapter_id)
        latest_crash: LatestCrashSummary | None = None
        if incidents:
            most_recent = max(incidents, key=lambda inc: inc.host_restart_seq)
            latest_crash = LatestCrashSummary(
                host_restart_seq=most_recent.host_restart_seq,
                crash_signal_source=most_recent.crash_signal_source,
                crash_incident_id=most_recent.crash_incident_id,
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


__all__ = [
    "CONTROL_PROTOCOL_VERSION",
    "STATUS_QUERY_METHOD",
    "UNKNOWN_REQUEST_ID",
    "AdapterStatusLine",
    "ControlRequest",
    "ControlResponse",
    "CrashSignalSource",
    "DaemonStatusResult",
    "LatestCrashSummary",
    "RenderedAdapterState",
    "build_daemon_status_result",
]
