"""Daemon control-plane request/response models + the status.query builder (#288, ADR-0038).

The protocol module is the "introspection contract v1" — transport-agnostic frozen
Pydantic models + a pure live builder. These tests lock:

* the EXACT field set of every wire model (correction sec-MEDIUM-4 / test-L4) — a new
  field is a deliberate wire change, never an accident;
* ``extra="forbid"`` is load-bearing on the request (a peer-smuggled top-level key is
  rejected) AND ``ControlResponse.error`` carries ONLY non-sensitive tokens;
* the builder folds live observer state + reconciler incidents WITHOUT ever leaking
  raw crash text;
* the ``state == "unknown"`` union branch (reconciler-only adapter) + the
  ``latest_crash is None`` branch (observer-only adapter);
* latest-crash = the HIGHEST-seq incident (correction test-C1), proven by an
  OUT-OF-SEQ arrival.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from alfred.cli.daemon._daemon_control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    STATUS_QUERY_METHOD,
    AdapterStatusLine,
    ControlRequest,
    ControlResponse,
    DaemonStatusResult,
    LatestCrashSummary,
    build_daemon_status_result,
)
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_NOW = datetime(2026, 6, 20, 9, 30, 0, tzinfo=UTC)


class _FakeAudit:
    async def append_schema(self, **_kwargs: object) -> None:  # pragma: no cover - unused here
        return None


def _observer(epoch: str = "e" * 32) -> tuple[AdapterStatusObserver, CrashIncidentReconciler]:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=_FakeAudit(),
        expected_epoch=lambda: epoch,
        now=lambda: _NOW,
        reconciler=reconciler,
    )
    return observer, reconciler


# --------------------------------------------------------------------------- #
# Wire-envelope field-set locks (correction sec-MEDIUM-4 / test-L4)            #
# --------------------------------------------------------------------------- #


def test_control_request_field_set_is_locked() -> None:
    assert set(ControlRequest.model_fields) == {"version", "id", "method", "params"}


def test_control_response_field_set_is_locked() -> None:
    assert set(ControlResponse.model_fields) == {"id", "result", "error"}


def test_adapter_status_line_field_set_is_locked() -> None:
    assert set(AdapterStatusLine.model_fields) == {
        "adapter_id",
        "state",
        "occurred_at",
        "current_incarnation",
        "crash_incident_count",
        "latest_crash",
    }


def test_latest_crash_summary_field_set_is_locked() -> None:
    assert set(LatestCrashSummary.model_fields) == {
        "host_restart_seq",
        "crash_signal_source",
        "crash_incident_id",
    }


def test_daemon_status_result_field_set_is_locked() -> None:
    assert set(DaemonStatusResult.model_fields) == {"adapters"}


def test_control_request_rejects_unexpected_top_level_key() -> None:
    # ``extra="forbid"`` is load-bearing: a peer must not smuggle an unmodelled key.
    with pytest.raises(ValidationError):
        ControlRequest.model_validate(
            {"version": CONTROL_PROTOCOL_VERSION, "id": "1", "method": "x", "spy": "y"}
        )


def test_control_request_bounds_method_and_id_length() -> None:
    # A peer-controlled ``method`` is reflected in the error response — bound it.
    with pytest.raises(ValidationError):
        ControlRequest(id="1", method="m" * 10_000)
    with pytest.raises(ValidationError):
        ControlRequest(id="i" * 10_000, method="status.query")


def test_control_response_error_carries_only_non_sensitive_tokens() -> None:
    # ``error`` is a short closed-vocab token (method name + exc TYPE name), never
    # ``str(exc)`` — assert the model accepts a bounded token and the field exists.
    resp = ControlResponse(id="1", error="unknown_method:status.query")
    assert resp.result is None
    assert resp.error == "unknown_method:status.query"


def test_control_response_rejects_both_result_and_error() -> None:
    # The documented XOR invariant: a response carrying BOTH a result and an error is an
    # ambiguous success-and-error — malformed, rejected at construction (T3 / CR Minor).
    with pytest.raises(ValidationError):
        ControlResponse(id="1", result={"adapters": {}}, error="handler_error:RuntimeError")


def test_control_response_rejects_neither_result_nor_error() -> None:
    # The other half of the XOR: a response carrying NEITHER is an empty non-answer.
    with pytest.raises(ValidationError):
        ControlResponse(id="1")


# --------------------------------------------------------------------------- #
# build_daemon_status_result — the live fold                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_builder_folds_up_adapter_with_no_crash() -> None:
    observer, reconciler = _observer()
    await observer.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": "e" * 32})

    result = build_daemon_status_result(observer=observer, reconciler=reconciler)
    line = result.adapters["discord"]
    assert line.state == "up"
    assert line.occurred_at == _NOW.isoformat()
    assert line.crash_incident_count == 0
    assert line.latest_crash is None  # the no-incident branch


@pytest.mark.asyncio
async def test_builder_marks_reconciler_only_adapter_unknown() -> None:
    # An adapter the reconciler has seen (a crash) but the observer has NOT recorded a
    # snapshot for renders as ``unknown`` (the union branch).
    _observer_unused, reconciler = _observer()
    reconciler.observe_gateway_crash(adapter_id="tui", host_restart_seq=0)
    observer, _ = _observer()  # an observer with NO tui snapshot

    result = build_daemon_status_result(observer=observer, reconciler=reconciler)
    line = result.adapters["tui"]
    assert line.state == "unknown"
    assert line.occurred_at is None
    assert line.crash_incident_count == 1
    assert line.latest_crash is not None


@pytest.mark.asyncio
async def test_builder_never_leaks_raw_crash_text() -> None:
    observer, reconciler = _observer()
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "boom token=sk-supersecret",
            "host_restart_seq": 0,
        },
    )
    result = build_daemon_status_result(observer=observer, reconciler=reconciler)
    blob = result.model_dump_json()
    assert "boom" not in blob
    assert "RuntimeError" not in blob
    assert "sk-supersecret" not in blob


def test_builder_latest_crash_is_highest_seq_on_out_of_seq_arrival() -> None:
    # correction test-C1: pin "latest crash" = the HIGHEST host_restart_seq incident,
    # NOT insertion order. Feed an OUT-OF-SEQ arrival (high seq, THEN a stale low seq)
    # so insertion-order (incidents[-1]) would pick the WRONG (lower) one.
    observer, reconciler = _observer()
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=5)
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=2)  # stale, later

    result = build_daemon_status_result(observer=observer, reconciler=reconciler)
    line = result.adapters["discord"]
    assert line.crash_incident_count == 2
    assert line.latest_crash is not None
    assert line.latest_crash.host_restart_seq == 5  # highest seq wins, not last-inserted


def test_builder_empty_when_nothing_observed() -> None:
    observer, reconciler = _observer()
    result = build_daemon_status_result(observer=observer, reconciler=reconciler)
    assert result.adapters == {}


def test_status_query_method_constant_is_stable() -> None:
    assert STATUS_QUERY_METHOD == "status.query"
