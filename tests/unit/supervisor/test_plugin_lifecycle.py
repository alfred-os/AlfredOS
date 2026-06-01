"""PluginLifecycle tests — start_plugin + on_crash (Task 10).

Spec §10 — plugin lifecycle coordination owns the audit-row emission
narrative around gate refusal and subprocess crash. The breaker's pure
state machine lives in :mod:`alfred.supervisor.breaker`; this module wires
the breaker transitions into the audit log via
:data:`alfred.audit.audit_row_schemas.PLUGIN_LIFECYCLE_*_FIELDS` schemas
and the dispatcher's typed ``append_schema`` API (PR-S3-0a cceafbd).

Test discipline:

* Pure unit tests — no DB, no subprocess. The ``MagicMock`` gate and
  ``AsyncMock`` audit writer keep the focus on the orchestrator's
  contract (which fields each event family carries, which result label
  each emit uses, which schema constant is named for the dispatcher's
  symmetric guard).
* Frozen time — the breaker takes ``now=`` per-call so the threshold
  crossing happens deterministically.
* Every event family has its own test: ``load_refused``, ``loaded``,
  ``crashed`` (breaker still CLOSED post-record), ``quarantined``
  (breaker tripped to OPEN on this call). Field-list assertions pin the
  shape against the typed schema constant.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit.audit_row_schemas import (
    PLUGIN_LIFECYCLE_CRASHED_FIELDS,
    PLUGIN_LIFECYCLE_FIELDS,
    PLUGIN_LIFECYCLE_QUARANTINED_FIELDS,
)
from alfred.supervisor.breaker import BreakerState, CircuitBreaker
from alfred.supervisor.plugin_lifecycle import PluginLifecycle


@pytest.fixture
def mock_gate() -> MagicMock:
    """A gate that permits everything by default — tests flip to False where needed."""
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    return gate


@pytest.fixture
def mock_audit() -> AsyncMock:
    """An async-mock audit writer; ``.append_schema`` records every emit."""
    audit = AsyncMock()
    audit.append_schema = AsyncMock()
    return audit


def _make_breaker(component_id: str = "test-plugin") -> CircuitBreaker:
    """Construct a CircuitBreaker for lifecycle tests — session_scope unused."""
    return CircuitBreaker(component_id=component_id, session_scope=None)


# ---------------------------------------------------------------------------
# start_plugin — gate-refused / loaded paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_plugin_gate_refused_emits_load_refused(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """Gate denial emits ``plugin.lifecycle.load_refused`` with the gate-refused subject."""
    mock_gate.check_plugin_load.return_value = False
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()

    result = await pl.start_plugin(
        plugin_id="test-plugin",
        manifest_tier="system",
        breaker=breaker,
        trace_id="trace-1",
    )

    assert result == "load_refused"
    assert mock_audit.append_schema.await_count == 1
    kwargs = mock_audit.append_schema.call_args.kwargs
    assert kwargs["event"] == "plugin.lifecycle.load_refused"
    assert kwargs["result"] == "load_refused"
    assert kwargs["schema_name"] == "PLUGIN_LIFECYCLE_FIELDS"
    assert kwargs["fields"] is PLUGIN_LIFECYCLE_FIELDS
    assert kwargs["actor_user_id"] == "system"
    assert kwargs["actor_persona"] == "supervisor"
    assert kwargs["trust_tier_of_trigger"] == "T0"
    assert kwargs["trace_id"] == "trace-1"
    # subject covers EVERY declared key — symmetric-guard contract
    assert set(kwargs["subject"].keys()) == PLUGIN_LIFECYCLE_FIELDS
    assert kwargs["subject"]["plugin_id"] == "test-plugin"
    assert kwargs["subject"]["manifest_subscriber_tier"] == "system"
    assert kwargs["subject"]["breaker_state"] == "CLOSED"


@pytest.mark.asyncio
async def test_start_plugin_gate_allowed_emits_loaded(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """Gate-approved load emits ``plugin.lifecycle.loaded`` with the same field shape."""
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()

    result = await pl.start_plugin(
        plugin_id="test-plugin",
        manifest_tier="user-plugin",
        breaker=breaker,
        trace_id="trace-2",
    )

    assert result == "loaded"
    assert mock_audit.append_schema.await_count == 1
    kwargs = mock_audit.append_schema.call_args.kwargs
    assert kwargs["event"] == "plugin.lifecycle.loaded"
    assert kwargs["result"] == "success"
    assert kwargs["schema_name"] == "PLUGIN_LIFECYCLE_FIELDS"
    assert kwargs["fields"] is PLUGIN_LIFECYCLE_FIELDS
    assert set(kwargs["subject"].keys()) == PLUGIN_LIFECYCLE_FIELDS
    assert kwargs["subject"]["manifest_subscriber_tier"] == "user-plugin"


@pytest.mark.asyncio
async def test_start_plugin_threads_correlation_id_into_subject(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """If a correlation_id is passed it threads onto the subject, else stays None."""
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()

    await pl.start_plugin(
        plugin_id="p1",
        manifest_tier="system",
        breaker=breaker,
        trace_id="trace-3",
        correlation_id="corr-9",
    )
    kwargs = mock_audit.append_schema.call_args.kwargs
    assert kwargs["subject"]["correlation_id"] == "corr-9"


# ---------------------------------------------------------------------------
# on_crash — breaker increment + crashed vs quarantined row family
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_crash_increments_breaker_and_trips_at_threshold(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """Three crashes in the window trip the breaker to OPEN (state-machine wiring)."""
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        await pl.on_crash(
            plugin_id="test-plugin",
            exception_type="SubprocessExitedError",
            exit_code=1,
            signal=None,
            restart_count=i,
            breaker=breaker,
            trace_id=f"trace-{i}",
            now=base + dt.timedelta(seconds=i * 60),
        )
    assert breaker.state == BreakerState.OPEN
    assert breaker.trip_count == 1


@pytest.mark.asyncio
async def test_on_crash_breaker_closed_emits_crashed_row(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """A first-time crash (breaker still CLOSED) emits the ``crashed`` row.

    Uses :data:`PLUGIN_LIFECYCLE_CRASHED_FIELDS` (adds ``exception_type``).
    ``result`` label is ``"crashed"`` per migration 0007.
    """
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)

    await pl.on_crash(
        plugin_id="p1",
        exception_type="SubprocessExitedError",
        exit_code=2,
        signal=None,
        restart_count=0,
        breaker=breaker,
        trace_id="trace-c1",
        now=base,
    )

    assert breaker.state == BreakerState.CLOSED
    kwargs = mock_audit.append_schema.call_args.kwargs
    assert kwargs["event"] == "plugin.lifecycle.crashed"
    assert kwargs["result"] == "crashed"
    assert kwargs["schema_name"] == "PLUGIN_LIFECYCLE_CRASHED_FIELDS"
    assert kwargs["fields"] is PLUGIN_LIFECYCLE_CRASHED_FIELDS
    assert set(kwargs["subject"].keys()) == PLUGIN_LIFECYCLE_CRASHED_FIELDS
    assert kwargs["subject"]["exception_type"] == "SubprocessExitedError"
    assert kwargs["subject"]["exit_code"] == 2
    assert kwargs["subject"]["breaker_state"] == "CLOSED"


@pytest.mark.asyncio
async def test_on_crash_breaker_opens_emits_quarantined_row(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """The threshold-crossing crash emits ``quarantined`` with the OPEN subject.

    Uses :data:`PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` (adds
    ``kill_succeeded``, ``quarantine_reason``, ``trip_count``).
    ``result`` label is ``"quarantined"`` per migration 0007.
    """
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        await pl.on_crash(
            plugin_id="p1",
            exception_type="SubprocessExitedError",
            exit_code=1,
            signal=None,
            restart_count=i,
            breaker=breaker,
            trace_id=f"trace-{i}",
            now=base + dt.timedelta(seconds=i),
        )
    # The last call is the threshold crossing — emit row #3
    kwargs = mock_audit.append_schema.call_args_list[-1].kwargs
    assert kwargs["event"] == "plugin.lifecycle.quarantined"
    assert kwargs["result"] == "quarantined"
    assert kwargs["schema_name"] == "PLUGIN_LIFECYCLE_QUARANTINED_FIELDS"
    assert kwargs["fields"] is PLUGIN_LIFECYCLE_QUARANTINED_FIELDS
    assert set(kwargs["subject"].keys()) == PLUGIN_LIFECYCLE_QUARANTINED_FIELDS
    assert kwargs["subject"]["breaker_state"] == "OPEN"
    assert kwargs["subject"]["quarantine_reason"] == "circuit_breaker_open"
    assert kwargs["subject"]["trip_count"] == 1
    assert kwargs["subject"]["kill_succeeded"] is True  # default


@pytest.mark.asyncio
async def test_on_crash_kill_succeeded_threads_into_quarantined_row(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """Caller-supplied ``kill_succeeded=False`` lands on the quarantined row.

    A future supervisor that called ``transport.kill()`` BEFORE on_crash and
    saw the kill miss (race / already-dead) passes ``False`` through so the
    audit row reflects the truth (spec §4.6 + CR-S3-3a fix).
    """
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        await pl.on_crash(
            plugin_id="p1",
            exception_type="SubprocessExitedError",
            exit_code=1,
            signal=None,
            restart_count=i,
            breaker=breaker,
            trace_id=f"trace-{i}",
            kill_succeeded=False,
            now=base + dt.timedelta(seconds=i),
        )
    kwargs = mock_audit.append_schema.call_args_list[-1].kwargs
    assert kwargs["subject"]["kill_succeeded"] is False


@pytest.mark.asyncio
async def test_on_crash_never_emits_raw_exception_string(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """``exception_type`` is the Python type name only — never ``str(exc)``.

    Spec §5.6: subprocess crash traces can carry T3 fragments. The
    PluginLifecycle contract is that callers pre-funnel via
    ``type(exc).__name__``; this test verifies the row faithfully carries
    whatever string the caller passed and nothing else (no error_message,
    no exc.args).
    """
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()

    await pl.on_crash(
        plugin_id="p1",
        exception_type="ValueError",
        exit_code=None,
        signal=None,
        restart_count=0,
        breaker=breaker,
        trace_id="t",
    )

    subject: dict[str, Any] = mock_audit.append_schema.call_args.kwargs["subject"]
    # exception_type carries the type name only
    assert subject["exception_type"] == "ValueError"
    # No fields that could carry str(exc) / exc.args leak in
    for forbidden in ("error_message", "exc_args", "exc_str", "message"):
        assert forbidden not in subject


@pytest.mark.asyncio
async def test_on_crash_default_now_uses_wall_clock(
    mock_gate: MagicMock, mock_audit: AsyncMock
) -> None:
    """Omitting ``now=`` falls through to ``record_failure``'s default.

    Pins the production-call shape — Supervisor's crash handler does not
    inject a fixed clock; the row records whatever ``datetime.now(UTC)``
    returns at the moment of the crash.
    """
    pl = PluginLifecycle(gate=mock_gate, audit=mock_audit)
    breaker = _make_breaker()
    await pl.on_crash(
        plugin_id="p1",
        exception_type="SubprocessExitedError",
        exit_code=1,
        signal=None,
        restart_count=0,
        breaker=breaker,
        trace_id="t",
    )
    # No assertion on the timestamp — wall-clock varies. The breaker did
    # accept the failure, that's the contract.
    assert mock_audit.append_schema.await_count == 1


# ---------------------------------------------------------------------------
# Protocol stub coverage — exercise the NotImplementedError bodies so the
# coverage gate (100% on this file) does not flag the stubs as dead.
# Mirrors the pattern in tests/unit/orchestrator/ for ``UserLike`` etc.
# ---------------------------------------------------------------------------


def test_gate_like_protocol_body_raises() -> None:
    """The Protocol stub body is exercised so coverage counts it."""
    from alfred.supervisor.plugin_lifecycle import _GateLike

    class _Stub(_GateLike):
        def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
            return _GateLike.check_plugin_load(
                self, plugin_id=plugin_id, manifest_tier=manifest_tier
            )

    with pytest.raises(NotImplementedError):
        _Stub().check_plugin_load(plugin_id="p", manifest_tier="system")


@pytest.mark.asyncio
async def test_audit_like_protocol_body_raises() -> None:
    """The Protocol stub body is exercised so coverage counts it."""
    from alfred.supervisor.plugin_lifecycle import _AuditLike

    class _Stub(_AuditLike):
        async def append_schema(
            self,
            *,
            fields: frozenset[str],
            schema_name: str,
            event: str,
            actor_user_id: str | None,
            subject: dict[str, object],
            trust_tier_of_trigger: str,
            result: str,
            cost_estimate_usd: float,
            trace_id: str,
            actor_persona: str = "alfred",
            persona_id: str | None = None,
            cost_actual_usd: float | None = None,
            language: str = "en-US",
        ) -> None:
            await _AuditLike.append_schema(
                self,
                fields=fields,
                schema_name=schema_name,
                event=event,
                actor_user_id=actor_user_id,
                subject=subject,
                trust_tier_of_trigger=trust_tier_of_trigger,
                result=result,
                cost_estimate_usd=cost_estimate_usd,
                trace_id=trace_id,
                actor_persona=actor_persona,
                persona_id=persona_id,
                cost_actual_usd=cost_actual_usd,
                language=language,
            )

    with pytest.raises(NotImplementedError):
        await _Stub().append_schema(
            fields=PLUGIN_LIFECYCLE_FIELDS,
            schema_name="PLUGIN_LIFECYCLE_FIELDS",
            event="x",
            actor_user_id=None,
            subject={},
            trust_tier_of_trigger="T0",
            result="success",
            cost_estimate_usd=0.0,
            trace_id="t",
        )
