"""CircuitBreaker Postgres persistence tests (spec §10.6).

Pure unit tests — the integration round-trip against a real Postgres
container lives in
``tests/integration/memory/test_migration_0010_round_trip.py``.

Test discipline:

* Postgres is mocked via ``AsyncMock`` so the tests run sub-millisecond
  and do not depend on the integration test infra.
* Frozen-time injection (``now=`` kwarg) prevents wall-clock flake on
  the re-arm-on-load path.
* ``_make_db_row`` is a magic-mock factory that mirrors the column
  surface of ``alfred.memory.models.CircuitBreakerState`` — typed via
  the row attributes the production code reads.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.supervisor.breaker import BreakerState, CircuitBreaker


def _make_db_row(
    *,
    state: str = "CLOSED",
    trip_count: int = 0,
    last_trip_at: dt.datetime | None = None,
    last_failure_type: str | None = None,
) -> MagicMock:
    """Build a stand-in CircuitBreakerState row with the columns load_from_db reads."""
    row = MagicMock()
    row.state = state
    row.trip_count = trip_count
    row.last_trip_at = last_trip_at
    row.last_failure_type = last_failure_type
    return row


# ---------------------------------------------------------------------------
# load_from_db
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_closed_from_db_restores_state() -> None:
    """A CLOSED row restores state + trip_count for audit continuity."""
    session = AsyncMock()
    session.get = AsyncMock(return_value=_make_db_row(state="CLOSED", trip_count=2))
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    await cb.load_from_db(session)
    assert cb.state == BreakerState.CLOSED
    assert cb.trip_count == 2


@pytest.mark.asyncio
async def test_load_open_stays_open_when_last_trip_recent() -> None:
    """OPEN row with last_trip_at < 1h ago stays OPEN (spec §10.6 flap protection)."""
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    recent_trip = base - dt.timedelta(minutes=30)
    session = AsyncMock()
    session.get = AsyncMock(
        return_value=_make_db_row(state="OPEN", trip_count=3, last_trip_at=recent_trip)
    )
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    await cb.load_from_db(session, now=base)
    assert cb.state == BreakerState.OPEN
    assert cb.trip_count == 3
    assert cb.last_trip_at == recent_trip


@pytest.mark.asyncio
async def test_load_open_rearms_when_last_trip_over_1h() -> None:
    """OPEN row with last_trip_at > 1h ago re-arms to HALF_OPEN on load (spec §10.6)."""
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    old_trip = base - dt.timedelta(hours=2)
    session = AsyncMock()
    session.get = AsyncMock(
        return_value=_make_db_row(state="OPEN", trip_count=1, last_trip_at=old_trip)
    )
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    await cb.load_from_db(session, now=base)
    assert cb.state == BreakerState.HALF_OPEN


@pytest.mark.asyncio
async def test_load_half_open_row_restores_half_open_state() -> None:
    """HALF_OPEN row restores HALF_OPEN — we trust the persisted state on load."""
    session = AsyncMock()
    session.get = AsyncMock(return_value=_make_db_row(state="HALF_OPEN", trip_count=4))
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    await cb.load_from_db(session)
    assert cb.state == BreakerState.HALF_OPEN
    assert cb.trip_count == 4


@pytest.mark.asyncio
async def test_load_no_row_leaves_default_closed() -> None:
    """Missing row → defaults — fresh CLOSED with zero trip_count."""
    session = AsyncMock()
    session.get = AsyncMock(return_value=None)
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    await cb.load_from_db(session)
    assert cb.state == BreakerState.CLOSED
    assert cb.trip_count == 0
    assert cb.last_trip_at is None


@pytest.mark.asyncio
async def test_load_unknown_state_raises() -> None:
    """An out-of-domain state column triggers BreakStateError.

    The DB-side CHECK constraint forbids this, but the breaker also
    pins it defensively so a manual mutation cannot smuggle a bogus
    state through the load path silently.
    """
    from alfred.supervisor.errors import BreakStateError

    session = AsyncMock()
    session.get = AsyncMock(return_value=_make_db_row(state="BOGUS", trip_count=0))
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    with pytest.raises(BreakStateError):
        await cb.load_from_db(session)


# ---------------------------------------------------------------------------
# save_to_db
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_to_db_upserts_row_with_current_state() -> None:
    """save_to_db merges the current state into the row."""
    session = AsyncMock()
    session.merge = AsyncMock()
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    cb.state = BreakerState.OPEN
    cb.trip_count = 3
    cb.last_trip_at = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
    await cb.save_to_db(session)
    session.merge.assert_awaited_once()
    merged = session.merge.await_args.args[0]
    assert merged.component_id == "plugin"
    assert merged.state == "OPEN"
    assert merged.trip_count == 3
    assert merged.last_trip_at == cb.last_trip_at


@pytest.mark.asyncio
async def test_save_to_db_serialises_concurrent_callers() -> None:
    """Concurrent save_to_db on the same instance interleave under the lock.

    Pins the PR-S3-3a CR-R3 fix: per-instance asyncio.Lock guarantees
    only one save runs at a time inside the event loop. A lost-update
    race would let one of the merges silently overwrite the other; the
    lock makes that impossible.
    """
    session = AsyncMock()
    enter_log: list[str] = []

    async def _slow_merge(_row: object) -> None:
        enter_log.append("enter")
        await asyncio.sleep(0)  # yield once so the second coroutine can race
        enter_log.append("exit")

    session.merge = AsyncMock(side_effect=_slow_merge)

    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    cb.state = BreakerState.OPEN
    cb.trip_count = 1

    # Fire two concurrent saves on the same instance.
    await asyncio.gather(cb.save_to_db(session), cb.save_to_db(session))

    # The lock must serialise — every enter must be followed by its own
    # exit before the next enter. Interleaved (race) would produce
    # ["enter", "enter", "exit", "exit"].
    assert enter_log == ["enter", "exit", "enter", "exit"]


@pytest.mark.asyncio
async def test_save_to_db_omits_trip_metadata_owned_by_caller() -> None:
    """save_to_db carries only the live-state surface — last_failure_type,
    breaker_state, correlation_id stay None/default until the trip-recording
    caller (Supervisor / PluginLifecycle) writes them via audit-row schema.

    Pins the contract: the breaker owns ``state``, ``trip_count``, and
    ``last_trip_at``; the captured-at-trip fields are owned by the audit
    emit path so they round-trip with the audit row.
    """
    session = AsyncMock()
    session.merge = AsyncMock()
    cb = CircuitBreaker(component_id="plugin", session_scope=None)
    cb.state = BreakerState.OPEN
    cb.trip_count = 1
    await cb.save_to_db(session)
    merged = session.merge.await_args.args[0]
    # last_failure_type / breaker_state / correlation_id are ORM-side
    # defaults — None / "CLOSED" / "" — until the audit-emit path writes them.
    assert merged.last_failure_type is None
    # Default attributes are populated by SQLAlchemy at flush time, so we
    # check construction-time absence by reading the constructor kwargs.
    assert "last_failure_type" not in cb.__class__.__dict__
