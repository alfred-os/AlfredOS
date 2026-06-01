"""CircuitBreaker state-machine tests (spec §10.2).

Pins the three-state machine on a pure in-memory CircuitBreaker — DB
persistence is exercised separately in
``tests/unit/supervisor/test_persisted_state_restore.py``.

Test discipline:

* Pure unit tests — no DB, no clock. All transitions take an injected
  ``now=`` so we never sleep.
* Frozen-time pattern: a fixed ``base`` datetime and ``timedelta`` offsets
  describe every event. Wall-clock flake is impossible by construction.
* ``_make_cb`` injects an ``AsyncMock`` session_scope so save_to_db calls
  later (Task 8) do not need real DB plumbing in this file.
"""

from __future__ import annotations

from alfred.supervisor.breaker import BreakerState, CircuitBreaker


def test_initial_state_is_closed() -> None:
    """A fresh breaker starts CLOSED with zero trip count (spec §10.2)."""
    cb = CircuitBreaker(component_id="test-plugin", session_scope=None)
    assert cb.state == BreakerState.CLOSED
    assert cb.trip_count == 0
    assert cb.last_trip_at is None


def test_breaker_state_enum_values() -> None:
    """Exactly three states — closed domain pinned by DB CHECK constraint."""
    assert {s.value for s in BreakerState} == {"CLOSED", "OPEN", "HALF_OPEN"}
