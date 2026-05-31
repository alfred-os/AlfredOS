"""Supervisor error hierarchy (spec §10, ADR-0017 Decision 6).

The supervisor owns two errors directly and re-exports a third:

* :class:`SupervisorError` — root of the supervisor-domain hierarchy.
  Descends from :class:`alfred.errors.AlfredError` so the CLI top-level
  dispatch catches the whole family uniformly without swallowing unrelated
  exceptions.
* :class:`BreakStateError` — raised when a transition is invalid for the
  current :class:`alfred.supervisor.breaker.CircuitBreaker` state (e.g.
  attempting CLOSED→HALF_OPEN without going through OPEN). A typed subclass
  rather than ``ValueError`` so callers can distinguish state-machine
  protocol errors from arbitrary programmer mistakes.
* :class:`QuarantinedUnavailable` — re-exported from
  :mod:`alfred.plugins.errors`. ADR-0017 Decision 6 resolves the spec §5.5
  vs §10.1 contradiction in favour of the plugins location for the
  *definition*; the supervisor surface re-exports for ergonomic import so
  orchestrator and breaker code can write
  ``from alfred.supervisor.errors import QuarantinedUnavailable`` without
  crossing into the plugins namespace.

The re-export is the same class object (not a subclass) so ``except
QuarantinedUnavailable`` catches the plugins-side raise regardless of which
import path the catching code used. The unit test pins this with an
identity assertion.
"""

from __future__ import annotations

from alfred.errors import AlfredError

# ADR-0017 Decision 6: QuarantinedUnavailable is DEFINED in plugins/errors.py.
# Re-exported here so supervisor/orchestrator code can import it from the
# supervisor namespace — that's the import path spec §10 callers expect.
# Identity is pinned by tests/unit/supervisor/test_errors.py.
from alfred.plugins.errors import QuarantinedUnavailable


class SupervisorError(AlfredError):
    """Root for every supervisor-domain error.

    Descends from :class:`alfred.errors.AlfredError` so the CLI top-level
    dispatch catches the whole family uniformly without swallowing
    unrelated exceptions.
    """


class BreakStateError(SupervisorError):
    """A circuit-breaker state transition was invalid for the current state.

    Spec §10.2 fixes the three-state machine (CLOSED → OPEN → HALF_OPEN →
    CLOSED). Attempting an out-of-order transition (e.g. probe-success from
    CLOSED) raises this rather than a bare ``ValueError`` so callers can
    distinguish breaker-protocol errors from arbitrary programmer mistakes
    in a single ``except`` arm.
    """


__all__ = [
    "BreakStateError",
    "QuarantinedUnavailable",
    "SupervisorError",
]
