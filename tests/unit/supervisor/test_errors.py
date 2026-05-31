"""Supervisor error hierarchy — PR-S3-3b Task 1 (spec §10, ADR-0017 Decision 6).

The supervisor module owns two of its own errors and re-exports
:class:`QuarantinedUnavailable` from :mod:`alfred.plugins.errors`. ADR-0017
Decision 6 resolves the spec §5.5 vs §10.1 contradiction in favour of the
plugins location for the *definition*; the supervisor surface re-exports for
ergonomic import (orchestrator catches the same name regardless of where it's
imported from).

Pinned invariants:

* ``SupervisorError`` is a direct subclass of :class:`AlfredError` so the CLI
  top-level dispatch catches the whole family uniformly.
* ``BreakStateError`` is a ``SupervisorError`` — invalid state transitions on
  :class:`CircuitBreaker` raise this, not a bare :class:`ValueError`.
* ``QuarantinedUnavailable`` imported from ``alfred.supervisor.errors`` IS the
  same class object as the one imported from ``alfred.plugins.errors``
  (re-export, not re-declaration). A redefinition would silently break
  ``except`` arms in the orchestrator.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.plugins.errors import (
    QuarantinedUnavailable as PluginsQuarantinedUnavailable,
)
from alfred.supervisor.errors import (
    BreakStateError,
    QuarantinedUnavailable,
    SupervisorError,
)

# ---------------------------------------------------------------------------
# Root identity — every supervisor error must descend from AlfredError so the
# CLI top-level dispatch and orchestrator catch arms catch them uniformly.
# ---------------------------------------------------------------------------


def test_supervisor_error_is_alfred_error() -> None:
    """SupervisorError is the root of the supervisor-domain hierarchy."""
    assert issubclass(SupervisorError, AlfredError)


def test_break_state_error_is_supervisor_error() -> None:
    """BreakStateError descends from SupervisorError.

    Invalid state-machine transitions (e.g. CLOSED → HALF_OPEN without going
    through OPEN) raise this rather than a bare ValueError so callers can
    distinguish them from arbitrary programmer errors.
    """
    assert issubclass(BreakStateError, SupervisorError)


# ---------------------------------------------------------------------------
# QuarantinedUnavailable re-export — same class object, not a new subclass.
# ADR-0017 Decision 6: definition lives in plugins/errors.py; supervisor
# re-exports for ergonomic import.
# ---------------------------------------------------------------------------


def test_quarantined_unavailable_is_re_export() -> None:
    """``alfred.supervisor.errors.QuarantinedUnavailable`` is the same object.

    A re-export, not a re-declaration. If a future refactor accidentally
    introduces ``class QuarantinedUnavailable(SupervisorError): ...`` in the
    supervisor module, every ``except QuarantinedUnavailable`` arm that
    catches the plugins-side raise would silently stop catching it — and
    vice-versa. The identity check pins the contract.
    """
    assert QuarantinedUnavailable is PluginsQuarantinedUnavailable


def test_quarantined_unavailable_carries_reason() -> None:
    """The re-exported QuarantinedUnavailable preserves the plugins-side ctor.

    Spec §5.6 requires the ``reason`` attribute on the exception so the
    audit-log writer can carry a forensic label (closed vocabulary string,
    never T3 content) into the row. The re-export must not mask this.
    """
    exc = QuarantinedUnavailable(reason="subprocess_exited")
    assert exc.reason == "subprocess_exited"
    assert "subprocess_exited" in str(exc)


# ---------------------------------------------------------------------------
# Raise/catch — confirm a SupervisorError leaf is catchable as AlfredError
# at the CLI top level.
# ---------------------------------------------------------------------------


def test_break_state_error_caught_as_alfred_error() -> None:
    """A BreakStateError is catchable as AlfredError at the CLI top level."""
    try:
        raise BreakStateError("invalid transition")
    except AlfredError as exc:
        assert isinstance(exc, BreakStateError)
        assert "invalid transition" in str(exc)
    else:  # pragma: no cover - defensive
        msg = "BreakStateError did not propagate as AlfredError"
        raise AssertionError(msg)
