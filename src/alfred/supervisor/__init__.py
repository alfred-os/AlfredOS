"""AlfredOS supervisor — quarantined-LLM circuit breaker + plugin lifecycle.

Spec §10: the supervisor owns the ``asyncio.TaskGroup`` under which every
plugin stdio-reader runs, the per-component :class:`CircuitBreaker` state
machine, and the 30s per-action deadline that gates
``Orchestrator.handle_user_message``.

This package is the public import surface for the rest of AlfredOS:

* ``SupervisorError`` / ``BreakStateError`` — supervisor-domain errors.
* ``QuarantinedUnavailable`` — re-exported from
  :mod:`alfred.plugins.errors` (ADR-0017 Decision 6 — owned by ``plugins/``
  but re-exported here so orchestrator code can ``from alfred.supervisor
  import QuarantinedUnavailable`` without crossing modules).

Concrete classes (``Supervisor``, ``CircuitBreaker``, ``BreakerState``) are
added by later PR-S3-3b tasks; this PR ships Tasks 1-3 (errors + ORM model +
migration 0010) only.
"""

from __future__ import annotations

from alfred.supervisor.errors import (
    BreakStateError,
    QuarantinedUnavailable,
    SupervisorError,
)

__all__ = [
    "BreakStateError",
    "QuarantinedUnavailable",
    "SupervisorError",
]
