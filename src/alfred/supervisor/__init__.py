"""AlfredOS supervisor — quarantined-LLM circuit breaker + plugin lifecycle.

Spec §10: the supervisor owns the ``asyncio.TaskGroup`` under which every
plugin stdio-reader runs, the per-component :class:`CircuitBreaker` state
machine, and the 30s per-action deadline that gates
``Orchestrator.handle_user_message``.

This package is the public import surface for the rest of AlfredOS:

* :class:`Supervisor` — top-level coordinator (start / stop /
  reset_breaker / get_or_create_breaker / load_all_breakers).
* :class:`CircuitBreaker` — three-state breaker
  (CLOSED / OPEN / HALF_OPEN) with Postgres persistence (spec §10.2).
* :class:`BreakerState` — enum of breaker states.
* :class:`SupervisorError` / :class:`BreakStateError` — supervisor-domain
  errors. :class:`SupervisorError` descends from
  :class:`alfred.errors.AlfredError` so the CLI top-level dispatch catches
  the family uniformly.
* :class:`QuarantinedUnavailable` — re-exported from
  :mod:`alfred.plugins.errors` (ADR-0017 Decision 6 — owned by
  ``plugins/`` but re-exported here so orchestrator code can
  ``from alfred.supervisor import QuarantinedUnavailable`` without
  crossing modules). Identity is pinned by
  ``tests/unit/supervisor/test_errors.py`` (the re-export is the same
  class object, not a subclass).

Dependencies: PR-S3-0a (audit_row_schemas), PR-S3-0b (migrations +
i18n), PR-S3-3a (AlfredPluginSession contract). See plan:
``docs/superpowers/plans/2026-05-31-slice-3-pr-s3-3b-supervisor.md``.
"""

from __future__ import annotations

from alfred.supervisor.breaker import BreakerState, CircuitBreaker
from alfred.supervisor.core import Supervisor
from alfred.supervisor.errors import (
    BreakStateError,
    QuarantinedUnavailable,
    SupervisorError,
)
from alfred.supervisor.protocols import (
    OperatorResolverProtocol,
    PoliciesSnapshotRefProtocol,
)

__all__ = [
    "BreakStateError",
    "BreakerState",
    "CircuitBreaker",
    "OperatorResolverProtocol",
    "PoliciesSnapshotRefProtocol",
    "QuarantinedUnavailable",
    "Supervisor",
    "SupervisorError",
]
