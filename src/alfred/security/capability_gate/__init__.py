"""Real :class:`CapabilityGate` — hybrid storage (state.git + Postgres).

Spec §8 (Fork 7) production implementation, landing across PR-S3-2.
PR-S3-2 Tasks 1-8 ship :class:`GatePolicy` / :class:`GrantRow` (the pure
policy layer), :class:`PostgresBackend` (the Postgres projection of the
state.git capability-grant tree), and :class:`RealGate` (the production
:class:`alfred.hooks.capability.CapabilityGate` implementation).

Subsequent PR-S3-2 tasks bring in the proposals flow, fail-closed
heartbeat, the gate_factory bootstrap, and the integration test against
real Postgres / state.git.

Public surface this slice (Tasks 1-8 batch):

* :class:`GatePolicy` — immutable in-memory grant snapshot.
* :class:`GrantRow` — a single grant row read from ``plugin_grants``.
* :class:`RealGate` — the production gate (added at Task 8); matches
  the :class:`alfred.hooks.capability.CapabilityGate`
  ``@runtime_checkable`` Protocol structurally.
"""

from __future__ import annotations

# Relative imports per PR-S3-1 R2 (CR reviewer F2): the package's own
# re-exports stay relative so an external rename of
# ``alfred.security.capability_gate`` requires no churn in this file.
from ._gate import RealGate
from .policy import GatePolicy, GrantRow

__all__ = ["GatePolicy", "GrantRow", "RealGate"]
