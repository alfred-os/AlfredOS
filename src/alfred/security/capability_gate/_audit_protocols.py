"""Audit-sink structural Protocol shared across the capability_gate package.

Spec §8.1 / §8.3 / §8.5: the gate (:class:`._gate.RealGate`) and the
proposal flow (:mod:`.proposals`) both need to emit audit rows through a
:meth:`alfred.audit.log.AuditWriter.append_schema`-shaped sink — gate
transitions (entering / exiting fail-closed) on the gate side,
``plugin.grant.requested`` on the proposal side.

Both sites previously declared their own private ``_AuditSink`` Protocol;
the two declarations were byte-for-byte identical except for module
location. CR reviewer F1 flagged this as a DRY violation that risks
silent drift: if one site updates the signature (a new kwarg, a
different ``cost_estimate_usd`` type) without updating the other, the
gate and proposal paths accept different shapes for the same logical
contract — a recipe for "audit row emit succeeds in tests but fails in
production" once the real :class:`AuditWriter` enforces the union of both
signatures.

Centralising here:

* Keeps the gate / proposal modules free of the SQLAlchemy import graph
  the production :class:`alfred.audit.log.AuditWriter` brings in
  (sec-007 layering posture — capability_gate is hot-path code; the
  audit subsystem is a sink, not a dependency).
* Gives reviewers exactly ONE place to change the contract when the
  audit signature evolves; both call sites then inherit the new shape
  automatically.
* Preserves the ``@runtime_checkable`` posture so dispatcher code can
  ``isinstance``-narrow at runtime.

Private (leading underscore) because the audit-sink seam is a
package-internal layering device — production wires the real
:class:`AuditWriter`; tests inject a spy with the same signature. No
external code should consume this Protocol directly.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class _AuditSink(Protocol):
    """Structural seam matching :meth:`AuditWriter.append_schema`.

    Production wires the real :class:`alfred.audit.log.AuditWriter`; tests
    inject a spy with the same keyword-only signature. The Protocol is
    ``@runtime_checkable`` so the dispatcher / bootstrap can
    ``isinstance``-narrow at runtime.
    """

    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
    ) -> None:
        raise NotImplementedError  # pragma: no cover


__all__ = ["_AuditSink"]
