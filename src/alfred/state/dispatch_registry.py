"""Dispatch registry for side-effecting state.git proposals (ADR-0021).

The dispatcher pluggable surface — one entry per side-effecting proposal
type. Declarative-projection proposals (``PluginGrantProposal`` and the
``WebAllowlistProposal`` / ``ConfigSetProposal`` families per
ADR-0021 §Scope) do NOT register here; their effect is the projected
Postgres state that ``RealGate.rebuild_from_state_git`` materialises.

Key types
---------

* :class:`DispatchOutcome` — the handler-reported outcome. The name
  ``DispatchOutcome`` is deliberate; ``ProposalResult`` already exists
  at :class:`alfred.cli._state_git.ProposalResult` (the CLI writer's
  return type, threaded through every proposal-write surface). The two
  types serve different layers — the CLI writer reports "the branch
  landed and here is its id", the runtime dispatcher reports "the
  approved proposal was applied". Sharing a name would force ambiguous
  imports across the runtime.
* :class:`ProposalEffectsProtocol` — the narrow capability surface
  exposed to handlers. ``Supervisor`` satisfies the Protocol
  structurally (its :meth:`Supervisor.reset_breaker` matches the
  signature). Handlers receive an instance of this Protocol, NOT the
  full ``Supervisor`` — so a future handler cannot reach into
  unrelated supervisor internals (lifecycle / breaker introspection
  / private session-scope). Widening the surface lands by adding a
  method to the Protocol + a handler.
* :class:`ProposalContext` — frozen bundle that threads
  framework-level dependencies into handlers without globals.
* :data:`PROPOSAL_HANDLERS` — ``Final[Mapping[str, ProposalHandler]]``
  registry keyed by ``proposal_type`` discriminator. Final + Mapping
  (not dict) so a handler cannot mutate the registry mid-cycle.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol, runtime_checkable

import structlog

from alfred.audit.log import AuditWriter
from alfred.state.proposal_payloads import (
    BreakerResetProposal,
    StateGitProposalPayload,
)
from alfred.supervisor.errors import NoSuchComponentError

# ---------------------------------------------------------------------------
# DispatchOutcome — handler-reported result
# ---------------------------------------------------------------------------

DispatchOutcomeKind = Literal["applied", "failed_handler"]
"""Closed vocab for ``DispatchOutcome.kind``.

The framework wraps uncaught exceptions in the dispatch loop separately
— those land in the ledger as ``result="failed_handler"`` /
``failure_kind="handler_uncaught_exception"`` and never reach this enum.
Handlers MUST narrow to one of these two values; raising on
operator-caused failure is a contract violation per ADR-0021.
"""


@dataclass(frozen=True, slots=True)
class DispatchOutcome:
    """Outcome reported by a proposal handler.

    Constructed only via :meth:`applied` / :meth:`failed` so the two
    legal shapes (no-reason on applied, mandatory-reason on failed)
    stay in lockstep. Frozen + slots — a handler must not be able to
    mutate its own reported outcome before the dispatcher records it.

    The runtime distinguishes this from the framework-level
    ``failed_handler / handler_uncaught_exception`` outcome — that
    branch is reached only when the dispatcher's ``try/except``
    catches an exception the handler should have converted to
    :meth:`failed`. See ADR-0021 §Handler registry for the discipline.
    """

    kind: DispatchOutcomeKind
    reason: str | None = None

    @classmethod
    def applied(cls) -> DispatchOutcome:
        """The handler applied the proposal cleanly."""
        return cls(kind="applied", reason=None)

    @classmethod
    def failed(cls, reason: str) -> DispatchOutcome:
        """The handler reports operator-caused failure with a closed-vocab reason.

        ``reason`` is recorded in the ledger as the truncated
        ``failure_detail``. Use closed-vocab strings
        (``component_id_not_registered``, ...) — free-form strings risk
        T3 fragments slipping through. CR rework round-1 CRITICAL #2:
        DLP scanning of this field is tracked at #173; today the
        boundary is truncation only, so closed-vocab discipline at the
        handler is the load-bearing defence.
        """
        return cls(kind="failed_handler", reason=reason)


# ---------------------------------------------------------------------------
# ProposalEffectsProtocol — narrow capability surface
# ---------------------------------------------------------------------------


@runtime_checkable
class ProposalEffectsProtocol(Protocol):
    """Narrow capability surface exposed to dispatch handlers.

    Currently exposes only :meth:`reset_breaker`. The runtime
    :class:`alfred.supervisor.core.Supervisor` satisfies this Protocol
    structurally (its ``reset_breaker`` method matches the signature) —
    no inheritance required. Pass a ``Supervisor`` instance wherever a
    ``ProposalEffectsProtocol`` is expected.

    Future side-effecting proposal types widen the surface by adding a
    method here AND registering a handler in :data:`PROPOSAL_HANDLERS`.
    The Protocol is the narrowing primitive that ADR-0021 §ProposalContext
    relies on.
    """

    async def reset_breaker(
        self,
        component_id: str,
        *,
        operator_user_id: str,
    ) -> None:
        """Reset the named breaker. Raises :class:`NoSuchComponentError`.

        Signature mirrors :meth:`alfred.supervisor.core.Supervisor.reset_breaker`
        exactly — ``component_id`` is positional, ``operator_user_id`` is
        keyword-only. CR rework round-1 HIGH #17 aligned the two so the
        Protocol stays a structural match without ``# type: ignore``
        accommodations.
        """
        ...


# ---------------------------------------------------------------------------
# ProposalContext — framework dependency bundle
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProposalContext:
    """Framework-level dependencies threaded into handlers without globals.

    Frozen + slots — handlers must not mutate the framework's view of its
    own dependencies. The ``effects`` field is typed
    :class:`ProposalEffectsProtocol` (NOT ``Supervisor``) so the
    capability narrowing is enforced at the type layer.

    Fields
    ------

    * ``audit_writer`` — for emitting ``state.proposal.*`` audit rows.
    * ``effects`` — the narrow capability surface; satisfied
      structurally by ``Supervisor``.
    * ``logger`` — handler-side structlog binding; the dispatcher
      attaches per-cycle correlation ids via :meth:`bind`.
    """

    audit_writer: AuditWriter
    effects: ProposalEffectsProtocol
    logger: structlog.BoundLogger


# ---------------------------------------------------------------------------
# Handler signature + registry
# ---------------------------------------------------------------------------

ProposalHandler = Callable[
    [StateGitProposalPayload, ProposalContext],
    Awaitable[DispatchOutcome],
]
"""Handler signature contract.

The dispatcher passes the parsed typed payload + the framework context
and awaits the returned :class:`DispatchOutcome`. Handlers MUST be async
(the cycle runs on the supervisor's event loop) and MUST NOT raise on
operator-caused failure — those return :meth:`DispatchOutcome.failed`.

Uncaught exceptions surface in the dispatch loop's framework-error
path (recorded as ``result="failed_handler"`` /
``failure_kind="handler_uncaught_exception"``).

**Idempotency contract** — CR rework round-1 CRITICAL #1. Handlers MUST
be idempotent: re-applying the same payload produces the same observable
outcome with no side-effect divergence. The framework guarantees
at-least-once dispatch with replay safety via the composite-PK lookup
in :func:`alfred.state.dispatch_loop._dispatch_one`. If a crash occurs
between a handler's transaction commit and the framework's ledger-row
commit, the next cycle's PK lookup misses the ledger row, the
HEAD-diff walk re-surfaces the same blob, and the handler runs again —
the idempotency contract is what keeps that replay safe in the
observable sense. Concretely for the breaker-reset handler: a re-applied
reset against a CLOSED breaker is a no-op (the state machine and the
``circuit_breakers`` row are both already CLOSED); for a future
handler, idempotency means designing the side-effect such that a
re-apply produces no incremental observable change.
"""


async def _handle_breaker_reset(
    payload: StateGitProposalPayload,
    ctx: ProposalContext,
) -> DispatchOutcome:
    """Apply an approved :class:`BreakerResetProposal`.

    Threads the typed payload through :meth:`ProposalEffectsProtocol.reset_breaker`
    — the supervisor's actual reset path then emits the existing
    ``supervisor.breaker.reset`` audit row with the operator's
    attribution. This handler does NOT emit ``supervisor.breaker.reset``
    itself; the dispatcher's per-row ``state.proposal.processed`` audit
    row is emitted at the loop level (see :mod:`alfred.state.dispatch_loop`).

    Operator-caused failure (``component_id`` not registered) returns
    :meth:`DispatchOutcome.failed` with the closed-vocab reason. Any
    other exception propagates to the dispatch loop's framework-error
    path per ADR-0021 §Handler registry — the handler does NOT swallow
    framework-internal bugs.
    """
    if not isinstance(payload, BreakerResetProposal):
        # The dispatcher verifies path/body type match before calling
        # the handler, so this is unreachable in production. Kept as a
        # defensive narrow so a future direct caller (test fixture, REPL
        # session) hits a clear ``TypeError`` rather than an
        # AttributeError deep inside the call. Exercised by
        # ``test_handle_breaker_reset_refuses_wrong_payload_type`` under
        # ``tests/unit/state/test_dispatch_registry.py``.
        msg = (
            f"_handle_breaker_reset received {type(payload).__name__}; "
            "expected BreakerResetProposal"
        )
        raise TypeError(msg)

    # CR rework round-1 HIGH #16: ``BreakerResetProposal``'s
    # ``model_validator`` refuses None / empty ``operator_user_id`` at
    # parse time so the runtime field is provably non-empty here. The
    # ``assert`` makes that contract visible to the type-checker (the
    # base-class annotation stays ``str | None`` for compatibility);
    # the validator is the load-bearing refusal, not the assert.
    # CR rework round-1 HIGH #17: ``component_id`` is positional on
    # :class:`ProposalEffectsProtocol`, mirroring Supervisor's shape.
    assert payload.operator_user_id, "validator refuses empty operator_user_id"
    try:
        await ctx.effects.reset_breaker(
            payload.component_id,
            operator_user_id=payload.operator_user_id,
        )
    except NoSuchComponentError:
        return DispatchOutcome.failed(reason="component_id_not_registered")
    return DispatchOutcome.applied()


PROPOSAL_HANDLERS: Final[Mapping[str, ProposalHandler]] = {
    BreakerResetProposal.proposal_type: _handle_breaker_reset,
}
"""Registry keyed by ``StateGitProposalPayload.proposal_type``.

Final + Mapping (NOT dict) — a handler cannot mutate the registry
mid-cycle. Future side-effecting proposal types register here AND in
the writer's :func:`alfred.cli._state_git._on_disk_files_for` path
convention so the dispatcher's HEAD-diff walker can discriminate the
type from the on-disk path.
"""


__all__ = [
    "PROPOSAL_HANDLERS",
    "DispatchOutcome",
    "DispatchOutcomeKind",
    "ProposalContext",
    "ProposalEffectsProtocol",
    "ProposalHandler",
    "_handle_breaker_reset",
]
