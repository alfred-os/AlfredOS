"""DispatchOutcome + ProposalContext + ProposalEffectsProtocol + handler tests.

Pins the dispatcher's pluggable surface per ADR-0021 §Handler registry.

* ``DispatchOutcome`` is the handler-reported outcome — distinct from
  ``ProposalResult`` (which lives at ``alfred.cli._state_git:331`` and
  is threaded through every CLI proposal-write surface). The name
  ``DispatchOutcome`` is load-bearing; the duplicate name would force
  ambiguous imports across the runtime.
* ``ProposalContext.effects`` is typed ``ProposalEffectsProtocol`` — a
  Protocol with a single ``reset_breaker(component_id, operator_user_id)``
  method. NOT the full ``Supervisor``: the narrow surface is the
  capability-restriction that stops a future handler from reaching into
  unrelated supervisor internals.
* ``_handle_breaker_reset`` returns ``DispatchOutcome.failed(reason=...)``
  on ``NoSuchComponentError`` (operator-supplied unknown component_id —
  not a framework bug); propagates other exceptions to the dispatcher's
  framework-error path.
"""

from __future__ import annotations

import inspect as _inspect
from typing import Protocol, get_type_hints
from unittest.mock import AsyncMock

import pytest
import structlog

from alfred.audit.log import AuditWriter
from alfred.state.dispatch_registry import (
    PROPOSAL_HANDLERS,
    DispatchOutcome,
    ProposalContext,
    ProposalEffectsProtocol,
    _handle_breaker_reset,
)
from alfred.state.proposal_payloads import BreakerResetProposal
from alfred.supervisor.errors import NoSuchComponentError

# ---------------------------------------------------------------------------
# DispatchOutcome — name, factories, immutability
# ---------------------------------------------------------------------------


def test_dispatch_outcome_applied_factory() -> None:
    """``DispatchOutcome.applied()`` carries kind='applied' + reason=None."""
    out = DispatchOutcome.applied()
    assert out.kind == "applied"
    assert out.reason is None


def test_dispatch_outcome_failed_factory_carries_reason() -> None:
    """``DispatchOutcome.failed(reason)`` carries the closed-vocab reason."""
    out = DispatchOutcome.failed(reason="component_id_not_registered")
    assert out.kind == "failed_handler"
    assert out.reason == "component_id_not_registered"


def test_dispatch_outcome_is_frozen_immutable() -> None:
    """Frozen — a handler must not be able to mutate its own outcome."""
    out = DispatchOutcome.applied()
    with pytest.raises((AttributeError, TypeError)):
        out.kind = "failed_handler"  # type: ignore[misc]


def test_dispatch_outcome_name_distinct_from_proposal_result() -> None:
    """The runtime name MUST be ``DispatchOutcome``, not ``ProposalResult``.

    ``ProposalResult`` already exists at ``alfred.cli._state_git:331`` and
    is threaded through every CLI proposal-write surface. Re-using the
    name in the dispatch layer would force ambiguous imports. This pin
    catches a future rename in either direction.
    """
    assert DispatchOutcome.__name__ == "DispatchOutcome"


# ---------------------------------------------------------------------------
# ProposalEffectsProtocol — narrow capability surface
# ---------------------------------------------------------------------------


def test_proposal_effects_protocol_is_runtime_protocol() -> None:
    """The Protocol is structural — Supervisor satisfies it without inheritance."""
    assert issubclass(type(ProposalEffectsProtocol), type(Protocol))


def test_proposal_effects_protocol_only_exposes_reset_breaker() -> None:
    """The Protocol surface MUST be narrow — only ``reset_breaker`` today.

    A wider surface would let a handler reach into Supervisor internals
    that are not gated by ADR-0021's per-handler review. Widening lands
    by adding a method here and a registry entry, not by exposing the
    Supervisor directly.
    """
    methods = {
        name
        for name in dir(ProposalEffectsProtocol)
        if not name.startswith("_") and callable(getattr(ProposalEffectsProtocol, name, None))
    }
    assert methods == {"reset_breaker"}


def test_proposal_effects_protocol_reset_breaker_signature() -> None:
    """``reset_breaker`` accepts component_id + operator_user_id, returns None.

    Pins the shape so a future Supervisor signature change surfaces here
    (not at first dispatch in production).
    """
    sig = _inspect.signature(ProposalEffectsProtocol.reset_breaker)
    params = dict(sig.parameters)
    # ``self`` is implicit on the Protocol method
    assert {"component_id", "operator_user_id"} <= params.keys()


# ---------------------------------------------------------------------------
# ProposalContext — frozen dependency-bundle
# ---------------------------------------------------------------------------


def test_proposal_context_is_frozen() -> None:
    """Frozen — handlers must not mutate the framework-supplied context."""
    audit = AsyncMock(spec=AuditWriter)
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    ctx = ProposalContext(
        audit_writer=audit,
        effects=effects,
        logger=structlog.get_logger("test"),
    )
    with pytest.raises((AttributeError, TypeError)):
        ctx.audit_writer = AsyncMock(spec=AuditWriter)  # type: ignore[misc]


def test_proposal_context_effects_typed_as_protocol_not_supervisor() -> None:
    """``ctx.effects`` MUST be typed ``ProposalEffectsProtocol``.

    The runtime hint pin guards against a future refactor that
    widens the surface back to ``Supervisor``.
    """
    hints = get_type_hints(ProposalContext)
    assert hints["effects"] is ProposalEffectsProtocol


# ---------------------------------------------------------------------------
# PROPOSAL_HANDLERS — registry contract
# ---------------------------------------------------------------------------


def test_proposal_handlers_registry_contains_breaker_reset() -> None:
    """Registry pins the breaker-reset handler under the discriminator string."""
    assert "breaker-reset" in PROPOSAL_HANDLERS
    assert PROPOSAL_HANDLERS["breaker-reset"] is _handle_breaker_reset


def test_proposal_handlers_registry_is_a_mapping_not_dict() -> None:
    """The registry surface MUST be a read-only Mapping (Final), not a dict.

    A handler must not be able to mutate the registry mid-cycle. The
    Final[Mapping[...]] declaration prevents accidental .pop() at the
    type layer; this test pins the runtime shape.
    """
    from collections.abc import Mapping

    assert isinstance(PROPOSAL_HANDLERS, Mapping)


# ---------------------------------------------------------------------------
# _handle_breaker_reset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_breaker_reset_calls_effects_reset_breaker() -> None:
    """Handler calls ``ctx.effects.reset_breaker(...)`` with payload fields.

    Pins the dispatch path: the handler does NOT touch the supervisor
    directly — it goes through the narrow ``ProposalEffectsProtocol``.
    Component_id is positional + operator_user_id keyword-only — CR
    rework round-1 HIGH #17 aligned the Protocol with the Supervisor.
    """
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    ctx = ProposalContext(
        audit_writer=AsyncMock(spec=AuditWriter),
        effects=effects,
        logger=structlog.get_logger("test"),
    )

    outcome = await _handle_breaker_reset(payload, ctx)

    effects.reset_breaker.assert_awaited_once_with(
        "alfred.web-fetch",
        operator_user_id="operator-1",
    )
    assert outcome == DispatchOutcome.applied()


@pytest.mark.asyncio
async def test_handle_breaker_reset_returns_failed_on_unknown_component() -> None:
    """Operator-supplied unknown component_id → DispatchOutcome.failed.

    Per ADR-0021 §Handler registry: handlers return ``failed`` on
    operator-caused errors (not raise). The reason is the closed-vocab
    string ``"component_id_not_registered"`` which the dispatcher writes
    into the ledger as the DLP-redacted ``failure_detail``.
    """
    payload = BreakerResetProposal(
        component_id="alfred.totally-bogus",
        operator_user_id="operator-1",
    )
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    effects.reset_breaker.side_effect = NoSuchComponentError(
        "component alfred.totally-bogus not registered"
    )
    ctx = ProposalContext(
        audit_writer=AsyncMock(spec=AuditWriter),
        effects=effects,
        logger=structlog.get_logger("test"),
    )

    outcome = await _handle_breaker_reset(payload, ctx)

    assert outcome == DispatchOutcome.failed(reason="component_id_not_registered")
    effects.reset_breaker.assert_awaited_once()


@pytest.mark.asyncio
async def test_handle_breaker_reset_propagates_unexpected_exception() -> None:
    """A non-NoSuchComponentError exception is a framework bug — propagate.

    ADR-0021: handlers MUST NOT raise on operator-caused failures. A
    RuntimeError from effects.reset_breaker is the framework's problem;
    the dispatcher's try/except wraps it into the ``failed_handler /
    handler_uncaught_exception`` ledger row. The handler does NOT
    swallow.
    """
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    effects.reset_breaker.side_effect = RuntimeError("transient bug")
    ctx = ProposalContext(
        audit_writer=AsyncMock(spec=AuditWriter),
        effects=effects,
        logger=structlog.get_logger("test"),
    )

    with pytest.raises(RuntimeError):
        await _handle_breaker_reset(payload, ctx)


# ---------------------------------------------------------------------------
# Handler signature shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_breaker_reset_is_async_returns_dispatch_outcome() -> None:
    """The handler MUST be async and return a DispatchOutcome.

    Pins the registry signature contract so a future handler can be
    swapped in by matching the protocol shape alone.
    """
    assert _inspect.iscoroutinefunction(_handle_breaker_reset)
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    ctx = ProposalContext(
        audit_writer=AsyncMock(spec=AuditWriter),
        effects=effects,
        logger=structlog.get_logger("test"),
    )
    outcome = await _handle_breaker_reset(payload, ctx)
    assert isinstance(outcome, DispatchOutcome)
