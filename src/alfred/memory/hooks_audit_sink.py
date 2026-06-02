"""Adapter mapping PR-A hook-trace events to :class:`AuditWriter.append`.

Slice-2.5 PR-B Task 7. :class:`EpisodicAuditSink` is the seam between two
subsystems that ship under different contracts:

* **PR-A's :class:`alfred.hooks.audit_sink.AuditSink` Protocol** — the
  hook dispatcher's audit emit surface. Keyword-only
  ``emit(event, correlation_id, fields)`` where ``fields`` is a Mapping
  of per-event attributes (the canonical schemas live as the
  ``_REFUSAL_AUDIT_FIELDS`` / ``_SUBSCRIBER_ERROR_AUDIT_FIELDS`` /
  ``_CHAIN_TIMEOUT_AUDIT_FIELDS`` / ``_REENTRY_BYPASS_AUDIT_FIELDS``
  module constants in :mod:`alfred.hooks.invoke`).
* **Slice-1's :class:`alfred.audit.log.AuditWriter`** — the
  persistent audit log writer with a wider, row-shaped keyword-only
  surface (``actor_user_id`` / ``subject`` / ``trust_tier_of_trigger``
  / ``result`` / ``cost_estimate_usd`` / ``trace_id`` / ``persona_id``
  / ``language`` / …).

The adapter is a thin forwarder — no business logic — that translates
the dispatcher's narrow ``(event, correlation_id, fields)`` triple into
the writer's row-shaped call. The §0 field-mapping table below pins the
load-bearing transforms.

No recursion invariant
----------------------
This sink emits :class:`AuditWriter.append` rows directly; ``append``
itself is NOT the ``memory.episodic.record`` action and does NOT
re-enter the hook dispatch chain. The PoC action's hookpoint is
``memory.episodic.record``; a hook-trace fault row from THAT action
lands here and does NOT cause another ``memory.episodic.record``
invocation. Adding business logic, side effects, or hook-emitting
behaviour to this adapter would break the invariant — keep it a
forwarder.

Decision 3.6 / memB-1: fresh session per fault-row emit
-------------------------------------------------------
A ``hooks.write_failed`` row fires AFTER the turn's flush failed —
which leaves the turn's session in a poisoned ``InvalidRequestError``
state. If the fault row were to append on that session, the second
``flush`` would raise and the row would be LOST. The plan's mitigation
is "open a fresh short-lived session for each fault-row append".

The existing :class:`AuditWriter` ALREADY satisfies this. Its
constructor takes a ``session_factory`` (a zero-arg async-cm factory
that returns FRESH sessions, NOT the turn's session); its ``.append``
opens that factory on every call and commits inside it. So this
adapter's "fresh session per emit" guarantee comes from delegating to
the writer's existing contract — no separate ``session_scope`` parameter
is needed, and constructing the writer with the production session
factory at adapter-construction time wires the fresh-session-per-emit
semantic end-to-end.

PR-A's emit-site fields do NOT carry user-content attribution
-------------------------------------------------------------
PR-A's emit-site schemas (refusal / subscriber-error / chain-timeout /
reentry-bypass) deliberately OMIT ``ctx.input``-derived fields
(``user_id``, ``persona_id``, ``language``, ``trust_tier``) because
subscriber-supplied strings may carry T3 user content (CLAUDE.md hard
rule #1 — never log secrets). The plan's §0 field-mapping table
specifies ``actor_user_id=<from ctx.input.user_id when present, else
None>`` — the ``else None`` clause is the documented fallback this
adapter implements. The ``fields.get(...)`` calls below fall back to
``None`` / ``"T0"`` / ``"en-US"`` for fields PR-A doesn't emit, so the
adapter remains tolerant of a future schema widening (e.g. a Slice-3
``user_id`` addition) without a code change here.

Production-install site deferred to Slice 3
-------------------------------------------
This adapter is wired test-only this slice — the PoC integration test
in :mod:`tests.integration.memory.test_episodic_hooks_poc` constructs an
:class:`EpisodicAuditSink` and ``set_registry``-swaps it into the hook
registry for the test's duration. NO production-bootstrap module is
edited in PR-B (the §0 two-file source-edit envelope: this file plus
``hooks_audit_sink.py`` only). Promoting the adapter to a real
production installation site (e.g. the orchestrator bootstrap) is a
Slice-3 concern (arch-002: "no live reload this slice").
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

import structlog

from alfred.audit.log import AuditWriter
from alfred.hooks.audit_sink import (
    HOOKS_CHAIN_TIMEOUT,
    HOOKS_ERROR_SUPPRESSED,
    HOOKS_REENTRY_BYPASS,
    HOOKS_REFUSAL,
    HOOKS_SUBSCRIBER_ERROR,
    HOOKS_UNAUTHORIZED_REFUSAL,
)

_logger = structlog.get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Result-disposition table — §0 field mapping
# ──────────────────────────────────────────────────────────────────────
#
# Each PR-A ``HOOKS_*`` event identifier dispositions to one of the
# three §0 outcomes:
#
# * ``"refused"`` — a subscriber refused the action (authorized) or
#   tried to refuse without authorization. Both cases are operator-
#   visible as a refusal disposition because the action's outcome is
#   "did not run as the caller asked".
# * ``"fault"`` — the chain entered a fault state: chain-timeout,
#   unexpected subscriber error, or the error-handler suppressed a deny
#   the dispatcher would otherwise re-raise.
# * ``"bypass"`` — the dispatcher detected hookpoint re-entry and
#   skipped the inner chain on purpose (sec-008). Operator-visible
#   because a bypass means a subscriber's intent was NOT honoured.
#
# Centralised so the field-mapping table has one source of truth; the
# table-driven test in
# ``tests/unit/memory/test_hooks_audit_sink.py::TestEventMapping`` pins
# the same dispositions and surfaces drift the moment a future event
# adds itself to PR-A without a corresponding row here.
_RESULT_BY_EVENT: Final[Mapping[str, str]] = {
    HOOKS_REFUSAL: "refused",
    HOOKS_UNAUTHORIZED_REFUSAL: "refused",
    HOOKS_CHAIN_TIMEOUT: "fault",
    HOOKS_SUBSCRIBER_ERROR: "fault",
    HOOKS_ERROR_SUPPRESSED: "fault",
    HOOKS_REENTRY_BYPASS: "bypass",
}


# ──────────────────────────────────────────────────────────────────────
# Per-event subject-field allowlist — I1 hardening
# ──────────────────────────────────────────────────────────────────────
#
# Security review (PR-B Task 7 reviewer-gate) flagged the blind
# ``subject = dict(fields)`` forward as structurally trusting: a future
# PR-A schema-widening (or a different emitter that re-uses the
# ``AuditSink`` Protocol) could introduce a T3-bearing key into
# ``fields``, and the adapter would happily persist it into the
# audit row's JSON subject column — silently violating CLAUDE.md
# hard rule #1 (never log secrets / never log T3 content on system
# emit paths).
#
# Mitigation: project ONLY the keys this table names. Unknown keys
# are dropped at the adapter boundary; the dropped-key set is loud-
# logged via ``structlog`` so an operator can see the divergence
# without it ever reaching the durable audit row.
#
# Each entry MIRRORS the matching ``_*_AUDIT_FIELDS`` constant in
# :mod:`alfred.hooks.invoke` — those constants are private to PR-A's
# dispatcher (module-private by convention) so the adapter duplicates
# the values rather than reaching across the package boundary. The
# comment block below pins the mirror so a PR-A schema change surfaces
# here as a test failure (the table-driven projection test asserts
# both sides verbatim).
#
# Mirror map (adapter table → PR-A source-of-truth constant):
#   HOOKS_REFUSAL              → _REFUSAL_AUDIT_FIELDS
#   HOOKS_UNAUTHORIZED_REFUSAL → _REFUSAL_AUDIT_FIELDS (same schema —
#                                authorized vs unauthorized share keys)
#   HOOKS_CHAIN_TIMEOUT        → _CHAIN_TIMEOUT_AUDIT_FIELDS
#   HOOKS_SUBSCRIBER_ERROR     → _SUBSCRIBER_ERROR_AUDIT_FIELDS
#   HOOKS_ERROR_SUPPRESSED     → mirrors _SUBSCRIBER_ERROR_AUDIT_FIELDS
#                                (PR-A doesn't define an explicit schema
#                                constant for ``error_suppressed`` yet —
#                                see :data:`HOOKS_ERROR_SUPPRESSED`'s
#                                docstring; the suppression path's
#                                row shape is the subscriber-error shape
#                                because both are non-refusal
#                                exception-class events from a
#                                subscriber. If PR-A grows a dedicated
#                                schema constant, update both this
#                                comment and the entry below.)
#   HOOKS_REENTRY_BYPASS       → _REENTRY_BYPASS_AUDIT_FIELDS
_SUBJECT_FIELDS_BY_EVENT: Final[Mapping[str, frozenset[str]]] = {
    HOOKS_REFUSAL: frozenset({"hookpoint", "kind", "subscriber_name", "subscriber_tier"}),
    HOOKS_UNAUTHORIZED_REFUSAL: frozenset(
        {"hookpoint", "kind", "subscriber_name", "subscriber_tier"}
    ),
    HOOKS_CHAIN_TIMEOUT: frozenset({"hookpoint", "kind", "deadline_seconds", "cleanup_timed_out"}),
    HOOKS_SUBSCRIBER_ERROR: frozenset({"hookpoint", "kind", "subscriber_name", "exception_type"}),
    HOOKS_ERROR_SUPPRESSED: frozenset({"hookpoint", "kind", "subscriber_name", "exception_type"}),
    HOOKS_REENTRY_BYPASS: frozenset({"hookpoint", "kind"}),
}


# Default-result fallback for an event identifier not present in the
# table above. A new PR-A event landing without a registered disposition
# defaults to ``"fault"`` because a hook-trace event whose semantics the
# adapter does NOT recognise is, by definition, an unexpected fault —
# loud-failure defaulting (CLAUDE.md hard rule #7) is "treat the unknown
# as a fault and let the operator see it", not "silently swallow it as a
# success".
_DEFAULT_RESULT: Final[str] = "fault"


# Hook-trace rows are emitted by the DISPATCHER itself — they carry no
# user content (PR-A's emit-site schemas omit ``ctx.input`` fields). T0
# is the only ``ck_audit_log_trust_tier_of_trigger`` constraint value
# that semantically fits a system-emitted dispatcher-internal event.
_TRUST_TIER: Final[str] = "T0"


# Hook-trace rows are dispatcher events with no provider call attached.
# The §0 field table specifies ``cost_estimate_usd=0.0`` for every
# hook-trace row; the constant is named here so a future cost-attribution
# refactor surfaces at one site rather than at six call lines.
_COST_ZERO: Final[float] = 0.0


@dataclass(frozen=True, slots=True)
class EpisodicAuditSink:
    """Adapter implementing PR-A's :class:`AuditSink` Protocol.

    Forwards every :meth:`emit` call to :meth:`AuditWriter.append`,
    translating the dispatcher's narrow ``(event, correlation_id,
    fields)`` triple into the writer's row-shaped keyword-only call per
    the §0 field-mapping table.

    The adapter is a frozen dataclass with ``slots=True`` so the
    dispatcher's hot path doesn't pay for ``__dict__`` allocation per
    instance, and the injected :class:`AuditWriter` cannot be swapped
    after construction (configuration is the constructor's job).

    Args:
        audit: The :class:`AuditWriter` instance whose ``session_factory``
            constructor argument is the production fresh-session
            factory (``alfred.memory.db.build_session_scope`` /
            equivalent). The writer's own contract opens a FRESH session
            on every ``.append`` call — that's how the fresh-session-
            per-emit invariant (Decision 3.6 / memB-1) is satisfied
            without a separate ``session_scope`` parameter on this
            adapter's constructor.

    Example:
        Canonical wiring for the PoC integration test (the only install
        site this slice — see "Production-install site deferred to Slice
        3" in the module docstring). The pattern is: build a fresh-session
        factory, wrap it in :class:`AuditWriter`, hand the writer to
        :class:`EpisodicAuditSink`, swap the sink into a fresh
        :class:`HookRegistry`, and stash/restore the prior registry around
        the test body so other tests aren't affected.

        Imports and call sequence (illustrative — not a runnable doctest;
        the ``make_allow_system_gate()`` helper is the test-only seam,
        the production posture wires :class:`RealGate` via
        :mod:`alfred.bootstrap.gate_factory` which refuses ``system``
        unless a Postgres-backed grant exists)::

            >>> from alfred.audit.log import AuditWriter
            >>> from alfred.hooks.registry import (
            ...     HookRegistry,
            ...     get_registry,
            ...     set_registry,
            ... )
            >>> from alfred.memory.db import build_session_scope
            >>> from alfred.settings import Settings  # noqa: F401
            >>> from tests.helpers.gates import make_allow_system_gate
            >>>
            >>> session_factory = build_session_scope(settings)
            >>> writer = AuditWriter(session_factory=session_factory)
            >>> sink = EpisodicAuditSink(audit=writer)
            >>> registry = HookRegistry(
            ...     gate=make_allow_system_gate(),
            ...     sink=sink,
            ... )
            >>> prior = get_registry()
            >>> set_registry(registry)
            >>> try:
            ...     ...  # register subscribers, call record(...), assert
            ... finally:
            ...     set_registry(prior)
    """

    audit: AuditWriter

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        """Persist one hook-trace row by forwarding to :meth:`AuditWriter.append`.

        §0 field-mapping table:

        * ``event`` — forwarded verbatim. PR-A's six ``HOOKS_*``
          identifiers all flow through (a future event addition lands
          without a code change here — the result-disposition table
          falls back to ``"fault"`` for the unknown).
        * ``actor_user_id`` — ``fields.get("user_id")``. PR-A's
          emit-site schemas do NOT include ``user_id`` (the dispatcher
          deliberately keeps ``ctx.input`` content off the audit row —
          CLAUDE.md hard rule #1), so this is ``None`` for every PR-A
          event today. A future schema widening that introduces
          ``user_id`` would surface here automatically.
        * ``subject`` — projected through :data:`_SUBJECT_FIELDS_BY_EVENT`.
          ONLY the keys the per-event allowlist names land in the row's
          ``subject`` JSONB column; any other key in ``fields`` is
          dropped at the adapter boundary and structlog-warned so the
          divergence is operator-visible without ever reaching the
          durable audit row. This is the I1 hardening: a blind
          ``dict(fields)`` would persist a future PR-A schema-widening
          (or a different emitter that re-uses the Protocol) verbatim,
          including any T3-bearing key — silently violating CLAUDE.md
          hard rule #1. The allowlist projection makes the row's
          subject column a CLOSED surface keyed off the §0 schema
          constants in :mod:`alfred.hooks.invoke`.
        * ``trust_tier_of_trigger`` — always ``"T0"``. Hook-trace rows
          are dispatcher-emitted system events with no user content.
        * ``result`` — looked up in :data:`_RESULT_BY_EVENT` with
          ``"fault"`` as the loud-failure fallback for unknown events.
        * ``cost_estimate_usd`` — always ``0.0`` (§0 — hook-trace rows
          carry no provider cost).
        * ``trace_id`` — the ``correlation_id`` parameter, forwarded
          verbatim so the audit log joins to the dispatcher's
          correlation graph.
        * ``persona_id`` — ``fields.get("persona_id")``. PR-A doesn't
          emit this today; the fallback to ``None`` preserves the
          ``AuditWriter.append`` default contract.
        * ``language`` — ``fields.get("language", "en-US")``. PR-A
          doesn't emit this today; the fallback matches the writer's
          own default.

        Fresh-session invariant: every call delegates to
        :meth:`AuditWriter.append`, which itself opens a fresh
        ``session_factory`` invocation. Two emits → two fresh sessions
        (Decision 3.6 / memB-1).

        Loud failure: an exception raised by
        :meth:`AuditWriter.append` propagates uncaught (CLAUDE.md hard
        rule #7 — no silent failures in security paths). The hook
        dispatcher decides how to react.

        Args:
            event: One of the ``HOOKS_*`` identifiers from
                :mod:`alfred.hooks.audit_sink`. Forwarded as the
                ``event`` column.
            correlation_id: Cross-system trace correlation id. Forwarded
                as the ``trace_id`` column.
            fields: PR-A fault-row schema mapping. Copied into the row's
                ``subject`` JSONB column; specific keys are also
                projected into per-row dimensional columns
                (``actor_user_id`` / ``persona_id`` / ``language``)
                when present.
        """
        # Per-event subject projection (I1 hardening). The allowlist is
        # the §0 schema source-of-truth; an unmapped event lands as the
        # empty allowlist (subject = ``{}``) plus a structlog warning so
        # an operator sees the divergence WITHOUT it persisting to the
        # durable audit row.
        allowed_fields = _SUBJECT_FIELDS_BY_EVENT.get(event, frozenset())
        subject: dict[str, Any] = {k: v for k, v in fields.items() if k in allowed_fields}

        # Loud surface for drift — TWO orthogonal signals.
        #
        # 1. Unmapped event: the adapter has NO allowlist for this event
        #    id. Either PR-A added a new event without updating
        #    :data:`_SUBJECT_FIELDS_BY_EVENT` here, or a foreign emitter
        #    is reusing the AuditSink Protocol. Either way the operator
        #    should see it.
        # 2. Dropped keys on a MAPPED event: the dispatcher emitted keys
        #    the allowlist does not name. Could be a benign
        #    backward-compatible schema-widening on PR-A (operator
        #    decides to mirror them here) OR a hostile/unexpected
        #    payload (operator decides to investigate). The dropped set
        #    is logged WITHOUT the dropped VALUES — a value might carry
        #    T3 content, which is the whole reason we're dropping it
        #    from the durable row.
        # structlog conventionally uses the first positional argument as
        # the event-key (the log-line identifier). To avoid colliding
        # with that and to keep the hook-trace event id surfaced in the
        # log record without overloading the structlog ``event`` slot,
        # log the hook event under ``hook_event``.
        if event not in _SUBJECT_FIELDS_BY_EVENT:
            _logger.warning(
                "episodic_audit_sink.unmapped_event",
                hook_event=event,
                correlation_id=correlation_id,
            )
        else:
            dropped = sorted(set(fields.keys()) - allowed_fields)
            if dropped:
                _logger.warning(
                    "episodic_audit_sink.dropped_subject_keys",
                    hook_event=event,
                    correlation_id=correlation_id,
                    dropped_keys=dropped,
                )

        await self.audit.append(
            event=event,
            actor_user_id=_optional_str(fields.get("user_id")),
            subject=subject,
            trust_tier_of_trigger=_TRUST_TIER,
            result=_RESULT_BY_EVENT.get(event, _DEFAULT_RESULT),
            cost_estimate_usd=_COST_ZERO,
            trace_id=correlation_id,
            persona_id=_optional_str(fields.get("persona_id")),
            language=_str_with_default(fields.get("language"), "en-US"),
        )


def _optional_str(value: object | None) -> str | None:
    """Narrow an opaque ``object | None`` from a Mapping to ``str | None``.

    PR-A's emit-site Mapping is typed ``Mapping[str, object]``; the
    writer's ``actor_user_id`` / ``persona_id`` columns are typed
    ``str | None``. This helper does the narrowing: a non-string value
    forced into the audit log would be a downstream type error AND a
    likely partition-leak surface (a non-string ``user_id`` cannot scope
    to a user). Defensive runtime-narrowing here surfaces the misuse
    at the adapter boundary rather than at the database write.

    Returns ``None`` for ``None``; passes a ``str`` through; raises
    :class:`TypeError` for anything else.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise TypeError(
        f"EpisodicAuditSink expected str | None for an actor field, got {type(value).__name__!r}"
    )


def _str_with_default(value: object | None, default: str) -> str:
    """Narrow a ``object | None`` to ``str`` with a fallback default.

    Distinct from :func:`_optional_str` because ``language`` is a
    non-nullable column on the writer's contract: a missing ``language``
    falls back to the writer's own default (``"en-US"``) rather than to
    ``None``. Raises :class:`TypeError` for a non-string non-``None``
    value — same loud-failure discipline as :func:`_optional_str`.
    """
    if value is None:
        return default
    if isinstance(value, str):
        return value
    raise TypeError(
        f"EpisodicAuditSink expected str for an i18n field, got {type(value).__name__!r}"
    )
