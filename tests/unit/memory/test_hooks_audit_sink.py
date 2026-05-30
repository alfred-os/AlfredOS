"""Tests for :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink`.

Slice-2.5 PR-B Task 7. Pins the adapter that maps PR-A's hook-trace
``AuditSink`` Protocol (``event`` / ``correlation_id`` / ``fields``) to
the existing :class:`alfred.audit.log.AuditWriter` row contract.

The adapter is the seam between two subsystems that ship under different
contracts:

* **PR-A's :class:`AuditSink` Protocol** — keyword-only
  ``emit(event, correlation_id, fields)``. The dispatcher hands the sink
  a Mapping of fault-row attributes (schema constants
  :data:`_REFUSAL_AUDIT_FIELDS`, :data:`_SUBSCRIBER_ERROR_AUDIT_FIELDS`,
  :data:`_CHAIN_TIMEOUT_AUDIT_FIELDS`, :data:`_REENTRY_BYPASS_AUDIT_FIELDS`
  on :mod:`alfred.hooks.invoke`). Crucially, these schemas DO NOT include
  the action's ``user_id`` / ``persona_id`` / ``language`` / ``trust_tier``
  — PR-A's emit sites deliberately keep ``ctx.input`` content OFF the
  audit row because subscriber-supplied strings may carry T3 user content
  (CLAUDE.md hard rule #1).
* **Slice-1's :class:`alfred.audit.log.AuditWriter`** — keyword-only
  ``append(event, actor_user_id, subject, trust_tier_of_trigger, result,
  cost_estimate_usd, trace_id, actor_persona, persona_id,
  cost_actual_usd, language)``. Every fault-row append opens a FRESH
  short-lived session via the writer's own ``session_factory`` (see
  :func:`alfred.audit.log.AuditWriter.append`'s module docstring): this
  is the Decision 3.6 / memB-1 invariant the plan calls out — a
  ``write_failed`` row would otherwise try to write through the turn's
  POISONED session and raise ``InvalidRequestError``, losing the fault
  attribution. By delegating to :class:`AuditWriter`, the
  fresh-session-per-emit guarantee comes for free from the writer's
  existing contract.

Five invariants pinned (Task 7 acceptance):

1. **Signature-parity reflective drift-guard** (TE-1) — every required
   keyword-only parameter of :meth:`AuditWriter.append` is passed by
   :meth:`EpisodicAuditSink.emit` for every event. Mirrors Task 1's
   :class:`EpisodicRecordInput` drift-guard: the adapter cannot drift
   from ``append``'s signature without the test failing in CI before it
   can ship.
2. **Per-event field-mapping table** — for each of the six
   ``hooks.*`` event identifiers PR-A defines, the adapter writes the
   correct ``event``, ``result``, ``trust_tier_of_trigger``,
   ``subject``, and ``cost_estimate_usd=0.0``. The ``cost_estimate_usd``
   pin is load-bearing — :meth:`AuditWriter.append` requires it as a
   keyword-only no-default param, and hook-trace rows have no provider
   cost (the §0 field table specifies ``0.0``).
3. **``actor_user_id`` falls back to ``None``** when ``fields`` lacks a
   ``user_id`` key — which is the COMMON case because PR-A's emit
   schemas don't include user-data fields. The fallback is documented in
   the adapter module: PR-A's deliberate omission of user-content fields
   from the audit-row schemas (CLAUDE.md hard rule #1) means the
   adapter sees only system-emitted identifiers.
4. **Loud failure on :meth:`AuditWriter.append` raise** — an exception
   from the writer propagates uncaught through :meth:`emit`. CLAUDE.md
   hard rule #7 — no silent failures in security paths. The hook
   dispatcher (PR-A) is the layer that decides how to react to a failed
   audit write; the adapter must not swallow.
5. **Fresh session per emit** — the underlying :class:`AuditWriter`'s
   ``session_factory`` is called once per :meth:`emit` invocation, so
   the Decision 3.6 / memB-1 fresh-session invariant holds even after
   the turn's session has been marked failed-state. Proves the
   "session_scope factory called twice for two emits" semantic the plan
   calls out, expressed at the writer's contract surface.
"""

from __future__ import annotations

import dataclasses
import inspect
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit.log import AuditWriter
from alfred.hooks.audit_sink import (
    HOOKS_CHAIN_TIMEOUT,
    HOOKS_ERROR_SUPPRESSED,
    HOOKS_REENTRY_BYPASS,
    HOOKS_REFUSAL,
    HOOKS_SUBSCRIBER_ERROR,
    HOOKS_UNAUTHORIZED_REFUSAL,
    AuditSink,
)
from alfred.memory.hooks_audit_sink import (
    _SUBJECT_FIELDS_BY_EVENT,
    EpisodicAuditSink,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers — mock AuditWriter that records append() kwargs
# ──────────────────────────────────────────────────────────────────────


def _mock_session() -> AsyncMock:
    """AsyncSession surrogate matching the Slice-1 audit-log test helper.

    ``AsyncSession.add`` is sync; only ``flush`` / ``commit`` / ``execute``
    are async. Without this override, ``AsyncMock`` would coerce ``add``
    to async and emit a RuntimeWarning about an un-awaited coroutine.
    """
    session = AsyncMock()
    session.add = MagicMock()
    return session


def _factory_for(session: AsyncMock, calls: list[None]) -> Any:
    """Wrap a single session-mock in an async-context-manager factory.

    The ``calls`` list is appended-to on EVERY factory invocation so the
    fresh-session-per-emit test can count factory calls without relying
    on ``MagicMock.call_count`` (the factory is a plain async-cm
    function, not a ``MagicMock``).
    """

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncMock]:
        calls.append(None)
        yield session

    return _scope


def _build_writer_and_factory_calls() -> tuple[AuditWriter, list[None]]:
    """Return a real ``AuditWriter`` whose ``session_factory`` records its
    invocation count via the appended-to list.

    Proves the fresh-session-per-emit invariant at the writer's REAL
    contract surface — the same surface production code uses — rather
    than mocking the writer itself away.
    """
    session = _mock_session()
    calls: list[None] = []
    writer = AuditWriter(session_factory=_factory_for(session, calls))
    return writer, calls


# ──────────────────────────────────────────────────────────────────────
# 1. Adapter satisfies the AuditSink Protocol structurally
# ──────────────────────────────────────────────────────────────────────


class TestProtocolCompliance:
    """The adapter is structurally indistinguishable from PR-A's
    :class:`AuditSink` so the dispatcher's runtime check accepts it
    without a concrete-base relationship."""

    def test_adapter_is_runtime_audit_sink(self) -> None:
        writer, _ = _build_writer_and_factory_calls()
        adapter = EpisodicAuditSink(audit=writer)
        # ``AuditSink`` is ``@runtime_checkable`` — structural fit is
        # sufficient.
        assert isinstance(adapter, AuditSink)

    def test_emit_signature_matches_protocol(self) -> None:
        """:meth:`emit` exposes the same keyword-only shape as the
        Protocol — adding a positional arg here would silently re-order
        audit attribution at the dispatcher's call site."""
        sig = inspect.signature(EpisodicAuditSink.emit)
        # Drop ``self``; the remaining three must be keyword-only.
        params = [p for p in sig.parameters.values() if p.name != "self"]
        names = [p.name for p in params]
        assert names == ["event", "correlation_id", "fields"]
        for p in params:
            assert p.kind == inspect.Parameter.KEYWORD_ONLY


# ──────────────────────────────────────────────────────────────────────
# 2. Signature-parity reflective drift-guard (TE-1)
# ──────────────────────────────────────────────────────────────────────


def _append_required_kw_only_names() -> set[str]:
    """Names of every keyword-only parameter of :meth:`AuditWriter.append`
    that has NO default.

    These are the contractually-required kwargs every adapter call site
    MUST pass. If a future change adds a new required kwarg, this set
    grows and the drift-guard test fails the moment the adapter omits it.
    """
    sig = inspect.signature(AuditWriter.append)
    required: set[str] = set()
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        if param.kind != inspect.Parameter.KEYWORD_ONLY:
            continue
        if param.default is inspect.Parameter.empty:
            required.add(name)
    return required


class TestSignatureParityDriftGuard:
    """The adapter must pass EVERY required keyword-only param of
    :meth:`AuditWriter.append` on every :meth:`emit` call. Mirrors
    Task 1's :class:`EpisodicRecordInput` drift-guard pattern: a
    future ``append`` signature change surfaces as this test failing in
    CI rather than as a silent runtime ``TypeError`` at the first
    fault-row emission."""

    @pytest.mark.asyncio
    async def test_every_required_append_kwarg_is_passed(self) -> None:
        writer, _ = _build_writer_and_factory_calls()
        # Wrap ``append`` in an AsyncMock so we can introspect the kwargs
        # the adapter actually passed, without breaking the writer's
        # session-factory contract for OTHER tests.
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event=HOOKS_REFUSAL,
            correlation_id="corr-1",
            fields={
                "hookpoint": "memory.episodic.record.before_db_write",
                "kind": "pre",
                "subscriber_name": "dlp.subscribe",
                "subscriber_tier": "system",
            },
        )
        required = _append_required_kw_only_names()
        missing = required - recorded.keys()
        assert not missing, (
            f"EpisodicAuditSink.emit must pass every required kw-only "
            f"param of AuditWriter.append; missing: {sorted(missing)!r}"
        )

    @pytest.mark.asyncio
    async def test_cost_estimate_usd_is_zero(self) -> None:
        """The §0 field table specifies ``cost_estimate_usd=0.0`` for
        every hook-trace row — these rows carry no provider cost. The
        param is keyword-only no-default on :meth:`AuditWriter.append`
        so omitting it would be a ``TypeError`` at runtime, but the
        explicit value pin catches a regression that "fixes" both sides
        to a non-zero default."""
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event=HOOKS_CHAIN_TIMEOUT,
            correlation_id="corr-2",
            fields={
                "hookpoint": "memory.episodic.record.before_db_write",
                "kind": "pre",
                "deadline_seconds": 0.5,
                "cleanup_timed_out": False,
            },
        )
        assert recorded["cost_estimate_usd"] == 0.0


# ──────────────────────────────────────────────────────────────────────
# 3. Per-event field-mapping table
# ──────────────────────────────────────────────────────────────────────


# Plan §0 result-disposition vocabulary: refused / fault / bypass.
#
# Mapping rationale per event:
#
# * ``hooks.refusal`` / ``hooks.unauthorized_refusal`` — both are
#   refusals (an authorized one propagates, an unauthorized one is
#   audited-and-swallowed); both disposition as ``"refused"``.
# * ``hooks.chain_timeout`` / ``hooks.subscriber_error`` /
#   ``hooks.error_suppressed`` — fault states the chain entered;
#   ``"fault"``.
# * ``hooks.reentry_bypass`` — the dispatcher detected re-entry and
#   skipped the inner chain; ``"bypass"`` per §0.
_EVENT_RESULT_TABLE: list[tuple[str, str, Mapping[str, object]]] = [
    (
        HOOKS_REFUSAL,
        "refused",
        {
            "hookpoint": "memory.episodic.record.before_db_write",
            "kind": "pre",
            "subscriber_name": "dlp.refuse",
            "subscriber_tier": "system",
        },
    ),
    (
        HOOKS_UNAUTHORIZED_REFUSAL,
        "refused",
        {
            "hookpoint": "memory.episodic.record.before_db_write",
            "kind": "pre",
            "subscriber_name": "user_plugin.refuse",
            "subscriber_tier": "user-plugin",
        },
    ),
    (
        HOOKS_CHAIN_TIMEOUT,
        "fault",
        {
            "hookpoint": "memory.episodic.record.before_validate",
            "kind": "pre",
            "deadline_seconds": 0.5,
            "cleanup_timed_out": False,
        },
    ),
    (
        HOOKS_SUBSCRIBER_ERROR,
        "fault",
        {
            "hookpoint": "memory.episodic.record.after_flush",
            "kind": "post",
            "subscriber_name": "metrics.subscribe",
            "exception_type": "RuntimeError",
        },
    ),
    (
        HOOKS_ERROR_SUPPRESSED,
        "fault",
        {
            "hookpoint": "memory.episodic.record.write_failed",
            "kind": "error",
        },
    ),
    (
        HOOKS_REENTRY_BYPASS,
        "bypass",
        {
            "hookpoint": "memory.episodic.record.before_validate",
            "kind": "pre",
        },
    ),
]


class TestEventMapping:
    """Each of the six PR-A event identifiers maps to a specific
    ``result`` disposition and lands on :meth:`AuditWriter.append` with
    the expected kwargs. Table-driven so a future event addition lands
    as one row, not a fork of the test body."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("event", "expected_result", "fields"), _EVENT_RESULT_TABLE)
    async def test_event_maps_to_expected_append_call(
        self, event: str, expected_result: str, fields: Mapping[str, object]
    ) -> None:
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event=event,
            correlation_id="corr-evt",
            fields=fields,
        )

        # Event name forwards verbatim.
        assert recorded["event"] == event
        # Result disposition is the plan-locked value.
        assert recorded["result"] == expected_result
        # ``trust_tier_of_trigger`` is T0 — hook-trace rows are
        # system-emitted dispatcher events with no user content.
        # T0 is the only value the ``ck_audit_log_trust_tier_of_trigger``
        # check constraint accepts that semantically fits a
        # dispatcher-internal event.
        assert recorded["trust_tier_of_trigger"] == "T0"
        # ``cost_estimate_usd`` is always 0.0 for hook-trace rows.
        assert recorded["cost_estimate_usd"] == 0.0
        # Correlation id forwards verbatim as ``trace_id`` so the audit
        # log joins to the dispatcher's correlation graph.
        assert recorded["trace_id"] == "corr-evt"
        # The ``subject`` carries the PR-A fault-row schema fields so
        # the operator gets the per-event attribution (hookpoint, kind,
        # subscriber-name-and-type or deadline-and-cleanup, …) in a
        # single column.
        subject = recorded["subject"]
        assert isinstance(subject, dict)
        for key, value in fields.items():
            assert subject[key] == value


# ──────────────────────────────────────────────────────────────────────
# 4. actor_user_id falls back to None when fields lacks user_id
# ──────────────────────────────────────────────────────────────────────


class TestActorUserIdFallback:
    """PR-A's emit-site schemas do NOT include user-data fields
    (CLAUDE.md hard rule #1 — never log secrets; subscriber-supplied
    strings may carry T3 user content). The adapter must fall back to
    ``None`` for ``actor_user_id`` so :meth:`AuditWriter.append`'s
    ``str | None`` contract holds without a KeyError raise.

    The plan's §0 field table specifies
    ``actor_user_id=<from ctx.input.user_id when present, else None>``;
    the ``when present, else None`` clause is the documented fallback
    surface the adapter implements here."""

    @pytest.mark.asyncio
    async def test_actor_user_id_is_none_when_fields_lacks_user_id(self) -> None:
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event=HOOKS_SUBSCRIBER_ERROR,
            correlation_id="corr-3",
            fields={
                "hookpoint": "memory.episodic.record.after_flush",
                "kind": "post",
                "subscriber_name": "subscriber.fail",
                "exception_type": "RuntimeError",
            },
        )
        # Key was present (not raising on missing) AND was ``None``.
        assert "actor_user_id" in recorded
        assert recorded["actor_user_id"] is None


# ──────────────────────────────────────────────────────────────────────
# 5. Loud failure — append raise propagates uncaught
# ──────────────────────────────────────────────────────────────────────


class TestLoudFailure:
    """CLAUDE.md hard rule #7 — no silent failures in security paths.
    The adapter is a thin forwarder; an :meth:`AuditWriter.append`
    failure (DB down, conflict, integrity violation) MUST surface to
    the dispatcher, NOT be swallowed.

    The dispatcher (PR-A's ``_run_chain``) is the layer that decides
    how to surface an audit-write failure — typically by letting the
    exception propagate through the action's invoking-helper, which is
    what makes the failure operator-visible."""

    @pytest.mark.asyncio
    async def test_append_raise_propagates_uncaught(self) -> None:
        writer, _ = _build_writer_and_factory_calls()

        async def _raising_append(**kwargs: Any) -> None:
            raise RuntimeError("db down")

        writer.append = _raising_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        with pytest.raises(RuntimeError, match="db down"):
            await adapter.emit(
                event=HOOKS_CHAIN_TIMEOUT,
                correlation_id="corr-4",
                fields={
                    "hookpoint": "memory.episodic.record.after_flush",
                    "kind": "post",
                    "deadline_seconds": 0.5,
                    "cleanup_timed_out": False,
                },
            )


# ──────────────────────────────────────────────────────────────────────
# 6. Fresh session per emit — Decision 3.6 / memB-1
# ──────────────────────────────────────────────────────────────────────


class TestFreshSessionPerEmit:
    """Every :meth:`emit` invocation MUST trigger a fresh session open
    through the underlying :class:`AuditWriter`'s ``session_factory``.

    This is the Decision 3.6 / memB-1 invariant: a ``write_failed`` fault
    fires after the turn's flush failed, which leaves the turn's session
    in a poisoned ``InvalidRequestError`` state. Appending the fault row
    through the SAME session would lose the row. By delegating to
    :meth:`AuditWriter.append`, which itself opens its ``session_factory``
    on every call, the fresh-session-per-emit semantic comes for free —
    the test below proves the factory IS being re-invoked, not just
    that the writer was called twice.

    Two emits → two factory invocations is the load-bearing assertion;
    the plan's "session_scope factory called twice" pin expressed at the
    real writer surface."""

    @pytest.mark.asyncio
    async def test_factory_called_once_per_emit(self) -> None:
        writer, factory_calls = _build_writer_and_factory_calls()
        adapter = EpisodicAuditSink(audit=writer)

        await adapter.emit(
            event=HOOKS_REENTRY_BYPASS,
            correlation_id="corr-A",
            fields={
                "hookpoint": "memory.episodic.record.before_validate",
                "kind": "pre",
            },
        )
        await adapter.emit(
            event=HOOKS_REENTRY_BYPASS,
            correlation_id="corr-B",
            fields={
                "hookpoint": "memory.episodic.record.before_validate",
                "kind": "pre",
            },
        )

        # Each emit MUST have triggered ONE factory invocation. Two
        # emits → two fresh sessions.
        assert len(factory_calls) == 2


# ──────────────────────────────────────────────────────────────────────
# 7. Frozen-immutability runtime guard (I2)
# ──────────────────────────────────────────────────────────────────────


class TestSinkIsFrozen:
    """Construction-time configuration is the only path to setting the
    sink's :class:`AuditWriter`. A frozen+slots dataclass makes a
    post-construction swap structurally impossible: a hostile subscriber
    (or a future refactor that drops ``@dataclass(frozen=True)``) cannot
    re-target the writer between construction and dispatch.

    This pins the invariant at the test surface so a refactor that
    accidentally drops ``frozen=True`` fails this test BEFORE landing
    on main."""

    def test_audit_attribute_is_frozen_after_construction(self) -> None:
        writer, _ = _build_writer_and_factory_calls()
        sink = EpisodicAuditSink(audit=writer)
        # Attempting to swap the writer must raise — frozen dataclass
        # contract. ``slots=True`` additionally precludes adding any new
        # attribute (also tested below for belt-and-braces).
        with pytest.raises(dataclasses.FrozenInstanceError):
            sink.audit = writer  # type: ignore[misc]

    def test_unknown_attribute_assignment_is_rejected(self) -> None:
        """slots=True pin — the dataclass exposes ONLY the declared
        ``audit`` field. Anything else fails ``AttributeError`` (slots'
        contract; not ``FrozenInstanceError``)."""
        writer, _ = _build_writer_and_factory_calls()
        sink = EpisodicAuditSink(audit=writer)
        # slots=True precludes adding arbitrary attributes; frozen=True
        # would ALSO catch this. Either way, the assignment fails.
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            sink.poisoned_attribute = "x"  # type: ignore[attr-defined]


# ──────────────────────────────────────────────────────────────────────
# 8. Per-event subject projection (I1)
# ──────────────────────────────────────────────────────────────────────
#
# Security review (PR-B Task 7) flagged the previous ``subject =
# dict(fields)`` blind-forward as structurally trusting. The adapter now
# projects ``fields`` through :data:`_SUBJECT_FIELDS_BY_EVENT`, an
# explicit per-event allowlist that mirrors the §0 schema constants in
# :mod:`alfred.hooks.invoke`. These tests pin the projection's three
# load-bearing properties:
#
# 1. **Allowlist matches the §0 schemas verbatim.** A drift between
#    PR-A's ``_*_AUDIT_FIELDS`` constants and the adapter's mirror
#    table fails this test.
# 2. **Unknown keys are dropped.** A field key the allowlist does NOT
#    name never lands in the durable ``subject`` JSONB column — the
#    CLAUDE.md hard rule #1 hardening the I1 mitigation buys.
# 3. **Unmapped event defaults to an empty subject + a warning.** A
#    new event that lands without a registered allowlist degrades
#    gracefully (no crash) but loudly (operator-visible drift signal).


# Expected per-event allowed keys — mirrors
# :data:`alfred.memory.hooks_audit_sink._SUBJECT_FIELDS_BY_EVENT` and is
# itself a paranoia copy: if a future PR-A schema change updates BOTH
# the production constant AND the test constant (e.g. via a CodeRabbit
# auto-fix), we want the test author to acknowledge the update — so the
# test mirror is duplicated here verbatim rather than imported.
_EXPECTED_SUBJECT_FIELDS_BY_EVENT: Mapping[str, frozenset[str]] = {
    HOOKS_REFUSAL: frozenset({"hookpoint", "kind", "subscriber_name", "subscriber_tier"}),
    HOOKS_UNAUTHORIZED_REFUSAL: frozenset(
        {"hookpoint", "kind", "subscriber_name", "subscriber_tier"}
    ),
    HOOKS_CHAIN_TIMEOUT: frozenset({"hookpoint", "kind", "deadline_seconds", "cleanup_timed_out"}),
    HOOKS_SUBSCRIBER_ERROR: frozenset({"hookpoint", "kind", "subscriber_name", "exception_type"}),
    HOOKS_ERROR_SUPPRESSED: frozenset({"hookpoint", "kind", "subscriber_name", "exception_type"}),
    HOOKS_REENTRY_BYPASS: frozenset({"hookpoint", "kind"}),
}


class TestSubjectAllowlist:
    """The per-event subject projection MUST land only the schema-named
    keys in the durable ``subject`` column, regardless of what PR-A's
    dispatcher (or a future emitter) passes in the ``fields`` mapping.
    """

    def test_allowlist_matches_per_event_schema(self) -> None:
        """The adapter's per-event allowlist matches the test mirror
        verbatim. A drift between PR-A's schema constants and the
        adapter's mirror table surfaces here as a failing test, NOT as a
        silent T3-bearing key sneaking into the audit row."""
        assert dict(_SUBJECT_FIELDS_BY_EVENT) == dict(_EXPECTED_SUBJECT_FIELDS_BY_EVENT)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("event", "expected_keys"),
        [
            (HOOKS_REFUSAL, _EXPECTED_SUBJECT_FIELDS_BY_EVENT[HOOKS_REFUSAL]),
            (
                HOOKS_UNAUTHORIZED_REFUSAL,
                _EXPECTED_SUBJECT_FIELDS_BY_EVENT[HOOKS_UNAUTHORIZED_REFUSAL],
            ),
            (HOOKS_CHAIN_TIMEOUT, _EXPECTED_SUBJECT_FIELDS_BY_EVENT[HOOKS_CHAIN_TIMEOUT]),
            (
                HOOKS_SUBSCRIBER_ERROR,
                _EXPECTED_SUBJECT_FIELDS_BY_EVENT[HOOKS_SUBSCRIBER_ERROR],
            ),
            (
                HOOKS_ERROR_SUPPRESSED,
                _EXPECTED_SUBJECT_FIELDS_BY_EVENT[HOOKS_ERROR_SUPPRESSED],
            ),
            (HOOKS_REENTRY_BYPASS, _EXPECTED_SUBJECT_FIELDS_BY_EVENT[HOOKS_REENTRY_BYPASS]),
        ],
    )
    async def test_event_projects_exactly_the_schema_keys(
        self, event: str, expected_keys: frozenset[str]
    ) -> None:
        """For every PR-A event, the subject column receives EXACTLY the
        schema's keys — no more, no less — when the caller passes the
        schema's keys."""
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        # Build a synthetic ``fields`` mapping containing exactly the
        # schema-named keys with sentinel values. The values are opaque
        # — only key projection is under test.
        fields = {key: f"value-{key}" for key in expected_keys}
        await adapter.emit(event=event, correlation_id="corr-allow", fields=fields)

        subject = recorded["subject"]
        assert isinstance(subject, dict)
        assert set(subject.keys()) == set(expected_keys)
        # Values forward unchanged for the allowed keys.
        for key in expected_keys:
            assert subject[key] == f"value-{key}"

    @pytest.mark.asyncio
    async def test_unknown_fields_are_dropped(self) -> None:
        """Keys not on the per-event allowlist NEVER land in the
        durable ``subject``. This is the I1 hardening: a future
        schema-widening (or a foreign emitter reusing the Protocol)
        cannot smuggle a T3-bearing key past the adapter."""
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        # Schema-conforming keys PLUS an extra "rogue" key the
        # allowlist does NOT name. The rogue key's value is a string
        # that would obviously be a CLAUDE.md hard rule #1 violation
        # if persisted ("hunter2" as a stand-in for a T3-tainted
        # value).
        fields = {
            "hookpoint": "memory.episodic.record.before_db_write",
            "kind": "pre",
            "subscriber_name": "rogue.subscribe",
            "subscriber_tier": "user-plugin",
            "rogue_t3_smuggled_key": "hunter2",  # MUST be dropped
            "another_unknown": {"nested": "payload"},  # MUST be dropped
        }
        await adapter.emit(event=HOOKS_REFUSAL, correlation_id="corr-rogue", fields=fields)

        subject = recorded["subject"]
        assert isinstance(subject, dict)
        # The allowed keys land.
        assert subject == {
            "hookpoint": "memory.episodic.record.before_db_write",
            "kind": "pre",
            "subscriber_name": "rogue.subscribe",
            "subscriber_tier": "user-plugin",
        }
        # The rogue keys are dropped — the audit row never sees them.
        assert "rogue_t3_smuggled_key" not in subject
        assert "another_unknown" not in subject

    @pytest.mark.asyncio
    async def test_unmapped_event_yields_empty_subject(self) -> None:
        """An event id NOT in :data:`_SUBJECT_FIELDS_BY_EVENT` degrades
        gracefully — the row still writes (loud failure on the writer
        layer is a separate concern), but with an empty subject. The
        result disposition falls back to ``"fault"`` (the loud-failure
        default) so the operator sees the unknown event as a fault
        row."""
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event="hooks.totally_new_event_pra_added_yesterday",
            correlation_id="corr-unmapped",
            fields={"hookpoint": "x", "kind": "pre", "anything": "at all"},
        )

        # No allowlist → empty subject. The schema-conforming row STILL
        # writes; the operator sees the unknown event via:
        #   1. The empty ``subject`` (visible drift signal).
        #   2. ``result == "fault"`` (the §0 loud-failure default).
        #   3. The structlog warning at the adapter boundary (covered
        #      by ``test_unmapped_event_logs_warning`` below).
        assert recorded["subject"] == {}
        assert recorded["result"] == "fault"

    @pytest.mark.asyncio
    async def test_unmapped_event_logs_warning(self) -> None:
        """Unmapped event → structlog warning at the adapter boundary so
        the operator sees the divergence even when the audit row's
        ``subject`` would otherwise be empty / indistinguishable from a
        legitimate empty-payload event.

        Uses :func:`structlog.testing.capture_logs` rather than pytest's
        ``caplog`` fixture because structlog's default configuration in
        this project writes through its own ConsoleRenderer pipeline
        rather than through stdlib ``logging`` — ``caplog`` therefore
        misses the message even though it lands on stdout."""
        import structlog.testing

        writer, _ = _build_writer_and_factory_calls()

        async def _capturing_append(**kwargs: Any) -> None:
            pass

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        with structlog.testing.capture_logs() as captured:
            await adapter.emit(
                event="hooks.unknown_event",
                correlation_id="corr-unknown",
                fields={"hookpoint": "x", "kind": "pre"},
            )

        # The event key ``episodic_audit_sink.unmapped_event`` is the
        # load-bearing identifier operators dashboard for; the
        # ``hook_event`` field carries the unknown event id.
        unmapped = [c for c in captured if c.get("event") == "episodic_audit_sink.unmapped_event"]
        assert len(unmapped) == 1, f"expected one unmapped warning, got: {captured!r}"
        assert unmapped[0]["log_level"] == "warning"
        assert unmapped[0]["hook_event"] == "hooks.unknown_event"
        assert unmapped[0]["correlation_id"] == "corr-unknown"

    @pytest.mark.asyncio
    async def test_mapped_event_with_dropped_keys_logs_warning(self) -> None:
        """A MAPPED event whose ``fields`` contains keys the allowlist
        does NOT name → structlog warning naming the dropped keys (but
        NOT their values, which could carry T3 content)."""
        import structlog.testing

        writer, _ = _build_writer_and_factory_calls()

        async def _capturing_append(**kwargs: Any) -> None:
            pass

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        with structlog.testing.capture_logs() as captured:
            await adapter.emit(
                event=HOOKS_REFUSAL,
                correlation_id="corr-dropkeys",
                fields={
                    "hookpoint": "memory.episodic.record.before_db_write",
                    "kind": "pre",
                    "subscriber_name": "x",
                    "subscriber_tier": "system",
                    "extra_unknown": "value_with_possibly_t3_content",
                },
            )

        dropped = [
            c for c in captured if c.get("event") == "episodic_audit_sink.dropped_subject_keys"
        ]
        assert len(dropped) == 1, f"expected one dropped-keys warning, got: {captured!r}"
        assert dropped[0]["log_level"] == "warning"
        # The dropped KEY NAME appears (it's a schema-level identifier,
        # safe to log).
        assert dropped[0]["dropped_keys"] == ["extra_unknown"]
        # The dropped VALUE must NOT appear anywhere in the captured
        # record (potential T3 — CLAUDE.md hard rule #1).
        assert "value_with_possibly_t3_content" not in str(dropped[0])


# ──────────────────────────────────────────────────────────────────────
# 9. Narrowing helpers — _optional_str / _str_with_default branch coverage
# ──────────────────────────────────────────────────────────────────────
#
# Task 11 review-gap closure. The adapter's two narrowing helpers
# (:func:`_optional_str` and :func:`_str_with_default`) each have a
# str-passthrough branch and a non-str ``TypeError`` branch that the
# existing tests don't exercise — :class:`TestActorUserIdFallback` covers
# only the ``None`` branch of :func:`_optional_str`, and no test exercises
# the str-passthrough or non-str branches of either helper. These tests
# close those gaps end-to-end at the :meth:`emit` surface (no direct
# helper-import — the public surface is the only thing callers see, and
# pinning behaviour there means a refactor that inlines the helpers still
# keeps the invariant).
#
# Why through ``emit`` rather than calling the helpers directly:
#
# * The helpers are module-private (``_``-prefixed) and the public
#   contract is the :meth:`emit` keyword-only surface. Pinning at the
#   public surface is robust to a future refactor that inlines or
#   renames the helpers.
# * The ``user_id`` → ``actor_user_id`` and ``language`` → ``language``
#   paths through :meth:`emit` are the production call sites for these
#   helpers; a regression that changes the narrowing semantic shows up
#   here as a behavioural failure, not just a unit-test failure on a
#   private function.


class TestNarrowingHelpersBranchCoverage:
    """Cover the str-passthrough and non-str ``TypeError`` branches of
    :func:`_optional_str` and :func:`_str_with_default` end-to-end at the
    :meth:`emit` surface.

    :class:`TestActorUserIdFallback` above already covers the ``None``
    branch of :func:`_optional_str` (PR-A's common case: ``user_id`` not
    in ``fields``). These four tests pin the remaining branches:

    1. :func:`_optional_str` with a ``str`` value forwards verbatim to
       ``actor_user_id``.
    2. :func:`_optional_str` with a non-``str`` value raises
       :class:`TypeError` at the adapter boundary — surfacing the misuse
       BEFORE the database write (CLAUDE.md hard rule #7 — loud failure
       in security paths; a non-string ``user_id`` cannot scope to a
       user and would be a partition-leak surface downstream).
    3. :func:`_str_with_default` with a ``str`` value forwards verbatim
       to ``language``.
    4. :func:`_str_with_default` with a non-``str`` value raises
       :class:`TypeError` — same loud-failure discipline as
       :func:`_optional_str`, applied to the writer's non-nullable
       ``language`` column.
    """

    @pytest.mark.asyncio
    async def test_optional_str_passthrough_for_string_user_id(self) -> None:
        """A ``str`` ``user_id`` in ``fields`` forwards verbatim to
        ``actor_user_id``. Mirrors :class:`TestActorUserIdFallback` but
        with the value present — the str-passthrough branch of
        :func:`_optional_str`."""
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event=HOOKS_SUBSCRIBER_ERROR,
            correlation_id="corr-pass-uid",
            fields={
                "user_id": "alice",
                "hookpoint": "memory.episodic.record.after_flush",
                "kind": "post",
                "subscriber_name": "subscriber.fail",
                "exception_type": "RuntimeError",
            },
        )
        assert recorded["actor_user_id"] == "alice"

    @pytest.mark.asyncio
    async def test_optional_str_raises_typeerror_on_non_string_user_id(self) -> None:
        """A non-``str`` ``user_id`` raises :class:`TypeError` at the
        adapter boundary. Surfaces the misuse loudly BEFORE the database
        write — a non-string ``user_id`` cannot partition to a user and
        would otherwise be a downstream type error AND a partition-leak
        surface (CLAUDE.md hard rule #7 — loud failure in security
        paths)."""
        writer, _ = _build_writer_and_factory_calls()

        async def _capturing_append(**kwargs: Any) -> None:
            pass

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        with pytest.raises(TypeError, match="actor field"):
            await adapter.emit(
                event=HOOKS_SUBSCRIBER_ERROR,
                correlation_id="corr-bad-uid",
                fields={
                    "user_id": 42,  # non-string — must raise at adapter boundary
                    "hookpoint": "memory.episodic.record.after_flush",
                    "kind": "post",
                    "subscriber_name": "subscriber.fail",
                    "exception_type": "RuntimeError",
                },
            )

    @pytest.mark.asyncio
    async def test_str_with_default_passthrough_for_string_language(self) -> None:
        """A ``str`` ``language`` in ``fields`` forwards verbatim to the
        writer's ``language`` column. The str-passthrough branch of
        :func:`_str_with_default` — distinct from the default-fallback
        branch (``"en-US"`` when absent) which other tests cover
        implicitly."""
        writer, _ = _build_writer_and_factory_calls()
        recorded: dict[str, Any] = {}

        async def _capturing_append(**kwargs: Any) -> None:
            recorded.update(kwargs)

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        await adapter.emit(
            event=HOOKS_SUBSCRIBER_ERROR,
            correlation_id="corr-pass-lang",
            fields={
                "language": "fr-CA",
                "hookpoint": "memory.episodic.record.after_flush",
                "kind": "post",
                "subscriber_name": "subscriber.fail",
                "exception_type": "RuntimeError",
            },
        )
        assert recorded["language"] == "fr-CA"

    @pytest.mark.asyncio
    async def test_str_with_default_raises_typeerror_on_non_string_language(self) -> None:
        """A non-``str`` ``language`` raises :class:`TypeError` at the
        adapter boundary. Same loud-failure discipline as
        :func:`_optional_str`, applied to the writer's non-nullable
        ``language`` column — a non-string value cannot be a valid
        BCP-47 tag and would be a downstream type error at the database
        write."""
        writer, _ = _build_writer_and_factory_calls()

        async def _capturing_append(**kwargs: Any) -> None:
            pass

        writer.append = _capturing_append  # type: ignore[method-assign]

        adapter = EpisodicAuditSink(audit=writer)
        with pytest.raises(TypeError, match="i18n field"):
            await adapter.emit(
                event=HOOKS_SUBSCRIBER_ERROR,
                correlation_id="corr-bad-lang",
                fields={
                    "language": 42,  # non-string — must raise at adapter boundary
                    "hookpoint": "memory.episodic.record.after_flush",
                    "kind": "post",
                    "subscriber_name": "subscriber.fail",
                    "exception_type": "RuntimeError",
                },
            )
