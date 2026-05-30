"""Slice-2.5 PR-B integration tests against real Postgres.

This module ships TWO classes of integration assertion:

* **Task 3 — golden-row regression baseline.** With zero hookpoint
  subscribers, :meth:`EpisodicMemory.record` writes a row byte-identical
  to the pre-hooks code path. The unit-level characterization tests
  (``tests/unit/memory/test_episodic_hooks_wiring.py``) pin the
  session-call shape against an ``AsyncMock``; this is the matching
  real-Postgres assertion that nothing in the round-trip — flush
  ordering, SQLAlchemy default callable invocation, Python-side type
  coercion — drifts under the hook plumbing.
* **Task 8 — no-recursion / fresh-session assertions.** The two tests
  at the bottom prove spec §6.8's recursion argument AND Decision 3.6
  /memB-1's fresh-session durability hold in practice against real
  Postgres with the real :class:`EpisodicAuditSink`. EXACT-count
  assertions (``post - pre == 1``, not ``>= 1``) pin the no-unbounded-
  rows invariant — an off-by-cascade bug would otherwise pass a
  ``>= 1`` check.

Why a *separate* integration test rather than promoting the unit
assertions into the unit suite:

* The unit suite pins what ``record`` hands to ``session.add`` + the
  exact mock-method call surface. It cannot pin what the *database*
  ends up holding once SQLAlchemy fires its Python-side default
  callables (``uuid4`` for ``id``, ``_now`` for ``created_at``,
  ``dict`` for ``metadata_``) at flush time.
* memB-2 (Task 2 hardening decision): those three columns are populated
  by **Python-side defaults**, not server-side ``server_default``
  migrations. A future contributor who notices ``NULL``-allowing columns
  could be tempted to add ``server_default=func.gen_random_uuid()`` to
  ``id`` "for safety"; that would silently break the Python-side ORM
  contract every caller depends on. This test pins the Python-side path.
* Decision 3.6 / memB-1 only manifests against a REAL session lifecycle:
  the turn session must be ACTUALLY poisoned (``IntegrityError`` after
  a CHECK-constraint violation) for the fresh-session-per-emit
  semantic to be observable. An ``AsyncMock`` session would silently
  accept any subsequent call and the test would prove nothing.

Why the explicit ``session.commit()`` in the golden-row test:

* mem-1 (spec §3 / pluggable-hooks design): the post hookpoint name is
  :data:`HookKind.AFTER_FLUSH`, NOT ``committed``. ``after_flush`` fires
  immediately after ``session.flush()`` — i.e. SQL emitted, transaction
  durability NOT yet established. The golden-row test commits explicitly
  to prove the *persisted* row matches the input — but the commit is the
  *test's* durability boundary, not the hook's. A future reader who
  proposes renaming ``AFTER_FLUSH`` to ``AFTER_COMMIT`` (or, equivalently,
  delaying post-hook dispatch until ``session.commit()`` returns) must
  re-read this comment first: the hook is intentionally pre-commit so
  subscribers can refuse with full transactional rollback. The test's
  ``commit`` is a *readback* tool, not a durability claim about the
  hookpoint.

Conventions: real Postgres via testcontainers (alfred-memory-engineer
quality bar — write paths get real DB, not in-memory fakes); per-test
container via the ``pg_engine`` / ``session`` / ``session_factory``
fixtures in :mod:`tests.integration.memory.conftest`; EXACT-count
assertions on the no-recursion bound (the off-by-cascade bug Task 8
exists to catch would silently pass any ``>= 1`` predicate).
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.audit.log import AuditWriter
from alfred.hooks.capability import DevGate
from alfred.hooks.context import HookContext
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.memory.episodic import EpisodicMemory, EpisodicRecordInput
from alfred.memory.hooks_audit_sink import EpisodicAuditSink
from alfred.memory.models import AuditEntry, Episode

# Representative payload — every field non-default where a default exists,
# so the byte-identity assertion exercises the real value-flow rather than
# just whatever ``EpisodicRecordInput`` would have filled in. Mirrors the
# unit suite's ``_RECORD_KWARGS`` shape (10 fields, same names) so a single
# update to ``record``'s signature breaks both layers in step.
#
# ``language="ja-JP"`` is deliberately non-en-US: CLAUDE.md i18n rule #3
# pins per-row language storage, and the byte-identity check is the only
# place that asserts the non-default value survives the round-trip on the
# write side (the working-pool tests cover the read side).
_GOLDEN_KWARGS: dict[str, object] = {
    "user_id": "u-123",
    "role": "user",
    "content": "hello alfred",
    "trust_tier": "T2",
    "tokens_in": 10,
    "tokens_out": 20,
    "cost_usd": 0.000_3,
    "persona": "alfred",
    "persona_id": "alfred-default",
    "language": "ja-JP",
}


# Helper: snapshot the audit_log row count using the writer's own fresh
# session factory — NOT the (possibly poisoned) turn session. The Task 8
# tests rely on EXACT-count assertions on this snapshot; reading through
# the turn session would conflate audit attribution with the test's own
# transaction state and silently break the bound on the
# fresh-session-fault test (where the turn session is intentionally
# poisoned by an ``IntegrityError`` and any read on it would itself
# raise).
async def _audit_count_via_factory(
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> int:
    """Return the total row count in ``audit_log`` via a fresh session.

    Read path independent of the turn session so a poisoned turn session
    cannot stall the count snapshot. The factory yields a committed
    session (mirrors ``build_session_scope``); reads inside it see every
    durable row, including those the ``AuditWriter`` has written in
    parallel from its own fresh sessions on the same engine.
    """
    async with session_factory() as s:
        result = await s.execute(select(func.count()).select_from(AuditEntry))
        return int(result.scalar_one())


@pytest.mark.integration
async def test_zero_subscriber_row_byte_identical(
    session: AsyncSession,
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """With zero hookpoint subscribers, ``record`` writes a row byte-identical
    to the pre-hooks code path.

    This is the BASELINE for Slice-2.5 PR-B: Tasks 4-9 add hookpoint
    wiring, validation, and an audit sink on top of ``_persist``. Any one
    of those tasks that mutates the persisted row shape (extra column
    written, default callable swapped, type coercion changed) trips this
    assertion immediately. The Task 8 tests below complement this
    baseline by pinning the no-recursion / fresh-session invariants on
    top of the same ``_persist`` path.

    mem-1: ``after_flush`` fires post-``flush``, pre-commit. The test
    commits explicitly to prove the *persisted bytes* match the input,
    NOT to claim the hook means durability. A reader proposing to rename
    ``AFTER_FLUSH`` → ``COMMITTED`` must re-read the module docstring's
    mem-1 paragraph before doing so.

    memB-2: ``id``, ``created_at``, ``metadata_`` are populated by their
    ORM Python-side defaults (``uuid4``, ``_now``, ``dict``) applied at
    flush time — NOT by ``server_default`` migrations. This test pins the
    Python-side path so a future contributor cannot silently introduce a
    server-side default and re-route the default-callable code path.

    Readback uses ``session_factory()`` (a FRESH session) rather than the
    write-session: with ``expire_on_commit=False`` on the per-test
    sessionmaker, SQLAlchemy's identity map would otherwise hand back the
    in-memory instance attached to the write session, so the byte-identity
    assertions would stay green even if persistence were broken at the DB
    layer. A fresh session forces a real SELECT against the durable
    Postgres row — the byte-identity claim is genuinely "round-trip via
    Postgres", not "round-trip via the ORM cache".
    """
    # Zero-subscriber registry, swap-and-restore around the call. Mirrors
    # the ``fresh_registry`` fixture in ``tests/unit/hooks/conftest.py``
    # but kept inline because that fixture lives in a different scope
    # tree — moving it would force a unit-scope conftest into the
    # integration tier, blurring the layering. The default
    # :class:`StructlogAuditSink` is fine here: with zero subscribers no
    # fault-path audit row ever fires, so the sink choice is invisible.
    prior = get_registry()
    fresh_reg = HookRegistry(gate=DevGate())
    set_registry(fresh_reg)
    try:
        memory = EpisodicMemory(session=session)
        await memory.record(**_GOLDEN_KWARGS)  # type: ignore[arg-type]
        # Explicit commit so the round-trip readback below sees the row.
        # See module docstring's mem-1 paragraph: the commit is the
        # TEST'S durability boundary, not the hook's.
        await session.commit()
    finally:
        set_registry(prior)

    # Round-trip readback via a FRESH session (NOT the write session).
    # ``expire_on_commit=False`` on the per-test sessionmaker means a
    # readback through the write session would resolve through SQLAlchemy's
    # identity map and could hand back the in-memory instance — the
    # assertions would stay green even if the row never reached Postgres.
    # A new session on the same engine forces a real SELECT against the
    # durable row, so the byte-identity claim is grounded in DB state.
    #
    # All ``row.*`` assertions live INSIDE the ``async with`` so attribute
    # access happens while the fresh session is still open — once the
    # session closes, lazy-loaded attribute access would re-trigger an
    # I/O on a closed session and raise. ``user_id`` is the only filter
    # we need; the container is fresh per test (the ``session`` fixture's
    # ``PostgresContainer`` scope), so exactly one row exists.
    async with session_factory() as fresh:
        result = await fresh.execute(select(Episode).where(Episode.user_id == "u-123"))
        row = result.scalar_one()

        # --- Input-derived columns: every field of _GOLDEN_KWARGS must
        # survive the round-trip verbatim. Iterating the dict (rather
        # than 10 hand assertions) means adding an 11th kwarg to
        # ``record`` + ``Episode`` is covered the moment ``_GOLDEN_KWARGS``
        # is updated. The unit-level ``test_episodic_record_input.py``
        # drift-guard pins that ``EpisodicRecordInput`` mirrors ``record``'s
        # signature, so the set of names traversed here cannot silently
        # shrink.
        for field_name, expected_value in _GOLDEN_KWARGS.items():
            assert getattr(row, field_name) == expected_value, (
                f"field {field_name!r} did not survive the Postgres round-trip"
            )

        # --- memB-2 columns: populated by Python-side defaults at flush
        # time. The assertions are *shape* assertions, not value
        # assertions — the actual UUID / timestamp / dict values are
        # non-deterministic. What we pin is: they are non-null AND of the
        # expected Python type, which together prove the Python-side
        # default callable fired.
        assert row.id is not None
        assert isinstance(row.id, uuid.UUID), (
            "id must be a uuid.UUID — uuid4 default callable applied Python-side, "
            "not a server_default migration (memB-2)"
        )
        assert row.created_at is not None
        assert isinstance(row.created_at, dt.datetime), (
            "created_at must be a datetime — _now() default callable applied "
            "Python-side, not a server_default migration (memB-2)"
        )
        assert row.created_at.tzinfo is not None, (
            "_now() returns UTC-aware datetimes; tzinfo loss indicates a default callable swap"
        )
        assert row.metadata_ == {}, (
            "metadata_ must default to an empty dict via the ``dict`` default "
            "callable (memB-2); a non-empty default would mean a side-effect "
            "leaked into the ORM-level Python default"
        )


# ──────────────────────────────────────────────────────────────────────
# Task 8 — no-recursion / fresh-session integration assertions
# ──────────────────────────────────────────────────────────────────────
#
# The two tests below prove spec §6.8's recursion argument AND Decision
# 3.6 / memB-1's fresh-session durability hold in practice. The key
# discipline is the EXACT-count assertion (``post - pre == 1``, NOT
# ``>= 1``): a recursive cascade or a missed loud-failure would produce
# N>1 rows AND any ``>= 1`` predicate would silently pass that bug. The
# EXACT bound surfaces the off-by-cascade defect the moment it lands.


# Subset of the golden payload used by the Task 8 tests. Same shape as
# ``_GOLDEN_KWARGS`` but the fields the Task 8 assertions care about are
# the input arguments — not the round-trip readback — so a minimal kwarg
# set keeps the test focused on the no-recursion / fresh-session invariant.
_TASK8_KWARGS: dict[str, object] = {
    "user_id": "u-task8",
    "role": "user",
    "content": "task-8 payload",
    "trust_tier": "T2",
    "language": "en-US",
}


@pytest.mark.integration
async def test_audit_sink_no_recursion(
    session: AsyncSession,
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """One fault-emitting subscriber produces EXACTLY ONE audit row.

    Spec §6.8 + alfred-core-engineer-1: ``audit.append`` (and therefore
    the :class:`EpisodicAuditSink` forwarder) MUST NOT re-enter
    ``memory.episodic.record`` — if it did, the fault-row append would
    fire its own ``hooks.subscriber_error`` cascade and the recursion
    would compound until the chain deadline or the stack limit fired.

    This test PROVES that bound holds end-to-end with a real
    :class:`AuditWriter` + real :class:`EpisodicAuditSink` + real
    Postgres. A subscriber on the open ``before_validate`` hookpoint
    raises :class:`ValueError`; the dispatcher's
    :func:`_emit_subscriber_error_audit` (PR-A Task 10) writes ONE
    ``hooks.subscriber_error`` row through the sink AND continues the
    chain (``fail_closed=False`` default on ``before_validate``) so
    ``_persist`` still runs and the Episode lands.

    The EXACT-count assertion (``post - pre == 1``) is the proof: a
    recursive cascade would produce N>1 rows and a ``>= 1`` predicate
    would silently pass that bug. The bound is also what makes Task 7's
    "PoC-is-not-audit.append" design choice operator-observable —
    rewiring the sink to re-enter ``record`` would land here as N>1.
    """
    prior = get_registry()
    # System tier permitted so the test could grow a system-tier
    # subscriber without rewriting the fixture; the subscriber registered
    # below is operator-tier (allow_system is irrelevant to its grant).
    registry = HookRegistry(
        gate=DevGate(allow_system=True),
        sink=EpisodicAuditSink(audit=AuditWriter(session_factory=session_factory)),
    )
    set_registry(registry)
    try:
        # The fault-emitting subscriber: a buggy operator-tier
        # ``before_validate`` hook that raises a generic exception. Per
        # PR-A Task 10's contract on the pre chain with
        # ``fail_closed=False`` (the default :meth:`Flow.pre` value for
        # ``before_validate``): the dispatcher emits ONE
        # ``hooks.subscriber_error`` audit row, rewinds ``chain_ctx`` to
        # last-good, and the chain continues. The action body still runs.
        async def buggy_subscriber(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            raise ValueError("simulated subscriber bug")

        registry.register(
            hook_fn=buggy_subscriber,
            hookpoint="before_validate",
            kind="pre",
            tier="operator",
        )

        # Snapshot via the writer's fresh-session factory — NOT the turn
        # session — so the count surface is independent of any
        # transaction state the turn session accumulates during the
        # ``record`` call below.
        pre_count = await _audit_count_via_factory(session_factory)

        memory = EpisodicMemory(session=session)
        await memory.record(**_TASK8_KWARGS)  # type: ignore[arg-type]
        await session.commit()  # Make the Episode durable for the readback assertion below.

        post_count = await _audit_count_via_factory(session_factory)
    finally:
        set_registry(prior)

    # EXACT-count assertion — the load-bearing no-recursion proof.
    # A recursive cascade (the audit sink re-entering ``record``) would
    # produce N>1 rows; ``>= 1`` would silently pass that bug. Pinning
    # ``post - pre == 1`` is the bound spec §6.8 promises.
    assert post_count - pre_count == 1, (
        f"no-recursion invariant violated: expected EXACTLY 1 new audit "
        f"row, got {post_count - pre_count} (pre={pre_count}, "
        f"post={post_count}). A count > 1 means the audit sink re-entered "
        f"memory.episodic.record — see spec §6.8."
    )

    # Identify the fault row's shape — the dispatcher's PR-A Task 10
    # contract pins ``event=hooks.subscriber_error``, ``result=fault``
    # (per EpisodicAuditSink's result-disposition table), and
    # ``subject`` projected through the per-event allowlist.
    async with session_factory() as s:
        result = await s.execute(
            select(AuditEntry).where(AuditEntry.event == "hooks.subscriber_error")
        )
        rows = list(result.scalars().all())
    assert len(rows) == 1, (
        f"expected exactly one hooks.subscriber_error audit row from a "
        f"single fault-emitting subscriber; got {len(rows)}"
    )
    fault_row = rows[0]
    assert fault_row.result == "fault"
    assert fault_row.trust_tier_of_trigger == "T0"
    assert fault_row.cost_estimate_usd == 0.0
    assert fault_row.trace_id  # uuid4 hex from invoking()'s correlation id
    assert fault_row.subject["hookpoint"] == "before_validate"
    assert fault_row.subject["kind"] == "pre"
    # NAME and TYPE only — never the exception message (CLAUDE.md hard
    # rule #1 / PR-A's _SUBSCRIBER_ERROR_AUDIT_FIELDS schema).
    assert fault_row.subject["subscriber_name"].endswith("buggy_subscriber")
    assert fault_row.subject["exception_type"] == "ValueError"
    # Allowlist projection (I1 hardening): only the four §0 fields land.
    assert set(fault_row.subject.keys()) == {
        "hookpoint",
        "kind",
        "subscriber_name",
        "exception_type",
    }

    # The Episode row was ALSO persisted — proving the chain continued
    # after the fault row landed (``fail_closed=False`` default on
    # ``before_validate``). A regression that promoted the default to
    # ``fail_closed=True`` would land here as a missing Episode.
    async with session_factory() as s:
        result = await s.execute(select(Episode).where(Episode.user_id == "u-task8"))
        episodes = list(result.scalars().all())
    assert len(episodes) == 1, (
        "Episode row missing — the fault-recovery chain should have "
        "continued past the buggy subscriber (fail_closed=False is the "
        "documented before_validate default)."
    )


@pytest.mark.integration
async def test_fault_row_persists_on_flush_failure(
    session: AsyncSession,
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """A poisoned turn session does NOT block the fault row from landing.

    Decision 3.6 / memB-1: an audit row emitted AFTER a flush failure
    fires on the :class:`AuditWriter`'s OWN fresh short-lived session —
    NOT the turn session, which is in an ``InvalidRequestError`` state
    after the flush raised. If the sink were to reuse the turn session
    the second ``flush`` would raise and the fault row would be LOST,
    violating CLAUDE.md hard rule #7 (no silent failures in security
    paths).

    This test forces the genuine SQLAlchemy poisoning by registering a
    ``before_db_write`` subscriber that mutates ``trust_tier`` to an
    invalid value — the ``ck_episodes_trust_tier`` CHECK constraint
    then makes the turn flush raise :class:`IntegrityError` for real
    (not a mock). The ``write_failed`` error chain fires; a registered
    error subscriber raises :class:`RuntimeError`, triggering the
    dispatcher's :func:`_emit_subscriber_error_audit` for the
    ``write_failed`` / error stage. The sink writes the fault row on
    its OWN fresh session (Decision 3.6) — independent of the poisoned
    turn session.

    The EXACT-count assertion (``post - pre == 1``) bounds the
    no-unbounded-rows invariant on the error arm too: a recursive
    cascade through the audit sink during the write_failed chain would
    produce N>1 rows and silently pass any ``>= 1`` predicate.

    Pattern choice (re: plan): a CHECK-constraint violation is the
    cleanest reproducible session-poisoning technique. A monkey-patch
    on ``session.flush`` that raises without actually touching SQL
    would NOT poison the session — the next ``flush`` on the same
    session would succeed, and the test would prove nothing about the
    fresh-session-per-emit invariant. The CHECK-constraint route forces
    the real ``InvalidRequestError`` path the production code is
    designed to survive.
    """
    prior = get_registry()
    # ``allow_system=True`` so the operator-tier subscribers below
    # register cleanly; ``before_db_write``'s
    # ``subscribable_tiers={"system","operator"}`` admits operator-tier
    # subscribers per the spec §6.5 contract.
    registry = HookRegistry(
        gate=DevGate(allow_system=True),
        sink=EpisodicAuditSink(audit=AuditWriter(session_factory=session_factory)),
    )
    set_registry(registry)
    try:
        # 1. A ``before_db_write`` subscriber that mutates ``trust_tier``
        #    to a value the ``ck_episodes_trust_tier`` CHECK rejects.
        #    Operator tier so the registration goes through; the
        #    subscriber is NOT refusing (returns a rewritten ctx) so
        #    refusable_tiers={"system"} doesn't bite.
        async def poison_trust_tier(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            return ctx.with_input(replace(ctx.input, trust_tier="T9"))

        registry.register(
            hook_fn=poison_trust_tier,
            hookpoint="before_db_write",
            kind="pre",
            tier="operator",
        )

        # 2. A ``write_failed`` error subscriber that raises so the
        #    dispatcher fires :func:`_emit_subscriber_error_audit` on the
        #    error chain. Without this, the write_failed chain has NO
        #    subscribers; the dispatcher would re-raise without emitting
        #    any audit row AND the fresh-session invariant would not be
        #    exercised at all. The subscriber's exception is the trigger
        #    for the audit emit that proves Decision 3.6.
        async def faulty_error_handler(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            raise RuntimeError("write_failed handler bug")

        registry.register(
            hook_fn=faulty_error_handler,
            hookpoint="write_failed",
            kind="error",
            tier="operator",
        )

        pre_count = await _audit_count_via_factory(session_factory)

        memory = EpisodicMemory(session=session)
        # The original IntegrityError propagates: no error subscriber
        # substituted (the only one raised), so _run_error re-raises the
        # upstream exc per spec §6.6 / CLAUDE.md hard rule #7.
        with pytest.raises(IntegrityError):
            await memory.record(**_TASK8_KWARGS)  # type: ignore[arg-type]

        # The turn session is now poisoned. We deliberately do NOT
        # rollback here — that's the whole point: the audit row was
        # written through the AuditWriter's OWN fresh session WHILE the
        # turn session was in this state. The count snapshot below
        # reads via session_factory, which opens an independent session
        # and is therefore unaffected by the poisoning.
        post_count = await _audit_count_via_factory(session_factory)
    finally:
        # Rollback before the fixture's session.close runs — otherwise
        # SQLAlchemy emits an "already in a transaction" warning at
        # teardown. The rollback is a TEST-CLEANUP detail, NOT part of
        # the production semantic under test.
        await session.rollback()
        set_registry(prior)

    # EXACT-count assertion — the no-unbounded-rows bound on the error
    # arm. A recursive cascade through the sink would produce N>1 rows;
    # ``>= 1`` would silently pass. Pinning ``post - pre == 1`` is the
    # error-arm equivalent of test (a)'s no-recursion proof.
    assert post_count - pre_count == 1, (
        f"fresh-session-fault invariant violated: expected EXACTLY 1 "
        f"new audit row, got {post_count - pre_count} (pre={pre_count}, "
        f"post={post_count}). A count > 1 means the audit sink "
        f"re-entered memory.episodic.record on the error arm — see "
        f"spec §6.8 and Decision 3.6."
    )

    # Identify the fault row's shape on the error arm. ``kind=error``
    # distinguishes it from test (a)'s ``kind=pre`` row — the dispatcher
    # routes both through the same :func:`_emit_subscriber_error_audit`
    # helper but with the kind-specific stage threaded through.
    async with session_factory() as s:
        result = await s.execute(
            select(AuditEntry).where(AuditEntry.event == "hooks.subscriber_error")
        )
        rows = list(result.scalars().all())
    assert len(rows) == 1
    fault_row = rows[0]
    assert fault_row.result == "fault"
    assert fault_row.trust_tier_of_trigger == "T0"
    assert fault_row.subject["hookpoint"] == "write_failed"
    assert fault_row.subject["kind"] == "error"
    assert fault_row.subject["subscriber_name"].endswith("faulty_error_handler")
    assert fault_row.subject["exception_type"] == "RuntimeError"

    # The Episode row was NOT persisted — the flush raised, the turn
    # session never committed, the row never landed. A regression that
    # somehow allowed the row to land despite the IntegrityError would
    # surface here as ``len(episodes) > 0``. The independent session
    # used for this readback is the same reason the audit row IS visible
    # above: a fresh session on the same engine sees only durably-
    # committed rows.
    async with session_factory() as s:
        result = await s.execute(select(Episode).where(Episode.user_id == "u-task8"))
        episodes = list(result.scalars().all())
    assert episodes == [], (
        "Episode row should NOT have persisted — the turn flush raised "
        "IntegrityError and the transaction never committed. A row "
        "landing here would mean the turn session leaked durable state "
        "through the IntegrityError path."
    )
