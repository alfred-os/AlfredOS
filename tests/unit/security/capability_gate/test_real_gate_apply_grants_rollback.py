"""Unit tests for :meth:`RealGate._apply_grants` partial-failure rollback.

sec-pr-s3-6-02 / perf-002 / err-003: the previous shape ran each of
``revoke_grant`` / ``upsert_grant`` / ``set_sync_hash`` as its own
transaction. A driver error mid-revoke (or between the revoke pass and
the upsert pass) left Postgres partially mutated with no sync-hash
update and no audit signal — three findings stacked:

* sec-pr-s3-6-02 (HIGH) — silent split-brain between in-memory policy
  and the persisted projection.
* perf-002 (HIGH) — R+G+1 round-trips per rebuild.
* err-003 (MEDIUM) — partial-failure path emitted no audit row, so
  forensic traversal lost the trigger.

The fix collapses the work into a single
:meth:`StorageBackend.apply_atomic` call inside one
``async with session.begin()`` block AND adds a rollback audit row in
the gate so success and failure both surface in the audit log.

Hard invariants pinned here:

* **Happy path** — :meth:`_apply_grants` flows through ONE
  ``apply_atomic`` call carrying the revokes, upserts, and commit hash.
  Per-op AsyncMocks are not awaited.
* **Mid-revoke failure** — ``apply_atomic`` raises a
  :class:`sqlalchemy.exc.SQLAlchemyError`; the gate emits a
  ``plugin.grant.rebuilt`` audit row with ``result="rolled_back"`` and
  re-raises. The in-memory policy is NOT swapped — the previous
  snapshot stays authoritative.
* **Mid-upsert failure** — same shape from the upsert side of the
  transaction.
* **set_sync_hash failure** — same shape on the trailing SQL.
* **Audit subject schema** — the rollback row uses the
  :data:`CAPABILITY_GATE_REBUILD_FIELDS` schema (symmetric-key check at
  the writer). ``backing_store_error_type`` is NOT in the rebuild
  schema — it lives on the ``supervisor.capability_gate_unavailable``
  family — so the gate captures ``type(exc).__name__`` in structlog
  only, not in the audit row (spec §5.6: never persist
  ``str(exc)`` / ``exc.args`` into JSONB).
* **In-memory policy preserved on rollback** — a hot-path ``check``
  after the failure answers per the OLD snapshot, not per the
  failed-attempt's grants. This is the security invariant the fix
  delivers: a half-applied transaction cannot leak a grant the
  operator never saw committed.
* **Cancellation passes through** — :class:`asyncio.CancelledError` is
  NOT swallowed by the rollback handler; cooperative shutdown stays
  prompt.

These tests stub the backend's ``apply_atomic`` to raise so the gate's
rollback handler is exercised in isolation; the integration tier
(``tests/integration/security/capability_gate``) exercises the real
PostgresBackend's transaction semantics against a live container.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from alfred.audit.audit_row_schemas import CAPABILITY_GATE_REBUILD_FIELDS
from alfred.security.capability_gate.policy import GrantRow


def _make_backend(
    grants: frozenset[GrantRow] | None = None,
    sync_hash: str | None = None,
) -> Any:
    """Stub StorageBackend matching ``test_real_gate``'s helper shape."""
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=grants or frozenset())
    backend.get_sync_hash = AsyncMock(return_value=sync_hash)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    backend.apply_atomic = AsyncMock(return_value=None)
    return backend


def _make_audit_sink() -> Any:
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def _make_sqlalchemy_error(message: str = "simulated db error") -> SQLAlchemyError:
    """Build a representative :class:`SQLAlchemyError` for the rollback path.

    :class:`OperationalError` is the canonical driver-layer failure
    (network blip, connection reset, lock-wait timeout). Using a
    concrete subclass — not the bare :class:`SQLAlchemyError` base —
    pins the gate's rollback handler against the production failure
    shape.
    """
    return OperationalError(message, params=None, orig=Exception(message))


# ---------------------------------------------------------------------------
# Happy path: single apply_atomic call, no audit row from _apply_grants
# ---------------------------------------------------------------------------


async def test_apply_grants_happy_path_uses_single_apply_atomic() -> None:
    """N revokes + M upserts collapse into ONE ``apply_atomic`` call.

    sec-pr-s3-6-02: the prior shape made R+G+1 calls; the fix collapses
    them into a single transaction. This test pins the call count
    against the regression — a future refactor that opens a per-op
    session inside ``apply_atomic`` would still pass the round-trip
    integration test but quietly resurrect the split-brain shape.
    """
    from alfred.security.capability_gate._gate import RealGate

    existing_a = GrantRow(
        plugin_id="legacy.a",
        subscriber_tier="operator",
        hookpoint="tool.a",
        content_tier=None,
        proposal_branch="proposal/policy-grant-legacy-a",
    )
    existing_b = GrantRow(
        plugin_id="legacy.b",
        subscriber_tier="operator",
        hookpoint="tool.b",
        content_tier=None,
        proposal_branch="proposal/policy-grant-legacy-b",
    )
    new_x = GrantRow(
        plugin_id="new.x",
        subscriber_tier="operator",
        hookpoint="tool.x",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new-x",
    )
    new_y = GrantRow(
        plugin_id="new.y",
        subscriber_tier="operator",
        hookpoint="tool.y",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new-y",
    )

    backend = _make_backend(grants=frozenset({existing_a, existing_b}))
    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    await gate._apply_grants(
        frozenset({new_x, new_y}),
        commit_hash="happy-path-hash",
    )

    # Exactly one apply_atomic call — not 2 (revokes) + 2 (upserts) + 1
    # (sync_hash) which the pre-fix shape would have produced.
    backend.apply_atomic.assert_awaited_once()
    kwargs = backend.apply_atomic.await_args.kwargs
    assert set(kwargs["revokes"]) == {existing_a, existing_b}
    assert set(kwargs["upserts"]) == {new_x, new_y}
    assert kwargs["commit_hash"] == "happy-path-hash"

    # No audit row emitted from _apply_grants on the happy path — the
    # success row lives in ``rebuild_from_state_git`` (one per rebuild,
    # not per apply).
    sink.append_schema.assert_not_awaited()

    # The per-op AsyncMocks remain unawaited — the gate goes through
    # ``apply_atomic`` exclusively.
    backend.revoke_grant.assert_not_awaited()
    backend.upsert_grant.assert_not_awaited()
    backend.set_sync_hash.assert_not_awaited()


# ---------------------------------------------------------------------------
# Mid-revoke failure: apply_atomic raises during the revoke pass
# ---------------------------------------------------------------------------


async def test_apply_grants_mid_revoke_failure_emits_rollback_row_and_reraises() -> None:
    """Mid-revoke SQLAlchemyError → rollback audit row → re-raise.

    The transaction inside ``apply_atomic`` rolls back atomically, so
    no Postgres mutation survives. The gate emits a
    ``plugin.grant.rebuilt`` row with ``result="rolled_back"`` and
    re-raises so the orchestrator's exception path fires.
    """
    from alfred.security.capability_gate._gate import RealGate

    existing = GrantRow(
        plugin_id="legacy.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-legacy",
    )

    backend = _make_backend(grants=frozenset({existing}))
    backend.apply_atomic = AsyncMock(side_effect=_make_sqlalchemy_error("revoke failure"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    with pytest.raises(SQLAlchemyError):
        await gate._apply_grants(frozenset(), commit_hash="failed-rebuild-hash")

    # Audit row emitted with result="rolled_back" matching the rebuild schema.
    sink.append_schema.assert_awaited_once()
    kwargs = sink.append_schema.await_args.kwargs
    assert kwargs["fields"] == CAPABILITY_GATE_REBUILD_FIELDS
    assert kwargs["schema_name"] == "CAPABILITY_GATE_REBUILD_FIELDS"
    assert kwargs["event"] == "plugin.grant.rebuilt"
    assert kwargs["result"] == "rolled_back"
    assert kwargs["trust_tier_of_trigger"] == "T0"
    assert kwargs["actor_user_id"] is None
    # Symmetric-key check — every declared field is present.
    subject = kwargs["subject"]
    assert set(subject.keys()) == set(CAPABILITY_GATE_REBUILD_FIELDS)
    assert subject["commit_hash"] == "failed-rebuild-hash"
    # grant_count is the size of the ATTEMPTED snapshot (the new
    # snapshot), so an operator can correlate "rolled back at 0 grants"
    # vs "rolled back at 47 grants" in the forensic graph.
    assert subject["grant_count"] == 0


async def test_apply_grants_mid_revoke_failure_does_not_swap_policy() -> None:
    """Rollback leaves the previous in-memory policy authoritative.

    The fix's central security invariant: a half-applied transaction
    cannot leak a grant (or unleak a revocation) the operator never
    saw committed. A hot-path check after the failure MUST answer per
    the OLD snapshot, not per the failed-attempt's grants.
    """
    from alfred.security.capability_gate._gate import RealGate

    existing = GrantRow(
        plugin_id="legacy.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-legacy",
    )

    backend = _make_backend(grants=frozenset({existing}))
    backend.apply_atomic = AsyncMock(side_effect=_make_sqlalchemy_error("revoke failure"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    # Pre-failure check: the existing grant admits.
    assert (
        gate.check(
            plugin_id="legacy.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )

    # Attempt to revoke fails partway.
    with pytest.raises(SQLAlchemyError):
        await gate._apply_grants(frozenset(), commit_hash="failed-rebuild-hash")

    # Post-failure check: the old policy stays authoritative — the
    # "revoked" grant still admits because the transaction rolled back.
    assert (
        gate.check(
            plugin_id="legacy.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )


# ---------------------------------------------------------------------------
# Mid-upsert failure: apply_atomic raises during the upsert pass
# ---------------------------------------------------------------------------


async def test_apply_grants_mid_upsert_failure_emits_rollback_row_and_reraises() -> None:
    """Mid-upsert SQLAlchemyError → rollback audit row → re-raise.

    Same rollback shape as the mid-revoke case — the
    :meth:`apply_atomic` contract is "any DB error rolls back the
    entire transaction"; the gate cannot distinguish which row inside
    the transaction failed (and shouldn't, per spec §5.6 — the error
    type is captured in structlog only, never in the audit subject).
    """
    from alfred.security.capability_gate._gate import RealGate

    new_grant = GrantRow(
        plugin_id="new.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new",
    )

    backend = _make_backend(grants=frozenset())
    backend.apply_atomic = AsyncMock(side_effect=_make_sqlalchemy_error("upsert failure"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    with pytest.raises(SQLAlchemyError):
        await gate._apply_grants(
            frozenset({new_grant}),
            commit_hash="failed-upsert-hash",
        )

    sink.append_schema.assert_awaited_once()
    kwargs = sink.append_schema.await_args.kwargs
    assert kwargs["result"] == "rolled_back"
    subject = kwargs["subject"]
    assert subject["commit_hash"] == "failed-upsert-hash"
    # grant_count reflects the attempted snapshot size.
    assert subject["grant_count"] == 1


async def test_apply_grants_mid_upsert_failure_does_not_swap_policy() -> None:
    """Upsert rollback leaves the previous (empty) policy authoritative."""
    from alfred.security.capability_gate._gate import RealGate

    new_grant = GrantRow(
        plugin_id="new.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new",
    )

    backend = _make_backend(grants=frozenset())
    backend.apply_atomic = AsyncMock(side_effect=_make_sqlalchemy_error("upsert failure"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    # Pre-failure: no grant admits.
    assert (
        gate.check(
            plugin_id="new.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )

    with pytest.raises(SQLAlchemyError):
        await gate._apply_grants(
            frozenset({new_grant}),
            commit_hash="failed-upsert-hash",
        )

    # Post-failure: still no grant admits — the upsert rolled back.
    assert (
        gate.check(
            plugin_id="new.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )


# ---------------------------------------------------------------------------
# set_sync_hash failure: apply_atomic raises on the trailing SQL
# ---------------------------------------------------------------------------


async def test_apply_grants_sync_hash_failure_rolls_back_all_prior_work() -> None:
    """Failure on the trailing ``set_sync_hash`` rolls back the revokes + upserts too.

    This is the most subtle case: the revoke and upsert SQL committed
    in-memory at the driver level, but the trailing ``set_sync_hash``
    raises. Without the single-transaction shape, the revokes and
    upserts would have already landed and the next process restart
    would observe the new grants WITHOUT the sync hash — a sync-hash
    underflow that triggers a redundant rebuild loop on every restart.
    The single ``async with session.begin()`` block in
    ``apply_atomic`` collapses all three SQL statements into one
    commit point so this can't happen.
    """
    from alfred.security.capability_gate._gate import RealGate

    existing = GrantRow(
        plugin_id="legacy.plugin",
        subscriber_tier="operator",
        hookpoint="tool.legacy",
        content_tier=None,
        proposal_branch="proposal/policy-grant-legacy",
    )
    new_grant = GrantRow(
        plugin_id="new.plugin",
        subscriber_tier="operator",
        hookpoint="tool.new",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new",
    )

    backend = _make_backend(grants=frozenset({existing}))
    backend.apply_atomic = AsyncMock(side_effect=_make_sqlalchemy_error("set_sync_hash failure"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    with pytest.raises(SQLAlchemyError):
        await gate._apply_grants(
            frozenset({new_grant}),
            commit_hash="failed-sync-hash",
        )

    # Audit row emitted with result="rolled_back".
    sink.append_schema.assert_awaited_once()
    kwargs = sink.append_schema.await_args.kwargs
    assert kwargs["result"] == "rolled_back"
    subject = kwargs["subject"]
    assert subject["commit_hash"] == "failed-sync-hash"
    assert subject["grant_count"] == 1

    # In-memory policy preserved: the legacy grant still admits, the
    # new grant does not — the failed transaction left the gate exactly
    # as it was before the call.
    assert (
        gate.check(
            plugin_id="legacy.plugin",
            hookpoint="tool.legacy",
            requested_tier="operator",
        )
        is True
    )
    assert (
        gate.check(
            plugin_id="new.plugin",
            hookpoint="tool.new",
            requested_tier="operator",
        )
        is False
    )


# ---------------------------------------------------------------------------
# Cancellation passes through (does NOT trigger the rollback audit row)
# ---------------------------------------------------------------------------


async def test_apply_grants_cancelled_error_propagates_without_audit() -> None:
    """:class:`asyncio.CancelledError` is NOT swallowed by the rollback handler.

    The rollback handler catches :class:`sqlalchemy.exc.SQLAlchemyError`
    specifically; cooperative shutdown via task cancellation must pass
    through cleanly so the supervisor's graceful-shutdown sequence
    remains prompt. Emitting a "rolled_back" audit row on cancellation
    would also pollute the audit log with shutdown noise.
    """
    from alfred.security.capability_gate._gate import RealGate

    new_grant = GrantRow(
        plugin_id="new.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-new",
    )

    backend = _make_backend(grants=frozenset())
    backend.apply_atomic = AsyncMock(side_effect=asyncio.CancelledError())

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    with pytest.raises(asyncio.CancelledError):
        await gate._apply_grants(
            frozenset({new_grant}),
            commit_hash="cancelled-mid-apply",
        )

    # No audit row — cancellation is not a partial-failure path.
    sink.append_schema.assert_not_awaited()


# ---------------------------------------------------------------------------
# Non-SQLAlchemy errors also propagate (no rollback audit row, no swap)
# ---------------------------------------------------------------------------


async def test_apply_grants_unrelated_exception_propagates_without_audit() -> None:
    """A non-:class:`SQLAlchemyError` propagates without triggering the rollback row.

    The rollback handler is scoped to driver-layer errors because that's
    the only family the atomic-transaction contract addresses. Anything
    else (test bug, programming error, RuntimeError raised by an
    audit-sink fault before apply_atomic is even called) propagates
    unchanged so the operator sees the actual fault, not a misleading
    "rolled_back" attribution.
    """
    from alfred.security.capability_gate._gate import RealGate

    backend = _make_backend(grants=frozenset())
    backend.apply_atomic = AsyncMock(side_effect=RuntimeError("not a db error"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    with pytest.raises(RuntimeError, match="not a db error"):
        await gate._apply_grants(frozenset(), commit_hash="unrelated-failure")

    # No "rolled_back" audit row — wrong exception family.
    sink.append_schema.assert_not_awaited()


# ---------------------------------------------------------------------------
# rebuild_from_state_git does NOT emit the success row when _apply_grants rolls back
# ---------------------------------------------------------------------------


async def test_rebuild_does_not_emit_success_row_when_apply_grants_rolls_back() -> None:
    """``rebuild_from_state_git`` re-raises so the success row never lands.

    The order matters: ``_apply_grants`` is called BEFORE the success
    audit row in :meth:`rebuild_from_state_git`. When ``_apply_grants``
    raises, the success-row emit never executes — the only audit row
    is the rollback row from inside ``_apply_grants``. This is the
    err-003 invariant: a rolled-back rebuild surfaces ONE row, not zero
    AND not two.
    """
    from unittest.mock import patch

    from alfred.security.capability_gate._gate import RealGate

    backend = _make_backend(sync_hash="old-hash")
    backend.apply_atomic = AsyncMock(side_effect=_make_sqlalchemy_error("simulated"))

    sink = _make_audit_sink()
    gate = await RealGate.create(backend=backend, audit_sink=sink)

    with (
        patch(
            "alfred.security.capability_gate._gate.parse_state_git_head",
            return_value=frozenset(),
        ),
        pytest.raises(SQLAlchemyError),
    ):
        await gate.rebuild_from_state_git(state_git_head="new-hash")

    # Exactly ONE audit row: the rollback row from _apply_grants.
    # The success row from rebuild_from_state_git did not fire because
    # the re-raise happened before it.
    sink.append_schema.assert_awaited_once()
    kwargs = sink.append_schema.await_args.kwargs
    assert kwargs["result"] == "rolled_back"
