"""Integration: :class:`PostgresBackend` round-trip against a real Postgres.

Spec §8.1 (Fork 7) — the gate's hybrid storage runs every grant write
through Postgres so subsequent hot-path checks answer at millisecond
latency. This test exercises the full lifecycle against a per-test
Postgres testcontainer:

1. Migrations upgrade to HEAD (covers ``plugin_grants`` from migration
   0008 and ``capability_gate_sync`` from migration 0009).
2. :meth:`PostgresBackend.upsert_grant` inserts one grant row.
3. :meth:`PostgresBackend.load_grants` reads it back.
4. :meth:`PostgresBackend.set_sync_hash` writes the singleton sync row;
   :meth:`get_sync_hash` reads it back.
5. :meth:`PostgresBackend.upsert_grant` again — exercises the
   ``ON CONFLICT`` update path.
6. :meth:`PostgresBackend.revoke_grant` removes the row.
7. :meth:`PostgresBackend.load_grants` returns empty.
8. End-to-end via :class:`RealGate` — full
   ``create → check → _apply_grants → check`` lifecycle against real
   Postgres, validating the in-memory policy swap happens in concert
   with the persisted upsert.

Coverage rationale: ``backend.py`` is already exercised at unit tier via
mocked SQLAlchemy in ``test_storage_backend.py`` (100% line + branch).
This test pins the SQL strings against a real Postgres so a mismatched
column name, ``ON CONFLICT`` target, or migration drift surfaces at the
integration boundary — the unit tier cannot catch those.

Placement: alongside the outage scenarios (``test_fail_closed_outage.py``)
in ``tests/integration/security/capability_gate/`` so operators reading
the integration suite see the gate's storage and outage stories together.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from alfred.security.capability_gate.backend import PostgresBackend
from alfred.security.capability_gate.policy import GrantRow

# CR-139 finding #8: shared fixtures (alembic_cfg, migrated_postgres,
# make_audit_sink, backend_against) now live in
# tests/integration/security/capability_gate/conftest.py.

pytestmark = pytest.mark.integration

# Type alias for the ``backend_against`` fixture return — keeps the
# test signatures readable without re-declaring the long generic.
_BackendCM = Callable[
    [str],
    AbstractAsyncContextManager[tuple[PostgresBackend, async_sessionmaker[AsyncSession]]],
]


async def test_upsert_and_load_round_trip(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """Insert one grant via upsert, read it back via load_grants.

    Pins the SQL parameter binding (column ordering, types) against
    real Postgres — a column-name typo in :meth:`PostgresBackend.upsert_grant`
    would surface here as an ``InvalidColumnError`` instead of passing
    through the mocked unit suite.
    """
    grant = GrantRow(
        plugin_id="round.trip.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-rt-1",
    )
    async with backend_against(migrated_postgres) as (backend, _factory):
        await backend.upsert_grant(grant)
        loaded = await backend.load_grants()
    assert loaded == frozenset({grant})


async def test_upsert_conflict_updates_existing_row(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """A second upsert on the same key updates content_tier + proposal_branch.

    The unique key ``(plugin_id, hookpoint, subscriber_tier)`` matches
    migration 0008's ``uq_plugin_grants_plugin_hook_tier`` constraint;
    this test pins the ON CONFLICT target so a future SQL edit that
    drifts the conflict columns (e.g. drops ``subscriber_tier`` from the
    target) surfaces here.
    """
    initial = GrantRow(
        plugin_id="conflict.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-original",
    )
    updated = GrantRow(
        plugin_id="conflict.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier="T3",
        proposal_branch="proposal/policy-grant-updated",
    )
    async with backend_against(migrated_postgres) as (backend, _factory):
        await backend.upsert_grant(initial)
        await backend.upsert_grant(updated)
        loaded = await backend.load_grants()

    # Exactly one row exists; it carries the updated values.
    assert loaded == frozenset({updated})
    only = next(iter(loaded))
    assert only.content_tier == "T3"
    assert only.proposal_branch == "proposal/policy-grant-updated"


async def test_revoke_removes_grant(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """:meth:`revoke_grant` removes one grant; second revoke is idempotent.

    Spec §8.5: revocation is the reviewer-merge path's counterpart to
    upsert. Idempotency matters because PR-S3-6's rebuild path may revoke
    the same row twice if a proposal is merged then immediately
    superseded by a revocation proposal.
    """
    grant = GrantRow(
        plugin_id="revoke.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-revoke",
    )
    async with backend_against(migrated_postgres) as (backend, _factory):
        await backend.upsert_grant(grant)
        await backend.revoke_grant(
            plugin_id="revoke.plugin",
            hookpoint="tool.web.fetch",
            subscriber_tier="operator",
        )
        loaded_after_revoke = await backend.load_grants()

        # Idempotent: a second revoke on the same key does NOT raise.
        await backend.revoke_grant(
            plugin_id="revoke.plugin",
            hookpoint="tool.web.fetch",
            subscriber_tier="operator",
        )
        loaded_after_second_revoke = await backend.load_grants()

    assert loaded_after_revoke == frozenset()
    assert loaded_after_second_revoke == frozenset()


async def test_sync_hash_round_trip(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """``set_sync_hash`` writes; ``get_sync_hash`` reads back the singleton row.

    mem-004: the singleton-row contract (``CHECK (id = 1)``) means
    multiple ``set_sync_hash`` calls update the same row rather than
    inserting new ones. Validated by setting two different hashes then
    asserting the latest wins.
    """
    async with backend_against(migrated_postgres) as (backend, _factory):
        # Unseeded: returns None.
        assert await backend.get_sync_hash() is None

        await backend.set_sync_hash("deadbeef" * 5)
        assert await backend.get_sync_hash() == "deadbeef" * 5

        # Second set updates in place.
        await backend.set_sync_hash("c0ffee00" * 5)
        assert await backend.get_sync_hash() == "c0ffee00" * 5


async def test_ping_succeeds_against_live_postgres(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """:meth:`ping` succeeds against a healthy container.

    The heartbeat loop's success branch depends on ``ping`` returning
    normally — this is the integration-level analogue of the unit-tier
    ``ping`` mock. A connection-string drift would surface here as a
    raised exception.
    """
    async with backend_against(migrated_postgres) as (backend, _factory):
        await backend.ping()  # Must not raise.


async def test_grant_lifecycle_through_real_gate(
    migrated_postgres: str,
    backend_against: _BackendCM,
    make_audit_sink: Callable[[], Any],
) -> None:
    """End-to-end: ``RealGate.create → check → _apply_grants → check``.

    Drives :class:`RealGate` against the real Postgres backend so the
    full hot-path-check + persist path is exercised together. The
    initial ``create`` loads zero grants (empty table), then
    ``_apply_grants`` is called with one grant; both the in-memory
    policy swap AND the Postgres upsert MUST be visible after.

    The roundtrip is closed by constructing a second
    :class:`RealGate` against the same Postgres container — its initial
    ``load_grants`` must pick up the grant the first gate persisted,
    confirming the sync-hash + Postgres state survive process boundary.
    """
    from alfred.security.capability_gate._gate import RealGate

    grant = GrantRow(
        plugin_id="e2e.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-e2e",
    )
    async with backend_against(migrated_postgres) as (backend, _factory):
        sink = make_audit_sink()
        gate = await RealGate.create(backend=backend, audit_sink=sink, start_heartbeat=False)

        # Initial state: no grants, all checks deny.
        assert (
            gate.check(
                plugin_id="e2e.plugin",
                hookpoint="tool.web.fetch",
                requested_tier="operator",
            )
            is False
        )

        await gate._apply_grants(frozenset({grant}), commit_hash="e2e-rebuild-hash")

        # Post-apply: in-memory policy answers True.
        assert (
            gate.check(
                plugin_id="e2e.plugin",
                hookpoint="tool.web.fetch",
                requested_tier="operator",
            )
            is True
        )

        # Sync hash persisted.
        assert await backend.get_sync_hash() == "e2e-rebuild-hash"

    # Fresh process: build a brand-new RealGate against the same DB.
    async with backend_against(migrated_postgres) as (backend2, _factory2):
        sink2 = make_audit_sink()
        gate2 = await RealGate.create(backend=backend2, audit_sink=sink2, start_heartbeat=False)

        # Cross-process roundtrip: the grant survives because Postgres
        # persisted it. This is the test that fails loudly if a future
        # change swaps Postgres for an in-memory store that doesn't
        # survive ``async with``.
        assert (
            gate2.check(
                plugin_id="e2e.plugin",
                hookpoint="tool.web.fetch",
                requested_tier="operator",
            )
            is True
        )
        assert await backend2.get_sync_hash() == "e2e-rebuild-hash"
