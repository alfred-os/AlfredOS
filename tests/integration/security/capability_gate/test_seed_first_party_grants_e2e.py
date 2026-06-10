"""Integration: ``seed_first_party_grants`` against REAL Postgres (FIX 2).

The unit tier (``tests/unit/security/capability_gate/test_seed_first_party_grants.py``)
asserts the SQL TEXT the backend emits against a mocked session — it never
executes the ``ON CONFLICT`` clause against the live
``uq_plugin_grants_plugin_hook_tier`` UNIQUE constraint, nor proves the seed
leaves an operator grant untouched. This module closes that mock-theater gap
by driving :meth:`PostgresBackend.seed_first_party_grants` against a real
Postgres testcontainer (migrated to HEAD, so ``plugin_grants`` from migration
0008 carries the real UNIQUE + CHECK constraints).

Two ADR-0026 invariants, executed not asserted-on-SQL-text:

* **double-seed idempotency** — seeding TWICE lands EXACTLY ONE
  ``plugin_grants`` row for the first-party DLP subscriber. This proves the
  real ``ON CONFLICT (plugin_id, hookpoint, subscriber_tier) DO UPDATE``
  de-dupes against the live UNIQUE constraint (a duplicate INSERT would raise
  ``IntegrityError``; a missing ON CONFLICT target would create two rows).

* **operator-grant survival** — an operator grant upserted via the production
  ``apply_atomic`` path survives a subsequent seed as ``approved``. The seed
  is additive-only (no revoke-diff), so seeding AlfredOS's own defences must
  never collateral-revoke an operator's grant (CLAUDE.md hard rule #2 — no
  silent capability changes).

Placement mirrors ``test_grant_lifecycle_e2e.py`` (same
``migrated_postgres`` / ``backend_against`` conftest fixtures) so the
trust-boundary integration setup stays pinned to one fixture contract.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from alfred.security.capability_gate._bootstrap_grants import (
    FIRST_PARTY_SYSTEM_GRANTS,
)
from alfred.security.capability_gate.backend import PostgresBackend
from alfred.security.capability_gate.policy import GrantRow

pytestmark = pytest.mark.integration

_BackendCM = Callable[
    [str],
    AbstractAsyncContextManager[tuple[PostgresBackend, async_sessionmaker[AsyncSession]]],
]

# The single first-party row the seed lands today (ADR-0026). Bound off the
# production constant so a future change to FIRST_PARTY_SYSTEM_GRANTS surfaces
# here rather than letting a stale literal pass.
_DLP_GRANT: GrantRow = FIRST_PARTY_SYSTEM_GRANTS[0]


async def _count_rows(
    factory: async_sessionmaker[AsyncSession],
    *,
    plugin_id: str,
    hookpoint: str,
    subscriber_tier: str,
) -> int:
    """Return the raw ``plugin_grants`` row count for one grant identity.

    A raw ``COUNT(*)`` — NOT ``load_grants()`` — because ``load_grants``
    returns a ``frozenset`` that would silently collapse a genuine duplicate
    row into one element, hiding exactly the de-dupe regression this test
    exists to catch.
    """
    async with factory() as session, session.begin():
        result = await session.execute(
            sa.text(
                "SELECT COUNT(*) FROM plugin_grants "
                "WHERE plugin_id = :plugin_id "
                "AND hookpoint = :hookpoint "
                "AND subscriber_tier = :subscriber_tier"
            ),
            {
                "plugin_id": plugin_id,
                "hookpoint": hookpoint,
                "subscriber_tier": subscriber_tier,
            },
        )
        count: int = result.scalar_one()
    return count


async def _state_of(
    factory: async_sessionmaker[AsyncSession],
    *,
    plugin_id: str,
    hookpoint: str,
    subscriber_tier: str,
) -> str | None:
    """Return the ``state`` of one grant row, or ``None`` if absent."""
    async with factory() as session, session.begin():
        result = await session.execute(
            sa.text(
                "SELECT state FROM plugin_grants "
                "WHERE plugin_id = :plugin_id "
                "AND hookpoint = :hookpoint "
                "AND subscriber_tier = :subscriber_tier"
            ),
            {
                "plugin_id": plugin_id,
                "hookpoint": hookpoint,
                "subscriber_tier": subscriber_tier,
            },
        )
        row = result.fetchone()
    return None if row is None else str(row.state)


async def test_double_seed_is_idempotent_against_real_unique_constraint(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """Seeding TWICE lands EXACTLY ONE first-party DLP row (ADR-0026).

    Proves the real ``ON CONFLICT (plugin_id, hookpoint, subscriber_tier)``
    de-dupes against ``uq_plugin_grants_plugin_hook_tier``. A second INSERT
    without a working ON CONFLICT target would either raise IntegrityError
    (caught here by the absence of a raised exception) or create a second
    row (caught by the COUNT assertion).
    """
    async with backend_against(migrated_postgres) as (backend, factory):
        await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)
        await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)

        count = await _count_rows(
            factory,
            plugin_id=_DLP_GRANT.plugin_id,
            hookpoint=_DLP_GRANT.hookpoint,
            subscriber_tier=_DLP_GRANT.subscriber_tier,
        )
        assert count == 1, (
            f"double-seed produced {count} rows for the first-party DLP grant; "
            "expected exactly 1 — the ON CONFLICT de-dupe against "
            "uq_plugin_grants_plugin_hook_tier did not fire"
        )

        # The surviving row projects through load_grants (state='approved').
        loaded = await backend.load_grants()
        assert _DLP_GRANT in loaded


async def test_seed_does_not_revoke_an_operator_grant(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """An operator grant survives a subsequent seed as ``approved`` (ADR-0026).

    The seed is additive-only: it upserts only the FIRST_PARTY_SYSTEM_GRANTS
    rows and never computes a revoke-diff. An operator grant already in the
    table must therefore be untouched after the seed runs — seeding the
    host's defences must never collateral-revoke an operator's capability
    (CLAUDE.md hard rule #2).
    """
    operator_grant = GrantRow(
        plugin_id="operator.synthetic.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/operator-grant-survives-seed",
    )

    async with backend_against(migrated_postgres) as (backend, factory):
        # Upsert the operator grant via the SAME production path
        # (_execute_upsert_grant) the reviewer-merge rebuild uses, so the
        # row lands as state='approved'.
        await backend.upsert_grant(operator_grant)
        assert (
            await _state_of(
                factory,
                plugin_id=operator_grant.plugin_id,
                hookpoint=operator_grant.hookpoint,
                subscriber_tier=operator_grant.subscriber_tier,
            )
            == "approved"
        )

        # Now seed the first-party defences.
        await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)

        # The operator grant is STILL approved — no revoke-diff ran.
        assert (
            await _state_of(
                factory,
                plugin_id=operator_grant.plugin_id,
                hookpoint=operator_grant.hookpoint,
                subscriber_tier=operator_grant.subscriber_tier,
            )
            == "approved"
        ), (
            "seed_first_party_grants revoked/altered an operator grant — "
            "the seed must be additive-only"
        )

        # Both the operator grant AND the seeded first-party grant load.
        loaded = await backend.load_grants()
        assert operator_grant in loaded
        assert _DLP_GRANT in loaded
