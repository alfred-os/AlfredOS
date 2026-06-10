"""Integration: ``reconcile_comms_adapter_grants`` against REAL Postgres (FIX 2).

The unit tier
(``tests/unit/security/capability_gate/test_reconcile_comms_adapter_grants.py``)
asserts the SQL TEXT the backend emits against a mocked session. This module
closes the mock-theater gap by driving
:meth:`PostgresBackend.reconcile_comms_adapter_grants` against a real Postgres
testcontainer (migrated to HEAD), proving the load-bearing safety property
end-to-end: reconciling from one enabled comms adapter to a different one DROPS
the first adapter's stale ``bootstrap:first-party-comms-adapter`` load grant,
lands the new one, AND leaves a pre-existing operator grant + the DLP
``bootstrap:first-party-system`` system grant UNTOUCHED.

Placement mirrors ``test_seed_first_party_grants_e2e.py`` (same
``migrated_postgres`` / ``backend_against`` conftest fixtures) so the
trust-boundary integration setup stays pinned to one fixture contract.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from alfred.security.capability_gate._bootstrap_grants import (
    FIRST_PARTY_SYSTEM_GRANTS,
)
from alfred.security.capability_gate._comms_adapter_grants import (
    _COMMS_ADAPTER_PROPOSAL_BRANCH,
)
from alfred.security.capability_gate.backend import PostgresBackend
from alfred.security.capability_gate.policy import GrantRow

pytestmark = pytest.mark.integration

_BackendCM = Callable[
    [str],
    AbstractAsyncContextManager[tuple[PostgresBackend, async_sessionmaker[AsyncSession]]],
]

_DLP_GRANT: GrantRow = FIRST_PARTY_SYSTEM_GRANTS[0]


def _comms_grant(plugin_id: str) -> GrantRow:
    return GrantRow(
        plugin_id=plugin_id,
        subscriber_tier="user-plugin",
        hookpoint="*",
        content_tier=None,
        proposal_branch=_COMMS_ADAPTER_PROPOSAL_BRANCH,
    )


async def test_reconcile_swaps_adapter_and_leaves_other_grants_untouched(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """Reconcile A->B: A's grant gone, B's present, operator + DLP grants survive.

    The end-to-end proof of the FIX-2 safety property against the live
    ``plugin_grants`` UNIQUE/CHECK constraints:

    * The scoped revoke-diff DELETEs the stale comms-adapter-A grant.
    * It upserts the comms-adapter-B grant.
    * A pre-existing OPERATOR grant (different proposal_branch) is UNTOUCHED.
    * The DLP ``bootstrap:first-party-system`` system grant is UNTOUCHED.
    """
    adapter_a = _comms_grant("alfred.comms-a")
    adapter_b = _comms_grant("alfred.comms-b")
    operator_grant = GrantRow(
        plugin_id="operator.synthetic.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/operator-grant-survives-reconcile",
    )

    async with backend_against(migrated_postgres) as (backend, _factory):
        # Boot 1: seed the static DLP grant + an operator grant + enable adapter A.
        await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)
        await backend.upsert_grant(operator_grant)
        await backend.reconcile_comms_adapter_grants((adapter_a,))

        loaded = await backend.load_grants()
        assert adapter_a in loaded
        assert operator_grant in loaded
        assert _DLP_GRANT in loaded

        # Boot 2: operator swaps adapter A -> adapter B. The scoped reconcile must
        # drop A and land B WITHOUT touching the operator grant or the DLP grant.
        await backend.reconcile_comms_adapter_grants((adapter_b,))

        loaded = await backend.load_grants()
        # The stale adapter-A grant is GONE.
        assert adapter_a not in loaded
        # The new adapter-B grant is present.
        assert adapter_b in loaded
        # The load-bearing survival property: neither the operator grant nor the
        # DLP system grant was collateral-revoked by the comms-scoped reconcile.
        assert operator_grant in loaded, (
            "reconcile_comms_adapter_grants revoked an operator grant — the "
            "revoke WHERE must be scoped to the comms-adapter sentinel branch"
        )
        assert _DLP_GRANT in loaded, (
            "reconcile_comms_adapter_grants revoked the DLP first-party-system "
            "grant — the revoke WHERE must be scoped to the comms-adapter sentinel"
        )


async def test_reconcile_to_empty_drops_all_comms_grants_only(
    migrated_postgres: str,
    backend_against: _BackendCM,
) -> None:
    """Disabling all comms adapters drops every sentinel grant, nothing else."""
    adapter_a = _comms_grant("alfred.comms-a")
    operator_grant = GrantRow(
        plugin_id="operator.synthetic.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/operator-grant-survives-empty-reconcile",
    )

    async with backend_against(migrated_postgres) as (backend, _factory):
        await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)
        await backend.upsert_grant(operator_grant)
        await backend.reconcile_comms_adapter_grants((adapter_a,))
        assert adapter_a in await backend.load_grants()

        # Operator removes every comms adapter.
        await backend.reconcile_comms_adapter_grants(())

        loaded = await backend.load_grants()
        assert adapter_a not in loaded
        assert operator_grant in loaded
        assert _DLP_GRANT in loaded
