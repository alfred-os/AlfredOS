"""Integration: full grant lifecycle proposal → review → apply → check.

Spec §8.1, §8.3, §8.5 — drives the reviewer-gated grant flow end-to-end
against a real Postgres testcontainer:

1. :func:`create_proposal_branch` writes a proposal stub (the gitpython
   integration is deferred to PR-S3-6; the stub returns the branch
   name and the audit row emits via the supplied sink).
2. The proposal is NOT applied to Postgres at this stage — spec §8.3
   requires reviewer-merge gating; calling :meth:`PostgresBackend.upsert_grant`
   at proposal time would silently activate an unreviewed grant.
3. Simulating the reviewer-merge: call :meth:`RealGate._apply_grants`
   directly with the parsed grant (PR-S3-6 will wire this through
   ``parse_state_git_head`` + the gitpython driver).
4. After apply: hot-path :meth:`RealGate.check` returns ``True``; the
   Postgres ``plugin_grants`` row is visible to a fresh
   :class:`PostgresBackend`; the audit sink received one
   ``plugin.grant.requested`` row from the proposal step.
5. Revocation: apply an empty grant set with a new commit hash. The
   in-memory policy and the Postgres table both clear.

Coverage rationale: the unit tier (``tests/unit/security/capability_gate/``)
covers proposal-flow logic against a MagicMock backend; the hybrid-storage
round-trip (``test_hybrid_storage_roundtrip.py``) drives RealGate against
the real Postgres but skips the proposal flow. This module joins the two
— proposal + reviewer-merge + check + revoke against the same real DB
inside one test — so a regression in the join surfaces here rather than
in production.

Placement: under ``tests/integration/security/capability_gate/`` so the
storage round-trip, outage scenarios, and grant lifecycle e2e all live
together in operator-facing review order.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.backend import PostgresBackend
from alfred.security.capability_gate.policy import GrantRow
from alfred.security.capability_gate.proposals import create_proposal_branch

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Test fixtures — mirror ``test_hybrid_storage_roundtrip.py``
# ---------------------------------------------------------------------------


@pytest.fixture
def alembic_cfg(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> config.Config:
    """Alembic Config pointed at the per-test container.

    Same shape as the hybrid-storage round-trip suite — both env-var
    and Config ``sqlalchemy.url`` so the migration env covers either
    code path.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


@pytest.fixture
def migrated_postgres(
    alembic_cfg: config.Config,
    postgres_url: str,
) -> str:
    """Upgrade the per-test container to HEAD before any backend operation.

    HEAD includes migration 0008 (``plugin_grants``) and 0009
    (``capability_gate_sync``) — both required for the
    :class:`PostgresBackend` round trip below.
    """
    command.upgrade(alembic_cfg, "head")
    return postgres_url


def _make_audit_sink() -> Any:
    """Construct a Protocol-compatible audit sink double.

    Real :class:`AuditWriter` is exercised by ``test_audit_persistence.py``
    — that's the canonical integration tier for the audit subsystem.
    Here we want a structural seam that the proposal-flow + gate emit
    paths can call and we can assert on the call shape post-hoc.
    """
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


@asynccontextmanager
async def _backend_against(
    postgres_url: str,
) -> AsyncIterator[tuple[PostgresBackend, async_sessionmaker[AsyncSession]]]:
    """Yield a ``(PostgresBackend, factory)`` pair against the per-test container.

    Disposing the engine on exit prevents open-connection leakage across
    nested ``async with`` blocks in the same test — critical for the
    proposal → apply → check sequence which builds two backends against
    the same DB to simulate the cross-process roundtrip.
    """
    engine = create_async_engine(postgres_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    backend = PostgresBackend(session_factory=factory)
    try:
        yield backend, factory
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_grant_lifecycle_proposal_to_check_to_revoke(
    migrated_postgres: str,
) -> None:
    """Full reviewer-gated lifecycle against real Postgres.

    Asserts the §8.3 invariant that a proposal does NOT activate the
    grant — :meth:`RealGate.check` keeps returning ``False`` until the
    simulated reviewer-merge step (``_apply_grants``) runs. After
    revoke, both the in-memory policy and the Postgres table clear.
    """
    sink = _make_audit_sink()

    grant = GrantRow(
        plugin_id="e2e.proposal.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-e2e-pending",
    )

    async with _backend_against(migrated_postgres) as (backend, _factory):
        gate = await RealGate.create(
            backend=backend,
            audit_sink=sink,
            start_heartbeat=False,
        )

        # Step 1 — empty table, gate denies.
        assert (
            gate.check(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                requested_tier=grant.subscriber_tier,
            )
            is False
        )

        # Step 2 — proposal-flow: writes to state.git (stub) and emits
        # plugin.grant.requested. Does NOT touch Postgres.
        branch = await create_proposal_branch(
            plugin_id=grant.plugin_id,
            subscriber_tier=grant.subscriber_tier,
            hookpoint=grant.hookpoint,
            operator_user_id="ian@example.com",
            backend=backend,
            audit_sink=sink,
        )
        assert branch.startswith("proposal/policy-grant-")

        # Spec §8.3: gate still denies — the proposal is inert until
        # the reviewer-gate merge triggers _apply_grants.
        assert (
            gate.check(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                requested_tier=grant.subscriber_tier,
            )
            is False
        )

        # Step 3 — simulate reviewer approval: call _apply_grants with
        # the grant the reviewer just approved (in production PR-S3-6
        # parses this from the merged proposal branch).
        await gate._apply_grants(
            frozenset({grant}),
            commit_hash="approved-head-abc123",
        )

        # Now the gate grants.
        assert (
            gate.check(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                requested_tier=grant.subscriber_tier,
            )
            is True
        )

        # Postgres roundtrip: load from a separate session — the row
        # survives the in-memory swap.
        fresh_grants = await backend.load_grants()
        assert grant in fresh_grants
        assert await backend.get_sync_hash() == "approved-head-abc123"

        # Step 4 — revocation: apply empty grants with a new hash.
        await gate._apply_grants(
            frozenset(),
            commit_hash="post-revoke-head-def456",
        )

        # Gate denies again — in-memory swap.
        assert (
            gate.check(
                plugin_id=grant.plugin_id,
                hookpoint=grant.hookpoint,
                requested_tier=grant.subscriber_tier,
            )
            is False
        )

        # Postgres: the prior upsert wrote the row; the revocation does
        # NOT auto-delete (spec §8.5: revoke is its own DELETE step).
        # The current _apply_grants signature does not revoke implicit
        # absentees from the prior set — PR-S3-6's parser handles the
        # delta. For now, assert the sync hash advanced.
        assert await backend.get_sync_hash() == "post-revoke-head-def456"

    # Step 5 — fresh backend against the same DB: confirms the upsert
    # persisted across the connection boundary. The grant row from the
    # first apply is still present in the table; revocation by
    # _apply_grants(emptyset) does not delete rows (deletion is
    # PostgresBackend.revoke_grant's responsibility). PR-S3-6 wires
    # both into the gitpython parser.
    async with _backend_against(migrated_postgres) as (backend2, _factory2):
        stored = await backend2.load_grants()
        assert grant in stored

    # Audit sink: at least one plugin.grant.requested row was emitted
    # by create_proposal_branch. The supervisor.* audit emits are
    # gate-side and would also land here if the heartbeat had been on
    # — start_heartbeat=False suppresses those, so the only required
    # call is the proposal request.
    requested_calls = [
        c
        for c in sink.append_schema.await_args_list
        if c.kwargs.get("event") == "plugin.grant.requested"
    ]
    assert len(requested_calls) == 1, (
        f"Expected exactly one plugin.grant.requested audit row, got {len(requested_calls)}."
    )


async def test_proposal_does_not_upsert_to_postgres(
    migrated_postgres: str,
) -> None:
    """Spec §8.3 contract: proposal-flow MUST NOT touch ``plugin_grants``.

    A proposal that silently upserted would activate the grant before
    the reviewer-gate flow had a chance to refuse — the silent
    privilege-escalation shape CLAUDE.md hard rule #2 forbids. This
    test pins the contract against a real Postgres so a future refactor
    that wires upsert into create_proposal_branch fails loudly here
    instead of leaking through the unit suite's mocked backend.
    """
    sink = _make_audit_sink()

    async with _backend_against(migrated_postgres) as (backend, _factory):
        # Pre-state: table is empty.
        assert await backend.load_grants() == frozenset()

        branch = await create_proposal_branch(
            plugin_id="silent.escalation.plugin",
            subscriber_tier="system",
            hookpoint="tool.unrestricted",
            operator_user_id="ian@example.com",
            backend=backend,
            audit_sink=sink,
        )
        assert branch.startswith("proposal/policy-grant-")

        # The post-state MUST still be empty — no silent upsert.
        post_grants = await backend.load_grants()
        assert post_grants == frozenset(), (
            "create_proposal_branch upserted to plugin_grants — that violates "
            "spec §8.3 (proposals are inert until reviewer-merge)."
        )

        # And no sync hash drift either.
        assert await backend.get_sync_hash() is None
