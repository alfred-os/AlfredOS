"""Storage backend Protocol + :class:`PostgresBackend` for :class:`RealGate`.

Spec §8.1 (Fork 7): hot-path capability checks consult Postgres for
millisecond-latency answers. The ``plugin_grants`` and
``capability_gate_sync`` tables are defined in migrations
``0008_plugin_grants`` and ``0009_capability_gate_sync`` (PR-S3-0b);
the SQLAlchemy ORM models :class:`alfred.memory.models.PluginGrant` and
:class:`alfred.memory.models.CapabilityGateSyncRow` live alongside the
rest of the memory subsystem.

This module follows the sec-007 extension: it does NOT ``import os``.
``ALFRED_ENV`` selection (RealGate vs DevGate) lives in
:mod:`alfred.bootstrap.gate_factory` (a forthcoming PR-S3-2 task); the
DSN string is injected via dependency injection through the constructor.

The Postgres I/O surface uses SQLAlchemy 2.0 ``async_sessionmaker`` and
parameterised text queries — the schema is rigid enough (and the query
set small enough) that the typed-Core / ORM machinery would buy little
over the explicit ``sa.text`` form. Future PRs can lift to ORM if the
query shape becomes dynamic.

Hard invariants pinned by ``tests/unit/security/capability_gate/test_storage_backend.py``:

* :class:`StorageBackend` is ``@runtime_checkable``; concrete backends
  satisfy it structurally without subclassing.
* :class:`PostgresBackend` rejects an empty constructor (no
  ``session_factory`` AND no ``dsn``) with :class:`ValueError`.
* :meth:`PostgresBackend.upsert_grant` uses ``ON CONFLICT (plugin_id,
  hookpoint, subscriber_tier)`` — matches migration 0008's
  ``uq_plugin_grants_plugin_hook_tier`` UNIQUE constraint (mem-003).
* :meth:`PostgresBackend.revoke_grant` filters by all three key columns
  in the DELETE WHERE clause.
* :meth:`PostgresBackend.get_sync_hash` returns ``None`` on an unseeded
  table.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Final, Protocol, runtime_checkable

import sqlalchemy as sa
import structlog
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.security.capability_gate._comms_adapter_grants import (
    _COMMS_ADAPTER_PROPOSAL_BRANCH,
)
from alfred.security.capability_gate.policy import GrantRow

_log = structlog.get_logger(__name__)

# perf-002: hard cap on the ``SELECT ... FROM plugin_grants`` row count.
# 10_000 is several orders of magnitude above the expected grant count for
# a busy Slice-3+ deployment (low hundreds), so legitimate operators
# never hit the cap. If the load *does* hit the cap, it signals one of:
#  - a grant-table explosion (bug in the proposal flow / migration), or
#  - an attacker enumerating grants via a runaway proposal loop.
# Either way the supervisor needs to see it loudly — :meth:`load_grants`
# emits a structlog warning when the returned row count equals the cap.
#
# Full cursor-based pagination is deferred to Slice 4+ (the expected
# count makes pagination premature today); the warning + the cap together
# are the Slice-3 fail-loud contract per CLAUDE.md hard rule #7.
_LOAD_GRANTS_ROW_CAP: Final[int] = 10_000


def _grant_sort_key(grant: GrantRow) -> tuple[str, str, str, str, str]:
    """Composite sort key over every typed :class:`GrantRow` field.

    CR-149 round-6.5: :meth:`PostgresBackend.apply_atomic` receives
    :class:`frozenset`-shaped inputs from the gate (the parser returns
    ``frozenset[GrantRow]`` and the diff is computed by set algebra).
    ``list(...)`` alone preserves Python's set iteration order, which
    is hash-seeded and therefore unspecified between runs. Sorting by
    this composite key before iterating pins the per-row SQL/audit
    sequence so a rebuild always issues the same INSERT / UPDATE
    order — the audit-graph linkage assertions in the
    tier_laundering adversarial corpus rely on this determinism.

    The key includes every typed field, ordered most-specific-first,
    so two grants that disagree on ``content_tier`` (e.g.
    ``("alfred.web-fetch", "*", "operator", "T2", "branch")`` and
    ``("alfred.web-fetch", "*", "operator", "T3", "branch")``) sort
    deterministically rather than relying on set hash ordering.
    ``content_tier`` is coerced to ``""`` for the ``None`` case so the
    tuple comparison stays well-typed under ``mypy --strict``.
    """
    return (
        grant.plugin_id,
        grant.hookpoint,
        grant.subscriber_tier,
        grant.content_tier or "",
        grant.proposal_branch,
    )


@runtime_checkable
class StorageBackend(Protocol):
    """Structural Protocol for the :class:`RealGate` backing store.

    :class:`PostgresBackend` is the production implementation. Test
    doubles (and future backends — Redis-cached projection, in-memory
    for the dev gate fixture, etc.) implement this Protocol so
    :class:`RealGate` can compose with any backend without subclassing.

    The Protocol is ``@runtime_checkable`` so dispatcher code can
    ``isinstance``-narrow at runtime — same posture as
    :class:`alfred.hooks.capability.CapabilityGate`.
    """

    async def ping(self) -> None:
        """Raise on connectivity failure; return ``None`` on success.

        Used by the heartbeat task (spec §8.1) to detect backing-store
        outages. A raised exception trips the missed-heartbeat counter;
        crossing the 60s threshold flips the gate to fail-closed.
        """
        ...

    async def load_grants(self) -> frozenset[GrantRow]:
        """Load all active grants. Returns an empty ``frozenset`` if none."""
        ...

    async def upsert_grant(self, grant: GrantRow) -> None:
        """Insert or update one grant row.

        The unique key is ``(plugin_id, hookpoint, subscriber_tier)``;
        ``content_tier`` and ``proposal_branch`` are updated on conflict.
        """
        ...

    async def revoke_grant(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        subscriber_tier: str,
    ) -> None:
        """Remove a single grant. No-op if not present (idempotent)."""
        ...

    async def get_sync_hash(self) -> str | None:
        """Return the last-recorded state.git commit hash, or ``None`` if unseeded."""
        ...

    async def set_sync_hash(self, commit_hash: str) -> None:
        """Record the state.git commit hash after a successful rebuild."""
        ...

    async def apply_atomic(
        self,
        *,
        revokes: Iterable[GrantRow],
        upserts: Iterable[GrantRow],
        commit_hash: str,
    ) -> None:
        """Apply revokes + upserts + sync hash inside ONE transaction.

        sec-pr-s3-6-02 / perf-002 / err-003: the previous shape ran each
        of these as its own ``async with session.begin()`` block, so a
        database error mid-revoke (or between the revoke pass and the
        upsert pass, or before ``set_sync_hash`` lands) left Postgres
        with a partially-mutated grant table AND no sync-hash update — a
        silent split-brain shape. CLAUDE.md hard rule #7 (no silent
        failures in security paths) requires all-or-nothing: either every
        row in the snapshot lands and the sync hash advances, or NONE of
        them do and Postgres looks exactly like it did before the call.

        Atomicity contract:

        * One transaction. All revokes, all upserts, and the sync-hash
          set complete inside the same ``BEGIN``/``COMMIT`` block.
        * Any :class:`sqlalchemy.exc.SQLAlchemyError` raised by the
          driver mid-flight rolls the entire transaction back. The
          caller (:meth:`RealGate._apply_grants`) catches and emits an
          audit row with ``result="rolled_back"`` before re-raising.
        * Idempotent in the success path: a re-applied identical
          snapshot is a no-op at every SQL row (``DELETE`` of an absent
          row, ``ON CONFLICT DO UPDATE`` to the same values, ``UPSERT``
          of the same sync hash).

        Ordering inside the transaction matches the previous per-method
        sequence so the spec §8.1 audit-graph invariant ("revoke before
        any new grant's upsert") holds: revokes first, then upserts,
        then ``set_sync_hash``. The single transaction collapses these
        into one observable commit point; readers either see the entire
        new snapshot or the entire old one.

        Returns:
            ``None`` on success.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: Any driver-level error
                during DELETE / INSERT / UPSERT triggers the transaction
                rollback and is re-raised to the caller.
        """
        ...

    async def seed_first_party_grants(self, grants: Iterable[GrantRow]) -> None:
        """Upsert the first-party system grants inside ONE transaction.

        ADR-0026: AlfredOS's OWN defences (the system-tier
        ``security.quarantined.extract`` DLP subscriber) are seeded at
        boot rather than routed through the reviewer-gate proposal
        flow — the proposal flow runs inside the same daemon whose
        extractor needs the grant to construct, so routing it through
        the flow would be circular.

        Distinct from :meth:`apply_atomic`: this is ADDITIVE-only. It
        upserts each row as ``state='approved'`` and NEVER computes or
        applies a revoke set — seeding must not revoke an operator
        grant. Idempotent via ``ON CONFLICT DO UPDATE`` to the same
        values.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: Re-raised from the driver
                so a failed seed refuses boot (CLAUDE.md hard rule #7 —
                no silent failures in security paths).
        """
        ...

    async def reconcile_comms_adapter_grants(self, desired: Iterable[GrantRow]) -> None:
        """Make the comms-adapter LOAD grants in Postgres mirror ``desired`` exactly.

        FIX 2 (PR-S4-11b review). The config-sourced comms-adapter LOAD grants
        (ADR-0027, ``proposal_branch == 'bootstrap:first-party-comms-adapter'``)
        are DYNAMIC — driven by ``Settings.comms_enabled_adapters``. Unlike the
        STATIC :data:`FIRST_PARTY_SYSTEM_GRANTS` (never removed, so additive-only
        :meth:`seed_first_party_grants` is sufficient), a comms-adapter grant goes
        STALE the moment an operator removes the adapter — additive seeding never
        revokes it.

        This method is the SCOPED reconciliation — NOT a full revoke-diff. In ONE
        transaction it (a) DELETEs every existing ``plugin_grants`` row whose
        ``proposal_branch`` is the comms-adapter sentinel and whose identity is
        NOT in ``desired``, then (b) upserts ``desired`` as ``state='approved'``.
        The revoke WHERE clause is EXACTLY scoped to the
        ``bootstrap:first-party-comms-adapter`` sentinel, so it can NEVER touch
        the DLP ``bootstrap:first-party-system`` grant, an operator proposal
        grant, or any other row — that scoping is the load-bearing safety
        property (CLAUDE.md hard rule #2 — no silent capability changes outside
        the comms-adapter set).

        Raises:
            sqlalchemy.exc.SQLAlchemyError: Re-raised from the driver so a failed
                reconcile refuses boot (CLAUDE.md hard rule #7).
        """
        ...


class PostgresBackend:
    """Production :class:`StorageBackend` backed by Postgres.

    Operates on ``plugin_grants`` (migration 0008) for the grant rows
    and ``capability_gate_sync`` (migration 0009) for the rebuild-hash
    sync marker. Rebuilding is idempotent: :meth:`upsert_grant` and
    :meth:`set_sync_hash` are called atomically from
    :meth:`RealGate._apply_grants` when the state.git HEAD differs from
    the cached hash.

    Construction:

    * ``session_factory`` — a pre-built
      :class:`sqlalchemy.ext.asyncio.async_sessionmaker`; preferred when
      the surrounding app already manages the engine (production path).
    * ``dsn`` — a connection URL; the backend builds its own engine and
      sessionmaker. Convenience shortcut for tests that don't have a
      pre-built factory.

    Constructing with neither raises :class:`ValueError` — CLAUDE.md
    hard rule #7 (no silent failures) — a backend with no session
    factory cannot answer any of its Protocol methods.
    """

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        dsn: str | None = None,
    ) -> None:
        if session_factory is not None:
            self._session_factory = session_factory
        elif dsn is not None:
            engine = create_async_engine(dsn, echo=False)
            self._session_factory = async_sessionmaker(engine, expire_on_commit=False)
        else:
            msg = "PostgresBackend requires either session_factory or dsn; neither was provided"
            raise ValueError(msg)

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        """Open a session inside a ``BEGIN`` block (per-call transaction).

        Every backend method runs inside its own transaction so a
        failed write does not leave a half-applied state. The
        :func:`asynccontextmanager` decorator gives us ``async with``
        semantics over the two-level (factory + begin) nesting.
        """
        async with (
            self._session_factory() as session,
            session.begin(),
        ):
            yield session

    async def ping(self) -> None:
        """Issue ``SELECT 1`` against the backing store."""
        async with self._session() as session:
            await session.execute(sa.text("SELECT 1"))

    async def load_grants(self) -> frozenset[GrantRow]:
        """Load every active grant from ``plugin_grants`` as :class:`GrantRow`.

        Filters by ``state = 'approved'``. The closed-domain CHECK admits
        ``'requested' | 'approved' | 'denied' | 'revoked'``; only
        ``'approved'`` rows authorise hot-path dispatch. ``'requested'``
        rows are pending reviewer review; ``'denied'`` / ``'revoked'``
        are historical attribution kept for audit-graph traversal.
        Letting any non-approved row leak into the in-memory policy would
        be a silent privilege escalation — CLAUDE.md hard rule #7.

        perf-002: the SELECT is capped at :data:`_LOAD_GRANTS_ROW_CAP`
        (10_000) rows — several orders of magnitude above the expected
        grant count. If the cap is hit the method emits the
        ``capability_gate.load_grants.row_cap_hit`` warning so operators
        see the grant-table-explosion shape before the next rebuild
        loads the same truncated snapshot. Full cursor pagination is
        deferred to Slice 4+; the warning is the Slice-3 fail-loud
        contract.

        CR-142 round-3 sec-002: explicit ``ORDER BY plugin_id,
        hookpoint, subscriber_tier`` makes the truncation deterministic
        when the cap is hit. Without it, Postgres can return arbitrary
        rows under ``LIMIT`` — meaning two consecutive rebuilds on the
        same row count could load DIFFERENT 10_000-row subsets, leaving
        the in-memory policy non-reproducible. The three columns are
        the natural composite identity of a grant (per the
        ``UNIQUE (plugin_id, hookpoint, subscriber_tier)`` constraint
        on ``plugin_grants``), so the ordering is both stable across
        rebuilds and cheap on the existing index.
        """
        async with self._session() as session:
            result = await session.execute(
                sa.text(
                    "SELECT plugin_id, subscriber_tier, hookpoint, "
                    "content_tier, proposal_branch "
                    "FROM plugin_grants WHERE state = 'approved' "
                    "ORDER BY plugin_id, hookpoint, subscriber_tier "
                    "LIMIT :row_cap"
                ),
                {"row_cap": _LOAD_GRANTS_ROW_CAP},
            )
            rows = result.fetchall()
        if len(rows) >= _LOAD_GRANTS_ROW_CAP:
            # The cap is a release-blocker shape: every subsequent
            # rebuild will see the same truncated snapshot until the
            # underlying table shrinks below the cap. Emit at WARNING
            # level so the operator's alerting catches it without a
            # silent demotion of the in-memory policy.
            _log.warning(
                "capability_gate.load_grants.row_cap_hit",
                row_cap=_LOAD_GRANTS_ROW_CAP,
                row_count=len(rows),
            )
        return frozenset(
            GrantRow(
                plugin_id=r.plugin_id,
                subscriber_tier=r.subscriber_tier,
                hookpoint=r.hookpoint,
                content_tier=r.content_tier,
                proposal_branch=r.proposal_branch,
            )
            for r in rows
        )

    # ------------------------------------------------------------------
    # SQL-only helpers (no transaction management).
    #
    # sec-pr-s3-6-02: the public per-op methods below each open their
    # own ``async with session.begin()`` so external callers (tests,
    # integration round-trip, the proposal flow) get one-shot atomicity.
    # ``apply_atomic`` needs the *opposite* — many ops in one
    # transaction — so the SQL lives in these helpers, which both the
    # per-op methods and ``apply_atomic`` invoke. There is exactly ONE
    # source of truth for each SQL string.
    # ------------------------------------------------------------------

    @staticmethod
    async def _execute_upsert_grant(session: AsyncSession, grant: GrantRow) -> None:
        """Run the upsert SQL on an existing open session.

        The SQL string here is the single source of truth for the
        upsert shape; see :meth:`upsert_grant` for the docstring
        explaining the ON CONFLICT target, the NOT NULL column
        population strategy, and the ``state='approved'`` semantics.
        """
        now = dt.datetime.now(dt.UTC)
        # sec-pr-s3-6-cr-149: the ON CONFLICT branch MUST restore
        # ``state='approved'`` so a row that was previously in
        # ``requested``/``denied``/``revoked`` does not stay in that
        # state after a rebuild merges a fresh approval. Without the
        # state restore, :meth:`load_grants` would silently filter the
        # row out (it reads ``state = 'approved'`` only) and the
        # operator-visible grant would not project into the live
        # in-memory snapshot — a trust-boundary regression where an
        # approved capability becomes invisible. ``correlation_id`` is
        # refreshed alongside so the audit-graph correlator can join
        # the rebuild row against the latest projection event.
        await session.execute(
            sa.text(
                "INSERT INTO plugin_grants "
                "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                "content_tier, proposal_branch, correlation_id, state) "
                "VALUES (:id, :created_at, :plugin_id, :subscriber_tier, "
                ":hookpoint, :content_tier, :proposal_branch, "
                ":correlation_id, :state) "
                "ON CONFLICT (plugin_id, hookpoint, subscriber_tier) "
                "DO UPDATE SET content_tier = EXCLUDED.content_tier, "
                "proposal_branch = EXCLUDED.proposal_branch, "
                "state = EXCLUDED.state, "
                "correlation_id = EXCLUDED.correlation_id"
            ),
            {
                "id": uuid.uuid4(),
                "created_at": now,
                "plugin_id": grant.plugin_id,
                "subscriber_tier": grant.subscriber_tier,
                "hookpoint": grant.hookpoint,
                "content_tier": grant.content_tier,
                "proposal_branch": grant.proposal_branch,
                "correlation_id": str(uuid.uuid4()),
                "state": "approved",
            },
        )

    @staticmethod
    async def _execute_revoke_grant(
        session: AsyncSession,
        *,
        plugin_id: str,
        hookpoint: str,
        subscriber_tier: str,
    ) -> None:
        """Run the revoke DELETE on an existing open session.

        Idempotent (no error if the row is absent). The DELETE filter
        keys on all three uniqueness columns so a sibling grant (same
        plugin, different hookpoint or tier) is not collected.
        """
        await session.execute(
            sa.text(
                "DELETE FROM plugin_grants "
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

    @staticmethod
    async def _execute_set_sync_hash(
        session: AsyncSession,
        commit_hash: str,
    ) -> None:
        """Run the singleton-row upsert on an existing open session.

        mem-004: ``capability_gate_sync`` is the migration-0009 singleton
        table; the INTEGER PK has ``CHECK (id = 1)`` so this INSERT
        always targets ``id = 1`` and falls into the ``ON CONFLICT``
        update path on every call after the first.
        """
        await session.execute(
            sa.text(
                "INSERT INTO capability_gate_sync (id, commit_hash) "
                "VALUES (1, :commit_hash) "
                "ON CONFLICT (id) DO UPDATE SET "
                "commit_hash = EXCLUDED.commit_hash"
            ),
            {"commit_hash": commit_hash},
        )

    async def upsert_grant(self, grant: GrantRow) -> None:
        """Insert one grant or update on the (plugin_id, hookpoint, subscriber_tier) conflict.

        The ON CONFLICT target matches migration 0008's
        ``uq_plugin_grants_plugin_hook_tier`` UNIQUE constraint exactly;
        the mem-003 comment in that migration documents the contract.

        NOT NULL columns from migration 0008 — ``id``, ``created_at``,
        ``correlation_id``, ``state`` — are populated here at the SQL
        layer rather than at the :class:`GrantRow` boundary. Rationale:
        :class:`GrantRow` models the state.git source-of-truth shape;
        these four columns are persistence-layer attribution that lives
        in Postgres but not in the state.git proposal tree. Generating
        them here keeps the policy-layer immutable model lean.

        State semantics: every row written via this method represents an
        approved-and-merged grant (the reviewer-agent's
        ``state.git → main`` merge triggered the rebuild calling this
        path). The closed-domain CHECK in migration 0008 admits
        ``'approved'`` for that lifecycle position. ``'requested'`` rows
        come from the proposal flow (PR-S3-2 :mod:`proposals` writes to
        state.git, NOT this table); ``'denied'`` / ``'revoked'`` come
        from the reviewer-agent's tooling in a later PR.

        ``correlation_id`` is freshly minted per row — one rebuild
        operation upserts N grants and emits one audit row per upsert,
        each with its own correlation. The forensic graph follows the
        per-grant correlation upstream to the per-rebuild trace via
        ``state_git_commit_hash`` (populated by ``set_sync_hash``).
        """
        async with self._session() as session:
            await self._execute_upsert_grant(session, grant)

    async def revoke_grant(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        subscriber_tier: str,
    ) -> None:
        """Delete one grant; idempotent (no error if absent)."""
        async with self._session() as session:
            await self._execute_revoke_grant(
                session,
                plugin_id=plugin_id,
                hookpoint=hookpoint,
                subscriber_tier=subscriber_tier,
            )

    async def get_sync_hash(self) -> str | None:
        """Return the most recently recorded state.git HEAD hash, or ``None``."""
        async with self._session() as session:
            result = await session.execute(
                sa.text("SELECT commit_hash FROM capability_gate_sync ORDER BY id DESC LIMIT 1")
            )
            row = result.fetchone()
        if row is None:
            return None
        commit_hash: str = row.commit_hash
        return commit_hash

    async def set_sync_hash(self, commit_hash: str) -> None:
        """Upsert the singleton commit-hash marker (migration 0009).

        mem-004: the table's INTEGER PK has ``CHECK (id = 1)`` enforcing
        the singleton-row contract. The INSERT explicitly supplies
        ``id = 1``; the ``ON CONFLICT (id) DO UPDATE`` then updates the
        same row in place when called multiple times during a process
        lifetime (one set per state.git rebuild).
        """
        async with self._session() as session:
            await self._execute_set_sync_hash(session, commit_hash)

    async def apply_atomic(
        self,
        *,
        revokes: Iterable[GrantRow],
        upserts: Iterable[GrantRow],
        commit_hash: str,
    ) -> None:
        """Apply revokes + upserts + sync-hash in ONE transaction.

        sec-pr-s3-6-02 / perf-002 / err-003: see the
        :meth:`StorageBackend.apply_atomic` Protocol docstring for the
        full atomicity contract. The implementation here runs the
        existing SQL helpers inside a single ``async with
        session.begin()`` block — any :class:`sqlalchemy.exc.SQLAlchemyError`
        rolls back the entire transaction and propagates to the caller
        unchanged.

        ``revokes`` and ``upserts`` are materialised once via
        :func:`list` because the caller (the gate) may pass a single-use
        generator-like iterable; the SQL execution iterates in deterministic
        revoke-then-upsert order so the audit-graph invariant pinned by
        the tier_laundering adversarial suite holds.

        CR-149 round-6.5: the inputs are naturally :class:`frozenset`-
        shaped (the parser returns ``frozenset[GrantRow]`` and the
        policy diff is computed via set algebra), so ``list(...)``
        alone preserves an unspecified iteration order that can shuffle
        the audit-row sequence between calls. Sorting by the composite
        grant key — every typed field, in a fixed lexicographic order —
        pins the per-row SQL/audit sequence so a rebuild always issues
        the same INSERT / UPDATE order. The audit-graph linkage
        assertions in the tier_laundering adversarial corpus rely on
        this deterministic ordering to compare against recorded
        fixtures.
        """
        revoke_list = sorted(revokes, key=_grant_sort_key)
        upsert_list = sorted(upserts, key=_grant_sort_key)
        async with self._session() as session:
            for grant in revoke_list:
                await self._execute_revoke_grant(
                    session,
                    plugin_id=grant.plugin_id,
                    hookpoint=grant.hookpoint,
                    subscriber_tier=grant.subscriber_tier,
                )
            for grant in upsert_list:
                await self._execute_upsert_grant(session, grant)
            await self._execute_set_sync_hash(session, commit_hash)

    async def seed_first_party_grants(self, grants: Iterable[GrantRow]) -> None:
        """Upsert the ADR-0026 first-party system grants in ONE transaction.

        See the :meth:`StorageBackend.seed_first_party_grants` Protocol
        docstring for the full contract. The implementation reuses the
        single-source-of-truth :meth:`_execute_upsert_grant` SQL helper
        (state='approved', ON CONFLICT DO UPDATE — idempotent) inside one
        ``async with self._session()`` block — whose
        :func:`asynccontextmanager` body opens a single ``session.begin()``
        ``BEGIN``/``COMMIT`` for the whole seed (the per-call transaction
        contract every backend method shares; grep ``session.begin()`` lands
        on :meth:`_session`).

        ``grants`` is sorted by the same composite key
        :meth:`apply_atomic` uses so the per-row SQL/audit sequence is
        deterministic across boots — the audit-graph linkage assertions
        rely on a stable insert order. No revoke pass runs: a seed is
        additive only and must never remove an operator grant. A
        :class:`sqlalchemy.exc.SQLAlchemyError` mid-seed rolls the
        transaction back and propagates so a failed seed refuses boot.
        """
        seed_list = sorted(grants, key=_grant_sort_key)
        async with self._session() as session:
            for grant in seed_list:
                await self._execute_upsert_grant(session, grant)

    async def reconcile_comms_adapter_grants(self, desired: Iterable[GrantRow]) -> None:
        """Make the comms-adapter LOAD grants in Postgres mirror ``desired`` exactly.

        See the :meth:`StorageBackend.reconcile_comms_adapter_grants` Protocol
        docstring for the full contract + the load-bearing safety property.

        One transaction. First SELECT every existing ``plugin_grants`` row scoped
        to the comms-adapter sentinel ``proposal_branch`` (the WHERE pins the
        sentinel, so the read can never see the DLP ``bootstrap:first-party-system``
        grant or an operator branch). Then compute the STALE set
        ``existing minus desired`` by ``(plugin_id, hookpoint, subscriber_tier)``
        identity and DELETE each stale row — the DELETE WHERE ALSO pins the
        sentinel branch (defence in depth: even an identity collision across
        branches could only delete the sentinel row). Finally upsert ``desired``
        as ``state='approved'`` (idempotent ``ON CONFLICT DO UPDATE``).

        ``desired`` is sorted by the same composite key the seed/apply paths use
        so the per-row SQL/audit sequence is deterministic across boots.
        """
        desired_list = sorted(desired, key=_grant_sort_key)
        desired_identities = {(g.plugin_id, g.hookpoint, g.subscriber_tier) for g in desired_list}
        async with self._session() as session:
            existing = await session.execute(
                sa.text(
                    "SELECT plugin_id, hookpoint, subscriber_tier "
                    "FROM plugin_grants WHERE proposal_branch = :proposal_branch"
                ),
                {"proposal_branch": _COMMS_ADAPTER_PROPOSAL_BRANCH},
            )
            stale = sorted(
                (r.plugin_id, r.hookpoint, r.subscriber_tier)
                for r in existing.fetchall()
                if (r.plugin_id, r.hookpoint, r.subscriber_tier) not in desired_identities
            )
            for plugin_id, hookpoint, subscriber_tier in stale:
                await session.execute(
                    sa.text(
                        "DELETE FROM plugin_grants "
                        "WHERE plugin_id = :plugin_id "
                        "AND hookpoint = :hookpoint "
                        "AND subscriber_tier = :subscriber_tier "
                        "AND proposal_branch = :proposal_branch"
                    ),
                    {
                        "plugin_id": plugin_id,
                        "hookpoint": hookpoint,
                        "subscriber_tier": subscriber_tier,
                        "proposal_branch": _COMMS_ADAPTER_PROPOSAL_BRANCH,
                    },
                )
            for grant in desired_list:
                await self._execute_upsert_grant(session, grant)
