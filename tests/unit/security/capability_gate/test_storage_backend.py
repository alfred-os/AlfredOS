"""Tests for ``alfred.security.capability_gate.backend``.

Covers the StorageBackend Protocol and the PostgresBackend production
implementation. The Postgres I/O surface stays under unit-tier control
by stubbing
``async_sessionmaker``: each unit test injects a fake session factory
whose context-manager yields an ``AsyncSession`` mock and the test
asserts on the SQL the backend emits. A separate integration tier (under
``tests/integration/security/``) exercises the same code path against a
real :class:`testcontainers.postgres.PostgresContainer` to confirm the
DDL and the ON CONFLICT target line up with migration 0008.

Hard invariants pinned here:

* **StorageBackend is a runtime-checkable Protocol** — :class:`PostgresBackend`
  satisfies it structurally without subclassing. Other backing-store
  implementations (e.g. a Redis-cached projection in a future PR) can drop
  in without touching :class:`RealGate`.
* **PostgresBackend rejects empty constructor calls** — at least one of
  ``session_factory`` or ``dsn`` MUST be provided. Constructing with
  neither raises :class:`ValueError`; CLAUDE.md hard rule #7 (no silent
  failures) — a backend without a session factory cannot answer
  ``ping()`` / ``load_grants()`` / etc. and a silent ``None`` factory is
  the wrong shape.
* **upsert_grant uses the ON CONFLICT target migration 0008 declared**
  — ``(plugin_id, hookpoint, subscriber_tier)`` is the unique index;
  migration 0008's mem-003 comment pins this. The test asserts the SQL
  text contains the right ``ON CONFLICT`` clause so a future refactor
  cannot quietly drop the constraint.
* **revoke_grant DELETE filters by all three columns** — partial filter
  would delete sibling grants by accident.
* **get_sync_hash returns None on an empty table** — the bootstrap state
  before any state.git HEAD has been recorded. Distinct from a "stale
  cache" hash, which is non-None and out-of-date.

The integration-tier round-trip pin (real container, real plugin_grants
table) is intentionally deferred to ``tests/integration/`` so the unit
suite stays driver-free; this matches the pattern in
``tests/unit/memory/test_db.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest


def _fake_session_factory() -> tuple[MagicMock, MagicMock]:
    """Return ``(session_factory_mock, session_mock)``.

    ``session_factory()`` returns an async context manager whose ``__aenter__``
    yields ``session_mock``. ``session_mock.begin()`` returns a second async
    context manager. ``session_mock.execute()`` is an ``AsyncMock`` whose
    ``return_value`` defaults to a result with ``fetchone``/``fetchall``
    helpers — individual tests override as needed.
    """
    session_mock = MagicMock()

    # session.execute is an AsyncMock — the test sets return_value as needed.
    result_mock = MagicMock()
    result_mock.fetchone.return_value = None
    result_mock.fetchall.return_value = []
    session_mock.execute = AsyncMock(return_value=result_mock)

    # session.begin() returns an async context manager.
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=session_mock)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session_mock.begin = MagicMock(return_value=begin_cm)

    # session_factory() returns an async context manager yielding session_mock.
    factory_cm = MagicMock()
    factory_cm.__aenter__ = AsyncMock(return_value=session_mock)
    factory_cm.__aexit__ = AsyncMock(return_value=None)

    factory = MagicMock(return_value=factory_cm)
    return factory, session_mock


def test_storage_backend_is_runtime_checkable_protocol() -> None:
    """:class:`StorageBackend` is a runtime-checkable Protocol.

    Concrete backends (PostgresBackend; future Redis-cached projection)
    satisfy it structurally without subclassing. The Protocol is the
    typed seam :class:`RealGate` narrows against — without
    ``@runtime_checkable``, the structural dispatch would silently fall
    apart at runtime.
    """
    from alfred.security.capability_gate.backend import (
        PostgresBackend,
        StorageBackend,
    )

    # The Protocol has the methods every backend honours.
    assert hasattr(StorageBackend, "ping")
    assert hasattr(StorageBackend, "load_grants")
    assert hasattr(StorageBackend, "upsert_grant")
    assert hasattr(StorageBackend, "revoke_grant")
    assert hasattr(StorageBackend, "get_sync_hash")
    assert hasattr(StorageBackend, "set_sync_hash")

    # PostgresBackend satisfies the Protocol structurally.
    factory, _ = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    assert isinstance(backend, StorageBackend)


def test_postgres_backend_rejects_empty_constructor() -> None:
    """Constructor with neither ``session_factory`` nor ``dsn`` raises ValueError.

    CLAUDE.md hard rule #7 (no silent failures): a backend constructed
    with no session factory cannot answer ``ping`` / ``load_grants`` /
    etc., and a silent ``None`` factory is the wrong shape — better to
    fail loudly at construction time.
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    with pytest.raises(ValueError, match="session_factory or dsn"):
        PostgresBackend()


def test_postgres_backend_accepts_dsn_constructor() -> None:
    """Constructor with ``dsn`` builds an internal session factory.

    Used in tests that don't have a pre-built sessionmaker. The DSN goes
    through SQLAlchemy's ``create_async_engine`` — we don't connect, we
    just assert the constructor succeeds without raising.
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    backend = PostgresBackend(dsn="postgresql+asyncpg://user:pw@host/db")
    # No exception — backend is constructed; the engine is created lazily on
    # first session entry. We do NOT call ping() here because no DB exists.
    assert backend is not None


async def test_ping_executes_select_one() -> None:
    """``ping()`` issues ``SELECT 1`` against the backing store.

    The heartbeat task (PR-S3-2 Component E) calls ``ping()`` every 10s;
    a SELECT 1 is the canonical no-op liveness probe.
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    await backend.ping()

    # session.execute was called exactly once with SELECT 1.
    session.execute.assert_awaited_once()
    sql_arg = session.execute.await_args.args[0]
    assert "SELECT 1" in str(sql_arg)


async def test_load_grants_returns_empty_frozenset_when_no_rows() -> None:
    """An empty ``plugin_grants`` table yields an empty :class:`frozenset`."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, _session = _fake_session_factory()
    # fetchall returns [] from the default result_mock.
    backend = PostgresBackend(session_factory=factory)
    rows = await backend.load_grants()
    assert isinstance(rows, frozenset)
    assert len(rows) == 0


async def test_load_grants_maps_rows_to_grant_row() -> None:
    """Each DB row is mapped to a :class:`GrantRow` with named attributes."""
    from alfred.security.capability_gate.backend import PostgresBackend
    from alfred.security.capability_gate.policy import GrantRow

    factory, session = _fake_session_factory()

    # Build two row mocks (mimicking SQLAlchemy named-tuple Row API).
    row_a = MagicMock()
    row_a.plugin_id = "test.plugin"
    row_a.subscriber_tier = "operator"
    row_a.hookpoint = "tool.web.fetch"
    row_a.content_tier = None
    row_a.proposal_branch = "proposal/policy-grant-abc"

    row_b = MagicMock()
    row_b.plugin_id = "quarantine.host"
    row_b.subscriber_tier = "system"
    row_b.hookpoint = "tag.T3"
    row_b.content_tier = "T3"
    row_b.proposal_branch = "proposal/policy-grant-t3"

    result_mock = MagicMock()
    result_mock.fetchall.return_value = [row_a, row_b]
    session.execute = AsyncMock(return_value=result_mock)

    backend = PostgresBackend(session_factory=factory)
    rows = await backend.load_grants()
    assert isinstance(rows, frozenset)
    assert len(rows) == 2
    assert (
        GrantRow(
            plugin_id="test.plugin",
            subscriber_tier="operator",
            hookpoint="tool.web.fetch",
            content_tier=None,
            proposal_branch="proposal/policy-grant-abc",
        )
        in rows
    )
    assert (
        GrantRow(
            plugin_id="quarantine.host",
            subscriber_tier="system",
            hookpoint="tag.T3",
            content_tier="T3",
            proposal_branch="proposal/policy-grant-t3",
        )
        in rows
    )


async def test_upsert_grant_uses_correct_on_conflict_target() -> None:
    """``upsert_grant`` issues INSERT … ON CONFLICT (plugin_id, hookpoint, subscriber_tier).

    Migration 0008 (PR-S3-0b) declares the UNIQUE constraint on exactly
    these three columns (``uq_plugin_grants_plugin_hook_tier`` — mem-003
    comment in the migration). If a refactor silently drops the constraint
    or shrinks the target, every upsert raises ``InvalidColumnReference``
    at runtime. This test pins the SQL target so the breakage surfaces in
    the unit tier, not in integration.

    Persistence-layer fields auto-supplied by ``upsert_grant`` (mem-006):
    ``id``, ``created_at``, ``correlation_id``, ``state`` are NOT NULL in
    migration 0008 but absent from the policy-layer
    :class:`GrantRow`. The backend generates them at the SQL layer; this
    test asserts the GrantRow-derived columns match exactly and the
    auto-supplied columns are present (without pinning their generated
    values — UUIDs and timestamps differ run to run).
    """
    import datetime as dt
    import uuid as _uuid

    from alfred.security.capability_gate.backend import PostgresBackend
    from alfred.security.capability_gate.policy import GrantRow

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    grant = GrantRow(
        plugin_id="test.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-abc",
    )
    await backend.upsert_grant(grant)
    session.execute.assert_awaited_once()
    sql_arg, params = session.execute.await_args.args
    sql_text = str(sql_arg)
    assert "INSERT INTO plugin_grants" in sql_text
    assert "ON CONFLICT (plugin_id, hookpoint, subscriber_tier)" in sql_text

    # GrantRow-derived columns: exact match.
    assert params["plugin_id"] == "test.plugin"
    assert params["subscriber_tier"] == "operator"
    assert params["hookpoint"] == "tool.web.fetch"
    assert params["content_tier"] is None
    assert params["proposal_branch"] == "proposal/policy-grant-abc"

    # Auto-supplied persistence fields: shape match, not value match.
    assert isinstance(params["id"], _uuid.UUID)
    assert isinstance(params["created_at"], dt.datetime)
    assert params["created_at"].tzinfo is not None
    # correlation_id is a UUID rendered as str (the audit-row family
    # expects a string, not a UUID object — same shape as Slice-2.5
    # audit emitters).
    assert isinstance(params["correlation_id"], str)
    _uuid.UUID(params["correlation_id"])
    # state must be one of the migration-0008 closed-domain values; the
    # rebuild path writes 'approved' (post-reviewer-merge).
    assert params["state"] == "approved"


async def test_revoke_grant_deletes_by_all_three_keys() -> None:
    """``revoke_grant`` DELETE filters by ``plugin_id``, ``hookpoint``, and ``subscriber_tier``.

    A partial filter (missing any of the three) would delete sibling
    grants by accident — e.g. revoking ``mypl/operator`` would also
    delete ``mypl/system`` if the subscriber_tier filter were missing.
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    await backend.revoke_grant(
        plugin_id="test.plugin",
        hookpoint="tool.web.fetch",
        subscriber_tier="operator",
    )
    session.execute.assert_awaited_once()
    sql_arg, params = session.execute.await_args.args
    sql_text = str(sql_arg)
    assert "DELETE FROM plugin_grants" in sql_text
    assert "plugin_id = :plugin_id" in sql_text
    assert "hookpoint = :hookpoint" in sql_text
    assert "subscriber_tier = :subscriber_tier" in sql_text
    assert params == {
        "plugin_id": "test.plugin",
        "hookpoint": "tool.web.fetch",
        "subscriber_tier": "operator",
    }


async def test_get_sync_hash_returns_none_when_unseeded() -> None:
    """An empty ``capability_gate_sync`` table yields ``None``.

    The bootstrap state before any state.git HEAD has been recorded;
    distinct from a stale cache (non-None and out-of-date).
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, _ = _fake_session_factory()
    # fetchone defaults to None.
    backend = PostgresBackend(session_factory=factory)
    hash_ = await backend.get_sync_hash()
    assert hash_ is None


async def test_get_sync_hash_returns_stored_hash() -> None:
    """A row in ``capability_gate_sync`` yields the recorded commit hash."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    row = MagicMock()
    row.commit_hash = "abc123deadbeef"
    result = MagicMock()
    result.fetchone.return_value = row
    session.execute = AsyncMock(return_value=result)

    backend = PostgresBackend(session_factory=factory)
    hash_ = await backend.get_sync_hash()
    assert hash_ == "abc123deadbeef"


async def test_set_sync_hash_upserts() -> None:
    """``set_sync_hash`` upserts the commit hash (idempotent across calls).

    Migration 0009 (PR-S3-0b) declares the table with a single-row
    invariant. The upsert keeps the row count at exactly one and updates
    the hash on every rebuild.
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    await backend.set_sync_hash("new-head-hash")
    session.execute.assert_awaited_once()
    sql_arg, params = session.execute.await_args.args
    sql_text = str(sql_arg)
    assert "INSERT INTO capability_gate_sync" in sql_text
    assert "ON CONFLICT" in sql_text
    assert params == {"commit_hash": "new-head-hash"}
