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


async def test_load_grants_passes_limit_to_sql_query() -> None:
    """perf-002: the ``load_grants`` SQL carries ``LIMIT :row_cap`` (10_000).

    An unbounded ``SELECT * FROM plugin_grants`` is a denial-of-service
    risk on a grant-table explosion. The cap is several orders of
    magnitude above the expected count, so legitimate operators never
    notice; pinning it here protects against a future refactor silently
    dropping the LIMIT clause.
    """
    from alfred.security.capability_gate.backend import (
        _LOAD_GRANTS_ROW_CAP,
        PostgresBackend,
    )

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    await backend.load_grants()

    session.execute.assert_awaited_once()
    sql_arg = session.execute.await_args.args[0]
    assert "LIMIT :row_cap" in str(sql_arg), (
        f"load_grants SQL missing LIMIT clause; got: {sql_arg!s}"
    )
    # The cap is bound as a parameter so DB-level prepared-statement
    # caching works and the value is auditable from the call site.
    params = session.execute.await_args.args[1]
    assert params == {"row_cap": _LOAD_GRANTS_ROW_CAP}


async def test_load_grants_emits_warning_on_row_cap_hit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """perf-002: hitting the row cap emits ``capability_gate.load_grants.row_cap_hit``.

    A returned row count equal to the cap means the table held >= cap
    rows and the snapshot is truncated — the in-memory policy will
    silently lose grants. CLAUDE.md hard rule #7 (no silent failures):
    the warning surfaces the contract violation so the operator's
    alerting catches it before a real grant is denied unnoticed.
    """
    import structlog

    from alfred.security.capability_gate.backend import (
        _LOAD_GRANTS_ROW_CAP,
        PostgresBackend,
    )

    # Build exactly _LOAD_GRANTS_ROW_CAP minimal rows so the cap-hit
    # branch fires. The closed-domain GrantRow constructor would object
    # to bogus tier strings; we feed valid-looking ones.
    rows: list[MagicMock] = []
    for i in range(_LOAD_GRANTS_ROW_CAP):
        row = MagicMock()
        row.plugin_id = f"plugin.{i}"
        row.subscriber_tier = "operator"
        row.hookpoint = "tool.web.fetch"
        row.content_tier = None
        row.proposal_branch = f"proposal/policy-grant-{i}"
        rows.append(row)

    factory, session = _fake_session_factory()
    result_mock = MagicMock()
    result_mock.fetchall.return_value = rows
    session.execute = AsyncMock(return_value=result_mock)

    backend = PostgresBackend(session_factory=factory)
    with structlog.testing.capture_logs() as log_entries:
        result = await backend.load_grants()

    assert len(result) == _LOAD_GRANTS_ROW_CAP
    cap_hits = [
        e for e in log_entries if e.get("event") == "capability_gate.load_grants.row_cap_hit"
    ]
    assert cap_hits, (
        f"Expected capability_gate.load_grants.row_cap_hit warning; "
        f"got events: {[e.get('event') for e in log_entries]}"
    )
    entry = cap_hits[0]
    assert entry.get("log_level") == "warning"
    assert entry.get("row_cap") == _LOAD_GRANTS_ROW_CAP
    assert entry.get("row_count") == _LOAD_GRANTS_ROW_CAP


async def test_load_grants_no_warning_under_row_cap() -> None:
    """A normal-shaped grant set (well under the cap) emits NO cap-hit warning.

    The warning is reserved for the explosion shape — emitting it on
    every healthy rebuild would train operators to ignore it.
    """
    import structlog

    from alfred.security.capability_gate.backend import PostgresBackend

    row = MagicMock()
    row.plugin_id = "plugin.normal"
    row.subscriber_tier = "operator"
    row.hookpoint = "tool.web.fetch"
    row.content_tier = None
    row.proposal_branch = "proposal/policy-grant-x"

    factory, session = _fake_session_factory()
    result_mock = MagicMock()
    result_mock.fetchall.return_value = [row]
    session.execute = AsyncMock(return_value=result_mock)

    backend = PostgresBackend(session_factory=factory)
    with structlog.testing.capture_logs() as log_entries:
        await backend.load_grants()

    cap_hits = [
        e for e in log_entries if e.get("event") == "capability_gate.load_grants.row_cap_hit"
    ]
    assert not cap_hits, f"Healthy rebuild should not emit cap-hit warning; got: {cap_hits!r}"


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


# ---------------------------------------------------------------------------
# apply_atomic — single-transaction batch (sec-pr-s3-6-02 / perf-002 / err-003)
# ---------------------------------------------------------------------------


async def test_apply_atomic_runs_all_sql_inside_one_session() -> None:
    """``apply_atomic`` runs every DELETE / INSERT / UPSERT on ONE session.

    The atomicity contract: a single ``async with session.begin()``
    block wraps every SQL statement. The fake factory's ``begin`` mock
    is invoked exactly once across N revokes + M upserts + the
    trailing ``set_sync_hash`` — the sentinel that pins the batch
    against a regression where ``apply_atomic`` opens a per-op
    transaction inside.
    """
    from alfred.security.capability_gate.backend import PostgresBackend
    from alfred.security.capability_gate.policy import GrantRow

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    revokes = [
        GrantRow(
            plugin_id="legacy.a",
            subscriber_tier="operator",
            hookpoint="tool.a",
            content_tier=None,
            proposal_branch="proposal/policy-grant-legacy-a",
        ),
        GrantRow(
            plugin_id="legacy.b",
            subscriber_tier="operator",
            hookpoint="tool.b",
            content_tier=None,
            proposal_branch="proposal/policy-grant-legacy-b",
        ),
    ]
    upserts = [
        GrantRow(
            plugin_id="new.x",
            subscriber_tier="operator",
            hookpoint="tool.x",
            content_tier=None,
            proposal_branch="proposal/policy-grant-new-x",
        ),
    ]

    await backend.apply_atomic(
        revokes=revokes,
        upserts=upserts,
        commit_hash="atomic-head-hash",
    )

    # Exactly ONE ``session.begin()`` for the whole batch — proves the
    # single-transaction contract holds.
    session.begin.assert_called_once()

    # CR-149: ``begin.assert_called_once`` only pins ONE transaction;
    # an implementation that opens a SECOND session (e.g. to call
    # ``set_sync_hash`` against a fresh acquisition) would still
    # satisfy that assertion because the same context-manager mock
    # is reused on every call. ``factory.assert_called_once`` pins
    # ONE session acquisition, closing the loophole. The contract
    # docstring on :meth:`apply_atomic` already promises "one
    # session, one transaction"; this assertion makes both halves
    # of the promise enforceable.
    factory.assert_called_once()

    # The execute mock saw every SQL: 2 deletes + 1 insert + 1 sync-hash
    # upsert = 4 calls in revoke-then-upsert-then-sync-hash order.
    assert session.execute.await_count == 4
    sql_strings = [str(call.args[0]) for call in session.execute.await_args_list]
    assert "DELETE FROM plugin_grants" in sql_strings[0]
    assert "DELETE FROM plugin_grants" in sql_strings[1]
    assert "INSERT INTO plugin_grants" in sql_strings[2]
    assert "INSERT INTO capability_gate_sync" in sql_strings[3]


async def test_apply_atomic_empty_batches_still_set_sync_hash() -> None:
    """Empty revokes + empty upserts → only the ``set_sync_hash`` SQL fires.

    The bootstrap shape: a freshly-initialised state.git push has no
    grants but still advances the sync hash. The transaction stays
    well-formed (one begin, one execute).
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    await backend.apply_atomic(
        revokes=[],
        upserts=[],
        commit_hash="bootstrap-hash",
    )

    session.begin.assert_called_once()
    session.execute.assert_awaited_once()
    sql_arg, params = session.execute.await_args.args
    assert "INSERT INTO capability_gate_sync" in str(sql_arg)
    assert params == {"commit_hash": "bootstrap-hash"}


async def test_apply_atomic_propagates_sqlalchemy_error() -> None:
    """A driver-level error raised mid-batch propagates unchanged.

    The transaction-begin context manager handles rollback at the
    SQLAlchemy layer (its ``__aexit__`` rolls back on exception). The
    backend method does NOT catch the error — that's the gate's job in
    :meth:`RealGate._apply_grants`. This test pins the propagation
    contract so a misguided ``except SQLAlchemyError`` slip in the
    backend would surface here.
    """
    from sqlalchemy.exc import OperationalError, SQLAlchemyError

    from alfred.security.capability_gate.backend import PostgresBackend
    from alfred.security.capability_gate.policy import GrantRow

    factory, session = _fake_session_factory()
    # Make execute raise on the first call so the apply_atomic loop
    # surfaces the error to the caller.
    session.execute = AsyncMock(
        side_effect=OperationalError("simulated", params=None, orig=Exception("simulated"))
    )

    backend = PostgresBackend(session_factory=factory)
    revokes = [
        GrantRow(
            plugin_id="legacy.a",
            subscriber_tier="operator",
            hookpoint="tool.a",
            content_tier=None,
            proposal_branch="proposal/policy-grant-legacy-a",
        ),
    ]

    with pytest.raises(SQLAlchemyError):
        await backend.apply_atomic(
            revokes=revokes,
            upserts=[],
            commit_hash="failed-hash",
        )

    # Only one execute attempted — the loop short-circuited on the
    # first failure, which is what the single-transaction rollback
    # contract requires.
    assert session.execute.await_count == 1


def test_storage_backend_protocol_includes_apply_atomic() -> None:
    """``apply_atomic`` is declared on the :class:`StorageBackend` Protocol.

    sec-pr-s3-6-02: pinning the Protocol surface against a regression
    where someone implements ``apply_atomic`` only on
    :class:`PostgresBackend` and forgets the Protocol declaration —
    the gate would then bind structurally to the concrete backend and
    drift from the typed seam.
    """
    from alfred.security.capability_gate.backend import (
        PostgresBackend,
        StorageBackend,
    )

    assert hasattr(StorageBackend, "apply_atomic")

    # PostgresBackend still satisfies the Protocol with the new method.
    factory, _ = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)
    assert isinstance(backend, StorageBackend)
