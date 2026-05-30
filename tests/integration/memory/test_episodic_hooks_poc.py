"""Slice-2.5 PR-B Task 3 — golden-row regression baseline against real Postgres.

This test LOCKS the byte-identical row shape :meth:`EpisodicMemory.record`
produces *today* — with zero hookpoint subscribers — so the remainder of
PR-B (Task 4 / Task 5 hookpoint wiring, Task 6 ``_validate`` insertion,
Task 7+ ``EpisodicAuditSink``) is provably behaviour-preserving on the
end-to-end DB path. The unit-level characterization tests
(``tests/unit/memory/test_episodic_hooks_wiring.py``) already pin the
session-call shape against an ``AsyncMock``; this is the matching
real-Postgres assertion that nothing in the round-trip — flush ordering,
SQLAlchemy default callable invocation, Python-side type coercion —
drifts under the upcoming hook plumbing.

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

Why the explicit ``session.commit()``:

* mem-1 (spec §3 / pluggable-hooks design): the post hookpoint name is
  :data:`HookKind.AFTER_FLUSH`, NOT ``committed``. ``after_flush`` fires
  immediately after ``session.flush()`` — i.e. SQL emitted, transaction
  durability NOT yet established. This test commits explicitly to prove
  the *persisted* row matches the input — but the commit is the *test's*
  durability boundary, not the hook's. A future reader who proposes
  renaming ``AFTER_FLUSH`` to ``AFTER_COMMIT`` (or, equivalently,
  delaying post-hook dispatch until ``session.commit()`` returns) must
  re-read this comment first: the hook is intentionally pre-commit so
  subscribers can refuse with full transactional rollback. The test's
  ``commit`` is a *readback* tool, not a durability claim about the
  hookpoint.

Conventions: real Postgres via testcontainers (alfred-memory-engineer
quality bar — write paths get real DB, not in-memory fakes); per-test
session via the ``session`` fixture below so cross-test state is impossible.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.hooks.capability import DevGate
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import Base, Episode

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


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """Yield a per-test :class:`AsyncSession` against a fresh Postgres container.

    Per-test container is the alfred-memory-engineer write-path discipline:
    a leak across tests on the byte-identity baseline is exactly the kind
    of bug the integration tier exists to catch, and the ~5s container
    startup is the price we pay for that isolation. ``create_all`` (rather
    than ``alembic upgrade``) keeps the baseline immune to migration-shape
    drift; the migration-specific integration tests cover that axis.

    ``expire_on_commit=False`` so the test can read attributes off the
    returned ``Episode`` instance after ``session.commit()`` without
    triggering a refresh — the readback path uses an explicit ``select``,
    not an attribute access on the original, but the flag avoids the
    surprise SELECT-after-commit a future refactor might introduce.
    """
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            sm = async_sessionmaker(bind=engine, expire_on_commit=False)
            async with sm() as s:
                yield s
        finally:
            await engine.dispose()


@pytest.mark.integration
async def test_zero_subscriber_row_byte_identical(session: AsyncSession) -> None:
    """With zero hookpoint subscribers, ``record`` writes a row byte-identical
    to the pre-hooks code path.

    This is the BASELINE for Slice-2.5 PR-B: Tasks 4-9 add hookpoint
    wiring, validation, and an audit sink on top of ``_persist``. Any one
    of those tasks that mutates the persisted row shape (extra column
    written, default callable swapped, type coercion changed) trips this
    assertion immediately.

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

    # Round-trip readback. ``user_id`` is the only filter we need — the
    # container is fresh per test (the ``session`` fixture's
    # ``PostgresContainer`` scope), so exactly one row exists.
    result = await session.execute(select(Episode).where(Episode.user_id == "u-123"))
    row = result.scalar_one()

    # --- Input-derived columns: every field of _GOLDEN_KWARGS must survive
    # the round-trip verbatim. Iterating the dict (rather than 10 hand
    # assertions) means adding an 11th kwarg to ``record`` + ``Episode``
    # is covered the moment ``_GOLDEN_KWARGS`` is updated. The unit-level
    # ``test_episodic_record_input.py`` drift-guard pins that
    # ``EpisodicRecordInput`` mirrors ``record``'s signature, so the set
    # of names traversed here cannot silently shrink.
    for field_name, expected_value in _GOLDEN_KWARGS.items():
        assert getattr(row, field_name) == expected_value, (
            f"field {field_name!r} did not survive the Postgres round-trip"
        )

    # --- memB-2 columns: populated by Python-side defaults at flush time.
    # The assertions are *shape* assertions, not value assertions — the
    # actual UUID / timestamp / dict values are non-deterministic. What
    # we pin is: they are non-null AND of the expected Python type, which
    # together prove the Python-side default callable fired.
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
