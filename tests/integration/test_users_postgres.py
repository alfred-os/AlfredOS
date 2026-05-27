"""Postgres-only invariants for ``users`` + ``platform_identities`` (PR-A T13).

Five SQL-level constraint paths and one ``LISTEN/NOTIFY`` round-trip — the
combination of behaviours that SQLite-backed unit tests cannot enforce:

1. ``ck_users_authorization`` — CHECK rejects an unknown authorization tier.
2. ``ck_users_daily_budget_usd_positive`` — CHECK rejects ``daily_budget_usd <= 0``.
3. ``uq_platform_identity_platform_platform_id`` — global UNIQUE rejects two
   different users binding the same ``(platform, platform_id)``.
4. ``uq_platform_identities_user_id_platform_active`` — partial-unique index
   rejects two *live* bindings on the same ``(user_id, platform)`` while a
   *soft-deleted* prior binding on the same key is tolerated.
5. ``ON DELETE CASCADE`` — deleting a ``users`` row removes the matching
   ``platform_identities`` rows.
6. ``IdentityListener`` end-to-end — a NOTIFY emitted by the real resolver
   bumps the listener's version counter (cross-process invalidation path).

Constraint-name reconciliation
------------------------------

The plan body names a few constraints with placeholders that don't match the
authoritative ORM/migration names (e.g. ``daily_budget_positive`` vs the real
``ck_users_daily_budget_usd_positive``). We assert the *real* names because
those are what the migration emits — the plan placeholders were shorthand for
"the constraint that does X", not exact identifiers.

LISTEN/NOTIFY round-trip — why use the real psycopg path
--------------------------------------------------------

The unit test for ``IdentityListener`` injects test doubles to exercise the
supervisor's reconnect arithmetic. This integration test wires the real
``_default_connect`` + ``_default_listen_loop`` against a testcontainer
Postgres so we catch any drift between the contract those methods document
and the actual psycopg3 ``AsyncConnection`` API. That is also the only
covering test that confirms ``resolver._notify`` -> ``pg_notify`` ->
listener ``_on_notify`` -> ``version_counter.bump`` actually couples
end-to-end against a real Postgres.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from alembic import command, config
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from alfred.identity import (
    Authorization,
    IdentityVersionCounter,
    NullRateLimiter,
    Platform,
)
from alfred.identity.resolver import IdentityListener, IdentityResolver

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------- #
# Local fixtures — sync session bound to a testcontainer Postgres at head
# --------------------------------------------------------------------------- #


@pytest.fixture
def postgres_dsn(postgres_url: str) -> str:
    """psycopg3-compatible DSN derived from the testcontainer URL.

    ``postgres_url`` is the asyncpg-shaped URL the migration env consumes;
    psycopg3 wants the bare ``postgresql://`` scheme without a driver suffix.
    """
    return postgres_url.replace("postgresql+asyncpg://", "postgresql://")


@pytest.fixture
def migrated_engine(
    postgres_url: str,
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> Engine:
    """Run ``alembic upgrade head`` against the per-test container and yield the engine.

    The env-var publish mirrors ``test_migration_0004_backfill.py`` — the
    migration env.py resolves the DB URL from ``ALFRED_DATABASE_URL`` before
    falling back to the Config object.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_engine


@pytest.fixture
def postgres_session(migrated_engine: Engine) -> Iterator[Session]:
    """Sync SQLAlchemy session bound to the migrated testcontainer Postgres.

    Each test gets a fresh container (per the upstream ``postgres_url``
    fixture's per-function scope), so we don't roll back between tests —
    the container teardown handles isolation.
    """
    factory = sessionmaker(migrated_engine, expire_on_commit=False, future=True)
    with factory() as session:
        yield session


# --------------------------------------------------------------------------- #
# SQL-level constraint tests
# --------------------------------------------------------------------------- #


def test_authorization_check_constraint(postgres_session: Session) -> None:
    """An ``authorization`` value outside the closed domain raises IntegrityError.

    The CHECK constraint is the permanent gate (spec §2 line 223 forbids
    dropping/re-adding a Postgres ENUM for rollback symmetry), so this
    assertion is load-bearing against a destructive schema regression.
    """
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError, match="ck_users_authorization"):
        postgres_session.execute(
            text(
                'INSERT INTO users (slug, display_name, "authorization", '
                "daily_budget_usd, language) "
                "VALUES ('admin-user', 'Admin', 'admin', 1.0, 'en-US')"
            )
        )
        postgres_session.commit()


def test_daily_budget_positive_check(postgres_session: Session) -> None:
    """``daily_budget_usd <= 0`` is rejected — a zero budget would silently
    disable the BudgetGuard. Read-only users get ``authorization=read_only``
    instead.
    """
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError, match="ck_users_daily_budget_usd_positive"):
        postgres_session.execute(
            text(
                'INSERT INTO users (slug, display_name, "authorization", '
                "daily_budget_usd, language) "
                "VALUES ('broke-user', 'Broke', 'standard', 0.0, 'en-US')"
            )
        )
        postgres_session.commit()


def test_platform_identity_unique_platform_id(postgres_session: Session) -> None:
    """Two different users binding the same ``(discord, 111)`` collides on the
    global UNIQUE — same Discord snowflake can't point at two AlfredOS users.
    """
    from sqlalchemy.exc import IntegrityError

    postgres_session.execute(
        text(
            'INSERT INTO users (slug, display_name, "authorization", '
            "daily_budget_usd, language) "
            "VALUES ('alice', 'Alice', 'standard', 1.0, 'en-US'), "
            "('bob', 'Bob', 'standard', 1.0, 'en-US')"
        )
    )
    postgres_session.execute(
        text(
            "INSERT INTO platform_identities (user_id, platform, platform_id) "
            "VALUES ((SELECT id FROM users WHERE slug='alice'), 'discord', '111')"
        )
    )
    postgres_session.commit()

    with pytest.raises(IntegrityError, match="uq_platform_identity_platform_platform_id"):
        postgres_session.execute(
            text(
                "INSERT INTO platform_identities (user_id, platform, platform_id) "
                "VALUES ((SELECT id FROM users WHERE slug='bob'), 'discord', '111')"
            )
        )
        postgres_session.commit()


def test_partial_unique_on_active_bindings(postgres_session: Session) -> None:
    """The partial-unique index on ``(user_id, platform) WHERE deleted_at IS NULL``
    rejects a second *live* binding on the same key, while tolerating the same
    key when the prior binding has been soft-deleted.

    Two halves to the assertion:

    (a) Insert two live bindings → second one raises on the partial-unique index.
    (b) Soft-delete the first binding, then re-insert a third live binding on
        the same key → succeeds. This is the audit-preserving rebind path.
    """
    from sqlalchemy.exc import IntegrityError

    postgres_session.execute(
        text(
            'INSERT INTO users (slug, display_name, "authorization", '
            "daily_budget_usd, language) "
            "VALUES ('carol', 'Carol', 'standard', 1.0, 'en-US')"
        )
    )
    postgres_session.execute(
        text(
            "INSERT INTO platform_identities (user_id, platform, platform_id) "
            "VALUES ((SELECT id FROM users WHERE slug='carol'), 'discord', '222')"
        )
    )
    postgres_session.commit()

    with pytest.raises(IntegrityError, match="uq_platform_identities_user_id_platform_active"):
        postgres_session.execute(
            text(
                "INSERT INTO platform_identities (user_id, platform, platform_id) "
                "VALUES ((SELECT id FROM users WHERE slug='carol'), 'discord', '333')"
            )
        )
        postgres_session.commit()

    # Rollback the failed INSERT so the session is usable again, then exercise
    # the rebind-after-soft-delete path that the partial-unique index permits.
    postgres_session.rollback()
    postgres_session.execute(
        text(
            "UPDATE platform_identities SET deleted_at = now() "
            "WHERE platform = 'discord' AND platform_id = '222'"
        )
    )
    postgres_session.execute(
        text(
            "INSERT INTO platform_identities (user_id, platform, platform_id) "
            "VALUES ((SELECT id FROM users WHERE slug='carol'), 'discord', '444')"
        )
    )
    postgres_session.commit()
    live_count = postgres_session.execute(
        text(
            "SELECT COUNT(*) FROM platform_identities "
            "WHERE platform = 'discord' AND deleted_at IS NULL"
        )
    ).scalar_one()
    assert live_count == 1


def test_cascade_delete(postgres_session: Session) -> None:
    """Hard-deleting a ``users`` row cascades to ``platform_identities``.

    The production path soft-deletes (``deleted_at = now()``) to preserve
    audit-log referential integrity; the CASCADE exists as the schema-level
    guarantee that operator-initiated *hard* deletes (data-retention purges
    in a later slice) don't leave dangling identity rows.
    """
    postgres_session.execute(
        text(
            'INSERT INTO users (slug, display_name, "authorization", '
            "daily_budget_usd, language) "
            "VALUES ('dave', 'Dave', 'standard', 1.0, 'en-US')"
        )
    )
    postgres_session.execute(
        text(
            "INSERT INTO platform_identities (user_id, platform, platform_id) "
            "VALUES ((SELECT id FROM users WHERE slug='dave'), 'discord', '555')"
        )
    )
    postgres_session.commit()

    postgres_session.execute(text("DELETE FROM users WHERE slug='dave'"))
    postgres_session.commit()

    orphan_count = postgres_session.execute(
        text("SELECT COUNT(*) FROM platform_identities WHERE platform_id='555'")
    ).scalar_one()
    assert orphan_count == 0


# --------------------------------------------------------------------------- #
# LISTEN/NOTIFY round-trip — couples resolver._notify to listener._on_notify
# --------------------------------------------------------------------------- #


async def test_listen_notify_round_trip(
    migrated_engine: Engine,
    postgres_dsn: str,
) -> None:
    """Real-Postgres LISTEN/NOTIFY: a resolver mutation in one session bumps the
    listener's version counter in another.

    The listener uses ``_default_connect`` + ``_default_listen_loop`` (the
    production psycopg3 path) — this is the only test that exercises that
    code path against a real database. The unit-test layer injects test
    doubles for the reconnect arithmetic and never touches psycopg3.

    Timing
    ------

    The test waits in two phases — once after starting the listener (so the
    ``LISTEN`` SQL is in flight before we issue the ``NOTIFY``), once after
    the resolver mutation (so psycopg3's notify-poll loop can deliver the
    payload). 1.0s buffers are deliberately generous; the round-trip itself
    is sub-millisecond on a local container.
    """
    counter = IdentityVersionCounter()
    listener = IdentityListener(
        dsn=postgres_dsn,
        version_counter=counter,
        backoff_start_s=0.1,
        backoff_max_s=1.0,
    )
    listener_task = asyncio.create_task(listener.run())

    # Phase 1: let the listener finish its initial connect + LISTEN before we
    # NOTIFY. Otherwise the NOTIFY ships into a channel nobody has subscribed
    # to yet and the listener never sees it.
    await asyncio.sleep(1.0)

    # Drive a mutation through the real resolver — the dialect-aware
    # ``_notify`` branch emits ``pg_notify('alfred_identity_changed', …)`` on
    # transaction commit. We don't care about the counter inside this
    # process; the assertion is on the *listener's* counter, which lives on
    # a different connection.
    factory = sessionmaker(migrated_engine, expire_on_commit=False, future=True)
    resolver = IdentityResolver(
        session_factory=factory,
        version_counter=IdentityVersionCounter(),  # separate from listener's counter
        rate_limiter=NullRateLimiter(),
    )
    resolver.add(display_name="Eve", authorization=Authorization.STANDARD)
    resolver.bind(user_slug="eve", platform=Platform.DISCORD, platform_id="666")

    # Phase 2: let psycopg3's notify-poll loop deliver the payload.
    await asyncio.sleep(1.0)

    listener.stop()
    try:
        await asyncio.wait_for(listener_task, timeout=5.0)
    except TimeoutError:
        listener_task.cancel()
        with pytest.raises((asyncio.CancelledError, TimeoutError)):
            await listener_task

    # Two mutations (add + bind) → at least two NOTIFY deliveries → at least
    # two counter bumps on the listener's side. Lower-bound rather than
    # exact-match because psycopg3 may coalesce or the listener may see
    # spurious wakeups; the contract is "at least one bump per mutation".
    assert counter.current() >= 2, (
        f"listener counter advanced to {counter.current()}; expected >= 2 "
        "(one per resolver mutation). Either the LISTEN didn't land before "
        "the NOTIFY, or the dialect-aware _notify path regressed."
    )
