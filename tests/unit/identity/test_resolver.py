"""Unit tests for :class:`alfred.identity.resolver.IdentityResolver`.

The resolver is the only legitimate accessor for the ``User`` and
``PlatformIdentity`` ORMs (see ``src/alfred/identity/__init__.py``). It
mediates (platform, platform_id) -> User lookups with an in-process LRU
backed by a 60s TTL, invalidates on :class:`IdentityVersionCounter` bumps,
and enforces two security invariants:

1. **Operator upper-bound** — only one operator may exist concurrently.
   ``--replace-operator <existing>`` atomically demotes the old operator
   and promotes the new one in a single transaction.
2. **Last-operator-remove gate** — :meth:`remove` refuses to soft-delete
   the only remaining operator.

These tests pin the resolver's Python-level contract against an in-memory
SQLite engine. The SQL-level partial-unique-index enforcement and the
``LISTEN/NOTIFY`` dispatch path are exercised in the Postgres integration
test (T13).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select

from alfred.identity import (
    Authorization,
    IdentityResolutionError,
    IdentityResolver,
    IdentityVersionCounter,
    LastOperatorRemovalRefusedError,
    OperatorAlreadyExistsError,
    Platform,
    User,
)
from alfred.identity.resolver import IdentityListener

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from alfred.identity import _NullRateLimiter


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _build_resolver(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
    *,
    counter: IdentityVersionCounter | None = None,
) -> IdentityResolver:
    """Construct an :class:`IdentityResolver` with sensible defaults.

    The counter is exposed so tests that need to observe bumps can pass in
    a counter they hold a reference to.
    """
    return IdentityResolver(
        session_factory=session_factory,
        version_counter=counter or IdentityVersionCounter(),
        rate_limiter=rate_limiter,
    )


# --------------------------------------------------------------------------- #
# resolve()
# --------------------------------------------------------------------------- #


def test_resolve_miss_returns_none(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """Resolving an unknown (platform, platform_id) returns ``None``."""
    resolver = _build_resolver(session_factory, rate_limiter)

    assert resolver.resolve(Platform.DISCORD, "99999") is None


def test_bind_and_resolve_roundtrip(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """``bind`` then ``resolve`` yields the original user."""
    resolver = _build_resolver(session_factory, rate_limiter)
    user = resolver.add(display_name="Alice", authorization=Authorization.STANDARD)

    resolver.bind(user_slug=user.slug, platform=Platform.DISCORD, platform_id="12345")

    resolved = resolver.resolve(Platform.DISCORD, "12345")
    assert resolved is not None
    assert resolved.slug == user.slug


def test_resolve_soft_deleted_returns_none(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """A soft-deleted platform binding must not resolve."""
    resolver = _build_resolver(session_factory, rate_limiter)
    user = resolver.add(display_name="Bob", authorization=Authorization.STANDARD)
    resolver.bind(user_slug=user.slug, platform=Platform.DISCORD, platform_id="42")

    resolver.unbind(user_slug=user.slug, platform=Platform.DISCORD)

    assert resolver.resolve(Platform.DISCORD, "42") is None


# --------------------------------------------------------------------------- #
# add() / slug derivation + collision suffixing
# --------------------------------------------------------------------------- #


def test_add_minimal(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """Happy-path ``add`` returns a User with the derived slug + defaults."""
    resolver = _build_resolver(session_factory, rate_limiter)

    user = resolver.add(display_name="Carol", authorization=Authorization.OPERATOR)

    assert user.slug == "carol"
    assert user.display_name == "Carol"
    assert user.authorization == Authorization.OPERATOR.value
    assert user.language == "en-US"
    assert user.daily_budget_usd > 0


def test_add_slug_collision_suffixes(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """Same display name twice produces ``alice`` then ``alice-2``."""
    resolver = _build_resolver(session_factory, rate_limiter)

    first = resolver.add(display_name="Alice", authorization=Authorization.STANDARD)
    second = resolver.add(display_name="Alice", authorization=Authorization.STANDARD)

    assert first.slug == "alice"
    assert second.slug == "alice-2"


def test_add_slug_collision_with_soft_deleted_still_suffixes(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """Soft-deleted users still occupy their slug; the next ``add`` must suffix.

    The ``users.slug`` UNIQUE constraint is column-level (not partial), so
    even ``deleted_at IS NOT NULL`` rows hold their slug. The resolver must
    therefore consult ALL rows when finding the next-available suffix.
    """
    resolver = _build_resolver(session_factory, rate_limiter)
    first = resolver.add(display_name="Dave", authorization=Authorization.OPERATOR)
    # Add a second operator to keep us above the last-operator floor before
    # soft-deleting the first.
    resolver.add(
        display_name="Promoted",
        authorization=Authorization.OPERATOR,
        replace_operator=first.slug,
    )
    resolver.remove(slug=first.slug)

    new_dave = resolver.add(display_name="Dave", authorization=Authorization.STANDARD)

    assert new_dave.slug == "dave-2"


# --------------------------------------------------------------------------- #
# Operator invariants
# --------------------------------------------------------------------------- #


def test_add_operator_upper_bound(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """A second operator without ``replace_operator`` raises."""
    resolver = _build_resolver(session_factory, rate_limiter)
    resolver.add(display_name="Alice", authorization=Authorization.OPERATOR)

    with pytest.raises(OperatorAlreadyExistsError):
        resolver.add(display_name="Bob", authorization=Authorization.OPERATOR)


def test_replace_operator_atomic_demote_promote(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """``replace_operator`` demotes the named operator and promotes the new one."""
    resolver = _build_resolver(session_factory, rate_limiter)
    old = resolver.add(display_name="Old", authorization=Authorization.OPERATOR)

    new = resolver.add(
        display_name="New",
        authorization=Authorization.OPERATOR,
        replace_operator=old.slug,
    )

    operator = resolver.get_operator()
    assert operator.slug == new.slug
    # The demoted operator is still alive, demoted to TRUSTED per spec
    # §2 architect-001 and the ``cli.user.operator_replaced`` catalog entry.
    demoted = resolver.show(slug=old.slug)
    assert demoted is not None
    assert demoted.authorization == Authorization.TRUSTED.value


def test_remove_last_operator_refused(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """Removing the only operator raises :class:`LastOperatorRemovalRefusedError`."""
    resolver = _build_resolver(session_factory, rate_limiter)
    only = resolver.add(display_name="Solo", authorization=Authorization.OPERATOR)

    with pytest.raises(LastOperatorRemovalRefusedError):
        resolver.remove(slug=only.slug)


def test_get_operator_zero_raises(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """``get_operator`` on a deployment with no operator raises loudly."""
    resolver = _build_resolver(session_factory, rate_limiter)

    with pytest.raises(IdentityResolutionError):
        resolver.get_operator()


def test_get_operator_multi_raises(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """If somehow >1 operators exist, ``get_operator`` raises.

    The resolver's own ``add``/``set_`` paths prevent this state, but a bad
    migration or a direct ORM insert could leave two operators around. The
    method must refuse rather than silently picking one.
    """
    resolver = _build_resolver(session_factory, rate_limiter)
    with session_factory.begin() as session:
        session.add_all(
            [
                User(
                    slug="dual-1",
                    display_name="Dual One",
                    authorization=Authorization.OPERATOR.value,
                    daily_budget_usd=5.0,
                    language="en-US",
                ),
                User(
                    slug="dual-2",
                    display_name="Dual Two",
                    authorization=Authorization.OPERATOR.value,
                    daily_budget_usd=5.0,
                    language="en-US",
                ),
            ]
        )

    with pytest.raises(IdentityResolutionError):
        resolver.get_operator()


# --------------------------------------------------------------------------- #
# bind() guardrails
# --------------------------------------------------------------------------- #


def test_bind_double_platform_refused(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """A user already bound to a platform cannot bind a second active row for it."""
    resolver = _build_resolver(session_factory, rate_limiter)
    user = resolver.add(display_name="Alice", authorization=Authorization.STANDARD)
    resolver.bind(user_slug=user.slug, platform=Platform.DISCORD, platform_id="111")

    with pytest.raises(IdentityResolutionError):
        resolver.bind(user_slug=user.slug, platform=Platform.DISCORD, platform_id="222")


def test_bind_platform_id_in_use_refused(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """The same (platform, platform_id) cannot point at two different users."""
    resolver = _build_resolver(session_factory, rate_limiter)
    alice = resolver.add(display_name="Alice", authorization=Authorization.STANDARD)
    bob = resolver.add(display_name="Bob", authorization=Authorization.STANDARD)
    resolver.bind(user_slug=alice.slug, platform=Platform.DISCORD, platform_id="shared")

    with pytest.raises(IdentityResolutionError):
        resolver.bind(user_slug=bob.slug, platform=Platform.DISCORD, platform_id="shared")


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_add_invalid_language_rejected(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """A malformed BCP-47 language tag fails fast at the resolver boundary."""
    resolver = _build_resolver(session_factory, rate_limiter)

    with pytest.raises(ValueError, match="BCP-47"):
        resolver.add(
            display_name="Bad",
            authorization=Authorization.STANDARD,
            language="wat-NOT-VALID",
        )


# --------------------------------------------------------------------------- #
# Version-counter bump contract
# --------------------------------------------------------------------------- #


def test_every_mutating_method_bumps_counter(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """Each successful mutator advances the counter by exactly one.

    Load-bearing for PR B (BudgetGuard invalidation) and PR D2 (Discord
    adapter cache invalidation). If this regresses, the consumers silently
    serve stale data.
    """
    counter = IdentityVersionCounter()
    resolver = _build_resolver(session_factory, rate_limiter, counter=counter)
    baseline = counter.current()

    # add
    alice = resolver.add(display_name="Alice", authorization=Authorization.OPERATOR)
    assert counter.current() == baseline + 1

    # add (second standard user; no operator collision)
    bob = resolver.add(display_name="Bob", authorization=Authorization.STANDARD)
    assert counter.current() == baseline + 2

    # bind
    resolver.bind(user_slug=bob.slug, platform=Platform.DISCORD, platform_id="bob-123")
    assert counter.current() == baseline + 3

    # set_
    resolver.set_(slug=bob.slug, language="ja-JP")
    assert counter.current() == baseline + 4

    # unbind
    resolver.unbind(user_slug=bob.slug, platform=Platform.DISCORD)
    assert counter.current() == baseline + 5

    # remove (bob is not the only operator — alice is the operator)
    resolver.remove(slug=bob.slug)
    assert counter.current() == baseline + 6

    # Sanity: alice is still the operator.
    assert resolver.get_operator().slug == alice.slug


def test_resolve_lru_invalidates_on_counter_bump(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """A counter bump invalidates cached resolves on next access.

    Mutating the DB out-of-band would normally let a stale cache entry win;
    the version-counter check is what forces a re-fetch.
    """
    counter = IdentityVersionCounter()
    resolver = _build_resolver(session_factory, rate_limiter, counter=counter)
    user = resolver.add(display_name="Alice", authorization=Authorization.STANDARD)
    resolver.bind(user_slug=user.slug, platform=Platform.DISCORD, platform_id="cache-key")

    first = resolver.resolve(Platform.DISCORD, "cache-key")
    assert first is not None
    cached_language = first.language

    # Mutate the DB out-of-band — bump the counter as the listener would.
    with session_factory.begin() as session:
        db_user = session.execute(select(User).where(User.slug == user.slug)).scalar_one()
        db_user.language = "fr-FR"
    counter.bump()

    second = resolver.resolve(Platform.DISCORD, "cache-key")
    assert second is not None
    assert second.language == "fr-FR"
    assert second.language != cached_language


# --------------------------------------------------------------------------- #
# Read surfaces: show / list_
# --------------------------------------------------------------------------- #


def test_show_and_list(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """``show`` returns a single user; ``list_`` returns all live users."""
    resolver = _build_resolver(session_factory, rate_limiter)
    alice = resolver.add(display_name="Alice", authorization=Authorization.OPERATOR)
    bob = resolver.add(display_name="Bob", authorization=Authorization.STANDARD)

    shown = resolver.show(slug=alice.slug)
    assert shown is not None
    assert shown.slug == alice.slug

    listed_slugs = {u.slug for u in resolver.list_()}
    assert listed_slugs == {alice.slug, bob.slug}


def test_list_excludes_soft_deleted_by_default(
    session_factory: sessionmaker[Session],
    rate_limiter: _NullRateLimiter,
) -> None:
    """A soft-deleted user is hidden from ``list_()`` unless explicitly asked for."""
    resolver = _build_resolver(session_factory, rate_limiter)
    operator = resolver.add(display_name="Op", authorization=Authorization.OPERATOR)
    doomed = resolver.add(display_name="Doomed", authorization=Authorization.STANDARD)
    resolver.remove(slug=doomed.slug)

    live = {u.slug for u in resolver.list_()}
    assert doomed.slug not in live
    assert operator.slug in live

    # ``include_deleted=True`` shows everyone.
    all_users = {u.slug for u in resolver.list_(include_deleted=True)}
    assert doomed.slug in all_users
    assert operator.slug in all_users


# --------------------------------------------------------------------------- #
# IdentityListener — LISTEN/NOTIFY supervisor with exponential-backoff reconnect
# err-001 (spec §2 line 162). CLAUDE.md hard rule #7 — a silently-dropped
# listener would age out cross-process invalidations, so the supervisor's
# reconnect-on-disconnect behaviour is load-bearing.
# --------------------------------------------------------------------------- #


async def test_identity_listener_reconnect_on_connection_loss(
    version_counter: IdentityVersionCounter,
) -> None:
    """The listener wraps its LISTEN loop in an exponential-backoff supervisor.

    On a raised ``ConnectionError`` it sleeps ``backoff_s``, reconnects, and
    resets backoff on success. After three forced disconnects the version
    counter has bumped at least once per simulated NOTIFY between disconnects.
    """
    # Event ribbon read in order by the injected listen-loop:
    # - "disconnect"  → raise ConnectionError (supervisor reconnects)
    # - dict          → deliver as a NOTIFY payload
    # - "shutdown"    → set stop_event + return (clean exit)
    events: list[str | dict[str, object]] = [
        "disconnect",
        {"slug": "alice", "op": "add"},
        "disconnect",
        {"slug": "bob", "op": "add"},
        "disconnect",
        "shutdown",
    ]

    def fake_connect() -> MagicMock:
        conn = MagicMock()
        conn.add_listener = AsyncMock()
        conn.close = AsyncMock()
        return conn

    reconnect_count = 0

    async def fake_listen_loop(
        _conn: object,
        notify_callback: Any,
        stop_event: asyncio.Event,
    ) -> None:
        nonlocal reconnect_count
        while events:
            ev = events.pop(0)
            if ev == "disconnect":
                reconnect_count += 1
                raise ConnectionError("simulated disconnect")
            if ev == "shutdown":
                stop_event.set()
                return
            notify_callback(ev)

    listener = IdentityListener(
        dsn="postgresql://fake",
        version_counter=version_counter,
        backoff_start_s=0.001,
        backoff_max_s=0.01,
        connect_factory=fake_connect,
        listen_loop=fake_listen_loop,
    )
    task = asyncio.create_task(listener.run())
    # Give the supervisor enough wall-clock to chew through the event ribbon;
    # the backoff is sub-millisecond so 200ms is generous.
    await asyncio.sleep(0.2)
    listener.stop()
    await asyncio.wait_for(task, timeout=2.0)

    # Two NOTIFY payloads were delivered between three forced disconnects →
    # the version counter must have advanced at least twice.
    assert version_counter.current() >= 2
    assert reconnect_count == 3
