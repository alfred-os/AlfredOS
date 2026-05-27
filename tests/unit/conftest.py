"""Shared fixtures for ``tests/unit/``.

These fixtures are **unit-test only** — they boot an in-memory SQLite engine
with the Slice-2 ORM schema mirrored via :meth:`Base.metadata.create_all` and
hand it back as a sync ``sessionmaker``. The matching Postgres integration
test for the resolver lives at ``tests/integration/identity/`` (T13) and uses
``testcontainers`` to exercise the full DDL (CHECK + partial-unique index +
``LISTEN/NOTIFY``).

Why SQLite at the unit layer:

* The resolver's Python logic (LRU eviction, version-counter bumps, operator
  upper-bound, last-operator-remove gate, language/budget validation) does
  not depend on Postgres-specific features. Running these ~16 tests under
  SQLite keeps the unit suite hermetic and sub-second.
* The Postgres-only features the resolver does use — ``pg_notify`` for the
  NOTIFY hook, partial-unique index enforcement on
  ``(user_id, platform) WHERE deleted_at IS NULL`` — are exercised in T13.
  The resolver's :meth:`_notify` is dialect-aware (no-op on SQLite), so the
  unit tests can validate the surrounding transaction flow without a real
  Postgres.

The ``rate_limiter`` fixture returns the no-op double :class:`_NullRateLimiter`
(test-only re-export from ``alfred.identity``). PR D1 swaps in the real
in-process token-bucket implementation; until then, the resolver's
constructor accepts any object satisfying the ``RateLimiter`` Protocol.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from alfred.identity import _NullRateLimiter
from alfred.memory.models import Base


@pytest.fixture
def session_factory() -> Iterator[sessionmaker[Session]]:
    """In-memory SQLite session factory with the AlfredOS schema mirrored.

    A fresh engine per test keeps state isolation strict (no inter-test
    contamination) at the cost of paying ``create_all`` per test. The cost
    is negligible at this scale (~10ms per fixture); the isolation is
    load-bearing for the version-counter assertions, which would silently
    pass on a shared engine if a prior test left a row behind.
    """
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, future=True)
    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def rate_limiter() -> _NullRateLimiter:
    """No-op rate limiter satisfying the ``RateLimiter`` Protocol.

    The resolver only stores the reference (it never calls it directly —
    rate-limiting happens at the orchestrator boundary in PR B). The fixture
    exists so the constructor stays happy without dragging the production
    token-bucket implementation into the unit-test classpath.
    """
    return _NullRateLimiter()
