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

The ``rate_limiter`` fixture returns the no-op double :class:`NullRateLimiter`
(test-only re-export from ``alfred.identity``). PR D1 swaps in the real
in-process token-bucket implementation; until then, the resolver's
constructor accepts any object satisfying the ``RateLimiter`` Protocol.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from alfred.audit.log import AuditWriter
from alfred.identity import IdentityVersionCounter, NullRateLimiter
from alfred.memory.models import Base


@pytest.fixture(autouse=True)
def _hermetic_secrets_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Isolate the ADR-0012 host-default secrets file for every unit test (#363).

    Completing ADR-0012 makes ``Settings.secrets_file`` default to
    ``~/.config/alfred/secrets.toml``, so a ``SecretBroker`` built from a real ``Settings`` over
    the default ``os.environ`` now reads the DEVELOPER'S real home secrets file — previously
    inert while the field was phantom. Unit tests must be hermetic: point ``ALFRED_SECRETS_FILE``
    (the layer-2 override, which precedes the host default AND auto-maps onto the field) at a
    guaranteed-absent tmp path so any broker over the default environment resolves to the
    env-only backend, never the operator's real ``~/.config/alfred/secrets.toml``.

    Chosen over patching ``$HOME`` because the daemon builds an ``AF_UNIX`` socket under
    ``$HOME`` and a deep pytest tmp home overflows the ~104-char socket-path limit; a secrets
    *file* path has no such limit. Tests exercising the file backend pass ``secrets_file=`` (the
    constructor kwarg, which wins over this env layer) or override/clear ``ALFRED_SECRETS_FILE``
    themselves (e.g. the ``Settings.secrets_file`` default/override tests) and are unaffected.
    """
    monkeypatch.setenv("ALFRED_SECRETS_FILE", str(tmp_path / "no-secrets.toml"))


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
def rate_limiter() -> NullRateLimiter:
    """No-op rate limiter satisfying the ``RateLimiter`` Protocol.

    The resolver only stores the reference (it never calls it directly —
    rate-limiting happens at the orchestrator boundary in PR B). The fixture
    exists so the constructor stays happy without dragging the production
    token-bucket implementation into the unit-test classpath.
    """
    return NullRateLimiter()


@pytest.fixture
def version_counter() -> IdentityVersionCounter:
    """Fresh :class:`IdentityVersionCounter` per test.

    Consumed by the ``IdentityListener`` reconnect-supervisor test (T12) and
    by any other future test that needs to observe bumps in isolation.
    """
    return IdentityVersionCounter()


@pytest.fixture
def audit_buffer(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, Any]]]:
    """Capture every ``AuditWriter.append`` call into an in-memory list.

    Promoted to ``tests/unit/conftest.py`` (rather than the audit-test-local
    conftest) because two unrelated subsystems assert on audit-row contents:
    the audit-writer's own unit tests AND the identity CLI tests (T14). pytest
    only resolves fixtures from conftests on the path to the test file, so a
    fixture defined under ``tests/unit/audit/`` cannot be consumed from
    ``tests/unit/identity/``. The unit-level conftest sits on both paths and
    is the cheapest place to share the fixture without duplication.

    Yields the list itself so tests can ``assert audit_buffer[-1]["event"]``
    after invoking a CLI subcommand. The list is fresh per test — pytest
    scopes ``monkeypatch`` to function by default, so captures from one test
    never leak into another.

    Production callers continue to call ``AuditWriter(...).append(...)``
    unchanged; the monkeypatch swaps the bound method on the class for the
    duration of the test so any factory that constructs an
    :class:`AuditWriter` is a no-op as far as the database is concerned —
    we never touch Postgres in the unit layer.
    """
    buffer: list[dict[str, Any]] = []

    async def _capture(self: AuditWriter, **kwargs: Any) -> None:
        # Defensive copy: kwargs values may be mutable (e.g. ``subject``
        # dicts the caller continues to mutate after the call). Copy the
        # top-level dict so assertions inspect the value as it was at
        # call-time, not as it is at assertion-time.
        buffer.append(dict(kwargs))

    monkeypatch.setattr(AuditWriter, "append", _capture)
    yield buffer
