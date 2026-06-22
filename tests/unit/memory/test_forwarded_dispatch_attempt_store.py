"""PostgresForwardedDispatchAttemptStore increment/read semantics (fake session_scope; no DB).

Mirrors the sibling ``tests/unit/memory/test_inbound_idempotency_store.py``: the store
owns an async ``session_scope``; we inject an ``@asynccontextmanager`` yielding a fake
session so every branch (increment-returns / present-read / absent-read-zero /
DB-error-propagates) is exercised hermetically. The genuine-Postgres atomic-UPSERT
monotonicity property lives in the integration tier.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.forwarded_dispatch_attempts import (
    _ATTEMPT_COUNT_SQL,
    _INCREMENT_SQL,
    ForwardedDispatchAttemptStore,
    PostgresForwardedDispatchAttemptStore,
)


class _FakeResult:
    """Stands in for the ``Result`` of the UPSERT … RETURNING / SELECT."""

    def __init__(self, returned: int | None) -> None:
        self._returned = returned

    def scalar_one(self) -> int:
        # increment always RETURNs a row (INSERT-or-UPDATE) — scalar_one is total.
        assert self._returned is not None
        return self._returned

    def scalar_one_or_none(self) -> int | None:
        return self._returned


class _FakeSession:
    """Records executed SQL + params; returns a configured result (or raises)."""

    def __init__(self, *, returned: int | None = None, raises: Exception | None = None) -> None:
        self._returned = returned
        self._raises = raises
        self.executed: list[tuple[Any, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._returned)


def _scope_for(session: _FakeSession) -> Any:
    # Mirrors the inbound_idempotency unit test: the store's session_scope is a
    # Callable[[], AbstractAsyncContextManager[AsyncSession]]; the fake session is a
    # structural stand-in, so the scope factory is typed ``Any`` (the duck-typed fake
    # is intentional and the only honest typing for a hand-rolled session under strict).
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresForwardedDispatchAttemptStore(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, ForwardedDispatchAttemptStore)


async def test_increment_returns_scalar_one() -> None:
    # The UPSERT RETURNING attempt_count is surfaced verbatim as the new count.
    session = _FakeSession(returned=7)
    store = PostgresForwardedDispatchAttemptStore(session_scope=_scope_for(session))
    assert await store.increment(adapter_id="discord", inbound_id="m1") == 7
    # The right SQL ran with the composite key carried as bound params (never interpolated).
    stmt, params = session.executed[0]
    assert stmt is _INCREMENT_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_attempt_count_returns_value_when_present() -> None:
    session = _FakeSession(returned=3)
    store = PostgresForwardedDispatchAttemptStore(session_scope=_scope_for(session))
    assert await store.attempt_count(adapter_id="discord", inbound_id="m1") == 3
    stmt, params = session.executed[0]
    assert stmt is _ATTEMPT_COUNT_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_attempt_count_returns_zero_when_absent() -> None:
    # No row => scalar_one_or_none() is None => the read reports 0, never raises.
    session = _FakeSession(returned=None)
    store = PostgresForwardedDispatchAttemptStore(session_scope=_scope_for(session))
    assert await store.attempt_count(adapter_id="discord", inbound_id="absent") == 0


async def test_increment_db_error_propagates_fail_loud() -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a count —
    # it propagates loud at the boundary (a swallowed error would forge a low count
    # and reset the replay bound silently).
    boom = OperationalError("UPSERT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresForwardedDispatchAttemptStore(session_scope=_scope_for(session))
    with pytest.raises(OperationalError):
        await store.increment(adapter_id="discord", inbound_id="m1")


async def test_attempt_count_db_error_propagates_fail_loud() -> None:
    boom = OperationalError("SELECT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresForwardedDispatchAttemptStore(session_scope=_scope_for(session))
    with pytest.raises(OperationalError):
        await store.attempt_count(adapter_id="discord", inbound_id="m1")
