"""PostgresInboundIdempotencyStore commit-once semantics (fake session_scope; no DB engine).

Mirrors the ``tests/unit/identity/test_resolve_operator.py`` precedent: the store
owns an async ``session_scope``; we inject an ``@asynccontextmanager`` yielding a
fake session so every branch (won / replay / DB-error-propagates) is exercised
hermetically. The genuine-Postgres exactly-one-winner property lives in Task 8.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.inbound_idempotency import (
    InboundIdempotencyStore,
    PostgresInboundIdempotencyStore,
)


class _FakeResult:
    """Stands in for the ``Result`` of the INSERT … RETURNING."""

    def __init__(self, returned: str | None) -> None:
        self._returned = returned

    def scalar_one_or_none(self) -> str | None:
        return self._returned


class _FakeSession:
    """Records executed SQL + params; returns a configured result (or raises)."""

    def __init__(self, *, returned: str | None = None, raises: Exception | None = None) -> None:
        self._returned = returned
        self._raises = raises
        self.executed: list[tuple[Any, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._returned)


def _scope_for(session: _FakeSession) -> Any:
    # Mirrors the tests/unit/identity/test_resolve_operator.py precedent: the
    # store's session_scope is a Callable[[], AbstractAsyncContextManager[
    # AsyncSession]]; the fake session is a structural stand-in, so the scope
    # factory is typed ``Any`` (the duck-typed fake is intentional and the only
    # honest typing for an injected hand-rolled session under mypy --strict).
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, InboundIdempotencyStore)


async def test_first_commit_wins_when_row_returned() -> None:
    # A returned inbound_id == this caller won the INSERT (the row was fresh).
    session = _FakeSession(returned="frame-1")
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    assert await store.commit_once(inbound_id="frame-1", adapter_id="tui") is True
    # The composite key is carried as bound params (never SQL-interpolated).
    _stmt, params = session.executed[0]
    assert params == {"inbound_id": "frame-1", "adapter_id": "tui"}


async def test_replay_is_noop_when_no_row_returned() -> None:
    # ON CONFLICT DO NOTHING suppressed the insert => RETURNING yields no row.
    session = _FakeSession(returned=None)
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is False


async def test_db_error_propagates_fail_loud() -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a
    # won/replay bool — it propagates loud at the trust boundary.
    boom = OperationalError("INSERT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    with pytest.raises(OperationalError):
        await store.commit_once(inbound_id="frame-3", adapter_id="tui")
