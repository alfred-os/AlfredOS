"""has_committed read for the forwarded dispatched-edge dedup (Spec B G6-7-4, #309).

Mirrors ``tests/unit/memory/test_inbound_idempotency_store.py``: the store owns an
async ``session_scope``; we inject an ``@asynccontextmanager`` yielding a fake
session so every branch (found / not-found / DB-error-propagates) is exercised
hermetically — no DB engine. The fake here is STATEFUL across calls so the
non-mutating-read invariant (``has_committed`` never inserts) can be asserted
against a shared composite-keyed set, exactly as a real row store behaves.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from alfred.memory.inbound_idempotency import (
    _COMMIT_ONCE_SQL,
    _HAS_COMMITTED_SQL,
    PostgresInboundIdempotencyStore,
)


class _FakeResult:
    """Stands in for the ``Result`` of the INSERT … RETURNING / SELECT 1."""

    def __init__(self, returned: str | int | None) -> None:
        self._returned = returned

    def scalar_one_or_none(self) -> str | int | None:
        return self._returned


class _StatefulFakeSession:
    """A composite-keyed row store: ``commit_once`` inserts, ``has_committed`` reads.

    Routes by the SQL object identity so the read path is verifiably a pure SELECT
    (it never mutates ``_rows``). Lets the false→true-after-commit and
    read-does-not-commit invariants be asserted on one shared store.
    """

    def __init__(self) -> None:
        self._rows: set[tuple[str, str]] = set()
        self.executed: list[tuple[Any, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        self.executed.append((statement, params))
        key = (params["adapter_id"], params["inbound_id"])
        if statement is _COMMIT_ONCE_SQL:
            if key in self._rows:
                return _FakeResult(None)  # ON CONFLICT DO NOTHING => no row
            self._rows.add(key)
            return _FakeResult(params["inbound_id"])
        if statement is _HAS_COMMITTED_SQL:
            return _FakeResult(1 if key in self._rows else None)
        raise AssertionError(f"unexpected statement: {statement!r}")


class _RaisingSession:
    """Raises on every execute — the fail-loud (DB-error) injection."""

    def __init__(self, raises: Exception) -> None:
        self._raises = raises

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        raise self._raises


def _scope_for(session: Any) -> Any:
    # Mirrors test_inbound_idempotency_store.py: the store's session_scope is a
    # Callable[[], AbstractAsyncContextManager[AsyncSession]]; the fake session is
    # a structural stand-in, so the scope factory is typed ``Any``.
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


@pytest.mark.asyncio
async def test_has_committed_false_then_true_after_commit() -> None:
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(_StatefulFakeSession()))
    assert await store.has_committed(inbound_id="m1", adapter_id="discord") is False
    assert await store.commit_once(inbound_id="m1", adapter_id="discord") is True
    assert await store.has_committed(inbound_id="m1", adapter_id="discord") is True


@pytest.mark.asyncio
async def test_has_committed_is_composite_keyed() -> None:
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(_StatefulFakeSession()))
    await store.commit_once(inbound_id="dup", adapter_id="discord")
    assert await store.has_committed(inbound_id="dup", adapter_id="tui") is False


@pytest.mark.asyncio
async def test_has_committed_does_not_commit() -> None:
    session = _StatefulFakeSession()
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(session))
    assert await store.has_committed(inbound_id="readonly", adapter_id="discord") is False
    # The read inserted nothing — the subsequent commit_once still wins.
    assert await store.commit_once(inbound_id="readonly", adapter_id="discord") is True
    # And the read carried the composite key as bound params (never interpolated).
    read_stmt, read_params = session.executed[0]
    assert read_stmt is _HAS_COMMITTED_SQL
    assert read_params == {"inbound_id": "readonly", "adapter_id": "discord"}


@pytest.mark.asyncio
async def test_has_committed_propagates_db_error() -> None:
    # fail-loud (hard rule #7): a DB error MUST propagate, never be swallowed into a bool.
    boom: SQLAlchemyError = OperationalError("SELECT failed", {}, Exception("db down"))
    store = PostgresInboundIdempotencyStore(session_scope=_scope_for(_RaisingSession(boom)))
    with pytest.raises(SQLAlchemyError):
        await store.has_committed(inbound_id="x", adapter_id="discord")
