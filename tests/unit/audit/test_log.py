"""Tests for the slice 1 audit log writer.

The writer takes a ``session_factory`` (async context manager factory) and
owns its own transaction inside ``.append()``. The fixtures here build a
factory that yields a single shared session-mock so the assertions can
inspect what was added/flushed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit.log import AuditWriter


def _mock_session() -> AsyncMock:
    """AsyncMock with `add` as a sync MagicMock to match SQLAlchemy's API.

    `AsyncSession.add` is sync; only `flush`/`commit`/`execute` are async.
    Without this, `AsyncMock` would coerce `add` to async and emit a
    RuntimeWarning about an un-awaited coroutine.
    """
    session = AsyncMock()
    session.add = MagicMock()
    return session


def _factory_for(session: AsyncMock):  # type: ignore[no-untyped-def]
    """Wrap a single session-mock in an async-context-manager factory.

    Mirrors the shape of ``alfred.memory.db.build_session_scope``'s output:
    a zero-arg callable returning an async context manager that yields the
    session.
    """

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncMock]:
        yield session

    return _scope


@pytest.mark.asyncio
class TestAuditWriter:
    async def test_append_persists_required_fields(self) -> None:
        session = _mock_session()
        writer = AuditWriter(session_factory=_factory_for(session))
        await writer.append(
            event="provider.call",
            actor_user_id="operator",
            subject={"provider": "deepseek", "model": "deepseek-chat"},
            trust_tier_of_trigger="T2",
            result="success",
            cost_estimate_usd=0.0001,
            trace_id="abc-123",
        )
        assert session.add.call_count == 1
        added = session.add.call_args[0][0]
        assert added.event == "provider.call"
        assert added.subject["provider"] == "deepseek"
        assert added.result == "success"
        assert added.trust_tier_of_trigger == "T2"
        session.flush.assert_awaited_once()

    async def test_append_raises_on_persistence_failure(self) -> None:
        session = _mock_session()
        session.flush.side_effect = RuntimeError("db down")
        writer = AuditWriter(session_factory=_factory_for(session))
        with pytest.raises(RuntimeError, match="db down"):
            await writer.append(
                event="provider.call",
                actor_user_id="operator",
                subject={},
                trust_tier_of_trigger="T2",
                result="success",
                cost_estimate_usd=0.0,
                trace_id="abc",
            )
