"""PostgresReplayJournal append/read semantics (fake session_scope; no DB).

Mirrors tests/unit/memory/test_forwarded_dispatch_attempt_store.py and
tests/unit/memory/test_turn_side_effect_ledger_store.py: the store owns an
async session_scope; a fake session lets every branch run hermetically. The
genuine-Postgres ordering/persistence property lives in the integration tier
(tests/integration/test_replay_journal_postgres.py).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.replay_journal import (
    JournalEntry,
    PostgresReplayJournal,
    ReplayJournal,
)
from alfred.providers.base import ToolCall


class _FakeRow:
    def __init__(self, *, call_index: int, iteration: int, tool_call_id: str, tool_name: str, tool_arguments_json: str) -> None:
        self.call_index = call_index
        self.iteration = iteration
        self.tool_call_id = tool_call_id
        self.tool_name = tool_name
        self.tool_arguments_json = tool_arguments_json


_ADAPTER = "discord"


class _FakeResult:
    def __init__(self, rows: list[_FakeRow]) -> None:
        self._rows = rows

    def all(self) -> list[_FakeRow]:
        return self._rows


class _FakeSession:
    def __init__(self, *, rows: list[_FakeRow] | None = None, raises: Exception | None = None) -> None:
        self._rows = rows or []
        self._raises = raises
        self.executed: list[tuple[Any, Any]] = []

    async def execute(
        self, statement: Any, params: dict[str, Any] | list[dict[str, Any]]
    ) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._rows)


def _scope_for(session: _FakeSession) -> Any:
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresReplayJournal(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, ReplayJournal)


async def test_append_batch_sends_the_expected_params() -> None:
    session = _FakeSession()
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    call = ToolCall(id="tc-1", name="web.fetch", arguments={"url": "https://example.invalid"})
    await store.append_batch(
        adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[(0, call)]
    )
    _stmt, params_list = session.executed[0]
    assert len(params_list) == 1
    params = params_list[0]
    assert params["adapter_id"] == _ADAPTER
    assert params["inbound_id"] == "m1"
    assert params["call_index"] == 0
    assert params["iteration"] == 0
    assert params["tool_call_id"] == "tc-1"
    assert params["tool_name"] == "web.fetch"
    assert '"url": "https://example.invalid"' in params["tool_arguments_json"]


async def test_append_batch_writes_every_call_in_one_atomic_execute() -> None:
    """The core-001 regression pin: a multi-call iteration is ONE `execute()`, not N.

    Found during the `/review-plan` fleet's second pass (2026-08-07): the
    original design journalled one row per call, inside the dispatch loop —
    a crash between two calls of the same iteration could silently drop the
    un-journalled tail. `append_batch` must send the whole iteration's calls
    in a single `session.execute()` invocation so there is no such window:
    either the transaction commits with every call recorded, or none are.
    """
    session = _FakeSession()
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    call_a = ToolCall(id="tc-1", name="clock.now", arguments={})
    call_b = ToolCall(id="tc-2", name="web.fetch", arguments={"url": "https://example.invalid"})
    await store.append_batch(
        adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[(0, call_a), (1, call_b)]
    )
    assert len(session.executed) == 1  # ONE execute() call, not two
    _stmt, params_list = session.executed[0]
    assert len(params_list) == 2
    assert [p["call_index"] for p in params_list] == [0, 1]
    assert [p["tool_call_id"] for p in params_list] == ["tc-1", "tc-2"]


async def test_append_batch_rejects_an_empty_calls_sequence() -> None:
    """review-pr fleet, 2026-08-11: SQLAlchemy 2.0 silently no-ops

    `session.execute(stmt, [])` — no error, no rows written — so an empty
    batch would vanish without a trace instead of failing loud. The sole
    production caller only invokes ``append_batch`` when the planner
    actually requested tool calls, so an empty ``calls`` sequence reaching
    here is a genuine caller-contract violation, not a legitimate
    nothing-to-do case.
    """
    session = _FakeSession()
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    with pytest.raises(ValueError, match="empty"):
        await store.append_batch(adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[])
    assert session.executed == []  # never reached session.execute()


async def test_read_returns_empty_tuple_when_absent() -> None:
    session = _FakeSession(rows=[])
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    assert await store.read(adapter_id=_ADAPTER, inbound_id="absent") == ()


async def test_read_reconstructs_tool_calls_in_call_index_order() -> None:
    session = _FakeSession(
        rows=[
            _FakeRow(
                call_index=0,
                iteration=0,
                tool_call_id="tc-1",
                tool_name="clock.now",
                tool_arguments_json="{}",
            ),
            _FakeRow(
                call_index=1,
                iteration=0,
                tool_call_id="tc-2",
                tool_name="web.fetch",
                tool_arguments_json='{"url": "https://example.invalid"}',
            ),
        ]
    )
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    entries = await store.read(adapter_id=_ADAPTER, inbound_id="m1")
    assert entries == (
        JournalEntry(
            call_index=0,
            iteration=0,
            tool_call=ToolCall(id="tc-1", name="clock.now", arguments={}),
        ),
        JournalEntry(
            call_index=1,
            iteration=0,
            tool_call=ToolCall(
                id="tc-2", name="web.fetch", arguments={"url": "https://example.invalid"}
            ),
        ),
    )


@pytest.mark.parametrize("method_name", ["append_batch", "read"])
async def test_db_error_propagates_fail_loud(method_name: str) -> None:
    boom = OperationalError("query failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresReplayJournal(session_scope=_scope_for(session))
    with pytest.raises(OperationalError):
        if method_name == "append_batch":
            await store.append_batch(
                adapter_id=_ADAPTER,
                inbound_id="m1",
                iteration=0,
                calls=[(0, ToolCall(id="tc-1", name="clock.now", arguments={}))],
            )
        else:
            await store.read(adapter_id=_ADAPTER, inbound_id="m1")
