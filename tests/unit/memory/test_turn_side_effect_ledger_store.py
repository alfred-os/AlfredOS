"""PostgresTurnSideEffectLedger try-apply semantics (fake session_scope; no DB).

Mirrors tests/unit/memory/test_forwarded_dispatch_attempt_store.py: the store
owns an async session_scope; a fake session lets every branch (first-apply /
already-applied / DB-error-propagates) run hermetically. The genuine-Postgres
atomic-UPSERT property lives in the integration tier
(tests/integration/test_turn_side_effect_ledger_postgres.py).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from alfred.memory.turn_side_effects import (
    _TRY_APPLY_ASSISTANT_TURN_SQL,
    _TRY_APPLY_USER_TURN_SQL,
    PostgresTurnSideEffectLedger,
    TurnSideEffectLedger,
)


class _FakeResult:
    def __init__(self, returned: bool | None) -> None:
        self._returned = returned

    def scalar_one_or_none(self) -> bool | None:
        return self._returned


class _FakeSession:
    def __init__(self, *, returned: bool | None = None, raises: Exception | None = None) -> None:
        self._returned = returned
        self._raises = raises
        self.executed: list[tuple[Any, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any]) -> _FakeResult:
        self.executed.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return _FakeResult(self._returned)


def _scope_for(session: _FakeSession) -> Any:
    @asynccontextmanager
    async def _scope() -> Any:
        yield session

    return _scope


def test_store_satisfies_protocol() -> None:
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(_FakeSession()))
    assert isinstance(store, TurnSideEffectLedger)


async def test_try_apply_user_turn_proceeds_on_first_apply() -> None:
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_user_turn(adapter_id="discord", inbound_id="m1") is True
    stmt, params = session.executed[0]
    assert stmt is _TRY_APPLY_USER_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_user_turn_skips_when_already_applied() -> None:
    # No row returned (the WHERE ...=FALSE guard didn't match) => already applied.
    session = _FakeSession(returned=None)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_user_turn(adapter_id="discord", inbound_id="m1") is False


async def test_try_apply_assistant_turn_proceeds_on_first_apply() -> None:
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_assistant_turn(adapter_id="discord", inbound_id="m1") is True
    stmt, params = session.executed[0]
    assert stmt is _TRY_APPLY_ASSISTANT_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_assistant_turn_skips_when_already_applied() -> None:
    session = _FakeSession(returned=None)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_assistant_turn(adapter_id="discord", inbound_id="m1") is False


async def test_adapter_id_is_part_of_the_key_not_a_free_column() -> None:
    # A different adapter_id, same inbound_id, must not be treated as the same gate.
    session = _FakeSession(returned=True)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    assert await store.try_apply_user_turn(adapter_id="tui", inbound_id="m1") is True
    _stmt, params = session.executed[0]
    assert params == {"adapter_id": "tui", "inbound_id": "m1"}


@pytest.mark.parametrize("method_name", ["try_apply_user_turn", "try_apply_assistant_turn"])
async def test_db_error_propagates_fail_loud(method_name: str) -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a
    # False (which would silently re-permit a side effect that should have
    # stayed blocked, or block one that should have proceeded).
    boom = OperationalError("UPSERT failed", {}, Exception("db down"))
    session = _FakeSession(raises=boom)
    store = PostgresTurnSideEffectLedger(session_scope=_scope_for(session))
    method = getattr(store, method_name)
    with pytest.raises(OperationalError):
        await method(adapter_id="discord", inbound_id="m1")
