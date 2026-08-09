"""PostgresTurnSideEffectLedger try-apply semantics (fake session; no DB).

#410 PR1 transactional revision: the ledger no longer owns any session or
scope — each ``try_apply_*`` call executes its single UPSERT statement on the
CALLER's ``AsyncSession``, inside the caller's transaction, so the gate and
the write it guards commit or roll back together. A fake session lets every
branch (first-apply / already-applied / DB-error-propagates) run hermetically.
The genuine-Postgres atomic-UPSERT and rollback-coupling properties live in
the integration tier (tests/integration/test_turn_side_effect_ledger_postgres.py).
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.turn_side_effects import (
    _TRY_APPLY_ASSISTANT_TURN_SQL,
    _TRY_APPLY_USER_TURN_SQL,
    PostgresTurnSideEffectLedger,
    TurnSideEffectLedger,
)


class _FakeResult:
    def __init__(self, *, returned: bool | None) -> None:
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
        return _FakeResult(returned=self._returned)


def test_store_satisfies_protocol() -> None:
    assert isinstance(PostgresTurnSideEffectLedger(), TurnSideEffectLedger)


async def test_try_apply_user_turn_proceeds_on_first_apply() -> None:
    fake_session = _FakeSession(returned=True)
    session: AsyncSession = cast(AsyncSession, fake_session)
    store = PostgresTurnSideEffectLedger()
    assert await store.try_apply_user_turn(session, adapter_id="discord", inbound_id="m1") is True
    stmt, params = fake_session.executed[0]
    assert stmt is _TRY_APPLY_USER_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_user_turn_skips_when_already_applied() -> None:
    # No row returned (the WHERE ...=FALSE guard didn't match) => already applied.
    session: AsyncSession = cast(AsyncSession, _FakeSession(returned=None))
    store = PostgresTurnSideEffectLedger()
    assert await store.try_apply_user_turn(session, adapter_id="discord", inbound_id="m1") is False


async def test_try_apply_assistant_turn_proceeds_on_first_apply() -> None:
    fake_session = _FakeSession(returned=True)
    session: AsyncSession = cast(AsyncSession, fake_session)
    store = PostgresTurnSideEffectLedger()
    assert (
        await store.try_apply_assistant_turn(session, adapter_id="discord", inbound_id="m1") is True
    )
    stmt, params = fake_session.executed[0]
    assert stmt is _TRY_APPLY_ASSISTANT_TURN_SQL
    assert params == {"adapter_id": "discord", "inbound_id": "m1"}


async def test_try_apply_assistant_turn_skips_when_already_applied() -> None:
    session: AsyncSession = cast(AsyncSession, _FakeSession(returned=None))
    store = PostgresTurnSideEffectLedger()
    assert (
        await store.try_apply_assistant_turn(session, adapter_id="discord", inbound_id="m1")
        is False
    )


async def test_adapter_id_is_part_of_the_key_not_a_free_column() -> None:
    # A different adapter_id, same inbound_id, must not be treated as the same gate.
    fake_session = _FakeSession(returned=True)
    session: AsyncSession = cast(AsyncSession, fake_session)
    store = PostgresTurnSideEffectLedger()
    assert await store.try_apply_user_turn(session, adapter_id="tui", inbound_id="m1") is True
    _stmt, params = fake_session.executed[0]
    assert params == {"adapter_id": "tui", "inbound_id": "m1"}


async def test_the_ledger_never_commits_or_rolls_back_the_callers_session() -> None:
    # The transactional contract in one assertion: the ledger's ONLY session
    # interaction is execute(). Commit/rollback belong to the caller's
    # session_scope — a ledger that committed would re-create the exact
    # independent-commit bug this revision removes.
    fake_session = _FakeSession(returned=True)
    session: AsyncSession = cast(AsyncSession, fake_session)
    store = PostgresTurnSideEffectLedger()
    await store.try_apply_user_turn(session, adapter_id="discord", inbound_id="m1")
    await store.try_apply_assistant_turn(session, adapter_id="discord", inbound_id="m1")
    assert not hasattr(store, "_session_scope")
    assert len(fake_session.executed) == 2  # two execute() calls and nothing else


@pytest.mark.parametrize("method_name", ["try_apply_user_turn", "try_apply_assistant_turn"])
async def test_db_error_propagates_fail_loud(method_name: str) -> None:
    # CLAUDE.md hard rule #7: a genuine DB failure is NEVER swallowed into a
    # False (which would silently re-permit a side effect that should have
    # stayed blocked, or block one that should have proceeded).
    boom = OperationalError("UPSERT failed", {}, Exception("db down"))
    session: AsyncSession = cast(AsyncSession, _FakeSession(raises=boom))
    store = PostgresTurnSideEffectLedger()
    method = getattr(store, method_name)
    with pytest.raises(OperationalError):
        await method(session, adapter_id="discord", inbound_id="m1")
