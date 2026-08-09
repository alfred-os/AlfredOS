"""#410 PR1: build_orchestrator arms the ledger and role-scopes its pools.

No DB is touched — build_session_scope and build_budget_guard are monkeypatched
at the _bootstrap module namespace; engine construction is lazy anyway.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.cli import _bootstrap
from alfred.config.settings import Settings
from alfred.memory.db import ConnectionRole
from alfred.memory.replay_journal import PostgresReplayJournal
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger


@dataclass(frozen=True)
class _StubUser:
    slug: str
    display_name: str
    language: str


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")


def _fake_scope() -> Any:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[MagicMock]:
        yield MagicMock()

    return _scope


def _stub_resolver() -> MagicMock:
    resolver = MagicMock()
    resolver.get_operator = MagicMock(
        return_value=_StubUser(slug="op", display_name="Op", language="en-US")
    )
    return resolver


def test_default_scopes_are_role_scoped_and_the_ledger_is_armed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base_env(monkeypatch)
    settings = Settings()
    recorded_roles: list[ConnectionRole] = []

    def _fake_build_session_scope(
        _config: Any,
        *,
        role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
        tuning: Any = None,
    ) -> Any:
        recorded_roles.append(role)
        return _fake_scope()

    monkeypatch.setattr(_bootstrap, "build_session_scope", _fake_build_session_scope)
    monkeypatch.setattr(_bootstrap, "build_budget_guard", lambda _r, _s: MagicMock())

    orch = _bootstrap.build_orchestrator(
        settings, broker=MagicMock(), router=MagicMock(), resolver=_stub_resolver()
    )
    # The at-most-once gate is ARMED on the production construction path.
    assert isinstance(orch._side_effect_ledger, PostgresTurnSideEffectLedger)
    # #410 PR2: the replay journal is armed unconditionally too, using the
    # SAME already-resolved audit_session_scope its sibling
    # ForwardedDispatchAttemptStore uses (SIDE_EFFECT-role, not TURN).
    assert isinstance(orch._replay_journal, PostgresReplayJournal)
    # Turn scope first, audit (SIDE_EFFECT) scope second — and nothing else.
    assert recorded_roles == [ConnectionRole.TURN, ConnectionRole.SIDE_EFFECT]


def test_injected_scopes_are_used_verbatim_no_default_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base_env(monkeypatch)
    settings = Settings()
    recorded_roles: list[ConnectionRole] = []

    def _fake_build_session_scope(
        _config: Any,
        *,
        role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
        tuning: Any = None,
    ) -> Any:
        recorded_roles.append(role)
        return _fake_scope()

    monkeypatch.setattr(_bootstrap, "build_session_scope", _fake_build_session_scope)
    monkeypatch.setattr(_bootstrap, "build_budget_guard", lambda _r, _s: MagicMock())

    orch = _bootstrap.build_orchestrator(
        settings,
        broker=MagicMock(),
        router=MagicMock(),
        resolver=_stub_resolver(),
        session_scope=_fake_scope(),
        audit_session_scope=_fake_scope(),
    )
    assert isinstance(orch._side_effect_ledger, PostgresTurnSideEffectLedger)
    # #410 PR2: the replay journal is armed unconditionally too, using the
    # SAME already-resolved audit_session_scope its sibling
    # ForwardedDispatchAttemptStore uses (SIDE_EFFECT-role, not TURN).
    assert isinstance(orch._replay_journal, PostgresReplayJournal)
    # The comms boot graph injects both scopes — the builder must not build
    # shadow ones (a shadow TURN engine would double the budgeted pool).
    assert recorded_roles == []
