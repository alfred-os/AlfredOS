"""Tests for the AsyncEngine registry / disposal lifecycle.

The previous `functools.cache` wrapper only forgot Python references on
`.cache_clear()` and never disposed the SQLAlchemy pool. The explicit
registry below has to actually dispose every engine so pools close their
sockets — these tests pin that contract.

We mock ``create_async_engine`` directly so the suite stays a pure unit test
(no driver dependency). A real-driver integration check lives alongside
``tests/integration/test_memory_postgres.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.memory import db as db_mod


@pytest.fixture(autouse=True)
async def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[None, None]:
    """Replace the registry with an empty dict for each test and restore after.

    Other tests in the suite may legitimately populate the real registry; we
    isolate this file's effects so a leaked engine here can never bleed into
    other tests, and a real cached engine from another test can never
    interfere with the assertions below.
    """
    fresh: dict[tuple[str, db_mod.ConnectionRole], object] = {}
    monkeypatch.setattr(db_mod, "_ENGINES", fresh)
    yield


@pytest.fixture
def fake_engine_factory(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace `create_async_engine` with a factory returning AsyncMock engines.

    Each call returns a fresh AsyncMock so `is`-identity in the cache test
    is meaningful: a second call with the same URL must hit the registry
    (NOT re-enter the factory).
    """
    factory = MagicMock(side_effect=lambda *_a, **_kw: AsyncMock(name="engine"))
    monkeypatch.setattr(db_mod, "create_async_engine", factory)
    return factory


class TestEngineRegistry:
    async def test_same_url_returns_cached_engine(self, fake_engine_factory: MagicMock) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        first = db_mod._engine_for_url(url)
        second = db_mod._engine_for_url(url)
        assert first is second, "registry should de-duplicate engines per DSN"
        assert fake_engine_factory.call_count == 1

    async def test_different_urls_get_distinct_engines(
        self, fake_engine_factory: MagicMock
    ) -> None:
        a = db_mod._engine_for_url("postgresql+asyncpg://x:y@host-a/db")
        b = db_mod._engine_for_url("postgresql+asyncpg://x:y@host-b/db")
        assert a is not b
        assert fake_engine_factory.call_count == 2

    async def test_dispose_all_engines_clears_registry(
        self, fake_engine_factory: MagicMock
    ) -> None:
        db_mod._engine_for_url("postgresql+asyncpg://x:y@host-a/db")
        db_mod._engine_for_url("postgresql+asyncpg://x:y@host-b/db")
        assert len(db_mod._ENGINES) == 2
        await db_mod.dispose_all_engines()
        assert len(db_mod._ENGINES) == 0

    async def test_dispose_all_engines_invokes_dispose_on_each(self) -> None:
        # Direct registry injection: the contract under test is "every engine
        # in the registry gets `.dispose()` awaited". Going through the real
        # factory adds nothing here.
        probe_a = AsyncMock(name="engine-a")
        probe_b = AsyncMock(name="engine-b")
        db_mod._ENGINES["fake-a"] = probe_a
        db_mod._ENGINES["fake-b"] = probe_b
        await db_mod.dispose_all_engines()
        probe_a.dispose.assert_awaited_once()
        probe_b.dispose.assert_awaited_once()
        assert db_mod._ENGINES == {}


class TestConsumersAcceptNarrowConfig:
    async def test_make_engine_reads_only_database_url_from_a_stub(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """make_engine consumes MemoryDbConfig — a plain stub with just database_url."""
        from pydantic import PostgresDsn

        captured: list[str] = []
        captured_tuning: list[db_mod.DbPoolTuning | None] = []

        def _fake_engine_for_url(
            url: str,
            *,
            role: db_mod.ConnectionRole = db_mod.ConnectionRole.SIDE_EFFECT,
            tuning: db_mod.DbPoolTuning | None = None,
        ) -> object:
            captured.append(url)
            captured_tuning.append(tuning)
            return object()

        monkeypatch.setattr(db_mod, "_engine_for_url", _fake_engine_for_url)

        class _StubCfg:
            database_url = PostgresDsn("postgresql+asyncpg://alfred:alfred@db:5432/alfred")

        db_mod.make_engine(_StubCfg())  # type-checks iff make_engine takes MemoryDbConfig
        assert captured == ["postgresql+asyncpg://alfred:alfred@db:5432/alfred"]
        # Fleet finding M-12: the "structural fallback to defaults" guarantee
        # is ASSERTED, not just exercised — a stub without the tuning fields
        # must resolve to the DOCUMENTED DbPoolTuning defaults (which Task 2
        # pins as equal to the Settings field defaults), never to "some
        # tuning" or None.
        assert captured_tuning == [db_mod.DbPoolTuning()]
        assert captured_tuning[0] == db_mod.DbPoolTuning(
            turn_pool_max_connections=32,
            side_pool_max_connections=16,
            checkout_timeout_seconds=10.0,
            idle_in_transaction_timeout_seconds=5.0,
        )


class TestRoleScopedEngines:
    """#410 PR1: one cached engine per (dsn, role), each with role-shaped pool params."""

    async def test_same_url_different_roles_get_distinct_engines(
        self, fake_engine_factory: MagicMock
    ) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        turn = db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN)
        side = db_mod._engine_for_url(url, role=db_mod.ConnectionRole.SIDE_EFFECT)
        assert turn is not side
        assert fake_engine_factory.call_count == 2
        # Same (url, role) still deduplicates.
        assert db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN) is turn
        assert fake_engine_factory.call_count == 2

    async def test_turn_and_side_effect_pool_parameters_reach_create_async_engine(
        self, fake_engine_factory: MagicMock
    ) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        tuning = db_mod.DbPoolTuning(
            turn_pool_max_connections=7,
            side_pool_max_connections=3,
            checkout_timeout_seconds=2.5,
            idle_in_transaction_timeout_seconds=1.0,
        )
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN, tuning=tuning)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 7
        assert kwargs["max_overflow"] == 0
        assert kwargs["pool_timeout"] == 2.5
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["pool_recycle"] == 1800
        assert kwargs["connect_args"] == {
            "server_settings": {"idle_in_transaction_session_timeout": "1000"}
        }
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.SIDE_EFFECT, tuning=tuning)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 3
        assert kwargs["max_overflow"] == 0
        # Pass-2 finding: pool_recycle is pinned on BOTH runtime roles, not
        # just TURN — the SIDE_EFFECT engine is equally long-lived.
        assert kwargs["pool_recycle"] == 1800

    async def test_control_role_gets_stock_pool_and_no_idle_timeout(
        self, fake_engine_factory: MagicMock
    ) -> None:
        # CONTROL (CLI / Alembic / gate backend / identity resolver) does
        # human-scale multi-statement work — a tight idle-in-transaction bound
        # would kill a paused operator psql-style session mid-migration.
        url = "postgresql+asyncpg://x:y@localhost/test"
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.CONTROL)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 5
        assert kwargs["max_overflow"] == 10
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["pool_recycle"] == 1800
        assert "connect_args" not in kwargs

    async def test_tuning_is_auto_derived_from_a_settings_shaped_config(
        self, fake_engine_factory: MagicMock
    ) -> None:
        """A config carrying the four db_* tuning fields (i.e. the real Settings)
        is picked up structurally — no call site has to thread tuning= by hand,
        so operator env overrides can never be lost to call-site ordering."""
        from pydantic import PostgresDsn

        class _TunedCfg:
            database_url = PostgresDsn("postgresql+asyncpg://a:b@db:5432/x")
            db_turn_pool_max_connections = 9
            db_side_pool_max_connections = 4
            db_pool_checkout_timeout_seconds = 1.5
            db_idle_in_transaction_timeout_seconds = 2.0

        db_mod.make_engine(_TunedCfg(), role=db_mod.ConnectionRole.TURN)
        kwargs = fake_engine_factory.call_args.kwargs
        assert kwargs["pool_size"] == 9
        assert kwargs["pool_timeout"] == 1.5
        assert (
            kwargs["connect_args"]["server_settings"]["idle_in_transaction_session_timeout"]
            == "2000"
        )

    async def test_dispose_all_engines_covers_every_role(
        self, fake_engine_factory: MagicMock
    ) -> None:
        url = "postgresql+asyncpg://x:y@localhost/test"
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.TURN)
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.SIDE_EFFECT)
        db_mod._engine_for_url(url, role=db_mod.ConnectionRole.CONTROL)
        assert len(db_mod._ENGINES) == 3
        await db_mod.dispose_all_engines()
        assert db_mod._ENGINES == {}


def _fake_session_factory() -> tuple[Any, MagicMock]:
    """A factory() whose product is an async-CM yielding a commit/rollback-capable
    session mock — the minimal shape session_scope drives."""
    from contextlib import asynccontextmanager

    session = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()

    @asynccontextmanager
    async def _open() -> AsyncGenerator[MagicMock, None]:
        yield session

    return _open, session


class TestSessionScopeRoleGuard:
    """#410 PR1 / ADR-0062: closed acquisition hierarchy. While a TURN scope is
    held in this task/context, SIDE_EFFECT is the ONLY role that may open a
    second scope (the AuditWriter durability path, hard rule #7). A second TURN
    or a CONTROL scope is a hold-and-wait deadlock seed and fails loud."""

    async def test_nested_turn_scope_raises(self) -> None:
        factory, _session = _fake_session_factory()
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            with pytest.raises(db_mod.NestedTurnConnectionError):
                async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                    pass  # pragma: no cover — the guard raises at __aenter__

    async def test_control_scope_inside_turn_raises(self) -> None:
        factory, _session = _fake_session_factory()
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            with pytest.raises(db_mod.NestedTurnConnectionError):
                async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.CONTROL):
                    pass  # pragma: no cover — the guard raises at __aenter__

    async def test_side_effect_scope_inside_turn_is_allowed_and_counted(self) -> None:
        from prometheus_client import REGISTRY

        factory, _session = _fake_session_factory()
        before = REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total") or 0.0
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):  # noqa: SIM117 nested async contexts are intentional for testing nesting
            async with db_mod.session_scope(
                factory, role=db_mod.ConnectionRole.SIDE_EFFECT
            ) as inner:
                assert inner is _session
        after = REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total")
        assert after == before + 1.0

    async def test_side_effect_scope_outside_turn_is_not_counted(self) -> None:
        from prometheus_client import REGISTRY

        factory, _session = _fake_session_factory()
        before = REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total") or 0.0
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.SIDE_EFFECT):
            pass
        after = REGISTRY.get_sample_value("alfred_db_side_effect_scope_inside_turn_total") or 0.0
        assert after == before

    async def test_turn_flag_resets_even_when_the_scope_body_raises(self) -> None:
        factory, _session = _fake_session_factory()
        with pytest.raises(RuntimeError, match="boom"):
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                raise RuntimeError("boom")
        _session.rollback.assert_awaited()
        # The contextvar must have been reset — a fresh TURN scope opens cleanly.
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            pass

    async def test_cancelled_error_rolls_back_explicitly_and_resets_the_flag(self) -> None:
        """#410 PR1 fleet finding H-1: asyncio.CancelledError is a BaseException,
        NOT an Exception. An `except Exception:` scope would let a cancellation
        mid-Phase-A/C skip the rollback call entirely and lean on
        AsyncSession.close()'s IMPLICIT rollback — driver behaviour this
        codebase would then be assuming, not proving. The scope must roll back
        EXPLICITLY on BaseException; the real-driver twin of this test is
        tests/integration/test_turn_side_effect_ledger_postgres.py::
        test_cancellation_mid_transaction_rolls_the_gate_back (Task 4)."""
        factory, _session = _fake_session_factory()
        with pytest.raises(asyncio.CancelledError):
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                raise asyncio.CancelledError()
        _session.rollback.assert_awaited()
        _session.commit.assert_not_awaited()
        # The contextvar reset survives the BaseException path too.
        async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
            pass

    async def test_turn_scope_is_isolated_per_task_not_process_global(self) -> None:
        """#410 PR1 fleet finding H-6: the documented reason the guard is a
        ContextVar and not a module flag is per-TASK isolation — task B must be
        able to open TURN (or CONTROL) scopes while task A holds a TURN scope.
        A regression to module-level state makes task B raise
        NestedTurnConnectionError here (the TaskGroup then fails the test)."""
        factory, _session = _fake_session_factory()
        a_holding = asyncio.Event()
        release_a = asyncio.Event()

        async def task_a() -> None:
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                a_holding.set()
                await release_a.wait()

        async def task_b() -> None:
            await a_holding.wait()
            # Task A holds its TURN scope RIGHT NOW (released only after this
            # body completes) — an unrelated task must be unaffected.
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.TURN):
                pass
            async with db_mod.session_scope(factory, role=db_mod.ConnectionRole.CONTROL):
                pass
            release_a.set()

        async with asyncio.timeout(5):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(task_a())
                tg.create_task(task_b())


pytestmark = pytest.mark.asyncio
