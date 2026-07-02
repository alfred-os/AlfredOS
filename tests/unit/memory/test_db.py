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

from collections.abc import AsyncGenerator
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
    fresh: dict[str, object] = {}
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

        def _fake_engine_for_url(url: str) -> object:
            captured.append(url)
            return object()

        monkeypatch.setattr(db_mod, "_engine_for_url", _fake_engine_for_url)

        class _StubCfg:
            database_url = PostgresDsn("postgresql+asyncpg://alfred:alfred@db:5432/alfred")

        db_mod.make_engine(_StubCfg())  # type-checks iff make_engine takes MemoryDbConfig
        assert captured == ["postgresql+asyncpg://alfred:alfred@db:5432/alfred"]


pytestmark = pytest.mark.asyncio
