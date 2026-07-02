"""SQLAlchemy 2.0 async engine + session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.memory._config_protocols import MemoryDbConfig

# Explicit DSN→engine registry. We dropped the previous `functools.cache`
# wrapper because `.cache_clear()` only forgets the Python references — it
# does NOT call `engine.dispose()`, so the SQLAlchemy pool kept its sockets
# open well past every cache-clearing test. The registry below lets
# `dispose_all_engines()` actually close the pools (see CR finding on
# `make_engine`'s previous shape). Keyed on the DSN string so callers with
# identical database URLs continue to share one engine and its pool.
_ENGINES: dict[str, AsyncEngine] = {}


def _engine_for_url(url: str) -> AsyncEngine:
    """Return the cached engine for ``url``, creating it on first use."""
    engine = _ENGINES.get(url)
    if engine is None:
        engine = create_async_engine(url, echo=False, future=True)
        _ENGINES[url] = engine
    return engine


def make_engine(config: MemoryDbConfig) -> AsyncEngine:
    """Return a cached async engine for ``config.database_url``.

    The engine owns a connection pool, so constructing a fresh one per
    ``make_session_factory`` call leaked pools — neither the CLI bootstrap nor
    the smoke test had a sensible place to ``.dispose()`` them. The cache is
    keyed on the DSN string (the config object isn't necessarily hashable), so
    callers with identical database URLs share one engine and its pool.

    Engine disposal is the process-lifetime contract: the engine lives until
    the process exits, when asyncio shutdown closes its pool. Tests / smoke
    fixtures that need per-test disposal call ``dispose_all_engines()``;
    ``functools.cache.cache_clear()`` was insufficient because it only drops
    Python references and leaks the pool's sockets.
    """
    return _engine_for_url(config.database_url.unicode_string())


async def dispose_all_engines() -> None:
    """Dispose every cached engine and clear the registry.

    Tests, fixtures, and any controlled shutdown path call this so the
    SQLAlchemy connection pools actually close their sockets. The previous
    `functools.cache.cache_clear()` only dropped Python references and left
    every pool's connections open until the process exited; long-running
    test sessions piled up sockets and eventually exhausted the testcontainer.
    """
    # Snapshot first: `engine.dispose()` yields control to the event loop and
    # we don't want a concurrent `_engine_for_url` to repopulate the dict
    # while we're iterating it.
    engines = list(_ENGINES.values())
    _ENGINES.clear()
    for engine in engines:
        await engine.dispose()


def make_session_factory(config: MemoryDbConfig) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=make_engine(config),
        expire_on_commit=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Transactional async session scope. Commits on success; rolls back on failure.

    Accepts the factory explicitly so tests / smoke tests can inject one.
    """
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def build_session_scope(config: MemoryDbConfig):  # type: ignore[no-untyped-def]
    """Bind `session_scope` to a config-derived factory.

    Returns a no-arg callable suitable for the orchestrator's `session_scope`
    parameter — `async with session_scope() as session: ...`. Wraps the
    `make_session_factory(config)` + `session_scope(factory)` plumbing so
    the orchestrator only needs one zero-arg callable.
    """
    factory = make_session_factory(config)

    def _scope():  # type: ignore[no-untyped-def]
        return session_scope(factory)

    return _scope


async def healthcheck(scope) -> None:  # type: ignore[no-untyped-def]
    """Smoke-check the database is reachable.

    Called at CLI bootstrap so a missing/down Postgres surfaces as a clean
    "ERROR: Postgres unreachable" message instead of an asyncpg traceback
    inside the TUI on first keystroke. Raises SQLAlchemyError on failure.
    """
    from sqlalchemy import text as _text

    async with scope() as session:
        await session.execute(_text("SELECT 1"))
