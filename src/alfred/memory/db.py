"""SQLAlchemy 2.0 async engine + session factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.config.settings import Settings


def make_engine(settings: Settings):  # type: ignore[no-untyped-def]
    return create_async_engine(settings.database_url.unicode_string(), echo=False, future=True)


def make_session_factory(settings: Settings) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=make_engine(settings),
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


def build_session_scope(settings: Settings):  # type: ignore[no-untyped-def]
    """Bind `session_scope` to a settings-derived factory.

    Returns a no-arg callable suitable for the orchestrator's `session_scope`
    parameter — `async with session_scope() as session: ...`. Wraps the
    `make_session_factory(settings)` + `session_scope(factory)` plumbing so
    the orchestrator only needs one zero-arg callable.
    """
    factory = make_session_factory(settings)

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
