"""Merge-blocking operator-session lifecycle integration test (#153, spec §11.5).

Exercises login -> resolve (operator-attributed command) -> logout against a
real Postgres testcontainer, asserting the ``operator_sessions`` row lifecycle
(create / revoke), the ``audit_log`` row chain (CREATED -> ... -> REVOKED),
and the resolver's 250ms hard timeout. The CLI ``_impl`` coroutines and the
production ``DefaultOperatorSessionResolver`` are wired against the live DB so
the SQLAlchemy queries (not just the fakes) are covered.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.cli.operator_session import (
    OperatorSessionDeps,
    login_impl,
    logout_impl,
)
from alfred.cli.operator_session import (
    _PickerUser as PickerUser,
)
from alfred.identity._resolver import DefaultOperatorSessionResolver
from alfred.identity.models import User
from alfred.identity.operator_session import (
    OperatorSessionTimeout,
)
from alfred.memory.models import AuditEntry, Base
from alfred.memory.models import OperatorSession as OperatorSessionRow

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

_PEPPER = "0" * 64
_HOST = "alfred-itest-host"


class _Broker:
    def get(self, name: str) -> str:
        assert name == "audit.hash_pepper"
        return _PEPPER


class _Machine:
    async def read_raw(self) -> bytes:
        return b"machine-raw"


class _Hooks:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def __call__(self, name: str, payload: dict[str, Any]) -> None:
        self.events.append(name)


@pytest.fixture
async def scope(
    postgres_url: str,
) -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
    engine = create_async_engine(postgres_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(bind=engine, expire_on_commit=False)

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        async with sm() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    try:
        yield _scope
    finally:
        await engine.dispose()


async def _seed_alice(scope: Any) -> int:
    async with scope() as db:
        alice = User(
            slug="alice",
            display_name="Alice",
            authorization="operator",
            daily_budget_usd=10.0,
            language="en",
        )
        db.add(alice)
        await db.flush()
        return int(alice.id)


def _deps(scope: Any, alice_id: int, session_path: Path, hooks: _Hooks) -> OperatorSessionDeps:
    def _picker(uid: int) -> PickerUser:
        return PickerUser(user_id=uid, slug="alice", display_name="Alice", language="en")

    async def _list_users() -> list[PickerUser]:
        return [_picker(alice_id)]

    async def _by_slug(slug: str) -> PickerUser | None:
        return _picker(alice_id) if slug == "alice" else None

    async def _by_id(uid: int) -> PickerUser | None:
        return _picker(uid) if uid == alice_id else None

    async def _insert(**kwargs: Any) -> None:
        async with scope() as db:
            db.add(OperatorSessionRow(**kwargs))

    async def _revoke(token_hash: str) -> None:
        async with scope() as db:
            await db.execute(
                update(OperatorSessionRow)
                .where(OperatorSessionRow.token_hash == token_hash)
                .values(revoked_at=datetime.now(UTC))
            )

    return OperatorSessionDeps(
        secret_broker=_Broker(),
        audit_writer=AuditWriter(session_factory=scope),
        hook_dispatcher=hooks,
        machine_id_provider=_Machine(),
        host=_HOST,
        session_file_path=session_path,
        list_users=_list_users,
        lookup_user_by_slug=_by_slug,
        lookup_user_by_id=_by_id,
        insert_session_row=_insert,
        revoke_session_row=_revoke,
    )


async def _audit_events(scope: Any) -> list[str]:
    async with scope() as db:
        rows = (await db.execute(select(AuditEntry.event).order_by(AuditEntry.id))).scalars()
        return list(rows)


async def test_operator_session_full_lifecycle(scope: Any, tmp_path: Path) -> None:
    alice_id = await _seed_alice(scope)
    session_path = tmp_path / ".config" / "alfred" / "session"
    hooks = _Hooks()
    deps = _deps(scope, alice_id, session_path, hooks)

    # --- login ---
    await login_impl(deps, as_user="alice", expires_in=None, refresh=False)
    assert (session_path.stat().st_mode & 0o777) == 0o600
    async with scope() as db:
        row = (
            await db.execute(
                select(OperatorSessionRow).where(OperatorSessionRow.user_id == alice_id)
            )
        ).scalar_one()
        assert row.revoked_at is None
    assert "operator.session.created" in hooks.events

    # --- resolve (operator-attributed command path) ---
    resolver = DefaultOperatorSessionResolver(
        session_scope=scope,
        secret_broker=_Broker(),
        machine_id_provider=_Machine(),
        audit_writer=AuditWriter(session_factory=scope),
        hook_dispatcher=hooks,
        host=_HOST,
        session_file_path=session_path,
    )
    assert await resolver.resolve() == str(alice_id)

    # --- logout ---
    await logout_impl(deps)
    assert not session_path.exists()
    async with scope() as db:
        row = (
            await db.execute(
                select(OperatorSessionRow).where(OperatorSessionRow.user_id == alice_id)
            )
        ).scalar_one()
        assert row.revoked_at is not None  # revoked, not deleted

    events = await _audit_events(scope)
    assert "operator.session.created" in events
    assert "operator.session.revoked" in events
    assert events.index("operator.session.created") < events.index("operator.session.revoked")


async def test_resolver_hard_timeout(scope: Any, tmp_path: Path) -> None:
    """A DB query that sleeps past 250ms raises OperatorSessionTimeout (err-008)."""
    alice_id = await _seed_alice(scope)
    session_path = tmp_path / ".config" / "alfred" / "session"
    hooks = _Hooks()
    deps = _deps(scope, alice_id, session_path, hooks)
    await login_impl(deps, as_user="alice", expires_in=None, refresh=False)

    @asynccontextmanager
    async def _slow_scope() -> AsyncIterator[Any]:
        class _Slow:
            async def execute(self, *_a: Any, **_k: Any) -> Any:
                await asyncio.sleep(1.0)
                raise AssertionError("should have timed out")

        yield _Slow()

    resolver = DefaultOperatorSessionResolver(
        session_scope=_slow_scope,
        secret_broker=_Broker(),
        machine_id_provider=_Machine(),
        audit_writer=AuditWriter(session_factory=scope),
        hook_dispatcher=hooks,
        host=_HOST,
        session_file_path=session_path,
    )
    started = asyncio.get_event_loop().time()
    with pytest.raises(OperatorSessionTimeout):
        await resolver.resolve()
    assert asyncio.get_event_loop().time() - started < 0.6
