"""The 250ms resolver budget must bound RESOLUTION, not cold DB connect (#527).

``DefaultOperatorSessionResolver.resolve`` wraps the whole pipeline in a 250ms
``asyncio.wait_for`` (err-008) so the resolver can never hang a CLI command
silently. That budget also covered **connection acquisition**, because
``_resolve_inner`` reaches the database through ``session_scope()`` and
``memory/db.py`` builds the engine with no ``pool_pre_ping`` and no prewarm.

Both production call sites run the resolver as the FIRST database work in the
process, on a fresh ``asyncio.run`` loop:

* ``cli/operator_session.py`` — ``asyncio.run(resolver.resolve())``
* ``cli/supervisor.py``       — ``asyncio.run(resolver.resolve())``

so the pool is always cold there and the TCP connect plus Postgres auth land
inside the 250ms window. Against a local container that is a few milliseconds;
against a loaded, remote or TLS-terminated Postgres it can exceed the budget —
and the failure mode is a **refusal**, so a legitimate operator running
``alfred supervisor status`` is denied.

It also made ``tests/integration/test_operator_session_lifecycle.py`` an implicit
wall-clock assertion on shared CI, where it blocked PRs #529 and #530.

err-008's intent is preserved exactly: the resolution logic is still hard-bounded
at 250ms. Only the connection setup moves outside it.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from alfred.identity._resolver import DefaultOperatorSessionResolver
from alfred.identity.operator_session import (
    OperatorSessionTimeout,
)

pytestmark = pytest.mark.asyncio

_HOST = "test-host"

# Comfortably past the 250ms budget, so a cold connect that is charged to the
# resolution window is unambiguously fatal rather than marginal.
_COLD_CONNECT_DELAY_S = 0.6


class _SlowFirstConnectScope:
    """A ``session_scope`` whose FIRST STATEMENT is slow, like a cold pool.

    Fidelity matters here and cost a CI round-trip. ``async_sessionmaker`` builds
    the session LAZILY: entering the scope touches no connection at all, and the
    pool is not hit until the first statement executes. An earlier version of this
    double slept on scope ENTRY, which made a warm that only entered the scope look
    like it worked — while in production it warmed nothing and CI still timed out.

    So the delay lives on the first ``execute``, which is where the real connect,
    auth and SQLAlchemy one-time setup actually happen.
    """

    def __init__(self, *, rows: dict[str, tuple[int, datetime | None]]) -> None:
        self._rows = rows
        self.acquisitions = 0
        self.statements = 0

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[Any]:
        self.acquisitions += 1
        yield _FakeDb(self._rows, self)


class _FakeDb:
    def __init__(
        self, rows: dict[str, tuple[int, datetime | None]], scope: _SlowFirstConnectScope
    ) -> None:
        self._rows = rows
        self._scope = scope

    async def execute(self, *_args: object, **_kwargs: object) -> Any:
        self._scope.statements += 1
        if self._scope.statements == 1:
            await asyncio.sleep(_COLD_CONNECT_DELAY_S)
        return _FakeResult(next(iter(self._rows.values()), None))


class _FakeResult:
    def __init__(self, row: tuple[int, datetime | None] | None) -> None:
        self._row = row

    def one_or_none(self) -> tuple[int, datetime | None] | None:
        return self._row

    def first(self) -> tuple[int, datetime | None] | None:
        return self._row

    def scalar_one_or_none(self) -> object:
        return self._row


class _Broker:
    """``BrokerLike.get`` is SYNCHRONOUS (`_session_protocols.py`), and
    `_read_pepper_or_emit_fileless` calls `.get(...).encode("utf-8")` directly.

    Declaring this `async def` would return a coroutine and raise
    `AttributeError: 'coroutine' object has no attribute 'encode'` the moment a
    test reached that path. The cases here stub `_resolve_inner`, so none does
    today — which is exactly how a double drifts from the contract unnoticed.
    """

    def get(self, _name: str) -> str:
        return "x" * 64


class _Machine:
    async def read(self) -> str:
        return "machine-id"


class _Audit:
    async def append_schema(self, **_kwargs: object) -> None:
        return None


class _Hooks:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def __call__(self, name: str, _payload: dict[str, object]) -> None:
        self.events.append(name)


def _resolver(scope: _SlowFirstConnectScope, session_path: Path) -> DefaultOperatorSessionResolver:
    return DefaultOperatorSessionResolver(
        session_scope=scope,
        secret_broker=_Broker(),
        machine_id_provider=_Machine(),
        audit_writer=_Audit(),
        hook_dispatcher=_Hooks(),
        host=_HOST,
        session_file_path=session_path,
    )


async def test_a_cold_connection_does_not_consume_the_resolution_budget(
    tmp_path: Path,
) -> None:
    """THE #527 case: a slow FIRST connection must not refuse a valid operator.

    The pipeline is stubbed to do exactly what the real one does that matters here
    — acquire a session scope — and nothing else. Building a fully valid session
    file, host and machine hash would exercise a lot of unrelated surface to reach
    the same single question: is the cold connect charged to the 250ms budget?

    Non-vacuous by construction: it FAILED before the fix with
    ``OperatorSessionTimeout``, because the 600ms first acquisition ran inside the
    window. The ``acquisitions`` assertion guards against the opposite vacuity —
    a stub that never touches the DB at all would prove nothing.
    """
    scope = _SlowFirstConnectScope(rows={})
    resolver = _resolver(scope, tmp_path / "session")

    async def _pipeline_that_hits_the_db() -> str:
        async with resolver._session_scope() as db:
            await db.execute(None)
            return "42"

    resolver._resolve_inner = _pipeline_that_hits_the_db  # type: ignore[method-assign]

    resolved = await resolver.resolve()

    assert resolved == "42"
    assert scope.statements >= 2, (
        "expected the warm to EXECUTE a statement plus the pipeline's own. Entering "
        "the scope is not enough — async_sessionmaker is lazy and warms nothing."
    )


async def test_the_hard_timeout_still_bounds_the_resolution_itself(
    tmp_path: Path,
) -> None:
    """err-008 is preserved: slow RESOLUTION still refuses at 250ms.

    The complement of the case above, and the one that stops the fix from being a
    silent removal of the hard timeout. Warming is not what is slow here — the
    pipeline is — so the budget must still fire.
    """
    session_path = tmp_path / "session"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    scope = _SlowFirstConnectScope(rows={})
    resolver = _resolver(scope, session_path)

    async def _slow_pipeline() -> str:
        await asyncio.sleep(_COLD_CONNECT_DELAY_S)
        return "never"

    resolver._resolve_inner = _slow_pipeline  # type: ignore[method-assign]

    with pytest.raises(OperatorSessionTimeout):
        await resolver.resolve()


async def test_warming_never_masks_a_real_failure(tmp_path: Path) -> None:
    """A warm that fails (DB genuinely down) must not change the error contract.

    Best-effort by design: if warming raises, the pipeline still runs and produces
    whatever it would have produced before this fix, rather than surfacing a new
    error type the CLI's arms do not know how to render.
    """

    class _ExplodingScope:
        def __init__(self) -> None:
            self.acquisitions = 0

        @asynccontextmanager
        async def __call__(self) -> AsyncIterator[Any]:
            self.acquisitions += 1
            raise OSError("database is down")
            yield  # pragma: no cover - unreachable, keeps this an async generator

    scope = _ExplodingScope()
    resolver = _resolver(scope, tmp_path / "missing" / "session")  # type: ignore[arg-type]

    with pytest.raises(Exception) as caught:
        await resolver.resolve()

    # The file-missing refusal still wins; the dead DB does not become the error.
    assert not isinstance(caught.value, OSError), (
        "a failed warm leaked out and replaced the pipeline's own refusal"
    )


async def test_a_pathological_database_still_fails_fast(tmp_path: Path) -> None:
    """The warm must not inflate the worst case err-008 exists to bound.

    err-008's purpose is that the resolver fails FAST rather than hanging a CLI
    command. A generous warm ceiling inverts that: my first attempt used 5s, which
    put a 5s wait in front of a 250ms budget — 20x worse for exactly the
    pathological database the rule protects against. The integration suite's
    `test_resolver_hard_timeout` caught it via its <0.6s assertion; this pins the
    property at the unit tier too, where it is cheap to run.

    Worst case is warm + resolution, both bounded by the same constant.
    """

    class _WedgedScope:
        @asynccontextmanager
        async def __call__(self) -> AsyncIterator[Any]:
            yield _WedgedDb()

    class _WedgedDb:
        async def execute(self, *_a: object, **_k: object) -> Any:
            await asyncio.sleep(30)  # never returns within any sane budget
            raise AssertionError("unreachable")

    resolver = _resolver(_WedgedScope(), tmp_path / "session")  # type: ignore[arg-type]

    async def _pipeline_that_hits_the_db() -> str:
        async with resolver._session_scope() as db:
            await db.execute(None)
            return "unreachable"

    resolver._resolve_inner = _pipeline_that_hits_the_db  # type: ignore[method-assign]

    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(OperatorSessionTimeout):
        await resolver.resolve()
    elapsed = loop.time() - started

    assert elapsed < 0.6, (
        f"resolver took {elapsed:.2f}s against a wedged database — the warm ceiling "
        "has been widened and err-008's fail-fast guarantee is weakened"
    )
