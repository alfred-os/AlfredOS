"""SQLAlchemy 2.0 async engine + session factory, role-scoped (#410 PR1 / ADR-0062).

Every Postgres connection in the core is acquired under one of three closed
:class:`ConnectionRole`\\ s, each with its own cached engine + pool per DSN:

- ``TURN`` — the orchestrator's per-phase transactions (Phase A / Phase C of
  the three-phase turn). Sub-millisecond hold times by design: the ONLY
  in-transaction work is the ledger UPSERT + one episodic write (bounded by
  the episodic before-write hook chain, ``HOOK_CHAIN_DEADLINE_SECONDS`` =
  0.25 s x 2 hookpoints ~= 0.5 s worst case), so the tight
  ``idle_in_transaction_session_timeout`` below (default 5 s = 10x that
  bound) is safe — under the pre-#410 single-turn-transaction design it was
  NOT (a healthy turn idled in-transaction for the whole provider call).
- ``SIDE_EFFECT`` — durability-guaranteed writes that must survive a caller's
  rollback: the audit writers (CLAUDE.md hard rule #7), idempotency stores,
  working-pool rehydrate. The default role, so pre-#410 call sites keep
  their behaviour without edits.
- ``CONTROL`` — CLI / Alembic / gate-backend / identity-resolver traffic:
  human-scale, multi-statement, deliberately NOT idle-bounded.

Acquisition hierarchy (enforced by :func:`session_scope`'s contextvar guard):
while a ``TURN`` scope is held in the current task, ``SIDE_EFFECT`` is the
ONLY role permitted to open a second scope — that is the audit-durability
exception, and it is counted on
``alfred_db_side_effect_scope_inside_turn_total`` so the load-bearing
exception stays visible. A second ``TURN`` (or a ``CONTROL``) scope raises
:class:`NestedTurnConnectionError`: two-connections-per-task on a bounded
pool is the hold-and-wait shape that deadlocked 16/16 concurrent turns in
the #410 PR1 investigation.

Registry lifecycle: engines are cached per ``(dsn, role)``. The FIRST
construction for a key wins its pool parameters (same first-wins contract the
previous DSN-only registry had); production always derives tuning from the
one ``Settings`` instance (structurally, via :class:`MemoryDbTuningConfig`),
so all call sites agree. ``dispose_all_engines()`` is the test/shutdown
reaper — ``functools.cache.cache_clear()`` was insufficient because it only
dropped Python references and leaked the pools' sockets.
"""

from __future__ import annotations

import enum
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final

from prometheus_client import Counter
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.errors import AlfredError
from alfred.memory._config_protocols import MemoryDbConfig, MemoryDbTuningConfig


class ConnectionRole(enum.Enum):
    """Closed vocabulary of Postgres-connection acquisition roles (ADR-0062)."""

    TURN = "turn"
    SIDE_EFFECT = "side_effect"
    CONTROL = "control"


@dataclass(frozen=True, slots=True)
class DbPoolTuning:
    """Per-role pool parameters.

    Defaults MIRROR the ``Settings`` field defaults (Task 2 of the #410 PR1
    plan) so a config object without the tuning fields (narrow test stubs)
    behaves identically to an un-overridden production Settings.
    """

    turn_pool_max_connections: int = 32
    side_pool_max_connections: int = 16
    checkout_timeout_seconds: float = 10.0
    idle_in_transaction_timeout_seconds: float = 5.0


class NestedTurnConnectionError(AlfredError):
    """A TURN or CONTROL scope was opened while a TURN scope was already held.

    Holding one pooled connection while acquiring a second (non-SIDE_EFFECT)
    one in the same task is the hold-and-wait deadlock seed #410 PR1 exists
    to eliminate — fail loud at the acquisition site, never wait it out.
    """


# Composite-key registry: one engine (and pool) per (dsn, role).
_ENGINES: dict[tuple[str, ConnectionRole], AsyncEngine] = {}

# Per-task flag: is a TURN-role scope currently open? A ContextVar, not a
# module flag — the core is async and a flag would leak the "held" state
# across concurrently-running tasks (same reasoning as
# alfred.security.tiers._T3_CONSTRUCTION_AUTHORIZED and
# alfred.hooks.registry._reentry).
_TURN_SCOPE_ACTIVE: ContextVar[bool] = ContextVar("alfred_db_turn_scope_active", default=False)

_SIDE_EFFECT_INSIDE_TURN: Final[Counter] = Counter(
    "alfred_db_side_effect_scope_inside_turn_total",
    "SIDE_EFFECT-role session scopes opened while a TURN-role scope was held "
    "(the audit-durability exception to the no-nesting rule, CLAUDE.md hard "
    "rule #7 — counted so the load-bearing exception stays visible).",
)

# CONTROL keeps SQLAlchemy's stock QueuePool shape — made EXPLICIT here (and
# named in Settings' DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET arithmetic)
# rather than left as the silent library default the #410 investigation
# started from.
_CONTROL_POOL_SIZE: Final[int] = 5
_CONTROL_MAX_OVERFLOW: Final[int] = 10
# Recycle connections older than 30 minutes — long-lived daemon processes
# otherwise accumulate server-side-stale connections across Postgres restarts
# that pool_pre_ping alone detects one checkout too late.
_POOL_RECYCLE_SECONDS: Final[int] = 1800


def _tuning_for(config: MemoryDbConfig, tuning: DbPoolTuning | None) -> DbPoolTuning:
    """Resolve tuning: explicit arg > config's own fields > defaults."""
    if tuning is not None:
        return tuning
    if isinstance(config, MemoryDbTuningConfig):
        return DbPoolTuning(
            turn_pool_max_connections=config.db_turn_pool_max_connections,
            side_pool_max_connections=config.db_side_pool_max_connections,
            checkout_timeout_seconds=config.db_pool_checkout_timeout_seconds,
            idle_in_transaction_timeout_seconds=config.db_idle_in_transaction_timeout_seconds,
        )
    return DbPoolTuning()


def _engine_kwargs(role: ConnectionRole, tuning: DbPoolTuning) -> dict[str, Any]:
    # dict[str, Any] (not object) is required to **-unpack into
    # create_async_engine's typed signature — the values are heterogeneous
    # engine kwargs, which is exactly what Any is for here.
    if role is ConnectionRole.CONTROL:
        return {
            "pool_size": _CONTROL_POOL_SIZE,
            "max_overflow": _CONTROL_MAX_OVERFLOW,
            "pool_pre_ping": True,
            "pool_recycle": _POOL_RECYCLE_SECONDS,
        }
    pool_size = (
        tuning.turn_pool_max_connections
        if role is ConnectionRole.TURN
        else tuning.side_pool_max_connections
    )
    # asyncpg forwards server_settings in the startup packet; the GUC's unit
    # is milliseconds, sent as a bare-integer string.
    idle_ms = str(int(tuning.idle_in_transaction_timeout_seconds * 1000))
    return {
        "pool_size": pool_size,
        # max_overflow=0: the pool size IS the cap. Overflow connections would
        # make the Settings-level connection-budget validator a fiction.
        "max_overflow": 0,
        "pool_timeout": tuning.checkout_timeout_seconds,
        "pool_pre_ping": True,
        "pool_recycle": _POOL_RECYCLE_SECONDS,
        "connect_args": {"server_settings": {"idle_in_transaction_session_timeout": idle_ms}},
    }


def _engine_for_url(
    url: str,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> AsyncEngine:
    """Return the cached engine for ``(url, role)``, creating it on first use."""
    key = (url, role)
    engine = _ENGINES.get(key)
    if engine is None:
        engine = create_async_engine(
            url,
            echo=False,
            future=True,
            **_engine_kwargs(role, tuning if tuning is not None else DbPoolTuning()),
        )
        _ENGINES[key] = engine
    return engine


def make_engine(
    config: MemoryDbConfig,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> AsyncEngine:
    """Return a cached async engine for ``(config.database_url, role)``.

    First construction for a given key wins its pool parameters (see module
    docstring). ``tuning=None`` auto-derives from ``config`` when it carries
    the :class:`MemoryDbTuningConfig` fields (the real ``Settings`` does),
    else falls back to :class:`DbPoolTuning` defaults.
    """
    return _engine_for_url(
        config.database_url.unicode_string(),
        role=role,
        tuning=_tuning_for(config, tuning),
    )


async def dispose_all_engines() -> None:
    """Dispose every cached engine (all roles) and clear the registry.

    Tests, fixtures, and any controlled shutdown path call this so the
    SQLAlchemy connection pools actually close their sockets.
    """
    # Snapshot first: `engine.dispose()` yields control to the event loop and
    # we don't want a concurrent `_engine_for_url` to repopulate the dict
    # while we're iterating it.
    engines = list(_ENGINES.values())
    _ENGINES.clear()
    for engine in engines:
        await engine.dispose()


def make_session_factory(
    config: MemoryDbConfig,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=make_engine(config, role=role, tuning=tuning),
        expire_on_commit=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
) -> AsyncIterator[AsyncSession]:
    """Transactional async session scope. Commits on success; rolls back on failure.

    Enforces the ADR-0062 acquisition hierarchy: while a TURN scope is held
    in the current task/context, only SIDE_EFFECT may nest (counted); TURN
    and CONTROL raise :class:`NestedTurnConnectionError` — see the class
    docstring for why waiting instead of raising is the deadlock.

    Rollback fires on ``BaseException``, not ``Exception`` — deliberately.
    ``asyncio.CancelledError`` (and ``KeyboardInterrupt``/``SystemExit``) are
    ``BaseException``\\ s, and a cancellation delivered mid-transaction must
    un-do the transaction's writes (for the orchestrator's Phase A/C, that
    means un-marking the ledger gate) as EXPLICITLY as any other failure.
    Relying on ``AsyncSession.close()``'s implicit rollback-on-close would
    make the plan's headline safety property an unverified driver assumption;
    the explicit call is proven against real asyncpg by
    ``tests/integration/test_turn_side_effect_ledger_postgres.py``'s
    ``task.cancel()`` test.

    Two narrow-window cancellation residuals are ACCEPTED here, not solved
    — both named in ADR-0062's residual list (#410 PR1 pass-2 findings
    sec-101 / mem-p2-001; they are DISTINCT windows — closing one does not
    close the other):

    1. a SECOND cancellation landing while this explicit ``rollback()``'s
       own await is in flight re-raises out of the rollback; connection
       teardown then falls to ``AsyncSession.close()`` (via ``async with
       factory()``) — behaviour this codebase relies on for that window
       but does not independently prove;
    2. a cancellation delivered during the ORIGINAL statement's in-flight
       asyncpg network I/O can leave the connection protocol-wedged such
       that even an ordinary, uninterrupted ``rollback()`` call itself
       raises ``asyncpg.InterfaceError`` — a real, still-open upstream
       driver/ORM interaction (sqlalchemy/sqlalchemy#6592, #8145, #11125,
       #12099; MagicStack/asyncpg#863, #258, #1310; read against the
       installed sqlalchemy 2.0.51 / asyncpg 0.31.0).

    Neither window can strand the ledger gate: in both, the transaction
    never commits, so the server aborts it (at the latest when
    ``idle_in_transaction_session_timeout`` reaps the backend) and a replay
    correctly sees "not applied". The residual exposure is one
    possibly-unclean pooled connection, bounded by
    ``pool_pre_ping``/``pool_recycle`` — and the at-risk window is Phase
    A/C's sub-millisecond transactions, not the pre-#410 design's
    whole-provider-call span.
    """
    if _TURN_SCOPE_ACTIVE.get():
        if role is not ConnectionRole.SIDE_EFFECT:
            raise NestedTurnConnectionError(
                f"a {role.value!r}-role session scope was opened while a TURN-role "
                "scope is already held in this task; only SIDE_EFFECT may nest "
                "inside TURN (ADR-0062 acquisition hierarchy)"
            )
        _SIDE_EFFECT_INSIDE_TURN.inc()
    token = _TURN_SCOPE_ACTIVE.set(True) if role is ConnectionRole.TURN else None
    try:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                # BaseException on purpose (see docstring). Safe to await here:
                # @asynccontextmanager delivers body exceptions via athrow() at
                # the yield point, so the handler runs as normal coroutine code
                # — this is not a GeneratorExit-during-close path.
                await session.rollback()
                raise
    finally:
        if token is not None:
            _TURN_SCOPE_ACTIVE.reset(token)


def build_session_scope(
    config: MemoryDbConfig,
    *,
    role: ConnectionRole = ConnectionRole.SIDE_EFFECT,
    tuning: DbPoolTuning | None = None,
) -> Callable[[], AbstractAsyncContextManager[AsyncSession]]:
    """Bind `session_scope` to a config-derived, role-scoped factory.

    Returns a no-arg callable suitable for the orchestrator's `session_scope`
    parameter — `async with session_scope() as session: ...`.
    """
    factory = make_session_factory(config, role=role, tuning=tuning)

    def _scope() -> AbstractAsyncContextManager[AsyncSession]:
        return session_scope(factory, role=role)

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
