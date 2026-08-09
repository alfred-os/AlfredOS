"""Real-Postgres integration tests for the TRANSACTIONAL PostgresTurnSideEffectLedger.

#410 PR1 revision: the ledger executes inside the caller's transaction, so the
properties proven here move from "8 independent immediately-committing
sessions" to "N independent transactions that commit or roll back the gate
together with the write it guards" — the same one-winner shape, not a weaker
one — PLUS the three new properties the transactional design introduces:

1. a rollback after the gate leaves the gate UNSET (the direct regression
   test for the data-loss bug the revision fixes);
2. an ORPHANED transaction's row lock (crashed caller, connection never
   closed) is reclaimed within the TURN pool's
   idle_in_transaction_session_timeout — not OS TCP-keepalive timescales;
3. a loser blocked on the row lock resolves promptly once the winner's
   transaction concludes, and wins when the winner ROLLED BACK;
4. a REAL asyncio cancellation (task.cancel(), a BaseException — not an
   Exception subclass) delivered mid-transaction also leaves the gate UNSET,
   proven against the real asyncpg driver rather than assumed from
   AsyncSession.close() behaviour.

SQLite cannot express any of this; real Postgres only.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
import sqlalchemy as sa
from alembic import command, config
from pydantic import PostgresDsn
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.memory.db import (
    ConnectionRole,
    dispose_all_engines,
    make_engine,
    make_session_factory,
    session_scope,
)
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger

pytestmark = pytest.mark.integration

_ADAPTER = "discord"


@dataclass(frozen=True)
class _LedgerEnv:
    ledger: PostgresTurnSideEffectLedger
    factory: async_sessionmaker[AsyncSession]


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0025
    return postgres_url


@pytest.fixture
async def ledger_env(migrated_url: str) -> AsyncIterator[_LedgerEnv]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield _LedgerEnv(ledger=PostgresTurnSideEffectLedger(), factory=factory)
    finally:
        await engine.dispose()


async def _apply_user(env: _LedgerEnv, inbound_id: str, *, adapter_id: str = _ADAPTER) -> bool:
    """One gate call in its OWN committed transaction — the Phase-A shape."""
    async with session_scope(env.factory) as session:
        return await env.ledger.try_apply_user_turn(
            session, adapter_id=adapter_id, inbound_id=inbound_id
        )


async def _apply_assistant(env: _LedgerEnv, inbound_id: str, *, adapter_id: str = _ADAPTER) -> bool:
    """One gate call in its OWN committed transaction — the Phase-C shape."""
    async with session_scope(env.factory) as session:
        return await env.ledger.try_apply_assistant_turn(
            session, adapter_id=adapter_id, inbound_id=inbound_id
        )


async def test_first_apply_proceeds_each_gate(ledger_env: _LedgerEnv) -> None:
    assert await _apply_user(ledger_env, "m1") is True
    assert await _apply_assistant(ledger_env, "m1") is True


async def test_second_apply_skips_each_gate(ledger_env: _LedgerEnv) -> None:
    assert await _apply_user(ledger_env, "m2") is True
    assert await _apply_user(ledger_env, "m2") is False
    assert await _apply_assistant(ledger_env, "m2") is True
    assert await _apply_assistant(ledger_env, "m2") is False


async def test_gates_are_independent_columns_on_one_row(ledger_env: _LedgerEnv) -> None:
    # Applying assistant_turn does not pre-empt the OTHER gate on the same row.
    assert await _apply_assistant(ledger_env, "m3") is True
    assert await _apply_user(ledger_env, "m3") is True


async def test_inbound_id_namespaces_are_isolated(ledger_env: _LedgerEnv) -> None:
    assert await _apply_user(ledger_env, "m4") is True
    assert await _apply_user(ledger_env, "m5") is True  # different inbound_id


async def test_adapter_id_namespaces_are_isolated_on_the_same_inbound_id(
    ledger_env: _LedgerEnv,
) -> None:
    # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
    assert await _apply_user(ledger_env, "shared-id", adapter_id="discord") is True
    assert await _apply_user(ledger_env, "shared-id", adapter_id="tui") is True


async def test_rollback_after_gate_leaves_gate_unset(ledger_env: _LedgerEnv) -> None:
    """THE regression test for the #410 PR1 bug: the gate must travel with the
    transaction. Pre-revision, the gate committed independently and a caller
    rollback stranded it TRUE with the guarded write missing forever."""

    class _MidPhaseFailure(Exception):  # noqa: N818 -- test-only, not a real error class
        pass

    with pytest.raises(_MidPhaseFailure):
        async with session_scope(ledger_env.factory) as session:
            assert (
                await ledger_env.ledger.try_apply_user_turn(
                    session, adapter_id=_ADAPTER, inbound_id="rb1"
                )
                is True
            )
            raise _MidPhaseFailure()  # the phase fails after the gate said "proceed"

    # The rollback un-marked the gate: a replay gets to (re)apply the write.
    assert await _apply_user(ledger_env, "rb1") is True


async def test_cancellation_mid_transaction_rolls_the_gate_back(
    ledger_env: _LedgerEnv,
) -> None:
    """Fleet finding H-1's real-driver proof: asyncio.CancelledError is a
    BaseException, so an `except Exception:` scope would never roll it back
    explicitly — the whole safety property would silently rest on
    AsyncSession.close()'s implicit rollback, an asyncpg behaviour this suite
    would then be assuming rather than proving. This test delivers a REAL
    task.cancel() (not a manually-raised exception) while the coroutine is
    parked inside the transaction AFTER the gate said "proceed", and proves
    the gate is unset afterward — session_scope's explicit BaseException
    rollback, verified end-to-end against real Postgres."""
    gate_taken = asyncio.Event()

    async def cancelled_phase() -> None:
        async with session_scope(ledger_env.factory) as session:
            assert (
                await ledger_env.ledger.try_apply_user_turn(
                    session, adapter_id=_ADAPTER, inbound_id="cx1"
                )
                is True
            )
            gate_taken.set()
            # Park mid-transaction on a never-set Event; the ONLY exit from
            # this await is the CancelledError the test injects below.
            await asyncio.Event().wait()

    task = asyncio.create_task(cancelled_phase())
    async with asyncio.timeout(10):
        await gate_taken.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The BaseException rollback un-marked the gate: a replay re-applies.
    assert await _apply_user(ledger_env, "cx1") is True


async def test_concurrent_first_transactions_settle_to_exactly_one_winner(
    ledger_env: _LedgerEnv,
) -> None:
    # 8 concurrent TRANSACTIONS (not bare statements) on ONE key: the atomic
    # UPSERT + row lock serialise, so exactly one True and seven False.
    async def attempt() -> bool:
        async with session_scope(ledger_env.factory) as session:
            return await ledger_env.ledger.try_apply_user_turn(
                session, adapter_id=_ADAPTER, inbound_id="race"
            )

    results = await asyncio.gather(*(attempt() for _ in range(8)))
    assert sorted(results) == [False] * 7 + [True]


async def test_loser_blocked_on_the_row_lock_wins_after_the_winner_rolls_back(
    ledger_env: _LedgerEnv,
) -> None:
    """The concurrent-attempt-plus-rollback intersection: a loser blocked on the
    winner's row lock must (a) resolve promptly once the winner concludes and
    (b) WIN when the winner rolled back — the lock-footprint property the
    single-statement inspection argument does not cover."""

    gate_taken = asyncio.Event()
    release_winner = asyncio.Event()
    # Backend PIDs of the two connections under test, captured via
    # SELECT pg_backend_pid() right after each session opens (pass-2 finding
    # test2-1) — the probe below scopes its pg_locks poll to the loser's PID
    # so it can never be satisfied by an unrelated lock elsewhere in the
    # instance.
    winner_pid: list[int] = []
    loser_pid: list[int] = []

    class _WinnerAborts(Exception):  # noqa: N818 -- test-only, not a real error class
        pass

    async def winner() -> None:
        with pytest.raises(_WinnerAborts):
            async with session_scope(ledger_env.factory) as session:
                winner_pid.append(
                    (await session.execute(sa.text("SELECT pg_backend_pid()"))).scalar_one()
                )
                assert (
                    await ledger_env.ledger.try_apply_user_turn(
                        session, adapter_id=_ADAPTER, inbound_id="cr1"
                    )
                    is True
                )
                gate_taken.set()
                await release_winner.wait()
                raise _WinnerAborts()  # -> rollback releases the row lock

    async def loser() -> tuple[bool, float]:
        await gate_taken.wait()
        started = time.monotonic()
        async with session_scope(ledger_env.factory) as session:
            # PID captured BEFORE the gate call blocks, so the probe below
            # can scope its pg_locks poll to exactly this backend's wait.
            loser_pid.append(
                (await session.execute(sa.text("SELECT pg_backend_pid()"))).scalar_one()
            )
            result = await ledger_env.ledger.try_apply_user_turn(
                session, adapter_id=_ADAPTER, inbound_id="cr1"
            )  # blocks on the winner's in-flight transaction
        return result, time.monotonic() - started

    async def _loser_is_parked_on_a_transactionid_wait() -> bool:
        # What the loser waits on here is NOT a relation-level lock: a
        # blocked INSERT ... ON CONFLICT ... DO UPDATE ... WHERE ...
        # RETURNING on a contended key parks on the WINNER'S TRANSACTION ID
        # — pg_locks reports locktype='transactionid', mode='ShareLock',
        # granted=false against the loser's backend (verified against real
        # Postgres 18 during the #410 investigation). Filtering on the
        # loser's OWN backend pid AND locktype='transactionid' means this
        # probe is true ONLY when the specific loser under test is genuinely
        # blocked on that transaction-id wait — an unscoped
        # `WHERE NOT granted` count could be satisfied by any unrelated
        # not-granted lock anywhere in the Postgres instance, releasing the
        # winner early and letting the assertions pass without ever
        # exercising real contention. Observed over a THIRD connection (the
        # factory pool default of 5 accommodates winner + loser + this
        # probe).
        if not loser_pid:
            return False  # the loser has not opened its session yet
        async with session_scope(ledger_env.factory) as session:
            result = await session.execute(
                sa.text(
                    "SELECT 1 FROM pg_locks "
                    "WHERE NOT granted AND pid = :loser_pid "
                    "AND locktype = 'transactionid'"
                ),
                {"loser_pid": loser_pid[0]},
            )
            return result.scalar_one_or_none() is not None

    async with asyncio.timeout(30), asyncio.TaskGroup() as tg:
        tg.create_task(winner())
        loser_task = tg.create_task(loser())
        await gate_taken.wait()
        # Deterministic contention barrier (fleet finding H-5 — no bare
        # sleep-based synchronization): release the winner only once Postgres
        # ITSELF reports the loser's OWN backend blocked on a transactionid
        # wait, i.e. the specific loser under test is provably parked on the
        # winner's transaction. The 50 ms interval below is poll pacing, not
        # the synchronization mechanism — the release condition is the
        # server-side fact, and the enclosing asyncio.timeout(30) bounds the
        # poll.
        while not await _loser_is_parked_on_a_transactionid_wait():
            await asyncio.sleep(0.05)
        release_winner.set()

    won, waited = loser_task.result()
    assert won is True  # the winner rolled back, so the loser's insert succeeds
    assert waited < 10.0  # resolved promptly after the winner concluded, not a hang
    assert winner_pid and loser_pid and winner_pid[0] != loser_pid[0], (
        "winner and loser must be DISTINCT backends — same-backend reuse would "
        "make the contention this test exists to exercise impossible"
    )


async def test_orphaned_transaction_lock_is_reclaimed_by_the_idle_timeout(
    migrated_url: str,
) -> None:
    """A crashed process leaves a transaction holding the ledger row lock with
    nothing to roll it back. The TURN-role engine's
    idle_in_transaction_session_timeout must bound the replay's wait — NOT
    OS-level TCP keepalive defaults (hours). Uses the REAL role-scoped engine
    construction path so the setting is proven to reach the server."""

    class _TurnTunedCfg:
        database_url = PostgresDsn(migrated_url)
        db_turn_pool_max_connections = 4
        db_side_pool_max_connections = 2
        db_pool_checkout_timeout_seconds = 5.0
        db_idle_in_transaction_timeout_seconds = 1.0  # tight, to keep the test fast

    cfg = _TurnTunedCfg()
    engine = make_engine(cfg, role=ConnectionRole.TURN)
    factory = make_session_factory(cfg, role=ConnectionRole.TURN)
    ledger = PostgresTurnSideEffectLedger()
    holder = factory()  # the "crashed" caller's session — never committed, never closed
    try:
        assert (
            await ledger.try_apply_user_turn(holder, adapter_id=_ADAPTER, inbound_id="orphan")
            is True
        )
        # holder now idles in-transaction holding the row lock. Postgres kills
        # that backend after 1s; the blocked replay below then proceeds AND
        # wins (the orphan's un-committed insert died with its backend).
        started = time.monotonic()
        async with asyncio.timeout(20):
            async with session_scope(factory, role=ConnectionRole.TURN) as session:
                assert (
                    await ledger.try_apply_user_turn(
                        session, adapter_id=_ADAPTER, inbound_id="orphan"
                    )
                    is True
                )
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, (
            f"replay waited {elapsed:.1f}s — the idle_in_transaction timeout did not "
            "bound the orphaned lock"
        )
        # engine.pool sanity: the TURN pool really carries the configured size.
        assert engine.pool.size() == 4
    finally:
        # The server already terminated the holder's backend (that IS the
        # property under test); close() then raises the terminated-connection
        # error by design — suppress ONLY here, in teardown of a deliberately
        # killed connection, never in the assertion path above.
        with contextlib.suppress(Exception):
            await holder.close()
        await dispose_all_engines()
