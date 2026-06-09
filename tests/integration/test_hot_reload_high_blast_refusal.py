"""Merge-blocking integration test: hot-reload high-blast refusal (PR-S4-4 Task 25).

ADR-0023 §5 + index §4 + spec §5.7. Drives the REAL :class:`PolicyWatcher`
against a real temp ``policies.yaml`` and the REAL :class:`AuditWriter` backed
by a Postgres testcontainer.

The blast-radius partition is **default-refuse, allowlist-permit**: the
low-blast allowlist (:data:`alfred.policies.model.LOW_BLAST_ALLOWLIST`) is EMPTY
by design, so EVERY field currently modelled in ``PoliciesV1`` —
``rate_limits.*``, ``handle_caps.*``, ``high_blast.*`` — is high-blast and must
REFUSE hot-reload. This test pins that all three partitions refuse:

* a ``rate_limits.web_fetch_per_user_per_hour`` edit (anti-abuse DoS / bypass)
  is REFUSED — NOT applied silently with ``config.reload.applied`` (the bug
  the previous version of this test codified as correct);
* a ``handle_caps.web_fetch_max_concurrent_handles_per_user`` edit is REFUSED;
* a ``high_blast.quarantined_provider_url`` edit is REFUSED.

In every case the active snapshot is byte-identical afterwards (refusal is
total) and a ``config.reload.rejected`` row with ``reason="high_blast_change"``
lands. NO ``config.reload.applied`` row is ever written.

This test is promoted to a required status check at PR-S4-4 merge time
(index §4 / ops-007). It runs in CI; locally it requires Docker.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.audit.log import AuditWriter
from alfred.memory.models import AuditEntry, Base
from alfred.policies.load import canonical_bytes, compute_sha256
from alfred.policies.model import PoliciesV1
from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef
from alfred.policies.watcher import PolicyWatcher

pytestmark = pytest.mark.asyncio


def _model(
    *,
    rate_per_hour: int = 60,
    handle_cap: int = 8,
    provider_url: str = "https://quarantine.local/v1",
) -> PoliciesV1:
    return PoliciesV1.model_validate(
        {
            "schema_version": 1,
            "rate_limits": {
                "web_fetch_per_user_per_hour": rate_per_hour,
                "web_fetch_per_session_total": 200,
                "operator_daily_budget_usd": 5.0,
            },
            "handle_caps": {"web_fetch_max_concurrent_handles_per_user": handle_cap},
            "high_blast": {
                "quarantined_provider_url": provider_url,
                "secret_broker_config_ref": "broker://default",
            },
        }
    )


def _write(path: Path, model: PoliciesV1) -> None:
    path.write_bytes(canonical_bytes(model))


def _snapshot(path: Path, model: PoliciesV1) -> PoliciesSnapshot:
    return PoliciesSnapshot(
        policies=model,
        loaded_at=datetime.now(UTC),
        file_mtime=path.stat().st_mtime,
        file_sha256=compute_sha256(canonical_bytes(model)),
        file_path=path.resolve(),
    )


async def _rejections(sm: async_sessionmaker[AsyncSession], offending_key: str) -> list[AuditEntry]:
    async with sm() as session:
        rows = (await session.execute(select(AuditEntry))).scalars().all()
    return [
        r
        for r in rows
        if r.event == "config.reload.rejected"
        and r.subject.get("reason") == "high_blast_change"
        and r.subject.get("offending_key") == offending_key
    ]


async def _applied_rows(sm: async_sessionmaker[AsyncSession]) -> list[AuditEntry]:
    async with sm() as session:
        rows = (await session.execute(select(AuditEntry))).scalars().all()
    return [r for r in rows if r.event == "config.reload.applied"]


async def test_every_partition_refuses_hot_reload(tmp_path: Path) -> None:
    """ADR-0023 §5: rate-limit, handle-cap, AND high-blast edits all refuse."""
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            sm = async_sessionmaker(bind=engine, expire_on_commit=False)

            @asynccontextmanager
            async def session_scope() -> AsyncIterator[AsyncSession]:
                async with sm() as session, session.begin():
                    yield session

            audit = AuditWriter(session_factory=session_scope)

            cfg = tmp_path / "policies.yaml"
            initial = _model()
            _write(cfg, initial)
            ref = PoliciesSnapshotRef(_snapshot(cfg, initial))
            watcher = PolicyWatcher(
                config_path=cfg,
                snapshot_ref=ref,
                audit_writer=audit,
                poll_interval=0.05,
            )
            initial_snapshot = ref.current()

            # 1) Rate-limit edit (anti-abuse DoS / bypass) is REFUSED.
            _write(cfg, _model(rate_per_hour=0))
            await watcher._tick()
            assert ref.current() is initial_snapshot, "rate-limit edit must not swap"
            assert await _rejections(sm, "rate_limits.web_fetch_per_user_per_hour")

            # 2) Handle-cap edit is REFUSED.
            _write(cfg, _model(handle_cap=9999))
            await watcher._tick()
            assert ref.current() is initial_snapshot, "handle-cap edit must not swap"
            assert await _rejections(sm, "handle_caps.web_fetch_max_concurrent_handles_per_user")

            # 3) High-blast provider-URL edit is REFUSED.
            _write(cfg, _model(provider_url="https://evil.example/v1"))
            await watcher._tick()
            assert ref.current() is initial_snapshot, "high-blast edit must not swap"
            assert await _rejections(sm, "high_blast.quarantined_provider_url")

            # The active snapshot is byte-identical to bootstrap throughout, and
            # NO applied row was ever written — refusal is total for all three.
            assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 60
            assert (
                str(ref.current().policies.high_blast.quarantined_provider_url).rstrip("/")
                == "https://quarantine.local/v1"
            )
            assert await _applied_rows(sm) == []
        finally:
            await engine.dispose()
