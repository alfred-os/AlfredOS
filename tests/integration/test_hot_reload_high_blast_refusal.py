"""Merge-blocking integration test: hot-reload high-blast refusal (PR-S4-4 Task 25).

Index §4 + spec §5.7. Drives the REAL :class:`PolicyWatcher` against a real
temp ``policies.yaml`` and the REAL :class:`AuditWriter` backed by a Postgres
testcontainer:

1. A low-blast edit (``web_fetch_per_user_per_hour`` 60 -> 120) hot-reloads:
   the snapshot ref swaps and a ``config.reload.applied`` audit row lands.
2. A high-blast edit (``quarantined_provider_url``) is REFUSED: the active
   snapshot is unchanged (low-blast value AND high-blast URL both preserved —
   refusal is total) and a ``config.reload.rejected`` row with
   ``reason="high_blast_change"`` lands.

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
    *, rate_per_hour: int = 60, provider_url: str = "https://quarantine.local/v1"
) -> PoliciesV1:
    return PoliciesV1.model_validate(
        {
            "schema_version": 1,
            "rate_limits": {
                "web_fetch_per_user_per_hour": rate_per_hour,
                "web_fetch_per_session_total": 200,
                "operator_daily_budget_usd": 5.0,
            },
            "handle_caps": {"web_fetch_max_concurrent_handles_per_user": 8},
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


async def test_low_blast_hot_reloads_high_blast_refused(tmp_path: Path) -> None:
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
            initial = _model(rate_per_hour=60)
            _write(cfg, initial)
            ref = PoliciesSnapshotRef(_snapshot(cfg, initial))
            watcher = PolicyWatcher(
                config_path=cfg,
                snapshot_ref=ref,
                audit_writer=audit,
                poll_interval=0.05,
            )

            # 1) Low-blast change: 60 -> 120 hot-reloads.
            _write(cfg, _model(rate_per_hour=120))
            await watcher._tick()
            assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120

            async with sm() as session:
                applied = (await session.execute(select(AuditEntry))).scalars().all()
            applied_events = [r.event for r in applied]
            assert "config.reload.applied" in applied_events

            # 2) High-blast change: provider URL swap is REFUSED.
            _write(cfg, _model(rate_per_hour=120, provider_url="https://evil.example/v1"))
            await watcher._tick()

            # Refusal is total: low-blast value AND high-blast URL both preserved.
            assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120
            assert (
                str(ref.current().policies.high_blast.quarantined_provider_url).rstrip("/")
                == "https://quarantine.local/v1"
            )

            async with sm() as session:
                rows = (await session.execute(select(AuditEntry))).scalars().all()
            rejections = [
                r
                for r in rows
                if r.event == "config.reload.rejected"
                and r.subject.get("reason") == "high_blast_change"
            ]
            assert rejections, "expected a high_blast_change rejection row"
            assert rejections[-1].subject["offending_key"] == "high_blast.quarantined_provider_url"
        finally:
            await engine.dispose()
