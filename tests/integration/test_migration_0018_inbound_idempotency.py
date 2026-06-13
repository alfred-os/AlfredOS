"""0018 inbound_idempotency migration — forward creates the ledger, backward drops it."""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from alembic import command, config

pytestmark = pytest.mark.integration


def _alembic_cfg(url: str) -> config.Config:
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_0018_upgrade_creates_ledger_then_downgrade_drops_it(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = _alembic_cfg(postgres_url)

    command.upgrade(cfg, "0018")
    engine = sa.create_engine(postgres_url.replace("+asyncpg", "+psycopg2"))
    insp = sa.inspect(engine)
    cols = {c["name"] for c in insp.get_columns("inbound_idempotency")}
    assert cols == {"inbound_id", "adapter_id", "committed_at"}
    pk = insp.get_pk_constraint("inbound_idempotency")
    # Composite (adapter_id, inbound_id) — each adapter's id namespace is isolated.
    assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id"}
    index_names = {ix["name"] for ix in insp.get_indexes("inbound_idempotency")}
    assert "ix_inbound_idempotency_committed_at" in index_names

    command.downgrade(cfg, "0017")
    post_engine = sa.create_engine(postgres_url.replace("+asyncpg", "+psycopg2"))
    insp = sa.inspect(post_engine)
    assert "inbound_idempotency" not in insp.get_table_names()
    post_engine.dispose()
    engine.dispose()
