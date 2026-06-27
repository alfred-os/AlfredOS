"""0023 egress_idempotency migration — forward creates the tri-state ledger, backward drops it.

Mirrors test_migration_0018_inbound_idempotency. The egress ledger is the
side-effecting-egress dedup store (Spec C §5, G7-2a): one row per logical egress
call, tri-state (committed_no_response -> committed_with_response), with a
post-extraction T2 ``response`` column (never raw T3) and a BCP-47 ``language``
tag. The two CHECK constraints pin the closed state vocabulary and the
state<->response invariant; the retention index backs the TTL sweep.
"""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from alembic import command, config

pytestmark = pytest.mark.integration

_EXPECTED_COLUMNS = {
    "egress_id",
    "adapter_id",
    "inbound_id",
    "session_id",
    "call_index",
    "body_hash",
    "state",
    "response",
    "language",
    "committed_at",
}


def _alembic_cfg(url: str) -> config.Config:
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_0023_upgrade_creates_ledger_then_downgrade_drops_it(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = _alembic_cfg(postgres_url)

    command.upgrade(cfg, "0023")
    engine = sa.create_engine(postgres_url.replace("+asyncpg", "+psycopg2"))
    insp = sa.inspect(engine)

    cols = {c["name"] for c in insp.get_columns("egress_idempotency")}
    assert cols == _EXPECTED_COLUMNS

    pk = insp.get_pk_constraint("egress_idempotency")
    # The egress-id (a sha256 hexdigest) is the sole, durable dedup key.
    assert set(pk["constrained_columns"]) == {"egress_id"}

    check_names = {ck["name"] for ck in insp.get_check_constraints("egress_idempotency")}
    assert "ck_egress_idempotency_state" in check_names
    assert "ck_egress_idempotency_response_matches_state" in check_names

    index_names = {ix["name"] for ix in insp.get_indexes("egress_idempotency")}
    assert "ix_egress_idempotency_committed_at" in index_names

    command.downgrade(cfg, "0022")
    post_engine = sa.create_engine(postgres_url.replace("+asyncpg", "+psycopg2"))
    insp = sa.inspect(post_engine)
    assert "egress_idempotency" not in insp.get_table_names()
    post_engine.dispose()
    engine.dispose()
