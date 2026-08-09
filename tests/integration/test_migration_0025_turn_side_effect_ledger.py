"""Migration 0025 upgrade/downgrade round-trip: turn_side_effect_ledger."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.integration


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> AlembicConfig:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = AlembicConfig("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def test_upgrade_creates_table_with_expected_columns(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        columns = {c["name"] for c in inspector.get_columns("turn_side_effect_ledger")}
        assert columns == {
            "adapter_id",
            "inbound_id",
            "user_turn_applied",
            "assistant_turn_applied",
            "created_at",
        }
        pk = inspector.get_pk_constraint("turn_side_effect_ledger")
        assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id"}
    finally:
        engine.dispose()


def test_columns_default_false(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO turn_side_effect_ledger "
                    "(adapter_id, inbound_id, user_turn_applied) "
                    "VALUES ('discord', 'probe-1', TRUE)"
                )
            )
            row = conn.execute(
                text(
                    "SELECT assistant_turn_applied FROM turn_side_effect_ledger "
                    "WHERE adapter_id = 'discord' AND inbound_id = 'probe-1'"
                )
            ).one()
            assert row.assistant_turn_applied is False
    finally:
        engine.dispose()


def test_composite_key_namespaces_are_isolated(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
            conn.execute(
                text(
                    "INSERT INTO turn_side_effect_ledger "
                    "(adapter_id, inbound_id, user_turn_applied) "
                    "VALUES ('discord', 'shared-id', TRUE), ('tui', 'shared-id', FALSE)"
                )
            )
            rows = conn.execute(
                text(
                    "SELECT adapter_id, user_turn_applied FROM turn_side_effect_ledger "
                    "WHERE inbound_id = 'shared-id' ORDER BY adapter_id"
                )
            ).all()
            assert [(r.adapter_id, r.user_turn_applied) for r in rows] == [
                ("discord", True),
                ("tui", False),
            ]
    finally:
        engine.dispose()


def test_downgrade_drops_table(alembic_cfg: AlembicConfig, postgres_url: str) -> None:
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    command.upgrade(alembic_cfg, "head")
    command.downgrade(alembic_cfg, "-1")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        assert "turn_side_effect_ledger" not in inspector.get_table_names()
    finally:
        engine.dispose()


def test_length_checks_reject_empty_identifiers(
    alembic_cfg: AlembicConfig, postgres_url: str
) -> None:
    # The ORM twin (TurnSideEffectLedgerRow) deliberately omits these two
    # CHECK constraints — SQLite can't parse char_length() — so the migration
    # is their ONLY definition, and no other test asserts them. Pin both the
    # constraint names and the reject-empty-string behavior directly.
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        names = {
            c["name"] for c in inspect(engine).get_check_constraints("turn_side_effect_ledger")
        }
        assert {
            "ck_turn_side_effect_ledger_adapter_id_length",
            "ck_turn_side_effect_ledger_inbound_id_length",
        } <= names
        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO turn_side_effect_ledger (adapter_id, inbound_id) "
                    "VALUES ('', 'probe-2')"
                )
            )
    finally:
        engine.dispose()
