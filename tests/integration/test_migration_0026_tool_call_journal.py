"""Migration 0026 upgrade/downgrade round-trip: tool_call_journal."""

from __future__ import annotations

import pytest
from alembic import command, config
from sqlalchemy import create_engine, inspect, text

pytestmark = pytest.mark.integration


_ADAPTER = "discord"


def test_upgrade_creates_table_with_expected_columns(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        columns = {c["name"] for c in inspector.get_columns("tool_call_journal")}
        assert columns == {
            "adapter_id",
            "inbound_id",
            "call_index",
            "iteration",
            "tool_call_id",
            "tool_name",
            "tool_arguments_json",
            "created_at",
        }
        pk = inspector.get_pk_constraint("tool_call_journal")
        assert set(pk["constrained_columns"]) == {"adapter_id", "inbound_id", "call_index"}
    finally:
        engine.dispose()


def test_ordering_by_call_index_within_one_inbound_id(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES ('discord', 'm1', 1, 0, 'tc-2', 'web.fetch', '{}'), "
                    "('discord', 'm1', 0, 0, 'tc-1', 'clock.now', '{}')"
                )
            )
            rows = conn.execute(
                text(
                    "SELECT call_index FROM tool_call_journal "
                    "WHERE adapter_id = 'discord' AND inbound_id = 'm1' ORDER BY call_index ASC"
                )
            ).all()
            assert [r.call_index for r in rows] == [0, 1]
    finally:
        engine.dispose()


def test_composite_key_namespaces_are_isolated(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            # Two DIFFERENT adapters, SAME inbound_id + call_index — must NOT collide.
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES ('discord', 'shared-id', 0, 0, 'tc-discord', 'clock.now', '{}'), "
                    "('tui', 'shared-id', 0, 0, 'tc-tui', 'clock.now', '{}')"
                )
            )
            rows = conn.execute(
                text(
                    "SELECT adapter_id, tool_call_id FROM tool_call_journal "
                    "WHERE inbound_id = 'shared-id' ORDER BY adapter_id"
                )
            ).all()
            assert [(r.adapter_id, r.tool_call_id) for r in rows] == [
                ("discord", "tc-discord"),
                ("tui", "tc-tui"),
            ]
    finally:
        engine.dispose()


def test_oversized_tool_arguments_json_is_rejected(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        oversized = '{"padding": "' + ("x" * 300_000) + '"}'
        with (
            pytest.raises(Exception, match="ck_tool_call_journal_tool_arguments_json_length"),
            engine.begin() as conn,
        ):
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES (:adapter_id, 'm-oversized', 0, 0, 'tc-1', 'web.fetch', :payload)"
                ),
                {"adapter_id": _ADAPTER, "payload": oversized},
            )
    finally:
        engine.dispose()


def test_empty_adapter_id_is_rejected(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # review-pr fleet, 2026-08-10: of the 5 named CHECK constraints, only the
    # size cap above was pinned. The ORM twin (ToolCallJournalRow) omits
    # these length CHECKs — SQLite can't parse char_length() — so this
    # migration is their ONLY definition, mirroring migration 0025's
    # equivalent pin (test_length_checks_reject_empty_identifiers).
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with (
            pytest.raises(Exception, match="ck_tool_call_journal_adapter_id_length"),
            engine.begin() as conn,
        ):
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES ('', 'm-empty-adapter', 0, 0, 'tc-1', 'clock.now', '{}')"
                )
            )
    finally:
        engine.dispose()


def test_empty_inbound_id_is_rejected(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with (
            pytest.raises(Exception, match="ck_tool_call_journal_inbound_id_length"),
            engine.begin() as conn,
        ):
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES (:adapter_id, '', 0, 0, 'tc-1', 'clock.now', '{}')"
                ),
                {"adapter_id": _ADAPTER},
            )
    finally:
        engine.dispose()


def test_negative_call_index_is_rejected(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with (
            pytest.raises(Exception, match="ck_tool_call_journal_call_index_non_negative"),
            engine.begin() as conn,
        ):
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES (:adapter_id, 'm-negative-call-index', -1, 0, 'tc-1', "
                    "'clock.now', '{}')"
                ),
                {"adapter_id": _ADAPTER},
            )
    finally:
        engine.dispose()


def test_negative_iteration_is_rejected(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sync_url, future=True)
    try:
        with (
            pytest.raises(Exception, match="ck_tool_call_journal_iteration_non_negative"),
            engine.begin() as conn,
        ):
            conn.execute(
                text(
                    "INSERT INTO tool_call_journal "
                    "(adapter_id, inbound_id, call_index, iteration, tool_call_id, "
                    "tool_name, tool_arguments_json) "
                    "VALUES (:adapter_id, 'm-negative-iteration', 0, -1, 'tc-1', "
                    "'clock.now', '{}')"
                ),
                {"adapter_id": _ADAPTER},
            )
    finally:
        engine.dispose()


def test_downgrade_drops_table(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "-1")

    engine = create_engine(sync_url, future=True)
    try:
        inspector = inspect(engine)
        assert "tool_call_journal" not in inspector.get_table_names()
    finally:
        engine.dispose()
