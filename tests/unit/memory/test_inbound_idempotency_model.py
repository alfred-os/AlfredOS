"""The InboundIdempotency ORM model mirrors migration 0018 for SQLite unit tests."""

from __future__ import annotations

from alfred.memory.models import Base, InboundIdempotency


def test_model_maps_inbound_idempotency_table() -> None:
    table = InboundIdempotency.__table__
    assert table.name == "inbound_idempotency"
    assert {c.name for c in table.columns} == {"inbound_id", "adapter_id", "committed_at"}
    # Composite (adapter_id, inbound_id) PK — order-independent membership check.
    assert {c.name for c in table.primary_key.columns} == {"adapter_id", "inbound_id"}
    # No user text => no language column (i18n hard-rule #3 satisfied by construction).
    assert "language" not in table.columns


def test_model_is_registered_on_base_metadata() -> None:
    assert "inbound_idempotency" in Base.metadata.tables
