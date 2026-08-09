"""Test-only raw-SQL schema helpers for tables with no ORM model.

Almost every table in the schema has a mapped class under
:data:`alfred.memory.models.Base`, so integration-test fixtures that want a
throwaway schema (rather than replaying the full Alembic chain — see e.g.
``test_orchestrator_bootstrap.py``'s module docstring for why some fixtures
deliberately avoid that) just call ``Base.metadata.create_all``. A handful of
tables are raw-SQL-only by design (no ORM model at all — the production code
never binds them to a mapped class), so ``create_all`` cannot create them.
This module is the narrow escape hatch for exactly those tables, shared so
the DDL has ONE source instead of drifting across per-file copies.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.sql.elements import TextClause

# #410 PR1: ``turn_side_effect_ledger`` (migration 0025) is read/written via
# raw SQL only (:mod:`alfred.memory.turn_side_effects`) — there is no ORM
# model, by design (see that module's docstring: the shape of the class IS
# the transactional contract, with no session-holding constructor seam).
# Mirrors migration 0025's ``upgrade()`` verbatim; kept in sync by
# inspection since both are additive-only and unlikely to drift.
CREATE_TURN_SIDE_EFFECT_LEDGER_SQL: TextClause = text(
    """
    CREATE TABLE turn_side_effect_ledger (
        adapter_id VARCHAR(128) NOT NULL,
        inbound_id VARCHAR(255) NOT NULL,
        user_turn_applied BOOLEAN NOT NULL DEFAULT FALSE,
        assistant_turn_applied BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
        CONSTRAINT pk_turn_side_effect_ledger PRIMARY KEY (adapter_id, inbound_id),
        CONSTRAINT ck_turn_side_effect_ledger_adapter_id_length
            CHECK (char_length(adapter_id) BETWEEN 1 AND 128),
        CONSTRAINT ck_turn_side_effect_ledger_inbound_id_length
            CHECK (char_length(inbound_id) BETWEEN 1 AND 255)
    )
    """
)

__all__ = ["CREATE_TURN_SIDE_EFFECT_LEDGER_SQL"]
