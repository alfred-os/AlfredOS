"""Slice-4 SQLAlchemy 2.0 typed models — column-set assertions.

PR-S4-0b Component E. Every column declared by a Slice-4 migration
(0012-0015) must be exposed as a ``Mapped[<type>]`` field on the
corresponding ORM model so consumers get type-safe access. These tests
fail loud at import-time when the schema drifts from the model OR
vice-versa.

The three models under test are added in this PR (Component E):
- ``OperatorSession``           — mirrors migration 0012
- ``PoliciesSnapshotHistory``    — mirrors migration 0013
- ``SandboxPolicyRegistry``      — mirrors migration 0015

Migration 0014 only extends the ``ck_audit_log_result`` CHECK closed
vocab (no new columns), so no new model is added for it — but the
``AuditEntry.__table_args__`` CHECK constraint string is updated to
include the 4 new Slice-4 ``result`` values so ``metadata.create_all()``
tests (which bypass alembic) stay consistent with the live DB shape.
"""

from __future__ import annotations

from sqlalchemy import inspect

from alfred.memory.models import (
    AuditEntry,
    OperatorSession,
    PoliciesSnapshotHistory,
    SandboxPolicyRegistry,
)


def test_operator_session_columns() -> None:
    """``OperatorSession`` exposes every column from migration 0012."""
    mapper = inspect(OperatorSession)
    assert {c.key for c in mapper.columns} == {
        "user_id",
        "token_hash",
        "issued_at",
        "expires_at",
        "host",
        "machine_id_hash",
        "revoked_at",
    }


def test_operator_session_pk_is_token_hash() -> None:
    """``OperatorSession.token_hash`` is the (single) primary key column.

    PR-S4-5's ``_resolve_operator`` reads via this column; the migration
    pins the index at the PK level. The model must match.
    """
    mapper = inspect(OperatorSession)
    pk_columns = [c.key for c in mapper.primary_key]
    assert pk_columns == ["token_hash"]


def test_operator_session_user_id_is_integer() -> None:
    """``OperatorSession.user_id`` is Integer (matches ``users.id`` autoincrement).

    Round-2 verification: a future widening to UUID-string would break
    the FK declaration in the migration.
    """
    import sqlalchemy as sa

    mapper = inspect(OperatorSession)
    user_id_col = mapper.columns["user_id"]
    assert isinstance(user_id_col.type, sa.Integer)


def test_policies_snapshot_history_columns() -> None:
    """``PoliciesSnapshotHistory`` exposes every column from migration 0013.

    Includes ``applied_by_operator_session_id`` per PR-S4-4 round-2
    closure 4 (forensic-replay link to the operator session that drove
    the swap).
    """
    mapper = inspect(PoliciesSnapshotHistory)
    assert {c.key for c in mapper.columns} == {
        "snapshot_id",
        "loaded_at",
        "file_sha256",
        "policies_json",
        "swapped_from_snapshot_id",
        "applied_by_operator_session_id",
    }


def test_policies_snapshot_history_pk_is_snapshot_id() -> None:
    """``snapshot_id`` is the single PK column."""
    mapper = inspect(PoliciesSnapshotHistory)
    pk_columns = [c.key for c in mapper.primary_key]
    assert pk_columns == ["snapshot_id"]


def test_sandbox_policy_registry_columns() -> None:
    """``SandboxPolicyRegistry`` exposes every column from migration 0015."""
    mapper = inspect(SandboxPolicyRegistry)
    assert {c.key for c in mapper.columns} == {
        "plugin_id",
        "host_os",
        "policy_ref",
        "last_resolved_at",
        "resolution_result",
    }


def test_sandbox_policy_registry_composite_pk() -> None:
    """``(plugin_id, host_os)`` is the composite PK.

    Order matters — the launcher's UPSERT key reads ``plugin_id`` first.
    """
    mapper = inspect(SandboxPolicyRegistry)
    pk_columns = [c.key for c in mapper.primary_key]
    assert pk_columns == ["plugin_id", "host_os"]


def test_audit_entry_result_check_includes_slice_4_values() -> None:
    """``AuditEntry.__table_args__`` CHECK now includes Slice-4 vocab.

    The DB-layer CHECK is extended by migration 0014. The ORM-side
    string in ``__table_args__`` is consumed by
    ``metadata.create_all()`` (bypassing alembic) — keep them aligned
    or tests that build schemas via metadata see the pre-Slice-4
    vocab and refuse Slice-4 inserts at the WRONG layer.
    """
    table_args = AuditEntry.__table_args__
    # The CheckConstraint is the second tuple element (the first is the
    # trust_tier_of_trigger CHECK). Find it by name.
    check_constraints = [
        c for c in table_args if hasattr(c, "name") and c.name == "ck_audit_log_result"
    ]
    assert len(check_constraints) == 1
    sqltext = str(check_constraints[0].sqltext)
    for slice_4_value in (
        "dispatched_with_redactions",
        "dispatched_clean",
        "recursion_refused",
        "audit_row_emitted",
    ):
        assert slice_4_value in sqltext, (
            f"missing Slice-4 result value {slice_4_value!r} from CHECK"
        )


# ---------------------------------------------------------------------------
# Round-2 review closures (memory + test + architect + cross-cutting MED
# convergence): assert that each model's ``__table_args__`` mirrors the
# migration's CHECK constraints, indexes, and named PK so
# ``Base.metadata.create_all()`` consumers get the same DB-layer refusal
# surface as the alembic-applied schema.
# ---------------------------------------------------------------------------


def _check_constraint_names(model_cls: type) -> set[str]:
    """Return the set of ``CheckConstraint`` names declared by the model."""
    import sqlalchemy as sa

    return {
        c.name
        for c in model_cls.__table_args__
        if isinstance(c, sa.CheckConstraint) and c.name is not None
    }


def _index_names(model_cls: type) -> set[str]:
    """Return the set of ``Index`` names declared by the model."""
    import sqlalchemy as sa

    return {
        c.name for c in model_cls.__table_args__ if isinstance(c, sa.Index) and c.name is not None
    }


def _pk_constraint_name(model_cls: type) -> str | None:
    """Return the named PK constraint, or None if unnamed."""
    import sqlalchemy as sa

    for c in model_cls.__table_args__:
        if isinstance(c, sa.PrimaryKeyConstraint):
            return c.name
    return None


def test_operator_session_check_constraints_postgres_only_in_migration() -> None:
    """All 6 CHECK constraints from migration 0012 are Postgres-specific
    (regex ``~``, ``char_length``, ``INTERVAL``) so they live in the alembic
    migration only — SQLite-backed unit tests cannot enforce them.
    The model carries no CHECK constraints (production DB has them via
    alembic; tests that need full enforcement use testcontainers Postgres).
    """
    assert _check_constraint_names(OperatorSession) == set()


def test_operator_session_indexes_mirror_migration() -> None:
    """``ix_operator_sessions_user_id_expires_at`` declared on the model."""
    assert _index_names(OperatorSession) == {"ix_operator_sessions_user_id_expires_at"}


def test_operator_session_pk_constraint_named() -> None:
    """PK constraint name matches the migration's named PK."""
    assert _pk_constraint_name(OperatorSession) == "uq_operator_sessions_token_hash"


def test_policies_snapshot_history_check_constraints_postgres_only_in_migration() -> None:
    """All 4 CHECK constraints from migration 0013 are Postgres-specific
    (regex ``~``, ``octet_length``) so they live in the alembic migration
    only. The model carries no CHECK constraints (production DB has them
    via alembic)."""
    assert _check_constraint_names(PoliciesSnapshotHistory) == set()


def test_policies_snapshot_history_indexes_mirror_migration() -> None:
    """``ix_policies_snapshot_history_loaded_at`` declared on the model."""
    assert _index_names(PoliciesSnapshotHistory) == {"ix_policies_snapshot_history_loaded_at"}


def test_policies_snapshot_history_pk_constraint_named() -> None:
    """PK constraint name matches the migration's named PK."""
    assert (
        _pk_constraint_name(PoliciesSnapshotHistory) == "uq_policies_snapshot_history_snapshot_id"
    )


def test_sandbox_policy_registry_check_constraints_mirror_migration() -> None:
    """SQLite-compatible CHECK constraints from migration 0015 are mirrored
    on the model. ``ck_..._plugin_id_format`` uses the Postgres ``~`` regex
    operator so it lives in the alembic migration only; the other 3 use
    portable ``IN`` / ``NOT LIKE`` and are present on the model."""
    assert _check_constraint_names(SandboxPolicyRegistry) == {
        "ck_sandbox_policy_registry_host_os",
        "ck_sandbox_policy_registry_resolution_result",
        "ck_sandbox_policy_registry_policy_ref_relative",
    }


def test_sandbox_policy_registry_pk_constraint_named() -> None:
    """Composite PK name matches the migration's named PK."""
    assert _pk_constraint_name(SandboxPolicyRegistry) == "uq_sandbox_policy_registry_plugin_host_os"
