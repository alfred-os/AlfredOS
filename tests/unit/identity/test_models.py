"""Shape tests for ``User`` + ``PlatformIdentity`` ORMs.

These tests pin the column set / nullability / closed-domain enum values
exposed by ``alfred.identity.models`` against the Slice 2 spec §4 (lines
606-619). The migration that translates this shape to live DDL lands in
Task 7; the integration test against a real Postgres instance lands in
Task 13. This file owns the import-time contract only.
"""

from __future__ import annotations

from sqlalchemy import Table

from alfred.identity.models import (
    Authorization,
    Platform,
    PlatformIdentity,
    User,
)

# ``DeclarativeBase.__table__`` is typed as ``FromClause`` by SQLAlchemy's
# stubs even though the runtime value is always a ``Table`` for mapped
# classes. The narrowed aliases below let mypy see ``.constraints`` and
# ``.indexes`` without an explicit ``# type: ignore`` at every access.
_USER_TABLE: Table = User.__table__  # type: ignore[assignment]  # reason: see comment above
_PLATFORM_IDENTITY_TABLE: Table = PlatformIdentity.__table__  # type: ignore[assignment]  # reason: see comment above


def test_user_column_contract() -> None:
    """``User`` exposes the column set + nullability the spec mandates."""

    columns = {col.name: col for col in _USER_TABLE.columns}
    expected_names = {
        "id",
        "slug",
        "display_name",
        "authorization",
        "daily_budget_usd",
        "language",
        "rate_limit_per_min",
        "rate_limit_per_day",
        "created_at",
        "deleted_at",
    }
    assert set(columns) == expected_names

    # Primary key + uniqueness — slug is the human-typed handle the resolver
    # joins on, so the column-level UNIQUE is part of the contract (not just
    # a CHECK).
    assert columns["id"].primary_key is True
    assert columns["slug"].unique is True
    assert columns["slug"].nullable is False

    # NOT NULL columns the spec pins as required.
    for required in (
        "display_name",
        "authorization",
        "daily_budget_usd",
        "language",
        "created_at",
    ):
        assert columns[required].nullable is False, f"{required} must be NOT NULL"

    # Nullable columns — rate-limit overrides are optional per-user.
    for nullable in ("rate_limit_per_min", "rate_limit_per_day", "deleted_at"):
        assert columns[nullable].nullable is True, f"{nullable} must be NULL-able"

    # CHECK constraints — at least the four named in the spec must exist.
    # We don't pin the SQL text (Alembic owns DDL); we pin the count + names.
    check_names = {
        c.name for c in _USER_TABLE.constraints if c.__class__.__name__ == "CheckConstraint"
    }
    expected_checks = {
        "ck_users_authorization",
        "ck_users_daily_budget_usd_positive",
        "ck_users_rate_limit_per_min_nonneg",
        "ck_users_rate_limit_per_day_nonneg",
    }
    assert expected_checks <= check_names, (
        f"missing CHECK constraints: {expected_checks - check_names}"
    )


def test_platform_identity_column_contract() -> None:
    """``PlatformIdentity`` exposes the column set + table-level constraints."""

    columns = {col.name: col for col in _PLATFORM_IDENTITY_TABLE.columns}
    expected_names = {
        "id",
        "user_id",
        "platform",
        "platform_id",
        "created_at",
        "deleted_at",
    }
    assert set(columns) == expected_names

    assert columns["id"].primary_key is True
    assert columns["user_id"].nullable is False
    assert columns["platform"].nullable is False
    assert columns["platform_id"].nullable is False
    assert columns["created_at"].nullable is False
    assert columns["deleted_at"].nullable is True

    # FK on user_id must cascade — orphaned identities are nonsense and the
    # spec pins ON DELETE CASCADE explicitly.
    fks = list(columns["user_id"].foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "users"
    assert fks[0].ondelete == "CASCADE"

    # Table args must carry the (platform, platform_id) UniqueConstraint, the
    # partial-unique index on (user_id, platform) WHERE deleted_at IS NULL,
    # and the CHECK on platform values. We assert non-emptiness + the spec
    # constraints by name rather than re-asserting SQL text.
    assert PlatformIdentity.__table_args__, "table args must include constraints + indices"

    constraint_names = {c.name for c in _PLATFORM_IDENTITY_TABLE.constraints if c.name is not None}
    assert "uq_platform_identity_platform_platform_id" in constraint_names
    assert "ck_platform_identities_platform" in constraint_names

    index_names = {idx.name for idx in _PLATFORM_IDENTITY_TABLE.indexes}
    assert "uq_platform_identities_user_id_platform_active" in index_names


def test_enum_values() -> None:
    """Closed-domain enums match the spec's wire values."""

    assert {a.value for a in Authorization} == {
        "read_only",
        "standard",
        "trusted",
        "operator",
    }
    assert {p.value for p in Platform} == {"tui", "discord"}
