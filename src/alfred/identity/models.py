"""AlfredOS identity ORMs (User + PlatformIdentity).

Closed-domain enums for ``authorization`` and ``platform`` ride alongside the
ORMs (rather than living in a separate module) so call sites import a single
symbol per concept.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from alfred.memory.models import Base


class Authorization(StrEnum):
    """Per-user authorization tier.

    Snake_case on the wire (DB column TEXT CHECK + Pydantic value); kebab-case
    on the CLI surface (the Typer custom type normalises). The enum stays in
    the schema permanently — dropping/re-adding across a Postgres CHECK is a
    destructive migration that breaks rollback symmetry (spec §2 line 223).
    """

    READ_ONLY = "read_only"
    STANDARD = "standard"
    TRUSTED = "trusted"
    OPERATOR = "operator"


class Platform(StrEnum):
    """Platform that owns the ``platform_id`` half of an identity binding.

    Slice 2 ships TUI + Discord; Telegram lands in Slice 4 by extending this
    enum (additive CHECK-constraint migration, no destructive rewrite).
    """

    TUI = "tui"
    DISCORD = "discord"


class User(Base):
    """A human (or bot) AlfredOS knows about.

    Soft-deletable via ``deleted_at`` so audit-log foreign keys (PR B in
    Slice 2) survive a user's removal — purging the row outright would
    break referential integrity on history that the operator still wants
    to read.
    """

    __tablename__ = "users"

    __table_args__ = (
        # The DB owns the enum domain — spec §2 line 223 forbids dropping /
        # re-adding the enum across rollback boundaries, so this CHECK is
        # the permanent gate rather than a Postgres ENUM type. New tiers
        # land via additive CHECK migrations.
        # ``authorization`` is a Postgres reserved keyword (per the SQL
        # standard: GRANT…AUTHORIZATION). Bare in a CHECK expression PG
        # parses it as the keyword and rejects the constraint; quote it so
        # the column reference survives DDL emission unambiguously.
        CheckConstraint(
            "\"authorization\" IN ('read_only', 'standard', 'trusted', 'operator')",
            name="ck_users_authorization",
        ),
        # Daily budget is a per-user spend cap consumed by BudgetGuard (PR
        # B). Zero or negative would silently disable the guard, so the DB
        # rejects it loudly. A user who shouldn't spend gets authorization
        # ``read_only`` instead.
        CheckConstraint(
            "daily_budget_usd > 0",
            name="ck_users_daily_budget_usd_positive",
        ),
        # Rate limits are optional overrides (NULL = inherit defaults). When
        # set, zero is a legitimate "deny everything for now" value — only
        # negative is nonsensical.
        CheckConstraint(
            "rate_limit_per_min IS NULL OR rate_limit_per_min >= 0",
            name="ck_users_rate_limit_per_min_nonneg",
        ),
        CheckConstraint(
            "rate_limit_per_day IS NULL OR rate_limit_per_day >= 0",
            name="ck_users_rate_limit_per_day_nonneg",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    authorization: Mapped[str] = mapped_column(String, nullable=False)
    daily_budget_usd: Mapped[float] = mapped_column(Float, nullable=False)
    # CLAUDE.md i18n rule #3: every stored user-content row carries a BCP-47
    # language tag — including the user row itself so personas can be
    # localised at the orchestrator boundary without a separate lookup.
    language: Mapped[str] = mapped_column(String, nullable=False)
    rate_limit_per_min: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_per_day: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ``Sequence[...]`` keeps the public reading surface read-only at the
    # type layer (callers iterate, they don't mutate), while
    # ``collection_class=list`` gives SQLAlchemy a concrete instantiable
    # container at the ORM layer. The two facets serve different audiences.
    identities: Mapped[Sequence[PlatformIdentity]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        collection_class=list,
    )


class PlatformIdentity(Base):
    """Binding from a platform-native id (Discord snowflake, TUI handle) to a User.

    A user can hold one active binding per platform plus any number of
    soft-deleted historical ones — the partial-unique index enforces that
    invariant without losing history.
    """

    __tablename__ = "platform_identities"

    __table_args__ = (
        # Global uniqueness — the same Discord snowflake can't point at two
        # different users at once. (A re-binding migrates the row rather
        # than inserting a fresh one.)
        UniqueConstraint(
            "platform",
            "platform_id",
            name="uq_platform_identity_platform_platform_id",
        ),
        # Per-user uniqueness, but only among *live* bindings — soft-deleted
        # rows stay around so audit history can join on them. ``text(...)``
        # rather than a ``mapped_column().is_(None)`` predicate so SQLAlchemy
        # emits the WHERE clause verbatim at DDL time (the column-expression
        # form fails import-side resolution under DeclarativeBase).
        Index(
            "uq_platform_identities_user_id_platform_active",
            "user_id",
            "platform",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        # Same closed-domain pattern as ``users.authorization``: the DB owns
        # the enum; new platforms (Telegram in Slice 4) land via additive
        # CHECK migrations.
        CheckConstraint(
            "platform IN ('tui', 'discord')",
            name="ck_platform_identities_platform",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    platform: Mapped[str] = mapped_column(String, nullable=False)
    platform_id: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="identities")
