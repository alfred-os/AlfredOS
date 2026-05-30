"""SQLAlchemy 2.0 ORM models for Slice 1.

Two tables for the first slice: episodes (raw conversation turns) and audit_log
(every action Alfred takes). More tables land per future slices.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy import JSON, CheckConstraint, DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all AlfredOS ORM models."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class Episode(Base):
    """A single conversation turn (user input or Alfred response)."""

    __tablename__ = "episodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # NOTE: no `index=True` on user_id — the (user_id, created_at DESC) composite
    # below covers `WHERE user_id = ?` as a leftmost-column scan, so a standalone
    # index would be a redundant maintenance cost on writes. Migration 0002
    # drops the historical `ix_episodes_user_id` accordingly.
    user_id: Mapped[str] = mapped_column(String(64))
    persona: Mapped[str] = mapped_column(String(64), default="alfred")
    # Slice-2 per-row attribution (migration 0004). Nullable to keep pre-Slice-2
    # rows valid; new writes set it to the active persona's id (``"alfred"`` in
    # Slice 1+2). Distinct from ``persona`` so the existing downstream readers
    # of that column keep working untouched.
    persona_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str] = mapped_column(String(16))  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text)
    trust_tier: Mapped[str] = mapped_column(String(4))  # T0..T3
    # CLAUDE.md i18n rule #3: every stored user-content row carries a BCP-47 language tag.
    language: Mapped[str] = mapped_column(String(16), default="en-US")
    tokens_in: Mapped[int] = mapped_column(default=0)
    tokens_out: Mapped[int] = mapped_column(default=0)
    cost_usd: Mapped[float] = mapped_column(default=0.0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    __table_args__ = (
        # PRD §7.1: trust_tier is a closed domain {T0,T1,T2,T3}. Enforce it at
        # the DB so a buggy writer (or future hand-edit) can't sneak an
        # invalid tier past the type layer and have downstream code trust it.
        CheckConstraint(
            "trust_tier IN ('T0', 'T1', 'T2', 'T3')",
            name="ck_episodes_trust_tier",
        ),
        # role is the other closed domain on this table — kept consistent so
        # the assistant-only / user-only branches downstream can rely on it.
        CheckConstraint(
            "role IN ('user', 'assistant')",
            name="ck_episodes_role",
        ),
        # Hot path: orchestrator loads `last N turns by user ORDER BY created_at
        # DESC LIMIT N` on startup (see EpisodicMemory.recent). The DESC ordering
        # on the second column lets Postgres serve the query as a forward scan
        # of the index; an ASC composite would force a backward scan. Migration
        # 0002 brings live databases in line with this definition.
        Index("ix_episodes_user_id_created_at", "user_id", sa.text("created_at DESC")),
    )


class AuditEntry(Base):
    """An append-only record of an action AlfredOS took."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    event: Mapped[str] = mapped_column(String(64))  # e.g. "provider.call", "memory.write"
    actor_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_persona: Mapped[str] = mapped_column(String(64), default="alfred")
    # Slice-2 per-row attribution (migration 0004). Nullable; new writes set
    # it to the active persona's id (``"alfred"`` for Slice 1+2). Kept
    # distinct from ``actor_persona`` so existing downstream readers of that
    # column stay untouched.
    persona_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    trust_tier_of_trigger: Mapped[str] = mapped_column(String(4))
    result: Mapped[str] = mapped_column(String(32))
    # Truthful cost accounting: estimate is what budget pre-check looked at;
    # actual is the post-call charge (None until reconciled).
    cost_estimate_usd: Mapped[float] = mapped_column(default=0.0)
    cost_actual_usd: Mapped[float | None] = mapped_column(nullable=True)
    # CLAUDE.md i18n rule #3: every stored user-content row carries a BCP-47 language tag.
    language: Mapped[str] = mapped_column(String(16), default="en-US")

    __table_args__ = (
        # PRD §7.1: same closed-domain enforcement as `episodes.trust_tier`.
        CheckConstraint(
            "trust_tier_of_trigger IN ('T0', 'T1', 'T2', 'T3')",
            name="ck_audit_log_trust_tier_of_trigger",
        ),
        # `result` is the audit subsystem's closed domain. The orchestrator
        # writes one of these values per turn (see Orchestrator._handle_turn),
        # the Slice-2 comms adapters write the refusal / rate-limited /
        # outbound-failure family (migration 0005), and Slice-2.5 PR-B's
        # :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink` writes
        # ``"fault"`` / ``"bypass"`` for the §0 hook-trace result-disposition
        # table (migration 0006). Keeping it pinned at the DB layer means a
        # typo in a future writer (or a manual row insert) fails fast
        # against the CHECK instead of polluting downstream analytics that
        # depend on a fixed enum. Source of truth: every value here MUST
        # also be in the upgrade path of the latest migration; CI's
        # migration-roundtrip test catches drift.
        CheckConstraint(
            "result IN ('success', 'budget_blocked', 'budget_overrun', "
            "'provider_failed', 'cancelled', "
            # Slice-2 (migration 0005) — comms-adapter outcomes.
            "'refused', 'refused_unknown_user', 'rate_limited', "
            "'dlp_failed', 'split_failed', 'send_failed', "
            "'recovery_send_failed', 'login_failed', 'gateway_unhealthy', "
            "'unknown_budget_user', "
            # Slice-2.5 (migration 0006) — hook-trace dispositions written
            # by :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink`.
            "'fault', 'bypass')",
            name="ck_audit_log_result",
        ),
    )
