"""SQLAlchemy 2.0 ORM models for Slice 1.

Two tables for the first slice: episodes (raw conversation turns) and audit_log
(every action Alfred takes). More tables land per future slices.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, reconstructor


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
            "'fault', 'bypass', "
            # Slice-3 (migration 0007) — quarantined-LLM / plugin-lifecycle /
            # plugin-grant / supervisor-breaker / content-handle dispositions
            # (spec §13). Order matches the migration's _SLICE_3_ADDITIONS.
            "'extracted', 'malformed_exhausted', 'load_refused', 'crashed', "
            "'quarantined', 'reloaded', 'requested', 'approved', 'denied', "
            "'revoked', 'tripped', 'reset', 'content_expired')",
            name="ck_audit_log_result",
        ),
    )


class PluginGrant(Base):
    """Postgres projection of a state.git capability grant (spec §8.1).

    ``RealGate`` (PR-S3-2) reads this table for millisecond-latency hot-path
    capability checks. Built from state.git when its commit hash drifts from
    :class:`CapabilityGateSync` (migration 0009). See migration 0008.

    Two grant axes per spec §4.3 — kept distinct in the schema so a future
    "subscriber tier T3" footgun is structurally impossible:

    * ``subscriber_tier`` (``'system' | 'operator' | 'user-plugin'``) — which
      hook-subscriber tier the plugin is permitted to serve.
    * ``content_tier`` (``'T0' | 'T1' | 'T2' | 'T3' | None``) — which content
      trust tier the plugin may handle. ``None`` means no content-tier
      restriction.

    The UNIQUE on ``(plugin_id, hookpoint, subscriber_tier)`` matches the
    PR-S3-2 ``PostgresBackend.upsert_grant`` ``ON CONFLICT`` target (mem-003);
    the round-trip test pins it so a future refactor cannot quietly drop the
    constraint.
    """

    __tablename__ = "plugin_grants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    plugin_id: Mapped[str] = mapped_column(String(128))
    # spec §4.3 naming rule: hook-subscription axis, NOT a content trust tier.
    subscriber_tier: Mapped[str] = mapped_column(String(32))
    hookpoint: Mapped[str] = mapped_column(String(128))
    # NULL = no content-tier restriction. When set, must be T0/T1/T2/T3.
    content_tier: Mapped[str | None] = mapped_column(String(8), nullable=True)
    operator_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    proposal_branch: Mapped[str | None] = mapped_column(String(256), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64))
    # Closed domain — same values as the plugin.grant.* audit family.
    state: Mapped[str] = mapped_column(String(32))
    state_git_commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "state IN ('requested', 'approved', 'denied', 'revoked')",
            name="ck_plugin_grants_state",
        ),
        CheckConstraint(
            "subscriber_tier IN ('system', 'operator', 'user-plugin')",
            name="ck_plugin_grants_subscriber_tier",
        ),
        CheckConstraint(
            "content_tier IS NULL OR content_tier IN ('T0', 'T1', 'T2', 'T3')",
            name="ck_plugin_grants_content_tier",
        ),
        # mem-003: matches PR-S3-2 PostgresBackend.upsert_grant ON CONFLICT target.
        UniqueConstraint(
            "plugin_id",
            "hookpoint",
            "subscriber_tier",
            name="uq_plugin_grants_plugin_hook_tier",
        ),
        Index("ix_plugin_grants_plugin_id_state", "plugin_id", "state"),
        Index("ix_plugin_grants_hookpoint", "hookpoint"),
    )


class CapabilityGateSync(Base):
    """Commit-hash cache for ``RealGate`` (spec §8.1).

    Singleton row with ``id = 1`` enforced by a CHECK constraint. Upserted
    by ``RealGate`` on each successful state.git sync. On AlfredOS startup
    ``RealGate`` reads ``commit_hash`` and compares against the current
    state.git HEAD — mismatch → rebuild :class:`PluginGrant` from state.git.
    See migration 0009.

    mem-002: column is ``commit_hash`` (NOT ``state_git_commit_hash``) so
    PR-S3-2 ``PostgresBackend`` SQL matches exactly.

    mem-004: ``id`` is INTEGER with ``CHECK (id = 1)``, not UUID. A UUID PK
    with ``default=uuid4`` would create a new row on every INSERT that
    omits ``id``, making the staleness check non-deterministic. The
    singleton sentinel guarantees one row always.
    """

    __tablename__ = "capability_gate_sync"

    # Singleton sentinel: id is always 1. autoincrement=False so Postgres
    # does not silently swap in a SERIAL/IDENTITY column that would defeat
    # the CHECK contract.
    id: Mapped[int] = mapped_column(
        Integer(),
        primary_key=True,
        autoincrement=False,
        default=1,
    )
    # NULL before first sync (before `alfred plugin grant init` runs).
    # spec §15.4 step 2 seeds this with the empty-tree hash on init.
    commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # mem-005: server_default=NOW() so raw-SQL writers (Alembic data ops,
    # psql, integration fixtures that omit the column) get a DB-supplied
    # timestamp. The Python-side default=_now stays for ORM-shaped INSERTs
    # so the resulting instance has the value populated without a refresh.
    synced_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=_now,
        server_default=sa.func.now(),
        nullable=False,
    )

    __table_args__ = (CheckConstraint("id = 1", name="ck_capability_gate_sync_singleton"),)


class CircuitBreakerState(Base):
    """Persisted state for a named circuit breaker (spec §10.6).

    One row per supervised component_id (e.g. ``"quarantined-llm"``,
    ``"web-fetch"``). On process restart, the supervisor loads each row and
    stays OPEN if ``last_trip_at < 1h`` ago — this is the flap protection
    on rolling restarts (spec §10.6).

    Audit-row mirroring
    -------------------

    Two columns mirror fields from
    :data:`alfred.audit.audit_row_schemas.SUPERVISOR_BREAKER_TRIPPED_FIELDS`:

    * ``breaker_state`` — always ``"OPEN"`` at trip time in the audit row;
      persisted here so the supervisor can reconstruct the last-trip
      event on restart without re-reading the audit log.
    * ``correlation_id`` — the trip event's correlation id. Lets operators
      pivot from a breaker row to the audit-log entry that opened it.

    Both are last-trip metadata: when the breaker resets (operator-initiated
    or HALF_OPEN probe success), they are NOT cleared — they retain the
    most-recent-trip values for forensic purposes. ``state`` is the live
    state; ``breaker_state`` is the captured-at-trip state.

    PII / T3 safety (spec §5.6)
    ---------------------------

    ``last_failure_type`` is the Python exception class name (e.g.
    ``"SubprocessExitedError"``). It MUST NOT be ``str(exc)`` because the
    exception message may contain T3 fragments from the plugin subprocess.
    The supervisor's failure-recording path enforces this; the column type
    is fixed at 128 characters so a stray ``str(exc)`` would truncate
    rather than overflow.

    Concurrency
    -----------

    ``_save_lock`` is a per-instance ``asyncio.Lock`` used by
    :meth:`CircuitBreaker.save_to_db` (Task 8) to serialise concurrent
    writes for the same row and prevent lost-update races. Per-instance,
    NOT class-level, so unrelated breakers do not block each other. PR-S3-3a
    R3 fix. Initialised in both ``__init__`` (Python-side construction
    path) and the SQLAlchemy ``@reconstructor`` (ORM-load path) so every
    materialised instance has a fresh lock.

    Downgrade semantics (migration 0010): DROP TABLE. Breaker state is
    transient — the next run re-discovers failures organically. Operators
    who need the trip history snapshot the table BEFORE downgrading.
    """

    __tablename__ = "circuit_breakers"

    component_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    state: Mapped[str] = mapped_column(String(16), default="CLOSED", server_default="CLOSED")
    # CLOSED | OPEN | HALF_OPEN — DB-side CHECK constraint pins the closed domain.
    trip_count: Mapped[int] = mapped_column(default=0, server_default="0")
    last_trip_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Python exception type name; never str(exc) — spec §5.6 T3 leak risk.
    last_failure_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Mirrors SUPERVISOR_BREAKER_TRIPPED_FIELDS["breaker_state"] — always
    # "OPEN" at trip time. Captured snapshot, not live state.
    breaker_state: Mapped[str] = mapped_column(
        String(16), default="CLOSED", server_default="CLOSED"
    )
    # Mirrors SUPERVISOR_BREAKER_TRIPPED_FIELDS["correlation_id"] — the
    # correlation id of the most-recent trip event. Empty string until the
    # breaker has ever tripped.
    correlation_id: Mapped[str] = mapped_column(String(64), default="", server_default="")

    __table_args__ = (
        CheckConstraint(
            "state IN ('CLOSED', 'OPEN', 'HALF_OPEN')",
            name="ck_circuit_breakers_state",
        ),
    )

    def __init__(self, **kwargs: Any) -> None:
        # Delegate the column-side construction to SQLAlchemy's declarative
        # __init__, then attach the per-instance asyncio.Lock used by
        # CircuitBreaker.save_to_db (Task 8). The lock is NOT a mapped
        # column — see test_save_lock_is_not_a_mapped_column.
        super().__init__(**kwargs)
        self._save_lock: asyncio.Lock = asyncio.Lock()

    @reconstructor
    def _init_save_lock_on_load(self) -> None:
        """Re-create ``_save_lock`` when SQLAlchemy materialises a row from DB.

        The ``@reconstructor`` decorator runs after a row is loaded via the
        ORM (where ``__init__`` is bypassed). Without this hook, an instance
        loaded from a SELECT would have no ``_save_lock`` attribute and the
        first ``save_to_db`` call would raise ``AttributeError``.
        """
        self._save_lock = asyncio.Lock()
