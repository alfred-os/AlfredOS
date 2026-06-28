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
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
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
            "'revoked', 'tripped', 'reset', 'content_expired', "
            # Slice-4 (migration 0014) — DLP-into-failure_detail (PR-S4-2),
            # carrier substitution (PR-S4-3), policies hot-reload (PR-S4-4),
            # plus the generic attestation result used by the
            # PR-S4-4 closure 7 audit-write-failure path.
            "'dispatched_with_redactions', 'dispatched_clean', "
            "'recursion_refused', 'audit_row_emitted', "
            # Slice-4 (migration 0016) — PR-S4-8 comms-MCP inbound + session
            # dispatch dispositions: T3 promotion, first-contact binding,
            # burst-limiter backpressure (capped) + hard drop, post-handshake
            # allow, handler failure, and the supervisor restart-request row
            # whose only production caller is the comms-wired session.
            "'promoted', 'binding_requested', 'dropped', 'capped', "
            "'allowed', 'failed', 'restart_requested', "
            # Slice-4 (migration 0017) — PR-S4-11b supervisor-shutdown
            # dispositions emitted by Supervisor.stop / reset_breaker: the
            # force-cancel "clean shutdown failed" row (cancelled_with_errors)
            # and the breaker-state persistence-failure row (persistence_failed).
            "'cancelled_with_errors', 'persistence_failed', "
            # Spec B G6-7-4 (migration 0019, #309) — the gateway dispatched-edge
            # dispatch-failure row: a forwarded inbound whose dispatch raised is
            # left NOT committed / NOT observed (the leg replays it) and recorded
            # with this DISTINCT discriminator (never the "dropped" replay value).
            "'dispatch_failed', "
            # Spec B G6-7-5 (#309) — the poison-ceiling row: a forwarded inbound
            # that has failed the post-extract region enough times to breach the
            # replay bound (ForwardedDispatchAttempt). The frame is then DRAINED
            # (observe-only, NO commit_once — it writes no idempotency row) so the
            # leg stops replaying it: a TERMINAL dead-letter, never committed,
            # distinct from the per-attempt 'dispatch_failed' row that leaves the
            # frame replayable.
            "'poisoned', "
            # Spec B G6-3 (migration 0021, #288/#309) — the core-side credential
            # resolver's signed ``core.adapter.spawn_grant`` row records that a
            # platform credential was released to the gateway over the trusted leg.
            # Closed-vocab grant outcome (the refusal sibling reuses 'refused');
            # the credential itself is NEVER in the row (audit_row_schemas
            # CORE_ADAPTER_SPAWN_GRANT_FIELDS has no credential field).
            "'granted', "
            # Issue #252 / #320 (migration 0022) — 14 latent-gap result values:
            # 13 the #320 static guard surfaced as literals + post_stage_refused
            # (C1, adversarial review) reached via a DYNAMIC helper-param flow
            # the guard cannot see. Each is genuinely written to this column via
            # the real AuditWriter but shipped without a CHECK migration (the
            # same bug class as 'granted'/0021). Quarantine extractor:
            # transport_failed (#252, the triggering issue), protocol_violation
            # (#134/#158), post_stage_refused (C1, post-stage T3 canary/DLP
            # refusal). web.fetch dispatcher (tool.web.fetch): dlp_scan_error /
            # domain_not_allowed / internal_ip_refused (#134), transport_error /
            # handle_id_mismatch / ok (#157), dispatch_param_invalid /
            # dispatch_shape_error (#147). Capability-gate grant-rebuild:
            # rolled_back. Comms addressing-drift detector: drift_detected. CLI
            # outbound-DLP sink: modified.
            "'transport_failed', 'protocol_violation', 'post_stage_refused', "
            "'dlp_scan_error', 'domain_not_allowed', 'internal_ip_refused', "
            "'transport_error', 'handle_id_mismatch', "
            "'dispatch_param_invalid', 'dispatch_shape_error', 'ok', "
            "'rolled_back', 'drift_detected', 'modified', "
            # Spec C G7-2c-1 (migration 0024, #333) — egress-relay refusal rows
            # written by RelayEgressClient._audit_refused (dynamic emit site;
            # manually audited in the G7-2c-1 C1 pass). 'denied' is already above.
            "'in_doubt', 'io_plane_unavailable')",
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


class ProcessedProposal(Base):
    """Replay-safety ledger for side-effecting state.git proposals (ADR-0021).

    One row per dispatched proposal. The composite primary key
    ``(proposal_type, proposal_id)`` is the at-most-once guarantee: a
    crash between the handler/ledger transaction and the sentinel-bump
    transaction leaves the ledger row behind, so the next cycle's
    HEAD-diff walk re-sees the same blob, SELECTs this PK, finds the
    row, and skips the handler call (``skipped_already_processed``).

    Column semantics
    ----------------

    * ``proposal_type`` / ``proposal_id`` — composite PK (ADR-0021
      §Decision / §Replay safety). String(64) on both — matches the
      writer's 16-hex id width with headroom for future composed
      discriminators.
    * ``blob_sha`` — content hash of the JSON blob on the merge commit
      (``git ls-tree`` blob sha).
    * ``commit_sha`` — the dispatch-cycle HEAD at the time of the
      HEAD-diff walk (the head that brought the blob into ``main``).
      Distinct from ``blob_sha`` — a blob can appear at multiple commits;
      the commit binds the action to the git object. The non-repudiable
      forensic join key per ADR-0021 §Threat model; ``operator_user_id``
      (below) is self-claimed forensic context only.
    * ``processed_at`` — timestamptz so the supervisor status footer's
      ``processed_at > NOW() - INTERVAL '1 hour'`` query works.
    * ``result`` — closed vocab pinned by ``ck_processed_proposals_result``
      (``applied``, ``failed_handler``, ``failed_parse``,
      ``failed_unknown_type``).
    * ``handler_version`` — integer; lets a future handler-shape
      migration replay the ledger without ambiguity.
    * ``failure_kind`` — String(48) closed vocab per spec §2.5 (six
      values: ``handler_returned_failed``, ``handler_uncaught_exception``,
      ``payload_validation``, ``unknown_proposal_type``, ``blob_not_found``,
      ``handler_timeout``), pinned by ``ck_processed_proposals_failure_kind``
      in addition to the dispatcher's ``Literal``-narrowed call sites.
      NULL on the applied path.
    * ``failure_detail`` — String(512). Currently truncated only; DLP
      redaction (``OutboundDlp.scan``) is tracked at
      `#173 <https://github.com/alfred-os/AlfredOS/issues/173>`_. Today's
      emit sites pass closed-vocab strings (``type(exc).__name__``,
      handler-returned reasons) so the realised leak surface is small;
      a future emit site that drops a Pydantic-validation-error message
      into this field would carry verbatim T3 fragments without the #173
      scanner.
    * ``operator_user_id`` — String(64) matching ``PluginGrant.operator_user_id``
      and ``AuditEntry.actor_user_id``. Self-claimed per ADR-0021 §Threat
      model; ``commit_sha`` is the non-repudiable key.

    Cross-column invariant
    ----------------------

    The ``result`` and ``failure_kind`` columns are coupled by
    ``ck_processed_proposals_result_failure_kind_consistency``: an
    ``applied`` row leaves ``failure_kind`` NULL (success carries no
    failure discriminator), and every ``failed_*`` row carries a
    non-NULL ``failure_kind``. The dispatcher's call-site Literals
    encode this invariant in Python today (CR-rework round-2 MAJOR T4);
    the CHECK is the defense-in-depth boundary so a future refactor
    that drops the typing narrowing still cannot land an "applied with
    failure_kind set" or "failed without failure_kind" row in the ledger.
    """

    __tablename__ = "processed_proposals"

    proposal_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    proposal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    blob_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    processed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    handler_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    failure_kind: Mapped[str | None] = mapped_column(String(48), nullable=True)
    failure_detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    operator_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        CheckConstraint(
            # CR rework round-1 (MEDIUM/LOW): ``skipped_already_processed``
            # dropped — the dispatcher's replay path short-circuits
            # via the composite-PK lookup BEFORE inserting any row,
            # so the value was never written to the ledger.
            "result IN ('applied', 'failed_handler', 'failed_parse', 'failed_unknown_type')",
            name="ck_processed_proposals_result",
        ),
        CheckConstraint(
            # HIGH #8: defense-in-depth alongside the dispatcher's
            # ``Literal``-narrowed :func:`_record_failure` call sites.
            # ``NULL`` is the applied-path shape; every failure path
            # writes one of the six closed-vocab values.
            "failure_kind IS NULL OR failure_kind IN ("
            "'handler_returned_failed', 'handler_uncaught_exception', "
            "'payload_validation', 'unknown_proposal_type', "
            "'blob_not_found', 'handler_timeout')",
            name="ck_processed_proposals_failure_kind",
        ),
        CheckConstraint(
            # CR-rework round-2 MAJOR T4: result x failure_kind invariant.
            # ``applied`` rows MUST leave ``failure_kind`` NULL; every
            # ``failed_*`` row MUST carry a non-NULL ``failure_kind``.
            # The dispatcher's call-site Literals encode this today but
            # the CHECK survives a refactor that drops the narrowing.
            "(result = 'applied' AND failure_kind IS NULL) "
            "OR (result IN ('failed_handler', 'failed_parse', "
            "'failed_unknown_type') AND failure_kind IS NOT NULL)",
            name="ck_processed_proposals_result_failure_kind_consistency",
        ),
    )


class ProcessedProposalsHead(Base):
    """Sentinel: tracks last-processed state.git HEAD (ADR-0021).

    Single-row table — enforced by ``ck_processed_proposals_head_singleton``
    pinning ``id = 1``. The dispatch loop reads this on every cycle to
    derive the ``git diff <last>..origin/main --diff-filter=A`` walk.

    ``head_sha`` starts NULL after the migration. The dispatch loop's
    first cycle detects NULL, writes ``git rev-parse origin/main`` as the
    bootstrap value (forward-from-now semantics — existing blobs are not
    reprocessed). This avoids the rejected alternative A6 in ADR-0021
    (subprocess at migration time); ``/var/lib/alfred/state.git`` does
    not exist at fresh-install migration time on every deployment shape.

    A separate-transaction sentinel bump is the second leg of the
    atomicity model: handler effect + ledger insert commit together;
    sentinel bump commits afterward. Crash-between-the-two is provably
    safe because the next cycle re-walks from the old sentinel, sees
    the same blob, hits the ledger PK, and skips.
    """

    __tablename__ = "processed_proposals_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (CheckConstraint("id = 1", name="ck_processed_proposals_head_singleton"),)


class OperatorSession(Base):
    """CLI operator-session token row.

    Mirrors the ``operator_sessions`` table (migration 0012). The
    session token itself never lands in the DB — only ``token_hash``
    does (HMAC-SHA256 hex of the random token, keyed by the HKDF-derived
    ``_TOKEN_HASH_SUBKEY`` per PR-S4-5 round-2 closure 3).

    ``token_hash`` is the natural primary key — globally unique
    (256-bit HMAC-SHA256 hex output) and the column PR-S4-5's
    ``_resolve_operator`` reads on every CLI invocation. Postgres
    auto-creates the unique btree on the PK; ADR-0024 budgets the
    lookup at <=5 ms p99.

    ``revoked_at`` is nullable — active sessions have NULL.
    ``alfred logout`` sets the column rather than deleting the row so
    the audit-log retains the session lifecycle.

    ``__table_args__`` mirrors migration 0012's CHECK constraints,
    indexes, and named PK so ``Base.metadata.create_all()`` tests
    that bypass alembic build the same DB-layer refusal surface PR-S4-5
    + the 5 ms p99 budget rely on.
    """

    __tablename__ = "operator_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    issued_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    machine_id_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        sa.PrimaryKeyConstraint("token_hash", name="uq_operator_sessions_token_hash"),
        Index(
            "ix_operator_sessions_user_id_expires_at",
            "user_id",
            "expires_at",
        ),
    )


class PoliciesSnapshotHistory(Base):
    """Optional rollback log for PR-S4-4 hot-reload swaps.

    Mirrors the ``policies_snapshot_history`` table (migration 0013;
    ADR-0023). One row per swapped-in ``PoliciesV1`` snapshot.

    ``swapped_from_snapshot_id`` is the self-reference to the previous
    snapshot (NULL for the bootstrap snapshot). ``ON DELETE RESTRICT``
    at the DB layer prevents silent lineage breakage; the model mirrors
    that contract.

    ``applied_by_operator_session_id`` carries the live-session LINK to
    the operator who drove a watcher-CLI-initiated swap; NULL when the
    watcher auto-swapped on an mtime change. **Forensic attribution
    lives in audit_log, not on this column** — see the migration
    docstring + PR #209 sec-1 closure.

    ``__table_args__`` mirrors migration 0013's CHECK constraints
    (snapshot_id UUID format, file_sha256 hex format, applied_by hex
    format, 256 KB JSONB size cap from PR-S4-4 round-2 closure 2) and
    the time-range lookup index. Consumers that bypass alembic
    (``metadata.create_all()``) get the same defence-in-depth surface.
    """

    __tablename__ = "policies_snapshot_history"

    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    loaded_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # JSONB on Postgres (production), JSON on SQLite (unit-test fallback) — same
    # logical type, dialect-portable. Production migration 0013 uses JSONB
    # exclusively; this with_variant keeps SQLite-backed tests buildable.
    policies_json: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
    )
    swapped_from_snapshot_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("policies_snapshot_history.snapshot_id", ondelete="RESTRICT"),
        nullable=True,
    )
    applied_by_operator_session_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("operator_sessions.token_hash", ondelete="SET NULL"),
        nullable=True,
    )

    # Postgres-specific CHECK constraints (regex ``~``, ``octet_length``)
    # live in migration 0013 only — SQLite-backed unit tests (which consume
    # this model via ``Base.metadata.create_all()``) cannot parse those
    # operators. Production DB (Postgres + alembic) carries the full
    # defence-in-depth surface (UUID hex format, SHA-256 hex format,
    # 256 KB JSONB size cap from PR-S4-4 closure 2). The dialect-portable
    # constraints (named PK + lookup index) stay on the model.
    __table_args__ = (
        sa.PrimaryKeyConstraint("snapshot_id", name="uq_policies_snapshot_history_snapshot_id"),
        Index("ix_policies_snapshot_history_loaded_at", "loaded_at"),
    )


class SandboxPolicyRegistry(Base):
    """Launcher policy-resolution observability.

    Mirrors the ``sandbox_policy_registry`` table (migration 0015;
    ADR-0015). Composite PK ``(plugin_id, host_os)`` — one row per
    plugin per host OS. Read-only observability; the launcher itself
    does NOT consult this table at spawn time (the live policy is in
    the plugin's manifest + the on-disk policy file). Operators query
    it to confirm every plugin's expected policy matches the resolved
    one across OSes.

    ``__table_args__`` mirrors migration 0015's CHECK constraints
    (host_os + resolution_result closed vocabs, plugin_id snake_case
    charset, policy_ref relative-path guard).
    """

    __tablename__ = "sandbox_policy_registry"

    plugin_id: Mapped[str] = mapped_column(String(128), nullable=False)
    host_os: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    last_resolved_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolution_result: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        sa.PrimaryKeyConstraint(
            "plugin_id",
            "host_os",
            name="uq_sandbox_policy_registry_plugin_host_os",
        ),
        CheckConstraint(
            "host_os IN ('linux', 'macos', 'windows')",
            name="ck_sandbox_policy_registry_host_os",
        ),
        CheckConstraint(
            "resolution_result IN ('resolved', 'refused_policy_missing', "
            "'refused_unreadable', 'refused_os_mismatch', 'stub_used')",
            name="ck_sandbox_policy_registry_resolution_result",
        ),
        CheckConstraint(
            "policy_ref NOT LIKE '/%' AND policy_ref NOT LIKE '%..%'",
            name="ck_sandbox_policy_registry_policy_ref_relative",
        ),
    )


class InboundIdempotency(Base):
    """Durable inbound accept-once ledger (Spec A / G0).

    One row per inbound comms frame the core has committed "accepted exactly
    once", keyed on the durable wire ``inbound_id``. A replayed frame (gateway
    buffer replay after a core restart) hits the existing row and short-circuits
    BEFORE any side effect. Dedup ledger, not a content store: NO body, NO user
    text, NO ``platform_user_id`` — so no ``language`` column (i18n hard-rule #3).
    """

    __tablename__ = "inbound_idempotency"

    inbound_id: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter_id: Mapped[str] = mapped_column(String(128), nullable=False)
    committed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # Composite (adapter_id, inbound_id) PK — mirrors migration 0018. Isolates
        # each adapter's id namespace so one adapter's reuse cannot drop another's
        # distinct message.
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_inbound_idempotency"),
        # Postgres-only char_length CHECKs live in migration 0018; SQLite unit
        # tests cannot parse them (PoliciesSnapshotHistory precedent). The
        # dialect-portable named PK + retention index stay here.
        Index("ix_inbound_idempotency_committed_at", "committed_at"),
    )


class EgressIdempotency(Base):
    """Durable tri-state side-effecting-egress dedup ledger (Spec C §5, G7-2a).

    Mirrors :class:`InboundIdempotency` but for OUTBOUND side-effects. One row per
    logical egress call, keyed on the deterministic, injective ``egress_id`` (a
    sha256 hexdigest, so exactly 64 chars). Tri-state: ``committed_no_response``
    before the side-effect, ``committed_with_response`` after — the absent row is
    the implicit third state. A duplicate ``egress_id`` replays the stored response
    rather than re-firing (the money/side-effect boundary must be at-most-once).

    ``response`` stores the POST-extraction **T2** result, NEVER the raw T3 tool
    response, so a duplicate-egress replay can never re-hand raw T3 to the
    orchestrator (HARD rule #5). ``language`` carries the BCP-47 tag because this
    row holds user-derived content (i18n hard-rule #3).
    """

    __tablename__ = "egress_idempotency"

    egress_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    adapter_id: Mapped[str] = mapped_column(String(128), nullable=False)
    inbound_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    call_index: Mapped[int] = mapped_column(Integer, nullable=False)
    body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    committed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # Closed state vocabulary + the state<->response invariant. Both are
        # dialect-portable (IN + boolean-equality parse + enforce under SQLite as well
        # as Postgres — no char_length() or other Postgres-only function), so the SAME
        # two CHECKs live here and in migration 0023, and they ride the ORM into the
        # unit-test SQLite create_all as well as the Postgres migration.
        sa.CheckConstraint(
            "state IN ('committed_no_response', 'committed_with_response')",
            name="ck_egress_idempotency_state",
        ),
        sa.CheckConstraint(
            "(state = 'committed_no_response') = (response IS NULL)",
            name="ck_egress_idempotency_response_matches_state",
        ),
        Index("ix_egress_idempotency_committed_at", "committed_at"),
    )


class ForwardedDispatchAttempt(Base):
    """Durable per-(adapter_id, inbound_id) dispatch-attempt ledger (Spec B G6-7-5, #309).

    ADR-0039 item 4b. The forwarded dispatched-edge path leaves a failed frame NOT
    committed/NOT observed so the leg replays it; this ledger BOUNDS that replay. It is
    DURABLE (Postgres) because replay happens across core restarts — an in-memory counter
    would reset exactly when the bound is needed. Composite PK isolates each adapter's
    free-form inbound_id namespace (mirrors InboundIdempotency); that isolation is
    load-bearing ONLY because upstream K4 admission mints adapter_id from the spawn
    binding (closed-vocab, un-forgeable — ADR-0039 item 4c).
    """

    __tablename__ = "forwarded_dispatch_attempts"

    adapter_id: Mapped[str] = mapped_column(String(128), nullable=False)
    inbound_id: Mapped[str] = mapped_column(String(255), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    first_failed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_failed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        sa.PrimaryKeyConstraint("adapter_id", "inbound_id", name="pk_forwarded_dispatch_attempts"),
        # Retention index mirroring InboundIdempotency's committed_at index — a
        # future age-based GC sweep prunes by last_failed_at off this index.
        Index("ix_forwarded_dispatch_attempts_last_failed_at", "last_failed_at"),
    )


# ---------------------------------------------------------------------------
# Cross-module Base.metadata registration
# ---------------------------------------------------------------------------
# OperatorSession (this module) declares a FK to ``users.id`` declared by
# ``alfred.identity.models.User``. Pyright/mypy resolve the FK string at
# runtime via ``Base.metadata`` — and SQLAlchemy ``Base.metadata.create_all()``
# refuses with ``NoReferencedTableError`` if ``users`` is not registered.
#
# Side-effect import at module bottom: ensures any consumer that imports
# ``alfred.memory.models`` also registers the identity tables with the same
# ``Base.metadata``. The import is placed AFTER ``Base`` is defined to break
# the (otherwise-circular) import — ``alfred.identity.models`` reaches up
# to read ``Base`` from this module, which by this line is fully populated.
import alfred.identity.models as _alfred_identity_models  # noqa: E402, F401
