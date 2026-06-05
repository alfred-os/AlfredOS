"""ProcessedProposal + ProcessedProposalsHead ORM model shape tests.

Pins the ledger schema at the model layer — Task 3 of #171.

The shape is load-bearing per ADR-0021:

* Composite PK on (proposal_type, proposal_id) — the ledger replay-safety
  contract. Crash-after-ledger-before-sentinel is provably safe because
  a re-walk SELECTs this PK and finds the row.
* ``commit_sha`` String(40) NOT NULL — the non-repudiable forensic join
  key against the git merge commit. Self-claimed ``operator_user_id`` is
  forensic context only.
* ``failure_kind`` String(48) — closed vocab (six values per spec §2.5);
  ``failure_detail`` String(512) — DLP-redacted via OutboundDlp.scan at
  write time.
* ``operator_user_id`` String(64) — matches PluginGrant.operator_user_id
  and AuditEntry.actor_user_id; NOT 128.
* ``head_sha`` nullable on the sentinel — first dispatch cycle bootstraps
  from ``git rev-parse origin/main`` rather than running subprocess at
  migration time (rejected alternative A6 in ADR-0021).

These are mypy/runtime-level checks; the DB-level CHECK constraint
enforcement is pinned by the migration round-trip integration test.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import CheckConstraint, inspect

from alfred.memory.models import ProcessedProposal, ProcessedProposalsHead

# ---------------------------------------------------------------------------
# ProcessedProposal — composite PK + column types
# ---------------------------------------------------------------------------


def test_processed_proposal_tablename() -> None:
    """Pin the table name so a rename surfaces here, not at migration time."""
    assert ProcessedProposal.__tablename__ == "processed_proposals"


def test_processed_proposal_composite_primary_key_is_type_plus_id() -> None:
    """Composite PK (proposal_type, proposal_id) is the replay-safety contract.

    A re-walk after a crash-between-ledger-and-sentinel SELECTs this PK and
    finds the row — so the handler is NOT re-invoked. Pinning the PK shape
    here means a future refactor that drops one component (or adds a
    surrogate id) fails this test, not the integration round-trip on a
    cold run.
    """
    pk_columns = {col.name for col in ProcessedProposal.__table__.primary_key.columns}
    assert pk_columns == {"proposal_type", "proposal_id"}


def test_processed_proposal_proposal_type_string_64() -> None:
    """proposal_type is String(64) — matches the discriminator surface."""
    col = ProcessedProposal.__table__.c["proposal_type"]
    assert col.type.length == 64
    assert col.nullable is False


def test_processed_proposal_proposal_id_string_64() -> None:
    """proposal_id is String(64) — matches the writer's 16-hex id width with headroom."""
    col = ProcessedProposal.__table__.c["proposal_id"]
    assert col.type.length == 64
    assert col.nullable is False


def test_processed_proposal_blob_sha_string_40_not_null() -> None:
    """blob_sha = the content hash of the JSON file."""
    col = ProcessedProposal.__table__.c["blob_sha"]
    assert col.type.length == 40
    assert col.nullable is False


def test_processed_proposal_commit_sha_string_40_not_null() -> None:
    """commit_sha = the merge-commit SHA from git log.

    Non-repudiable forensic key per ADR-0021 §Threat model. Distinct from
    blob_sha — blob can appear at multiple commits; the commit binds the
    action to the git object.
    """
    col = ProcessedProposal.__table__.c["commit_sha"]
    assert col.type.length == 40
    assert col.nullable is False


def test_processed_proposal_result_string_32_not_null() -> None:
    """result column carries the closed-vocab dispatch outcome."""
    col = ProcessedProposal.__table__.c["result"]
    assert col.type.length == 32
    assert col.nullable is False


def test_processed_proposal_processed_at_is_timestamptz_not_null() -> None:
    """processed_at must be timestamptz so the supervisor's NOW() comparisons work.

    A naive datetime here would silently break the
    ``processed_at > NOW() - INTERVAL '1 hour'`` query the status footer uses.
    """
    col = ProcessedProposal.__table__.c["processed_at"]
    assert col.type.timezone is True
    assert col.nullable is False


def test_processed_proposal_handler_version_integer_not_null() -> None:
    """handler_version pins the handler shape at dispatch time for forensic replay."""
    col = ProcessedProposal.__table__.c["handler_version"]
    assert col.nullable is False


def test_processed_proposal_failure_kind_string_48_nullable() -> None:
    """failure_kind is String(48) — closed vocab of six values per spec §2.5.

    NULL on the applied path; populated on failure paths. Spec says 48.
    """
    col = ProcessedProposal.__table__.c["failure_kind"]
    assert col.type.length == 48
    assert col.nullable is True


def test_processed_proposal_failure_detail_string_512_nullable() -> None:
    """failure_detail is bounded String(512), DLP-redacted at write time."""
    col = ProcessedProposal.__table__.c["failure_detail"]
    assert col.type.length == 512
    assert col.nullable is True


def test_processed_proposal_operator_user_id_string_64_nullable() -> None:
    """operator_user_id is String(64) — matches the rest of the ledger schema.

    NOT 128: PluginGrant.operator_user_id, AuditEntry.actor_user_id, and
    the IdentityResolver canonical-user-id surface all use String(64).
    """
    col = ProcessedProposal.__table__.c["operator_user_id"]
    assert col.type.length == 64
    assert col.nullable is True


def test_processed_proposal_has_result_check_constraint() -> None:
    """ck_processed_proposals_result pins the closed-vocab result domain.

    Five values per ADR-0021: applied, failed_handler, failed_parse,
    failed_unknown_type, skipped_already_processed.
    """
    constraints = [
        c for c in ProcessedProposal.__table__.constraints if isinstance(c, CheckConstraint)
    ]
    names = {c.name for c in constraints}
    assert "ck_processed_proposals_result" in names


def test_processed_proposal_has_result_failure_kind_consistency_constraint() -> None:
    """ck_processed_proposals_result_failure_kind_consistency pins the cross-column invariant.

    CR-rework round-2 MAJOR T4: ``applied`` rows MUST leave ``failure_kind``
    NULL; every ``failed_*`` row MUST carry a non-NULL ``failure_kind``.
    The dispatcher's ``Literal``-narrowed ``_record_failure`` call sites
    encode this invariant in Python today, but the DB CHECK survives a
    refactor that drops the typing narrowing. A regression to either arm
    would land an "applied with failure_kind set" or "failed without
    failure_kind" row — both are operator-confusing shapes that the
    CHECK refuses at the storage layer.
    """
    constraints = [
        c for c in ProcessedProposal.__table__.constraints if isinstance(c, CheckConstraint)
    ]
    names = {c.name for c in constraints}
    assert "ck_processed_proposals_result_failure_kind_consistency" in names


# ---------------------------------------------------------------------------
# ProcessedProposalsHead — sentinel
# ---------------------------------------------------------------------------


def test_processed_proposals_head_tablename() -> None:
    """Sentinel table name pin."""
    assert ProcessedProposalsHead.__tablename__ == "processed_proposals_head"


def test_processed_proposals_head_primary_key_is_id() -> None:
    """Single-row sentinel keyed on integer id (CheckConstraint pins id=1)."""
    pk_columns = {col.name for col in ProcessedProposalsHead.__table__.primary_key.columns}
    assert pk_columns == {"id"}


def test_processed_proposals_head_head_sha_string_40_nullable() -> None:
    """head_sha is nullable — first dispatch cycle bootstraps from origin/main.

    Spec §Migration / ADR-0021 §A6: rejected alternative was subprocess
    at migration time. The chosen design starts NULL and the first
    dispatch cycle's NULL-detector writes ``git rev-parse origin/main``.
    A regression to non-null here would break the bootstrap path.
    """
    col = ProcessedProposalsHead.__table__.c["head_sha"]
    assert col.type.length == 40
    assert col.nullable is True


def test_processed_proposals_head_updated_at_is_timestamptz_not_null() -> None:
    """updated_at must be timestamptz so sentinel-staleness queries work uniformly."""
    col = ProcessedProposalsHead.__table__.c["updated_at"]
    assert col.type.timezone is True
    assert col.nullable is False


def test_processed_proposals_head_has_singleton_check_constraint() -> None:
    """ck_processed_proposals_head_singleton pins id=1 — enforces single-row table."""
    constraints = [
        c for c in ProcessedProposalsHead.__table__.constraints if isinstance(c, CheckConstraint)
    ]
    names = {c.name for c in constraints}
    assert "ck_processed_proposals_head_singleton" in names


# ---------------------------------------------------------------------------
# Constructibility
# ---------------------------------------------------------------------------


def test_processed_proposal_constructs_with_full_field_set() -> None:
    """A typed construction with every column populated must succeed.

    This catches accidental nullable-vs-not-null drift between the model
    and the migration: SQLAlchemy will reject the construction if a
    declared NOT NULL field is missing.
    """
    row = ProcessedProposal(
        proposal_type="breaker-reset",
        proposal_id="abc123def4567890",
        blob_sha="a" * 40,
        commit_sha="b" * 40,
        result="applied",
        handler_version=1,
        failure_kind=None,
        failure_detail=None,
        operator_user_id="operator-1",
        processed_at=dt.datetime(2026, 6, 5, 12, 0, 0, tzinfo=dt.UTC),
    )
    assert row.proposal_type == "breaker-reset"
    assert row.proposal_id == "abc123def4567890"


def test_processed_proposals_head_constructs_with_null_head_sha() -> None:
    """Construction with head_sha=None must succeed — bootstrap-pending shape."""
    row = ProcessedProposalsHead(id=1, head_sha=None)
    assert row.id == 1
    assert row.head_sha is None


def test_processed_proposal_columns_present_via_inspection() -> None:
    """Belt-and-braces: inspector lists every load-bearing column."""
    cols = {c.name for c in inspect(ProcessedProposal).columns}
    assert cols == {
        "proposal_type",
        "proposal_id",
        "blob_sha",
        "commit_sha",
        "processed_at",
        "result",
        "handler_version",
        "failure_kind",
        "failure_detail",
        "operator_user_id",
    }
