"""CircuitBreakerState ORM model — PR-S3-3b Task 2 (spec §10.6).

Pins the model shape against the migration 0010 columns. The integration
round-trip test (``tests/integration/memory/test_migration_0010_round_trip``)
exercises the actual Postgres behaviour; this unit test pins the
Python-side surface so a future refactor of the model class doesn't
silently break the ``Mapped[...]`` declarations.

Pinned invariants:

* Table name is ``circuit_breakers`` — the migration 0010 contract.
* ``component_id`` is the primary key. One row per supervised component
  (e.g. ``"quarantined-llm"``, ``"web-fetch"``).
* ``state`` is a closed-domain string column. Application-level values are
  CLOSED/OPEN/HALF_OPEN; the CHECK constraint on the DB pins this.
* ``last_trip_at`` is timestamp-with-timezone and nullable (no trip yet).
* ``last_failure_type`` is a string column for the Python exception type
  name — NEVER ``str(exc)`` (T3 fragment risk, spec §5.6).
* ``breaker_state`` mirrors the audit-row field of the same name from
  :data:`SUPERVISOR_BREAKER_TRIPPED_FIELDS` (always ``"OPEN"`` at trip
  time). Persisted so the supervisor can reconstruct the last-trip event
  on restart.
* ``correlation_id`` is the correlation id of the most-recent trip event,
  mirroring the audit-row field. Lets operators link a persisted breaker
  row to the audit trail entry that opened it.
* ``_save_lock`` is an instance-level ``asyncio.Lock`` (PR-S3-3a R3) used
  by ``save_to_db`` (Task 8) to serialise concurrent writes for the same
  row and prevent lost-update races. Per-instance, not class-level — so
  unrelated breakers don't block each other. NOT a mapped column.
"""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest

from alfred.memory.models import CircuitBreakerState


def test_table_name() -> None:
    """The ORM table name is ``circuit_breakers`` — migration 0010 contract."""
    assert CircuitBreakerState.__tablename__ == "circuit_breakers"


def test_construct_minimal() -> None:
    """A row can be constructed with just the component id.

    Python-side ``default=`` runs at INSERT-flush time (not at attribute
    access), so unset columns read back as ``None`` on a transient
    instance. The migration round-trip test exercises the
    ``server_default`` path (raw-SQL INSERT without explicit values).
    """
    row = CircuitBreakerState(component_id="quarantined-llm")
    assert row.component_id == "quarantined-llm"
    # Defaults are applied at flush time, not at __init__ time — this
    # mirrors SQLAlchemy 2.0 ORM behaviour. The migration round-trip test
    # pins the post-flush values via raw SQL inserts that exercise
    # server_default directly.
    assert row.state is None
    assert row.trip_count is None
    assert row.last_trip_at is None
    assert row.last_failure_type is None


def test_construct_full_trip_row() -> None:
    """A trip-event row carries all the audit-mirror fields.

    breaker_state and correlation_id mirror the supervisor.breaker.tripped
    audit-row fields per :data:`SUPERVISOR_BREAKER_TRIPPED_FIELDS`.
    """
    now = dt.datetime(2026, 5, 31, 12, 0, 0, tzinfo=dt.UTC)
    row = CircuitBreakerState(
        component_id="quarantined-llm",
        state="OPEN",
        trip_count=1,
        last_trip_at=now,
        last_failure_type="SubprocessExitedError",
        breaker_state="OPEN",
        correlation_id="01J0Z3K4ABCDEF",
    )
    assert row.state == "OPEN"
    assert row.trip_count == 1
    assert row.last_trip_at == now
    assert row.last_failure_type == "SubprocessExitedError"
    # breaker_state mirrors the audit-row field for the trip event;
    # always "OPEN" at trip time per SUPERVISOR_BREAKER_TRIPPED_FIELDS.
    assert row.breaker_state == "OPEN"
    assert row.correlation_id == "01J0Z3K4ABCDEF"


def test_save_lock_present_and_per_instance() -> None:
    """``_save_lock`` is an instance-level asyncio.Lock (PR-S3-3a R3).

    Per-instance so concurrent saves for different rows do not block each
    other. Lost-update safety for ``save_to_db`` (Task 8) requires that
    two coroutines saving the SAME breaker serialise; two coroutines
    saving DIFFERENT breakers must not.
    """
    row_a = CircuitBreakerState(component_id="quarantined-llm")
    row_b = CircuitBreakerState(component_id="web-fetch")
    assert isinstance(row_a._save_lock, asyncio.Lock)
    assert isinstance(row_b._save_lock, asyncio.Lock)
    # Per-instance: different rows must own distinct lock objects.
    assert row_a._save_lock is not row_b._save_lock


def test_save_lock_is_not_a_mapped_column() -> None:
    """``_save_lock`` MUST NOT appear in the mapped columns.

    A ``Mapped[asyncio.Lock]`` would be incoherent (no SQL type), and
    SQLAlchemy would either reject it at mapper-config time or, worse,
    silently treat it as a relationship and confuse the migration
    autogenerate. The unit test pins it as a non-mapped attribute.
    """
    mapped_cols = {c.name for c in CircuitBreakerState.__table__.columns}
    assert "_save_lock" not in mapped_cols
    # The expected mapped surface matches migration 0010 exactly.
    assert mapped_cols == {
        "component_id",
        "state",
        "trip_count",
        "last_trip_at",
        "last_failure_type",
        "breaker_state",
        "correlation_id",
    }


def test_component_id_is_primary_key() -> None:
    """``component_id`` is the primary key — one row per supervised component.

    Pins the schema contract: a future refactor that adds a surrogate UUID
    PK would silently break the supervisor's ``SELECT ... WHERE
    component_id = ?`` restore path. Idempotent upsert relies on this
    being the natural key.
    """
    pks = [c.name for c in CircuitBreakerState.__table__.primary_key]
    assert pks == ["component_id"]


@pytest.mark.parametrize("state", ["CLOSED", "OPEN", "HALF_OPEN"])
def test_state_closed_domain_accepts_each(state: str) -> None:
    """All three legal breaker states are accepted at the Python layer.

    The CHECK constraint at the DB layer (asserted by the migration
    round-trip test) enforces the closed domain on writes; this test
    pins the Python-side conformance.
    """
    row = CircuitBreakerState(component_id=f"test-{state}", state=state)
    assert row.state == state


def test_reconstructor_initialises_save_lock() -> None:
    """The ``@reconstructor`` hook re-attaches ``_save_lock`` on ORM load.

    SQLAlchemy bypasses ``__init__`` when materialising a row from a
    SELECT — instances are built via ``__new__`` and column values are
    assigned directly. Without the ``@reconstructor`` hook the loaded
    instance would have no ``_save_lock`` attribute and the first
    :meth:`save_to_db` call would raise ``AttributeError``.

    Simulating this here so coverage on the reconstructor body does not
    require a Postgres round-trip — the integration round-trip test also
    exercises the path implicitly when it reads back a row, but the unit
    test pins the contract cheaply.
    """
    # __new__ + the reconstructor mirrors what SQLAlchemy does on load.
    row = CircuitBreakerState.__new__(CircuitBreakerState)
    assert not hasattr(row, "_save_lock")
    row._init_save_lock_on_load()
    assert isinstance(row._save_lock, asyncio.Lock)
