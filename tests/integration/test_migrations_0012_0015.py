"""Round-trip tests for Slice-4 migrations 0012-0015.

Uses testcontainers to spin up a real Postgres 16 instance so CHECK
constraints, unique indexes, and column defaults are enforced at the DB
layer — not just in Python. Mirrors the discipline of
``tests/integration/test_migrations_0007_0009.py`` (Slice-3).

PR-S4-0b Component A — Task A1 (failing tests ship FIRST, before A2 lands
the migration). The strict TDD ordering catches off-by-one column-list
drift, missing indexes, and reversed CHECK predicates at the moment the
migration is being authored.
"""

from __future__ import annotations

import datetime as dt

import pytest
import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig

ALEMBIC_INI_PATH = "alembic.ini"

pytestmark = pytest.mark.integration


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> AlembicConfig:
    """Alembic config pointed at the per-test Postgres container.

    Mirrors the existing pattern from ``test_migration_0004_backfill.py``:
    the migration ``env.py`` resolves the DB URL from
    ``ALFRED_DATABASE_URL`` first (so it runs without forcing full
    ``Settings`` construction — which would require provider API keys
    that the CI matrix step doesn't carry). We publish the container URL
    both on the env var AND on the Config object to cover both code
    paths.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = AlembicConfig(ALEMBIC_INI_PATH)
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


@pytest.fixture
def engine_at_0011(alembic_cfg: AlembicConfig, postgres_url: str) -> sa.Engine:
    """Apply migrations up to 0011 (Slice-3 carryover baseline).

    Returns a sync engine for inspection / INSERT / SELECT. The conftest
    ``postgres_url`` fixture yields an asyncpg-shaped URL because
    ``env.py`` uses async; tests use psycopg2 for sync-friendly assertions.
    """
    alembic_command.upgrade(alembic_cfg, "0011")
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    return sa.create_engine(sync_url, future=True)


def _insert_user(engine: sa.Engine, slug: str) -> int:
    """Insert a minimal user row and return the autoincrement id.

    The FK on ``operator_sessions.user_id`` references this column.
    """
    with engine.begin() as conn:
        row = conn.execute(
            sa.text(
                "INSERT INTO users "
                '(slug, display_name, "authorization", daily_budget_usd, language) '
                "VALUES (:slug, :name, 'operator', 1.0, 'en') "
                "RETURNING id"
            ),
            {"slug": slug, "name": f"user-{slug}"},
        ).one()
    return int(row[0])


# ---------------------------------------------------------------------------
# 0012 operator_sessions
# ---------------------------------------------------------------------------


def test_0012_upgrade_creates_operator_sessions_table(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Column-set matches plan §A exactly. Drift caught here."""
    alembic_command.upgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    assert "operator_sessions" in inspector.get_table_names()

    cols = {c["name"]: c for c in inspector.get_columns("operator_sessions")}
    assert set(cols.keys()) == {
        "user_id",
        "token_hash",
        "issued_at",
        "expires_at",
        "host",
        "machine_id_hash",
        "revoked_at",
    }
    # token_hash NOT NULL — load-bearing for PR-S4-5 lookup path.
    assert cols["token_hash"]["nullable"] is False
    # revoked_at nullable — NULL is the live-session signal.
    assert cols["revoked_at"]["nullable"] is True


def test_0012_primary_key_is_token_hash(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """PRIMARY KEY on token_hash. ORM mapping (PR-S4-0b Component E) requires it.

    Postgres allows a tableless-PK declaration but SQLAlchemy ORM does not —
    every mapped class needs a PK. token_hash is the natural lookup column
    AND globally unique (HMAC-SHA256 hex of 256-bit token), so it doubles as PK.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    pk = inspector.get_pk_constraint("operator_sessions")
    assert pk["constrained_columns"] == ["token_hash"], (
        f"expected PK on (token_hash); got {pk['constrained_columns']}"
    )


def test_0012_pk_constraint_named_for_perf_primitive(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """PK constraint name + columns match PR-S4-5's `_resolve_operator` contract.

    Replaces an earlier vacuous duplicate of ``test_0012_primary_key_is_token_hash``
    (rev-cross-cutting + TE-2 finding). PR-S4-5's resolver query plan references
    the PK constraint by name; the constraint name is the public surface that
    PR-S4-5 + ops runbooks call out. Renaming the PK constraint (e.g. dropping
    to Postgres's auto-name `operator_sessions_pkey`) would silently shift the
    contract.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    pk = inspector.get_pk_constraint("operator_sessions")
    assert pk["name"] == "uq_operator_sessions_token_hash", (
        f"expected PK named 'uq_operator_sessions_token_hash'; got {pk['name']!r}"
    )
    assert pk["constrained_columns"] == ["token_hash"]


def test_0012_lookup_index_user_id_expires_at_exists(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """(user_id, expires_at) index covers the session-list UX path.

    Column ORDER is load-bearing (TE-2 finding): a future flip to
    ``(expires_at, user_id)`` would preserve the index name but break
    PR-S4-5's query plan because the WHERE clause leads with user_id.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    ix = next(
        (
            ix
            for ix in inspector.get_indexes("operator_sessions")
            if ix["name"] == "ix_operator_sessions_user_id_expires_at"
        ),
        None,
    )
    assert ix is not None, "missing index ix_operator_sessions_user_id_expires_at"
    # Order matters for index usability — assert list equality, not set.
    assert ix["column_names"] == ["user_id", "expires_at"], (
        f"expected column order ['user_id', 'expires_at']; got {ix['column_names']}"
    )


def test_0012_unique_token_hash_refuses_duplicate(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Duplicate token_hash inserts are refused (replay-defence)."""
    alembic_command.upgrade(alembic_cfg, "0012")
    user_a = _insert_user(engine_at_0011, "dupe-user-a")
    user_b = _insert_user(engine_at_0011, "dupe-user-b")
    with engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO operator_sessions "
                "(user_id, token_hash, issued_at, expires_at, host, machine_id_hash) "
                "VALUES (:u, :th, :i, :e, :h, :m)"
            ),
            {
                "u": user_a,
                "th": "a" * 64,
                "i": dt.datetime.now(dt.UTC),
                "e": dt.datetime.now(dt.UTC) + dt.timedelta(hours=12),
                "h": "ops-a.local",
                "m": "1" * 64,
            },
        )
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO operator_sessions "
                "(user_id, token_hash, issued_at, expires_at, host, "
                "machine_id_hash) "
                "VALUES (:u, :th, :i, :e, :h, :m)"
            ),
            {
                "u": user_b,
                "th": "a" * 64,  # duplicate token_hash
                "i": dt.datetime.now(dt.UTC),
                "e": dt.datetime.now(dt.UTC) + dt.timedelta(hours=12),
                "h": "ops-b.local",
                "m": "2" * 64,
            },
        )


@pytest.mark.parametrize(
    "bad_token_hash",
    [
        "TOO-SHORT",
        "x" * 63,  # 63 chars
        "X" * 64,  # upper-case hex rejected by ^[0-9a-f]{64}$
        "g" * 64,  # 'g' outside hex range
        "0" * 65,  # 65 chars
    ],
)
def test_0012_check_token_hash_refuses_bad_format(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_token_hash: str,
) -> None:
    """CHECK ck_operator_sessions_token_hash_sha256_hex refuses non-hex64 values."""
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(
        engine_at_0011, f"bad-hash-{bad_token_hash.encode().hex()[:12]}"
    )  # deterministic suffix; PYTHONHASHSEED randomises Python hash()
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO operator_sessions "
                "(user_id, token_hash, issued_at, expires_at, host, "
                "machine_id_hash) "
                "VALUES (:u, :th, :i, :e, :h, :m)"
            ),
            {
                "u": user_id,
                "th": bad_token_hash,
                "i": dt.datetime.now(dt.UTC),
                "e": dt.datetime.now(dt.UTC) + dt.timedelta(hours=12),
                "h": "ops-check.local",
                "m": "f" * 64,
            },
        )


def test_0012_check_temporal_expires_after_issued(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """CHECK ck_operator_sessions_expires_after_issued refuses inverted bounds."""
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "temporal-check")
    now = dt.datetime.now(dt.UTC)
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO operator_sessions "
                "(user_id, token_hash, issued_at, expires_at, host, "
                "machine_id_hash) "
                "VALUES (:u, :th, :i, :e, :h, :m)"
            ),
            {
                "u": user_id,
                "th": "b" * 64,
                "i": now,
                "e": now - dt.timedelta(hours=1),  # past-relative expires_at
                "h": "ops-temporal.local",
                "m": "3" * 64,
            },
        )


def test_0012_check_expires_at_within_7d_window(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """CHECK ck_operator_sessions_expires_within_max_window refuses >7d sessions.

    Defence-in-depth: PR-S4-5 CLI clamps to [1h, 7d] but a raw-SQL writer
    (or compromised CLI) cannot mint a long-lived token.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "long-window")
    now = dt.datetime.now(dt.UTC)
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO operator_sessions "
                "(user_id, token_hash, issued_at, expires_at, host, "
                "machine_id_hash) "
                "VALUES (:u, :th, :i, :e, :h, :m)"
            ),
            {
                "u": user_id,
                "th": "c" * 64,
                "i": now,
                "e": now + dt.timedelta(days=8),  # > 7 days
                "h": "ops-window.local",
                "m": "4" * 64,
            },
        )


def test_0012_fk_user_id_cascade_on_user_delete(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """ON DELETE CASCADE on user_id removes operator-session rows.

    Confirms the security-engineer's flagged behaviour: deleting a user
    erases their session forensic trail in this table. The full audit
    log carries the session lifecycle separately.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "cascade-victim")
    now = dt.datetime.now(dt.UTC)
    with engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO operator_sessions "
                "(user_id, token_hash, issued_at, expires_at, host, machine_id_hash) "
                "VALUES (:u, :th, :i, :e, :h, :m)"
            ),
            {
                "u": user_id,
                "th": "d" * 64,
                "i": now,
                "e": now + dt.timedelta(hours=12),
                "h": "ops-cascade.local",
                "m": "5" * 64,
            },
        )
    with engine_at_0011.begin() as conn:
        conn.execute(sa.text("DELETE FROM users WHERE id = :u"), {"u": user_id})
    with engine_at_0011.begin() as conn:
        rows = conn.execute(
            sa.text("SELECT COUNT(*) FROM operator_sessions WHERE user_id = :u"),
            {"u": user_id},
        ).scalar()
    assert rows == 0


def test_0012_downgrade_drops_operator_sessions_and_indexes(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Downgrade removes both table AND its named indexes — no orphans."""
    alembic_command.upgrade(alembic_cfg, "0012")
    alembic_command.downgrade(alembic_cfg, "0011")
    inspector = sa.inspect(engine_at_0011)
    assert "operator_sessions" not in inspector.get_table_names()
    # Index names must not survive on Postgres after table drop.
    # (Postgres drops dependent indexes with the table; assertion guards
    # against any drift to a future schema that detaches them.)
    raw_indexes = (
        inspector.get_indexes("operator_sessions")
        if "operator_sessions" in inspector.get_table_names()
        else []
    )
    assert raw_indexes == []


def test_0012_downgrade_idempotent(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Re-running ``downgrade()`` after a partial rollback completes cleanly.

    Both the index drop AND the table drop use ``IF EXISTS`` so a retried
    rollback (e.g. after a transient ops error mid-downgrade) finishes
    without leaving alembic_version half-applied. We exercise the retry
    path by ``stamp``ing back to 0012 after a successful downgrade — that
    forces alembic to invoke ``downgrade()`` AGAIN against an already-empty
    schema, which is precisely the partial-rollback shape.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    alembic_command.downgrade(alembic_cfg, "0011")
    # Force-stamp the version back to 0012 WITHOUT re-creating the table,
    # then re-run downgrade. This is the retry shape: alembic believes
    # we're at 0012 and runs ``downgrade()``, but the schema is empty.
    alembic_command.stamp(alembic_cfg, "0012")
    alembic_command.downgrade(alembic_cfg, "0011")
    # End state: empty schema, alembic at 0011, no errors.
    inspector = sa.inspect(engine_at_0011)
    assert "operator_sessions" not in inspector.get_table_names()


# ---------------------------------------------------------------------------
# Round-2 review closures: belt-and-braces CHECK constraint coverage
# (TE-4: host length, TE-5: revoked_after_issued, TE-6: machine_id_hash).
# ---------------------------------------------------------------------------


def _ops_session_insert_payload(
    user_id: int,
    *,
    token_hash: str = "9" * 64,
    host: str = "ops-test.local",
    machine_id_hash: str = "f" * 64,
    issued_at: dt.datetime | None = None,
    expires_at: dt.datetime | None = None,
    revoked_at: dt.datetime | None = None,
) -> dict[str, object]:
    """Build a parameter dict for an ``operator_sessions`` INSERT.

    Defaults are valid; tests override the single field they're exercising.
    """
    now = dt.datetime.now(dt.UTC)
    return {
        "u": user_id,
        "th": token_hash,
        "i": issued_at or now,
        "e": expires_at or now + dt.timedelta(hours=12),
        "h": host,
        "m": machine_id_hash,
        "r": revoked_at,
    }


_INSERT_SQL = sa.text(
    "INSERT INTO operator_sessions "
    "(user_id, token_hash, issued_at, expires_at, host, machine_id_hash, "
    "revoked_at) "
    "VALUES (:u, :th, :i, :e, :h, :m, :r)"
)


@pytest.mark.parametrize(
    ("bad_host", "case"),
    [
        ("", "empty"),
        ("x" * 254, "oversized"),
    ],
)
def test_0012_check_host_length_refuses_out_of_range(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_host: str,
    case: str,
) -> None:
    """CHECK ck_operator_sessions_host_length refuses empty + >253 char hosts."""
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, f"host-len-{case}")
    payload = _ops_session_insert_payload(user_id, token_hash=f"{case[0]}" * 64, host=bad_host)
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(_INSERT_SQL, payload)


def test_0012_check_revoked_after_issued_refuses_inverted(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """CHECK ck_operator_sessions_revoked_after_issued refuses revoked<issued."""
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "revoked-before-issued")
    now = dt.datetime.now(dt.UTC)
    payload = _ops_session_insert_payload(
        user_id,
        token_hash="e" * 64,
        issued_at=now,
        expires_at=now + dt.timedelta(hours=12),
        revoked_at=now - dt.timedelta(hours=1),
    )
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(_INSERT_SQL, payload)


@pytest.mark.parametrize(
    "bad_machine_id_hash",
    [
        "TOO-SHORT",
        "x" * 63,
        "X" * 64,
        "g" * 64,
        "0" * 65,
    ],
)
def test_0012_check_machine_id_hash_refuses_bad_format(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_machine_id_hash: str,
) -> None:
    """CHECK ck_operator_sessions_machine_id_hash_sha256_hex refuses non-hex64.

    Symmetric to ``test_0012_check_token_hash_refuses_bad_format`` — both
    hash columns have identical format CHECKs, so they need identical
    refusal coverage to catch a future asymmetric regression.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(
        engine_at_0011, f"mid-hash-{bad_machine_id_hash.encode().hex()[:12]}"
    )  # deterministic suffix; PYTHONHASHSEED randomises Python hash()
    payload = _ops_session_insert_payload(
        user_id,
        token_hash="7" * 64,
        machine_id_hash=bad_machine_id_hash,
    )
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(_INSERT_SQL, payload)


# ---------------------------------------------------------------------------
# Round-3 review closures: boundary-triple coverage on CHECK predicates
# (TE-1 finding — n-1 refused, n accepted, n+1 refused for each predicate).
# ---------------------------------------------------------------------------


def test_0012_check_expires_within_7d_window_boundary(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Boundary triple for ``ck_operator_sessions_expires_within_max_window``.

    Exactly 7d accepted; 7d+1s refused. Catches a future flip from ``<=`` to
    ``<`` that would silently shrink the window by a femtosecond.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "win-boundary")
    now = dt.datetime.now(dt.UTC)
    # Accept at exactly 7d (predicate is ``<=``).
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_SQL,
            _ops_session_insert_payload(
                user_id,
                token_hash="6" * 64,
                issued_at=now,
                expires_at=now + dt.timedelta(days=7),
            ),
        )
    # Refuse at 7d + 1s.
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_SQL,
            _ops_session_insert_payload(
                user_id,
                token_hash="8" * 64,
                issued_at=now,
                expires_at=now + dt.timedelta(days=7, seconds=1),
            ),
        )


def test_0012_check_revoked_at_equals_issued_at_accepted(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Boundary case for ``ck_operator_sessions_revoked_after_issued``.

    ``revoked_at = issued_at`` is accepted because the predicate is ``>=``.
    Refusal at ``revoked_at = issued_at - 1µs`` covered by the inverted test.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "revoked-eq-issued")
    now = dt.datetime.now(dt.UTC)
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_SQL,
            _ops_session_insert_payload(
                user_id,
                token_hash="2" * 64,
                issued_at=now,
                expires_at=now + dt.timedelta(hours=12),
                revoked_at=now,
            ),
        )


@pytest.mark.parametrize(
    ("host", "case", "token_char"),
    [
        ("a", "min-1", "1"),
        ("a" * 253, "max", "2"),
    ],
)
def test_0012_check_host_length_boundary_accepts(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    host: str,
    case: str,
    token_char: str,
) -> None:
    """Boundary cases for ``ck_operator_sessions_host_length`` accept side.

    Length 1 (min) and 253 (max RFC 1035 hostname) accepted. Refusal at
    0 (empty) and 254 already covered by
    ``test_0012_check_host_length_refuses_out_of_range``. Per-case
    ``token_char`` is a hex-valid character ([0-9a-f]) — the earlier
    ``case[0]`` form picked 'm' which fails the token_hash hex CHECK
    regex.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, f"host-len-ok-{case}")
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_SQL,
            _ops_session_insert_payload(user_id, token_hash=token_char * 64, host=host),
        )


# ---------------------------------------------------------------------------
# Round-3 review closures: happy-path round-trip + column-type assertions
# (TE-3 finding — every prior test exercises refusal; pin the success path).
# ---------------------------------------------------------------------------


def test_0012_happy_path_insert_and_select_round_trip(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """A valid 7-column row persists with revoked_at=NULL = live-session signal."""
    alembic_command.upgrade(alembic_cfg, "0012")
    user_id = _insert_user(engine_at_0011, "happy-path")
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    token_hash = "f" * 64
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_SQL,
            _ops_session_insert_payload(
                user_id,
                token_hash=token_hash,
                issued_at=now,
                expires_at=now + dt.timedelta(hours=12),
                host="happy.example.local",
                machine_id_hash="9" * 64,
            ),
        )
    with engine_at_0011.begin() as conn:
        row = conn.execute(
            sa.text(
                "SELECT user_id, token_hash, issued_at, expires_at, host, "
                "machine_id_hash, revoked_at FROM operator_sessions "
                "WHERE token_hash = :th"
            ),
            {"th": token_hash},
        ).one()
    assert row.user_id == user_id
    assert row.token_hash == token_hash
    assert row.host == "happy.example.local"
    assert row.machine_id_hash == "9" * 64
    # The live-session signal: revoked_at IS NULL.
    assert row.revoked_at is None


def test_0012_column_types_match_orm_contract(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Column types match the PR-S4-0b Component E ORM mapping contract.

    Component E will introduce a SQLAlchemy 2.0 typed ``OperatorSession``
    mapped class; widening token_hash or machine_id_hash beyond VARCHAR(64)
    would silently break ``Mapped[str]`` length assumptions used by PR-S4-5's
    Pydantic validators.
    """
    alembic_command.upgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    cols = {c["name"]: c for c in inspector.get_columns("operator_sessions")}
    # Hash columns are VARCHAR(64) — 256-bit HMAC-SHA256 hex.
    assert isinstance(cols["token_hash"]["type"], sa.String)
    assert cols["token_hash"]["type"].length == 64
    assert isinstance(cols["machine_id_hash"]["type"], sa.String)
    assert cols["machine_id_hash"]["type"].length == 64
    # host is VARCHAR(253) — RFC 1035 hostname max.
    assert isinstance(cols["host"]["type"], sa.String)
    assert cols["host"]["type"].length == 253
    # All three timestamptz columns carry timezone=True.
    for tz_col in ("issued_at", "expires_at", "revoked_at"):
        col_type = cols[tz_col]["type"]
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True, f"{tz_col} must be timestamptz (timezone=True)"


# ---------------------------------------------------------------------------
# 0013 policies_snapshot_history
# ---------------------------------------------------------------------------


def test_0013_upgrade_creates_policies_snapshot_history(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Column-set matches plan §B exactly."""
    alembic_command.upgrade(alembic_cfg, "0013")
    inspector = sa.inspect(engine_at_0011)
    assert "policies_snapshot_history" in inspector.get_table_names()
    cols = {c["name"] for c in inspector.get_columns("policies_snapshot_history")}
    assert cols == {
        "snapshot_id",
        "loaded_at",
        "file_sha256",
        "policies_json",
        "swapped_from_snapshot_id",
        "applied_by_operator_session_id",
    }


def test_0013_snapshot_id_primary_key_named(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """PK is named ``uq_policies_snapshot_history_snapshot_id``."""
    alembic_command.upgrade(alembic_cfg, "0013")
    inspector = sa.inspect(engine_at_0011)
    pk = inspector.get_pk_constraint("policies_snapshot_history")
    assert pk["name"] == "uq_policies_snapshot_history_snapshot_id"
    assert pk["constrained_columns"] == ["snapshot_id"]


def test_0013_self_reference_swapped_from(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """swapped_from_snapshot_id is a self-FK preserving snapshot lineage."""
    alembic_command.upgrade(alembic_cfg, "0013")
    inspector = sa.inspect(engine_at_0011)
    fks = inspector.get_foreign_keys("policies_snapshot_history")
    assert any(
        fk["referred_table"] == "policies_snapshot_history"
        and fk["referred_columns"] == ["snapshot_id"]
        and fk["constrained_columns"] == ["swapped_from_snapshot_id"]
        for fk in fks
    ), f"missing self-FK on swapped_from_snapshot_id; got {fks}"


def test_0013_applied_by_operator_session_fk(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """applied_by_operator_session_id FKs operator_sessions.token_hash.

    PR-S4-4 round-2 closure 4: forensic-replay rows carry the
    session token-hash of the operator who triggered the swap (NULL
    for watcher-auto swaps).
    """
    alembic_command.upgrade(alembic_cfg, "0013")
    inspector = sa.inspect(engine_at_0011)
    fks = inspector.get_foreign_keys("policies_snapshot_history")
    assert any(
        fk["referred_table"] == "operator_sessions"
        and fk["referred_columns"] == ["token_hash"]
        and fk["constrained_columns"] == ["applied_by_operator_session_id"]
        for fk in fks
    ), f"missing FK applied_by → operator_sessions.token_hash; got {fks}"


def test_0013_lookup_index_loaded_at_exists(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """``ix_policies_snapshot_history_loaded_at`` covers time-range queries."""
    alembic_command.upgrade(alembic_cfg, "0013")
    inspector = sa.inspect(engine_at_0011)
    ix = next(
        (
            ix
            for ix in inspector.get_indexes("policies_snapshot_history")
            if ix["name"] == "ix_policies_snapshot_history_loaded_at"
        ),
        None,
    )
    assert ix is not None
    assert ix["column_names"] == ["loaded_at"]


@pytest.mark.parametrize(
    "bad_sha",
    [
        "TOO-SHORT",
        "9" * 63,
        "9" * 65,
        "Z" * 64,  # non-hex
    ],
)
def test_0013_check_file_sha256_refuses_bad_format(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_sha: str,
) -> None:
    """CHECK ``ck_policies_snapshot_history_file_sha256_hex`` refuses non-hex64."""
    alembic_command.upgrade(alembic_cfg, "0013")
    snapshot_id = "11111111-2222-3333-4444-555555555555"
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json) "
                "VALUES (:s, :l, :f, :j)"
            ),
            {
                "s": snapshot_id,
                "l": dt.datetime.now(dt.UTC),
                "f": bad_sha,
                "j": "{}",
            },
        )


def test_0013_check_snapshot_id_refuses_bad_uuid(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """CHECK ``ck_policies_snapshot_history_snapshot_id_uuid_hex`` refuses."""
    alembic_command.upgrade(alembic_cfg, "0013")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json) "
                "VALUES (:s, :l, :f, :j)"
            ),
            {
                "s": "not-a-uuid",
                "l": dt.datetime.now(dt.UTC),
                "f": "a" * 64,
                "j": "{}",
            },
        )


def test_0013_happy_path_bootstrap_snapshot_round_trip(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Bootstrap snapshot (swapped_from_snapshot_id IS NULL) round-trips."""
    alembic_command.upgrade(alembic_cfg, "0013")
    snapshot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    with engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json) "
                "VALUES (:s, :l, :f, :j)"
            ),
            {
                "s": snapshot_id,
                "l": now,
                "f": "0" * 64,
                "j": '{"rate_limit_window_seconds": 60}',
            },
        )
    with engine_at_0011.begin() as conn:
        row = conn.execute(
            sa.text(
                "SELECT snapshot_id, file_sha256, swapped_from_snapshot_id, "
                "applied_by_operator_session_id "
                "FROM policies_snapshot_history WHERE snapshot_id = :s"
            ),
            {"s": snapshot_id},
        ).one()
    assert row.snapshot_id == snapshot_id
    assert row.file_sha256 == "0" * 64
    # Bootstrap shape: both nullable FK fields are NULL.
    assert row.swapped_from_snapshot_id is None
    assert row.applied_by_operator_session_id is None


def test_0013_downgrade_drops_table_and_index(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Downgrade removes table + named index."""
    alembic_command.upgrade(alembic_cfg, "0013")
    alembic_command.downgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    assert "policies_snapshot_history" not in inspector.get_table_names()


def test_0013_downgrade_idempotent(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Symmetric fail-soft via IF EXISTS — re-downgrade no-ops cleanly."""
    alembic_command.upgrade(alembic_cfg, "0013")
    alembic_command.downgrade(alembic_cfg, "0012")
    # Re-stamp + re-downgrade exercises the retry path.
    alembic_command.stamp(alembic_cfg, "0013")
    alembic_command.downgrade(alembic_cfg, "0012")
    inspector = sa.inspect(engine_at_0011)
    assert "policies_snapshot_history" not in inspector.get_table_names()


# ---------------------------------------------------------------------------
# Round-2 review closures on 0013: FK refusals + applied_by hex + JSONB cap.
# ---------------------------------------------------------------------------


def test_0013_self_fk_refuses_dangling_swapped_from(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Self-FK on swapped_from_snapshot_id enforced at INSERT time.

    Round-2 TE-209-1 closure: previously only inspector-shape was checked.
    A future migration that dropped the FK clause would have silently passed.
    This test plants a non-existent parent UUID and asserts refusal.
    """
    alembic_command.upgrade(alembic_cfg, "0013")
    snapshot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    dangling = "11111111-2222-3333-4444-555555555555"
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json, "
                "swapped_from_snapshot_id) "
                "VALUES (:s, :l, :f, :j, :p)"
            ),
            {
                "s": snapshot_id,
                "l": dt.datetime.now(dt.UTC),
                "f": "1" * 64,
                "j": "{}",
                "p": dangling,
            },
        )


def test_0013_operator_session_fk_refuses_dangling_applied_by(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """operator_sessions FK enforced — dangling token_hash refused.

    Round-2 TE-209-2 closure + PR-S4-4 closure 4 attestation: the live
    session link cannot be forged at INSERT time; a token_hash that
    doesn't exist in operator_sessions is refused by the FK.
    """
    alembic_command.upgrade(alembic_cfg, "0013")
    snapshot_id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    dangling_session = "0" * 64
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json, "
                "applied_by_operator_session_id) "
                "VALUES (:s, :l, :f, :j, :a)"
            ),
            {
                "s": snapshot_id,
                "l": dt.datetime.now(dt.UTC),
                "f": "2" * 64,
                "j": "{}",
                "a": dangling_session,
            },
        )


@pytest.mark.parametrize(
    "bad_token_hash",
    [
        "TOO-SHORT",
        "x" * 63,
        "X" * 64,  # upper-case rejected by hex regex
        "g" * 64,  # 'g' outside hex range
    ],
)
def test_0013_check_applied_by_hex_refuses_bad_format(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_token_hash: str,
) -> None:
    """CHECK ck_..._applied_by_hex refuses non-hex64 values when non-NULL.

    Round-2 TE-209-3 closure: symmetric to file_sha256 + snapshot_id CHECK
    refusal tests, so a future asymmetric regression where applied_by's
    CHECK gets dropped doesn't slip through.
    """
    alembic_command.upgrade(alembic_cfg, "0013")
    snapshot_id = "cccccccc-dddd-eeee-ffff-000000000000"
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json, "
                "applied_by_operator_session_id) "
                "VALUES (:s, :l, :f, :j, :a)"
            ),
            {
                "s": snapshot_id,
                "l": dt.datetime.now(dt.UTC),
                "f": "3" * 64,
                "j": "{}",
                "a": bad_token_hash,
            },
        )


def test_0013_check_policies_json_size_refuses_oversized(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """CHECK ``ck_..._policies_json_size`` refuses payloads >256 KB.

    Round-2 sec-2 closure: defence-in-depth against direct-INSERT bypass
    of the PR-S4-4 watcher's 256 KB cap. Construct a JSONB payload that
    exceeds the 262144-byte ceiling.
    """
    alembic_command.upgrade(alembic_cfg, "0013")
    snapshot_id = "dddddddd-eeee-ffff-0000-111111111111"
    # 270 KB of JSON content
    huge_value = "x" * (270 * 1024)
    payload_json = f'{{"big": "{huge_value}"}}'
    assert len(payload_json) > 262144  # sanity
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO policies_snapshot_history "
                "(snapshot_id, loaded_at, file_sha256, policies_json) "
                "VALUES (:s, :l, :f, :j)"
            ),
            {
                "s": snapshot_id,
                "l": dt.datetime.now(dt.UTC),
                "f": "4" * 64,
                "j": payload_json,
            },
        )


# ---------------------------------------------------------------------------
# 0014 audit_log result CHECK extension (Slice-4 result values)
# ---------------------------------------------------------------------------


_SLICE_4_RESULT_ADDITIONS = (
    "dispatched_with_redactions",
    "dispatched_clean",
    "recursion_refused",
    "audit_row_emitted",
)


def _insert_audit_row(engine: sa.Engine, *, result: str, event: str = "test.event") -> None:
    """Insert a minimal audit_log row with the given ``result`` value.

    Uses the columns the Slice-1 ``audit_log`` table requires; the
    Slice-4 ``*_FIELDS`` shape data goes into ``subject`` JSON, so this
    helper only varies ``result`` to exercise the CHECK constraint.
    """
    import uuid as _uuid

    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO audit_log "
                "(id, created_at, trace_id, event, actor_persona, subject, "
                "trust_tier_of_trigger, result, cost_estimate_usd, language) "
                "VALUES (:id, :ts, :tr, :ev, :ap, :sj, :tt, :rs, :ce, :lang)"
            ),
            {
                "id": str(_uuid.uuid4()),
                "ts": dt.datetime.now(dt.UTC),
                "tr": "trace-test",
                "ev": event,
                "ap": "alfred",
                "sj": "{}",
                "tt": "T0",
                "rs": result,
                "ce": 0.0,
                "lang": "en-US",
            },
        )


@pytest.mark.parametrize("result_value", _SLICE_4_RESULT_ADDITIONS)
def test_0014_check_accepts_slice_4_result_value(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    result_value: str,
) -> None:
    """Each Slice-4 result value is accepted after migration 0014."""
    alembic_command.upgrade(alembic_cfg, "0014")
    _insert_audit_row(engine_at_0011, result=result_value)


def test_0014_check_refuses_pre_existing_typo(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """CHECK refuses typo values not in the closed vocab.

    Pins the gate: a future writer accidentally emitting "dispached"
    (typo of dispatched_clean) gets refused at the DB layer.
    """
    alembic_command.upgrade(alembic_cfg, "0014")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO audit_log "
                "(id, created_at, trace_id, event, actor_persona, subject, "
                "trust_tier_of_trigger, result, cost_estimate_usd, language) "
                "VALUES (:id, :ts, :tr, :ev, :ap, :sj, :tt, :rs, :ce, :lang)"
            ),
            {
                "id": "11111111-2222-3333-4444-555555555555",
                "ts": dt.datetime.now(dt.UTC),
                "tr": "trace-typo",
                "ev": "test.event",
                "ap": "alfred",
                "sj": "{}",
                "tt": "T0",
                "rs": "dispached",  # typo
                "ce": 0.0,
                "lang": "en-US",
            },
        )


def test_0014_preserves_slice_3_values(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Existing Slice-3 closed-vocab values still accepted after 0014.

    Spot-check several representative values from each historical slice
    to confirm the upgrade is strictly ADDITIVE — no Slice-3 emit-site
    silently breaks because its result value was dropped from the
    closed vocab.
    """
    alembic_command.upgrade(alembic_cfg, "0014")
    for v in (
        "success",  # Slice-1
        "refused",  # Slice-2
        "fault",  # Slice-2.5
        "extracted",  # Slice-3
        "tripped",
        "reset",
    ):
        _insert_audit_row(engine_at_0011, result=v, event=f"test.preserve.{v}")


def test_0014_downgrade_deletes_slice_4_rows(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Downgrade DELETES rows with Slice-4 result values before restoring
    the pre-Slice-4 CHECK.

    Loud-destruction discipline (matches migrations 0005 / 0006 / 0007):
    operators who care about Slice-4 audit history snapshot the table
    BEFORE downgrading. This test pins that contract.
    """
    alembic_command.upgrade(alembic_cfg, "0014")
    _insert_audit_row(engine_at_0011, result="dispatched_clean", event="will.die")
    _insert_audit_row(engine_at_0011, result="success", event="will.survive")
    alembic_command.downgrade(alembic_cfg, "0013")
    with engine_at_0011.begin() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT result FROM audit_log WHERE event IN "
                "('will.die', 'will.survive') ORDER BY event"
            )
        ).all()
    # 'will.die' (dispatched_clean) is deleted; 'will.survive' (success)
    # remains. Both events are in the result set on downgrade verification.
    surviving = [r.result for r in rows]
    assert "success" in surviving
    assert "dispatched_clean" not in surviving


def test_0014_downgrade_restores_slice_3_check(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """After downgrade, attempting to insert a Slice-4 value is refused."""
    alembic_command.upgrade(alembic_cfg, "0014")
    alembic_command.downgrade(alembic_cfg, "0013")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)):
        _insert_audit_row(engine_at_0011, result="dispatched_clean")


def test_0014_idempotent_upgrade_downgrade_roundtrip(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Upgrade → downgrade → upgrade preserves non-Slice-4 rows.

    Round-2 test-engineer closure: pins the realistic hotfix-rollback-
    then-re-apply path. Slice-3 baseline rows survive the round-trip;
    Slice-4 rows are destroyed (per downgrade contract) and would need
    to be replayed by the writers themselves.
    """
    alembic_command.upgrade(alembic_cfg, "0014")
    # Plant a baseline (Slice-1) row that must survive both transitions.
    _insert_audit_row(engine_at_0011, result="success", event="roundtrip.survivor")
    alembic_command.downgrade(alembic_cfg, "0013")
    # Re-upgrade — CHECK is restored to the Slice-4 vocab.
    alembic_command.upgrade(alembic_cfg, "0014")
    with engine_at_0011.begin() as conn:
        rows = conn.execute(
            sa.text("SELECT result FROM audit_log WHERE event = :ev"),
            {"ev": "roundtrip.survivor"},
        ).all()
    assert [r.result for r in rows] == ["success"], (
        f"baseline Slice-1 row didn't survive round-trip; saw {rows}"
    )
    # And Slice-4 INSERT is accepted again after the re-upgrade.
    _insert_audit_row(engine_at_0011, result="dispatched_clean", event="post-reup")


def test_0014_baseline_results_matches_slice_3_head() -> None:
    """``_BASE_RESULTS`` matches the Slice-3 (migration 0007) closed vocab.

    Round-2 cross-cutting closure: a future Slice-3 fixup that extends
    the vocab without updating this tuple would have downgrade restore
    a stale baseline that silently rejects emit-sites the operator was
    happy to use. This assertion pins the count + key Slice-3 members
    so the drift fails fast.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_mig_0014",
        "src/alfred/memory/migrations/versions/0014_audit_result_slice4_values.py",
    )
    assert spec is not None and spec.loader is not None
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    # 5 (Slice-1) + 10 (Slice-2) + 2 (Slice-2.5) + 13 (Slice-3) = 30 baseline.
    assert len(mig._BASE_RESULTS) == 30, (
        f"_BASE_RESULTS size drifted from Slice-3 head (expected 30); got {len(mig._BASE_RESULTS)}"
    )
    # Spot-check representative values per slice.
    for required in ("success", "refused", "fault", "extracted", "content_expired"):
        assert required in mig._BASE_RESULTS, (
            f"missing {required!r} in _BASE_RESULTS — Slice-3 baseline drift"
        )


# ---------------------------------------------------------------------------
# 0015 sandbox_policy_registry
# ---------------------------------------------------------------------------


_INSERT_REGISTRY_SQL = sa.text(
    "INSERT INTO sandbox_policy_registry "
    "(plugin_id, host_os, policy_ref, last_resolved_at, resolution_result) "
    "VALUES (:p, :o, :r, :t, :res)"
)


def _registry_payload(
    plugin_id: str = "alfred_quarantined_llm",
    host_os: str = "linux",
    policy_ref: str = "quarantined-llm.linux.bwrap",
    resolution_result: str = "resolved",
) -> dict[str, object]:
    """Build a parametric INSERT payload; defaults are valid."""
    return {
        "p": plugin_id,
        "o": host_os,
        "r": policy_ref,
        "t": dt.datetime.now(dt.UTC),
        "res": resolution_result,
    }


def test_0015_upgrade_creates_sandbox_policy_registry(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Column-set matches plan §D exactly."""
    alembic_command.upgrade(alembic_cfg, "0015")
    inspector = sa.inspect(engine_at_0011)
    assert "sandbox_policy_registry" in inspector.get_table_names()
    cols = {c["name"] for c in inspector.get_columns("sandbox_policy_registry")}
    assert cols == {
        "plugin_id",
        "policy_ref",
        "host_os",
        "last_resolved_at",
        "resolution_result",
    }


def test_0015_composite_pk_named(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """PK ``uq_sandbox_policy_registry_plugin_host_os`` is composite."""
    alembic_command.upgrade(alembic_cfg, "0015")
    inspector = sa.inspect(engine_at_0011)
    pk = inspector.get_pk_constraint("sandbox_policy_registry")
    assert pk["name"] == "uq_sandbox_policy_registry_plugin_host_os"
    # Order matters — the composite PK's column order influences index plan.
    assert pk["constrained_columns"] == ["plugin_id", "host_os"]


@pytest.mark.parametrize("host_os", ["linux", "macos", "windows"])
def test_0015_host_os_check_accepts_valid(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    host_os: str,
) -> None:
    """Each of the three valid host_os values is accepted."""
    alembic_command.upgrade(alembic_cfg, "0015")
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            _registry_payload(host_os=host_os),
        )


@pytest.mark.parametrize("bad_host_os", ["freebsd", "Linux", "android", "", "linux "])
def test_0015_host_os_check_refuses_invalid(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_host_os: str,
) -> None:
    """CHECK refuses host_os values outside the closed vocab."""
    alembic_command.upgrade(alembic_cfg, "0015")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            _registry_payload(
                plugin_id=f"badhost_{bad_host_os or 'empty'}",
                host_os=bad_host_os,
            ),
        )


@pytest.mark.parametrize(
    "bad_result",
    ["accepted", "resolved_ok", "stubbed", "", "REFUSED_POLICY_MISSING"],
)
def test_0015_resolution_result_check_refuses_invalid(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_result: str,
) -> None:
    """CHECK refuses resolution_result values outside the closed vocab."""
    alembic_command.upgrade(alembic_cfg, "0015")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            _registry_payload(
                plugin_id=f"badres_{bad_result or 'empty'}",
                resolution_result=bad_result,
            ),
        )


def test_0015_composite_pk_refuses_duplicate(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Two rows with the same ``(plugin_id, host_os)`` are refused."""
    alembic_command.upgrade(alembic_cfg, "0015")
    with engine_at_0011.begin() as conn:
        conn.execute(_INSERT_REGISTRY_SQL, _registry_payload())
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(_INSERT_REGISTRY_SQL, _registry_payload())


def test_0015_same_plugin_different_os_accepted(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Same plugin_id across different host_os is the canonical shape."""
    alembic_command.upgrade(alembic_cfg, "0015")
    for os_value in ("linux", "macos", "windows"):
        with engine_at_0011.begin() as conn:
            conn.execute(
                _INSERT_REGISTRY_SQL,
                _registry_payload(host_os=os_value),
            )
    with engine_at_0011.begin() as conn:
        count = conn.execute(
            sa.text("SELECT COUNT(*) FROM sandbox_policy_registry WHERE plugin_id = :p"),
            {"p": "alfred_quarantined_llm"},
        ).scalar()
    assert count == 3


def test_0015_happy_path_round_trip(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Insert + select round-trip preserves all 5 columns."""
    alembic_command.upgrade(alembic_cfg, "0015")
    plugin_id = "round_trip_plugin"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            {
                "p": plugin_id,
                "o": "linux",
                "r": "policies/round-trip.linux.bwrap",
                "t": now,
                "res": "resolved",
            },
        )
    with engine_at_0011.begin() as conn:
        row = conn.execute(
            sa.text(
                "SELECT plugin_id, host_os, policy_ref, "
                "last_resolved_at, resolution_result "
                "FROM sandbox_policy_registry WHERE plugin_id = :p"
            ),
            {"p": plugin_id},
        ).one()
    assert row.plugin_id == plugin_id
    assert row.host_os == "linux"
    assert row.policy_ref == "policies/round-trip.linux.bwrap"
    assert row.resolution_result == "resolved"
    # PR #211 cross-cutting closure: assert the 5th column too.
    assert row.last_resolved_at == now


def test_0015_downgrade_drops_table(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Downgrade removes the table cleanly."""
    alembic_command.upgrade(alembic_cfg, "0015")
    alembic_command.downgrade(alembic_cfg, "0014")
    inspector = sa.inspect(engine_at_0011)
    assert "sandbox_policy_registry" not in inspector.get_table_names()


def test_0015_downgrade_idempotent(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """Symmetric fail-soft via IF EXISTS — re-downgrade no-ops cleanly."""
    alembic_command.upgrade(alembic_cfg, "0015")
    alembic_command.downgrade(alembic_cfg, "0014")
    alembic_command.stamp(alembic_cfg, "0015")
    alembic_command.downgrade(alembic_cfg, "0014")
    inspector = sa.inspect(engine_at_0011)
    assert "sandbox_policy_registry" not in inspector.get_table_names()


# ---------------------------------------------------------------------------
# Round-2 review closures on 0015: UPSERT semantic, length boundaries,
# plugin_id charset CHECK, policy_ref path-traversal CHECK.
# ---------------------------------------------------------------------------


def test_0015_upsert_via_on_conflict_updates_in_place(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
) -> None:
    """``INSERT ... ON CONFLICT (plugin_id, host_os) DO UPDATE`` is the
    natural shape for the launcher's "latest state" write.

    PR #211 test-engineer MED closure: pins the UPSERT contract so a
    future PK rename / column re-order doesn't silently break the
    launcher's write path.
    """
    alembic_command.upgrade(alembic_cfg, "0015")
    plugin_id = "upsert_plugin"
    t1 = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=5)
    t2 = dt.datetime.now(dt.UTC).replace(microsecond=0)
    upsert_sql = sa.text(
        "INSERT INTO sandbox_policy_registry "
        "(plugin_id, host_os, policy_ref, last_resolved_at, resolution_result) "
        "VALUES (:p, :o, :r, :t, :res) "
        "ON CONFLICT (plugin_id, host_os) DO UPDATE SET "
        "policy_ref = EXCLUDED.policy_ref, "
        "last_resolved_at = EXCLUDED.last_resolved_at, "
        "resolution_result = EXCLUDED.resolution_result"
    )
    # First write: stub_used (e.g. dev environment).
    with engine_at_0011.begin() as conn:
        conn.execute(
            upsert_sql,
            {
                "p": plugin_id,
                "o": "linux",
                "r": "policies/upsert.linux.bwrap",
                "t": t1,
                "res": "stub_used",
            },
        )
    # Second write: same (plugin, OS) but resolved policy.
    with engine_at_0011.begin() as conn:
        conn.execute(
            upsert_sql,
            {
                "p": plugin_id,
                "o": "linux",
                "r": "policies/upsert-v2.linux.bwrap",
                "t": t2,
                "res": "resolved",
            },
        )
    with engine_at_0011.begin() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT policy_ref, last_resolved_at, resolution_result "
                "FROM sandbox_policy_registry WHERE plugin_id = :p"
            ),
            {"p": plugin_id},
        ).all()
    assert len(rows) == 1, "ON CONFLICT must keep exactly one row"
    assert rows[0].policy_ref == "policies/upsert-v2.linux.bwrap"
    assert rows[0].last_resolved_at == t2
    assert rows[0].resolution_result == "resolved"


@pytest.mark.parametrize(
    ("plugin_id_value", "case"),
    [
        ("a", "min-1"),
        ("a" * 128, "max"),
    ],
)
def test_0015_plugin_id_length_boundary_accepts(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    plugin_id_value: str,
    case: str,
) -> None:
    """plugin_id 1 and 128 chars accepted (boundary triple — refusal at
    129 covered by the format CHECK refusal test below)."""
    alembic_command.upgrade(alembic_cfg, "0015")
    with engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            _registry_payload(plugin_id=plugin_id_value),
        )


@pytest.mark.parametrize(
    "bad_plugin_id",
    [
        "Plugin-With-Hyphen",  # hyphen rejected by [a-z0-9_]
        "PLUGIN_UPPER",  # uppercase rejected
        "plugin.dotted",  # dot rejected
        "plugin space",  # whitespace rejected
        "",  # empty (zero-length rejected by {1,128})
        "a" * 129,  # 129 chars overflows the {1,128} cap
    ],
)
def test_0015_plugin_id_charset_check_refuses_invalid(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_plugin_id: str,
) -> None:
    """CHECK ``ck_sandbox_policy_registry_plugin_id_format`` refuses
    non-snake_case / overflow plugin_id values.

    PR #211 sec/mem closure: prevents silent PK sharding from typo'd
    or upper-cased writer-side ids.
    """
    alembic_command.upgrade(alembic_cfg, "0015")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            _registry_payload(plugin_id=bad_plugin_id),
        )


@pytest.mark.parametrize(
    "bad_policy_ref",
    [
        "/etc/passwd",  # absolute path
        "/usr/share/policies/x",  # absolute path
        "../../../etc/shadow",  # parent-directory escape
        "policies/../../etc/passwd",  # mid-path escape
        "x/../y",  # any .. anywhere
    ],
)
def test_0015_policy_ref_check_refuses_path_traversal(
    alembic_cfg: AlembicConfig,
    engine_at_0011: sa.Engine,
    bad_policy_ref: str,
) -> None:
    """CHECK ``ck_sandbox_policy_registry_policy_ref_relative`` refuses
    absolute paths and parent-directory escapes.

    PR #211 sec closure: defence-in-depth against a buggy/malicious
    writer planting paths that resolve outside the sandbox-policy root.
    """
    alembic_command.upgrade(alembic_cfg, "0015")
    with pytest.raises((sa.exc.IntegrityError, sa.exc.DataError)), engine_at_0011.begin() as conn:
        conn.execute(
            _INSERT_REGISTRY_SQL,
            _registry_payload(
                plugin_id="path_traversal_test",
                policy_ref=bad_policy_ref,
            ),
        )
