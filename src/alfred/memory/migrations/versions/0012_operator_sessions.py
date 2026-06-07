"""operator_sessions — CLI operator-session token table (Slice-4 PR-S4-5).

Revision ID: 0012
Revises: 0011
Create Date: 2026-06-07 00:00:00.000000

``operator_sessions`` holds one row per active CLI session created by
``alfred login --as <user>`` (PR-S4-5). The session token is hashed
before storage; the raw token lives only in ``~/.config/alfred/session``
on the operator's machine (mode 0600 — per the operator-session spec).
Each row has a 12-hour expiry by default plus a host-binding column so a
stolen token cannot be replayed from a different machine.

``token_hash`` is the natural lookup key and natural PRIMARY KEY: it is
globally unique (HMAC-SHA256 hex of a 256-bit token) AND the column
PR-S4-5's ``_resolve_operator`` reads on every CLI invocation. Postgres
auto-creates the unique index for the PK, giving the single-probe
performance ADR-0024 budgets at <= 5 ms p99.

Columns
-------

* ``user_id`` — Integer FK to ``users.id`` (the Slice-2 autoincrement
  PK, per migration 0004). ``ON DELETE CASCADE`` so a deleted operator's
  sessions vanish with the row. The full audit log carries session
  lifecycle for deleted users separately.
* ``token_hash`` — HMAC-SHA256 of the random session token, hex-encoded
  (64 chars = 256 bits, the full HMAC output). PRIMARY KEY. Keyed by an
  HKDF-derived subkey (``_TOKEN_HASH_SUBKEY``) from ``audit.hash_pepper``
  per PR-S4-5 round-2 closure 3 — the master pepper is HKDF-expanded
  into per-purpose subkeys for domain separation so a leaked DB cannot
  mass-replay tokens. The CHECK constraint is recipe-agnostic (256-bit
  hex either way); the recipe itself is enforced at the application layer.
* ``issued_at`` — timestamptz when ``alfred login`` minted the token.
* ``expires_at`` — timestamptz of expiry. CLI defaults to 12 h with
  ``[1 h, 7 d]`` bounds; the DB enforces an upper-bound 7 d window via
  CHECK (defence-in-depth against a raw-SQL writer minting long sessions).
* ``host`` — the hostname the token is bound to. Length CHECK keeps it
  in the [1, 253] range (RFC 1035 hostname max). Refusal reason
  ``host_mismatch`` fires when ``_resolve_operator`` sees a different
  ``socket.gethostname()``.
* ``machine_id_hash`` — HMAC-SHA256 of the per-OS system machine-id
  using the HKDF-derived ``_MACHINE_ID_HASH_SUBKEY`` from
  ``audit.hash_pepper`` (PR-S4-5 closure 3; domain-separated from
  ``_TOKEN_HASH_SUBKEY`` so a token-hash leak cannot be replayed as a
  machine-id-hash). The raw machine-id never lands in the DB. Refusal
  reason ``machine_mismatch`` fires when ``_resolve_operator`` sees a
  different machine-id hash.
* ``revoked_at`` — timestamptz of revocation; NULL for active sessions.
  ``alfred logout`` sets this column; later sessions for the same user
  create new rows.

Indexes
-------

* PRIMARY KEY on ``token_hash`` — Postgres auto-creates a unique btree;
  this is the load-bearing single-probe primitive for PR-S4-5's
  ``_resolve_operator`` 5 ms p99 budget.
* ``ix_operator_sessions_user_id_expires_at`` — covers the
  ``alfred user show <user>`` session-list path.

Constraints
-----------

* ``ck_operator_sessions_token_hash_sha256_hex`` — pins the SHA-256 hex
  64-char format (full HMAC-SHA256 output, no truncation). A future
  refactor to a different hash recipe (or accidental raw-bytes write)
  is refused at the DB layer.
* ``ck_operator_sessions_machine_id_hash_sha256_hex`` — same shape for
  the machine-id hash.
* ``ck_operator_sessions_host_length`` — host in [1, 253] chars
  (RFC 1035 max hostname). Refuses oversized writes that would conflate
  ``host_mismatch`` with ``malformed_host``.
* ``ck_operator_sessions_revoked_after_issued`` — temporal sanity.
* ``ck_operator_sessions_expires_after_issued`` — temporal sanity.
* ``ck_operator_sessions_expires_within_max_window`` — caps lifetime to
  7 days (CLI bound enforced at DB as defence in depth).

server_default rationale (mem-005 pattern)
------------------------------------------

``revoked_at`` is nullable with no server_default — the absence of a
value is the live-session signal. The other timestamptz columns
(``issued_at``, ``expires_at``) are populated by PR-S4-5's CLI code on
every insert and have no server_default; a raw-SQL writer must supply
them.

Downgrade
---------

DROP TABLE. Operators re-login on revert. The drop_index calls use
``if_exists=True`` so a retried rollback after a transient ops error
completes cleanly without leaving ``alembic_version`` half-applied.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Alembic reads ``revision`` / ``down_revision`` / ``branch_labels`` /
# ``depends_on`` via module introspection (see
# ``alembic.script.revision``). Declaring them in ``__all__`` silences
# CodeQL's py/unused-global-variable false positive — same pattern as
# migrations 0004-0011.
__all__ = [
    "branch_labels",
    "depends_on",
    "down_revision",
    "downgrade",
    "revision",
    "upgrade",
]


def upgrade() -> None:
    """Create operator_sessions table + indexes + CHECK constraints."""
    op.create_table(
        "operator_sessions",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # token_hash is the natural PK + 5 ms lookup primitive. Naming the
        # PK constraint matters: PR-S4-5's plan + integration tests assert
        # on the index name ``uq_operator_sessions_token_hash``. Postgres
        # auto-creates a unique btree for the PK; naming the constraint
        # explicitly publishes that name to consumers.
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("token_hash", name="uq_operator_sessions_token_hash"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("machine_id_hash", sa.String(64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_operator_sessions_token_hash_sha256_hex",
        ),
        sa.CheckConstraint(
            "machine_id_hash ~ '^[0-9a-f]{64}$'",
            name="ck_operator_sessions_machine_id_hash_sha256_hex",
        ),
        sa.CheckConstraint(
            "char_length(host) BETWEEN 1 AND 253",
            name="ck_operator_sessions_host_length",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= issued_at",
            name="ck_operator_sessions_revoked_after_issued",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at",
            name="ck_operator_sessions_expires_after_issued",
        ),
        sa.CheckConstraint(
            "expires_at <= issued_at + INTERVAL '7 days'",
            name="ck_operator_sessions_expires_within_max_window",
        ),
    )
    op.create_index(
        "ix_operator_sessions_user_id_expires_at",
        "operator_sessions",
        ["user_id", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop operator_sessions; operators re-login on revert.

    Symmetric fail-soft: BOTH the index drop AND the table drop use
    ``IF EXISTS`` so a retried rollback after a transient ops error
    completes cleanly without leaving ``alembic_version`` half-applied.
    The ``op.execute`` form is used for the table because alembic's
    ``op.drop_table`` has no ``if_exists`` kwarg in this version.
    """
    op.drop_index(
        "ix_operator_sessions_user_id_expires_at",
        table_name="operator_sessions",
        if_exists=True,
    )
    op.execute("DROP TABLE IF EXISTS operator_sessions")
