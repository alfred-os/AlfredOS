"""Migration 0004 backfill — four scenarios (spec §5 te-001).

(a) Custom ``ALFRED_OPERATOR_NAME`` — backfills ``episodes.user_id`` +
    ``audit_log.actor_user_id`` to the canonical slug.
(b) Default operator name ``operator`` — backfill UPDATE is a no-op (literal
    already == slug).
(c) Non-operator slug collision — refuses with ``OperatorSlugCollisionError``
    and the spec'd remediation message.
(d) ADD COLUMN coverage — pre-existing rows get NULL for the new
    ``persona_id`` column; downgrade drops the column + two tables without
    mangling 0003-shape row content.

Spec-vs-reality reconciliation
------------------------------

The spec's plan body inserts test rows with ``language=NULL`` and adds
``language`` as a new nullable column in 0004. ``language`` already shipped
in Slice 1 (migration 0001) as ``NOT NULL String(16)`` per CLAUDE.md i18n
rule #3, so the migration only adds the genuinely new ``persona_id`` column.
The tests below insert ``'en-US'`` for ``language`` accordingly. See the
0004 migration module docstring for the longer note.
"""

from __future__ import annotations

from typing import Any

import pytest
from alembic import command, config
from sqlalchemy import Engine, inspect, text

from alfred.identity.errors import OperatorSlugCollisionError

pytestmark = pytest.mark.integration


@pytest.fixture
def alembic_cfg(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> config.Config:
    """Alembic Config pointed at the per-test container.

    The migration env.py resolves the DB URL from ``ALFRED_DATABASE_URL``
    first (so it can run without Settings construction), so we publish the
    container URL there as well as on the Config object — covers both
    code paths in env.py without surprise.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


def _upgrade_to(cfg: config.Config, rev: str) -> None:
    command.upgrade(cfg, rev)


def _downgrade_to(cfg: config.Config, rev: str) -> None:
    command.downgrade(cfg, rev)


def _insert_episode(conn: Any, *, user_id: str, content: str = "hi") -> None:
    """Insert an episodes row via raw SQL (avoids ORM coupling to PR-A schema)."""
    conn.execute(
        text(
            "INSERT INTO episodes (id, created_at, user_id, persona, role, content, "
            "trust_tier, language, tokens_in, tokens_out, cost_usd, metadata) "
            "VALUES (gen_random_uuid(), now(), :user_id, 'alfred', 'user', :content, "
            "'T2', 'en-US', 0, 0, 0.0, '{}')"
        ),
        {"user_id": user_id, "content": content},
    )


def _insert_audit(conn: Any, *, actor_user_id: str) -> None:
    """Insert an audit_log row via raw SQL."""
    conn.execute(
        text(
            "INSERT INTO audit_log (id, created_at, trace_id, event, actor_user_id, "
            "actor_persona, subject, trust_tier_of_trigger, result, cost_estimate_usd, "
            "cost_actual_usd, language) "
            "VALUES (gen_random_uuid(), now(), 'trace-1', 'tui.turn', :actor_user_id, "
            "'alfred', '{}', 'T2', 'success', 0.0, NULL, 'en-US')"
        ),
        {"actor_user_id": actor_user_id},
    )


def test_backfill_a_custom_operator_name(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (a) — ``ALFRED_OPERATOR_NAME='Bruce Wayne'`` produces slug
    ``'bruce-wayne'``; episodes + audit_log rows referencing the literal old
    user_id are updated to the canonical slug; row counts preserved."""
    _upgrade_to(alembic_cfg, "0003")
    with postgres_engine.begin() as conn:
        _insert_episode(conn, user_id="Bruce Wayne")
        _insert_audit(conn, actor_user_id="Bruce Wayne")
        before_episodes = conn.scalar(text("SELECT COUNT(*) FROM episodes"))
        before_audit = conn.scalar(text("SELECT COUNT(*) FROM audit_log"))

    monkeypatch.setenv("ALFRED_OPERATOR_NAME", "Bruce Wayne")
    _upgrade_to(alembic_cfg, "0004")

    with postgres_engine.begin() as conn:
        operator = conn.execute(
            text(
                'SELECT slug, display_name, "authorization" FROM users '
                "WHERE \"authorization\"='operator'"
            )
        ).one()
        assert operator.slug == "bruce-wayne"
        assert operator.display_name == "Bruce Wayne"

        # Backfill correctness — every old row now points at the canonical slug.
        assert (
            conn.scalar(text("SELECT COUNT(*) FROM episodes WHERE user_id='bruce-wayne'"))
            == before_episodes
        )
        assert (
            conn.scalar(text("SELECT COUNT(*) FROM audit_log WHERE actor_user_id='bruce-wayne'"))
            == before_audit
        )

        # Append-only audit invariant — no audit row deleted.
        assert conn.scalar(text("SELECT COUNT(*) FROM audit_log")) == before_audit


def test_backfill_b_default_operator_no_op(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (b) — default ``operator`` produces slug ``operator``; the
    backfill UPDATE matches zero rows (literal already equals the slug)."""
    monkeypatch.delenv("ALFRED_OPERATOR_NAME", raising=False)
    _upgrade_to(alembic_cfg, "0003")
    with postgres_engine.begin() as conn:
        _insert_episode(conn, user_id="operator")

    _upgrade_to(alembic_cfg, "0004")

    with postgres_engine.begin() as conn:
        assert conn.scalar(text("SELECT COUNT(*) FROM episodes WHERE user_id='operator'")) == 1
        assert (
            conn.scalar(text("SELECT slug FROM users WHERE \"authorization\"='operator'"))
            == "operator"
        )


def test_backfill_c_collision_refusal(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (c) — a non-operator users row at slug ``'bruce-wayne'`` already
    exists; the operator install refuses with ``OperatorSlugCollisionError``
    naming the colliding slug.

    Construction note: the ``users`` table doesn't exist until 0004's
    ``CREATE TABLE``, so the colliding row can't be pre-inserted before the
    migration runs. We compose the migration's three helpers
    (``_create_tables``, ``_add_persona_id_columns``, ``_install_operator``)
    by hand under a real Alembic ``MigrationContext``, inserting the
    colliding non-operator row between the second and third steps. This
    exercises the same production code path — only the framing changes.
    Alembic's ``command.upgrade`` is not appropriate here because the
    framework loads each migration into a fresh module per invocation,
    making monkeypatch-based injection impossible.
    """
    import importlib

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    # File-name-with-leading-digit forces ``importlib.import_module``;
    # ``from alfred.memory.migrations.versions import 0004_…`` is a syntax error.
    v_0004 = importlib.import_module("alfred.memory.migrations.versions.0004_users_and_identities")

    _upgrade_to(alembic_cfg, "0003")
    monkeypatch.setenv("ALFRED_OPERATOR_NAME", "Bruce Wayne")

    # Run the three helpers manually with an injected collider between
    # ``_add_persona_id_columns`` and ``_install_operator``. ``Operations
    # .context(ctx)`` is a classmethod context manager that installs the
    # ``alembic.op`` proxy so the helpers (which call ``op.create_table``
    # etc.) resolve through our hand-built MigrationContext.
    with postgres_engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            v_0004._create_tables()
            v_0004._add_persona_id_columns()
            # Insert the non-operator collider after the tables exist.
            conn.execute(
                text(
                    'INSERT INTO users (slug, display_name, "authorization", '
                    "daily_budget_usd, language) "
                    "VALUES ('bruce-wayne', 'Other Bruce', 'standard', 1.0, 'en-US')"
                )
            )
            with pytest.raises(OperatorSlugCollisionError, match="bruce-wayne"):
                v_0004._install_operator(conn)


def test_backfill_d_add_column_and_downgrade(
    alembic_cfg: config.Config,
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (d) — ADD COLUMN coverage + downgrade-drops-cleanly invariant.

    The plan body asserts pre-existing rows get NULL for both ``language``
    and ``persona_id``. ``language`` already exists from migration 0001 as
    NOT NULL, so only the genuinely new ``persona_id`` column is asserted
    here. See module docstring + migration docstring for the reconciliation.
    """
    _upgrade_to(alembic_cfg, "0003")
    with postgres_engine.begin() as conn:
        _insert_episode(conn, user_id="operator", content="pre-0004 row")

    _upgrade_to(alembic_cfg, "0004")

    insp = inspect(postgres_engine)
    with postgres_engine.begin() as conn:
        # Pre-existing row has NULL for the new persona_id column (no
        # destructive backfill of stored content).
        row = conn.execute(
            text("SELECT persona_id, language FROM episodes WHERE content='pre-0004 row'")
        ).one()
        assert row.persona_id is None
        # ``language`` was set at insert time (Slice 1 NOT NULL invariant);
        # 0004 leaves it untouched.
        assert row.language == "en-US"

        ep_cols = {c["name"]: c["type"] for c in insp.get_columns("episodes")}
        al_cols = {c["name"]: c["type"] for c in insp.get_columns("audit_log")}
        assert "persona_id" in ep_cols
        assert "persona_id" in al_cols
        # TEXT, not VARCHAR — Postgres TEXT is the preferred unbounded form.
        assert str(ep_cols["persona_id"]).upper().startswith("TEXT")
        assert str(al_cols["persona_id"]).upper().startswith("TEXT")

    # Downgrade drops the new column + two tables.
    _downgrade_to(alembic_cfg, "0003")
    insp_after = inspect(postgres_engine)
    with postgres_engine.begin() as conn:
        assert "users" not in insp_after.get_table_names()
        assert "platform_identities" not in insp_after.get_table_names()
        ep_cols_after = {c["name"] for c in insp_after.get_columns("episodes")}
        al_cols_after = {c["name"] for c in insp_after.get_columns("audit_log")}
        assert "persona_id" not in ep_cols_after
        assert "persona_id" not in al_cols_after
        # 0003 row content survives the downgrade.
        assert conn.scalar(text("SELECT COUNT(*) FROM episodes WHERE content='pre-0004 row'")) == 1
