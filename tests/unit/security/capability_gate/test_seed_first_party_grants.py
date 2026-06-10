"""``PostgresBackend.seed_first_party_grants`` unit coverage (PR-S4-11b0).

The seed method lands the ADR-0026 first-party system grants into
``plugin_grants`` at boot, BEFORE the in-memory policy load. Driver-free
unit tier (mirrors :mod:`tests.unit.security.capability_gate.test_storage_backend`):
the session factory is stubbed and the test asserts on the SQL the
backend emits.

Pinned invariants:

* **One transaction** — all rows upsert inside a SINGLE ``session.begin()``
  block (one :meth:`PostgresBackend._session` open) so a seed is
  all-or-nothing.
* **No revoke-diff** — the seed NEVER issues a ``DELETE``; seeding must
  not revoke an operator grant (it is additive only). Distinct from
  :meth:`apply_atomic`, which computes a revoke set.
* **Idempotent** — the upsert SQL carries ``ON CONFLICT DO UPDATE`` so
  seeding twice lands the same approved row, no duplicate, no error.
* **Loud on driver error** — a :class:`SQLAlchemyError` mid-seed
  propagates (boot refuses); the method does NOT swallow it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import OperationalError

from alfred.security.capability_gate._bootstrap_grants import (
    FIRST_PARTY_SYSTEM_GRANTS,
)


def _fake_session_factory() -> tuple[MagicMock, MagicMock]:
    """Return ``(session_factory_mock, session_mock)`` — mirrors the
    storage-backend test's helper so the SQL-assertion shape is shared."""
    session_mock = MagicMock()
    result_mock = MagicMock()
    result_mock.fetchone.return_value = None
    result_mock.fetchall.return_value = []
    session_mock.execute = AsyncMock(return_value=result_mock)

    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=session_mock)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session_mock.begin = MagicMock(return_value=begin_cm)

    factory_cm = MagicMock()
    factory_cm.__aenter__ = AsyncMock(return_value=session_mock)
    factory_cm.__aexit__ = AsyncMock(return_value=None)

    factory = MagicMock(return_value=factory_cm)
    return factory, session_mock


async def test_seed_upserts_every_grant_in_one_transaction() -> None:
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)

    # Exactly one transaction opened for the whole seed.
    assert factory.call_count == 1
    session.begin.assert_called_once()

    # One INSERT ... ON CONFLICT per seeded grant, no DELETE.
    insert_calls = [
        c for c in session.execute.await_args_list if "INSERT INTO plugin_grants" in str(c.args[0])
    ]
    delete_calls = [
        c for c in session.execute.await_args_list if "DELETE FROM plugin_grants" in str(c.args[0])
    ]
    assert len(insert_calls) == len(FIRST_PARTY_SYSTEM_GRANTS)
    assert delete_calls == []


async def test_seed_writes_state_approved_and_on_conflict_idempotent() -> None:
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)

    insert_call = next(
        c for c in session.execute.await_args_list if "INSERT INTO plugin_grants" in str(c.args[0])
    )
    sql_text = str(insert_call.args[0])
    params = insert_call.args[1]
    assert "ON CONFLICT (plugin_id, hookpoint, subscriber_tier)" in sql_text
    assert "DO UPDATE" in sql_text
    assert params["state"] == "approved"
    assert params["plugin_id"] == "alfred.security._extract_dlp_subscriber"
    assert params["hookpoint"] == "security.quarantined.extract"
    assert params["subscriber_tier"] == "system"


async def test_seed_with_no_grants_opens_one_transaction_and_no_writes() -> None:
    """An empty seed set still runs the (no-op) transaction without
    error and without emitting any DML — keeps the method total."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    await backend.seed_first_party_grants(())

    assert factory.call_count == 1
    insert_calls = [
        c for c in session.execute.await_args_list if "INSERT INTO plugin_grants" in str(c.args[0])
    ]
    assert insert_calls == []


async def test_seed_propagates_driver_error_loud() -> None:
    """A :class:`SQLAlchemyError` mid-seed propagates — boot must refuse,
    not silently continue (CLAUDE.md hard rule #7)."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    session.execute = AsyncMock(
        side_effect=OperationalError("pg down", None, Exception("conn refused"))
    )
    backend = PostgresBackend(session_factory=factory)

    with pytest.raises(OperationalError):
        await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)
