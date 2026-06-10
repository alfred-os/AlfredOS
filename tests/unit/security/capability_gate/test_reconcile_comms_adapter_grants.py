"""``PostgresBackend.reconcile_comms_adapter_grants`` unit coverage (FIX 2).

The config-sourced comms-adapter LOAD grants (ADR-0027) are DYNAMIC — driven by
``Settings.comms_enabled_adapters``. The additive-only
:meth:`PostgresBackend.seed_first_party_grants` never removes a grant, so when an
operator REMOVES an adapter the adapter's
``bootstrap:first-party-comms-adapter`` load grant goes STALE in
``plugin_grants``. :meth:`reconcile_comms_adapter_grants` is the scoped
revoke-diff that closes that hygiene gap: in ONE transaction it DELETEs every
existing sentinel-branch row NOT in ``desired``, then upserts ``desired`` as
``state='approved'``.

Driver-free unit tier (mirrors
:mod:`tests.unit.security.capability_gate.test_seed_first_party_grants`): the
session factory is stubbed and the test asserts on the SQL the backend emits.
The load-bearing safety property — the revoke WHERE is EXACTLY scoped to the
``bootstrap:first-party-comms-adapter`` sentinel and never touches the DLP
``bootstrap:first-party-system`` grant or any operator branch — is pinned here
on SQL text + params, and end-to-end against real Postgres in
``tests/integration/security/capability_gate/test_reconcile_comms_adapter_grants_e2e.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import OperationalError

from alfred.security.capability_gate._comms_adapter_grants import (
    _COMMS_ADAPTER_PROPOSAL_BRANCH,
)
from alfred.security.capability_gate.policy import GrantRow

_SENTINEL = _COMMS_ADAPTER_PROPOSAL_BRANCH


def _grant(plugin_id: str) -> GrantRow:
    return GrantRow(
        plugin_id=plugin_id,
        subscriber_tier="user-plugin",
        hookpoint="*",
        content_tier=None,
        proposal_branch=_SENTINEL,
    )


def _fake_session_factory(
    *, existing_rows: list[tuple[str, str, str]] | None = None
) -> tuple[MagicMock, MagicMock]:
    """Return ``(session_factory_mock, session_mock)``.

    ``existing_rows`` is the ``(plugin_id, hookpoint, subscriber_tier)`` triples
    the reconcile's SELECT-of-existing-sentinel-rows returns, so a test can drive
    the revoke-set computation.
    """
    session_mock = MagicMock()
    result_mock = MagicMock()
    rows = [
        MagicMock(plugin_id=p, hookpoint=h, subscriber_tier=t)
        for (p, h, t) in (existing_rows or [])
    ]
    result_mock.fetchall.return_value = rows
    result_mock.fetchone.return_value = None
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


def _selects(session: MagicMock) -> list[object]:
    return [c for c in session.execute.await_args_list if "SELECT" in str(c.args[0])]


def _deletes(session: MagicMock) -> list[object]:
    return [
        c for c in session.execute.await_args_list if "DELETE FROM plugin_grants" in str(c.args[0])
    ]


def _inserts(session: MagicMock) -> list[object]:
    return [
        c for c in session.execute.await_args_list if "INSERT INTO plugin_grants" in str(c.args[0])
    ]


async def test_reconcile_runs_in_one_transaction() -> None:
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    await backend.reconcile_comms_adapter_grants((_grant("alfred.comms-a"),))

    # Exactly one transaction opened for the whole reconcile (all-or-nothing).
    assert factory.call_count == 1
    session.begin.assert_called_once()


async def test_reconcile_revoke_set_is_existing_minus_desired() -> None:
    """The revoke set is exactly (existing sentinel rows) - (desired)."""
    from alfred.security.capability_gate.backend import PostgresBackend

    # Postgres currently has sentinel rows for adapter A and adapter B; the
    # desired set is only adapter B -> adapter A's row must be DELETEd, B's not.
    factory, session = _fake_session_factory(
        existing_rows=[
            ("alfred.comms-a", "*", "user-plugin"),
            ("alfred.comms-b", "*", "user-plugin"),
        ]
    )
    backend = PostgresBackend(session_factory=factory)

    await backend.reconcile_comms_adapter_grants((_grant("alfred.comms-b"),))

    deletes = _deletes(session)
    # Exactly one stale row deleted (adapter A), and it is scoped to the sentinel.
    assert len(deletes) == 1
    del_params = deletes[0].args[1]
    assert del_params["plugin_id"] == "alfred.comms-a"
    assert del_params["proposal_branch"] == _SENTINEL


async def test_reconcile_delete_where_is_scoped_to_sentinel_branch() -> None:
    """The DELETE WHERE pins ``proposal_branch`` to the comms-adapter sentinel.

    Load-bearing safety property: the revoke can NEVER match the DLP
    ``bootstrap:first-party-system`` grant or an operator proposal branch — the
    DELETE filters on the exact sentinel value.
    """
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory(
        existing_rows=[("alfred.comms-stale", "*", "user-plugin")]
    )
    backend = PostgresBackend(session_factory=factory)

    await backend.reconcile_comms_adapter_grants(())

    # The SELECT that reads existing rows is scoped to the sentinel branch too.
    selects = _selects(session)
    assert selects, "reconcile must SELECT existing sentinel rows"
    assert any(":proposal_branch" in str(c.args[0]) for c in selects)
    assert all(c.args[1].get("proposal_branch") == _SENTINEL for c in selects if len(c.args) > 1)

    deletes = _deletes(session)
    assert len(deletes) == 1
    del_sql = str(deletes[0].args[0])
    del_params = deletes[0].args[1]
    assert "proposal_branch = :proposal_branch" in del_sql
    assert del_params["proposal_branch"] == _SENTINEL


async def test_reconcile_upserts_desired_as_approved() -> None:
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    desired = (_grant("alfred.comms-a"),)
    await backend.reconcile_comms_adapter_grants(desired)

    inserts = _inserts(session)
    assert len(inserts) == 1
    sql = str(inserts[0].args[0])
    params = inserts[0].args[1]
    assert "ON CONFLICT (plugin_id, hookpoint, subscriber_tier)" in sql
    assert params["state"] == "approved"
    assert params["plugin_id"] == "alfred.comms-a"
    assert params["proposal_branch"] == _SENTINEL


async def test_reconcile_empty_desired_with_no_existing_is_noop_dml() -> None:
    """Empty desired + no existing sentinel rows: one transaction, no DML."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    backend = PostgresBackend(session_factory=factory)

    await backend.reconcile_comms_adapter_grants(())

    assert factory.call_count == 1
    assert _deletes(session) == []
    assert _inserts(session) == []


async def test_reconcile_no_change_does_not_delete_the_live_grant() -> None:
    """Reconciling to the SAME set deletes nothing (the live grant survives)."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory(existing_rows=[("alfred.comms-a", "*", "user-plugin")])
    backend = PostgresBackend(session_factory=factory)

    await backend.reconcile_comms_adapter_grants((_grant("alfred.comms-a"),))

    assert _deletes(session) == []
    # The desired grant is still (idempotently) upserted.
    assert len(_inserts(session)) == 1


async def test_reconcile_propagates_driver_error_loud() -> None:
    """A driver error mid-reconcile propagates — boot refuses (hard rule #7)."""
    from alfred.security.capability_gate.backend import PostgresBackend

    factory, session = _fake_session_factory()
    session.execute = AsyncMock(
        side_effect=OperationalError("pg down", None, Exception("conn refused"))
    )
    backend = PostgresBackend(session_factory=factory)

    with pytest.raises(OperationalError):
        await backend.reconcile_comms_adapter_grants((_grant("alfred.comms-a"),))
