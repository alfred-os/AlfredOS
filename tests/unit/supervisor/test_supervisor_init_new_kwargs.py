"""Supervisor.__init__ accepts the Slice-4 stub kwargs (#174 PR-S4-1).

The two new kwargs must not break the Slice-3 5-kwarg call sites.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.supervisor.core import Supervisor
from tests.helpers.policies import _StubPoliciesSnapshotRef


def _make_minimal_session_scope() -> Callable[[], AbstractAsyncContextManager[Any]]:
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=MagicMock())
    cm.__aexit__ = AsyncMock(return_value=None)
    return lambda: cm


def test_construction_requires_policies_ref() -> None:
    """PR-S4-4 rev-003: ``policies_ref`` is a REQUIRED kwarg (no default)."""
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        state_git_path=None,
        proposal_dispatch_interval_s=30,
        policies_ref=_StubPoliciesSnapshotRef(),
    )
    assert sup is not None


def test_construction_with_new_slice4_kwargs() -> None:
    """policies_ref + operator_session_resolver accepted as kwargs."""

    class _StubResolver:
        async def resolve(self) -> str:
            return "_daemon_boot"

    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        state_git_path=Path("state.git"),
        proposal_dispatch_interval_s=30,
        policies_ref=_StubPoliciesSnapshotRef(),
        operator_session_resolver=_StubResolver(),
    )
    assert sup is not None


def test_policies_ref_is_required_kwarg() -> None:
    """Omitting ``policies_ref`` raises a TypeError (no default — rev-003)."""
    import pytest

    with pytest.raises(TypeError):
        Supervisor(  # type: ignore[call-arg]
            session_scope=_make_minimal_session_scope(),
            gate=MagicMock(),
            audit=MagicMock(),
        )


def test_operator_session_resolver_defaults_to_none() -> None:
    """``operator_session_resolver`` still defaults to None (PR-S4-5 wires it)."""
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        policies_ref=_StubPoliciesSnapshotRef(),
    )
    assert sup._policies_ref is not None
    assert sup._operator_session_resolver is None
