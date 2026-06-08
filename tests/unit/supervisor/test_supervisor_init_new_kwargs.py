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


def _make_minimal_session_scope() -> Callable[[], AbstractAsyncContextManager[Any]]:
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=MagicMock())
    cm.__aexit__ = AsyncMock(return_value=None)
    return lambda: cm


def test_legacy_5_kwarg_construction_still_works() -> None:
    """Slice-3 unit tests that pass 5 kwargs must keep passing."""
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        state_git_path=None,
        proposal_dispatch_interval_s=30,
    )
    assert sup is not None


def test_construction_with_new_slice4_kwargs() -> None:
    """policies_ref + operator_session_resolver accepted as kwargs."""

    class _StubRef:
        def current(self) -> object:
            return object()

        def snapshot_hash(self) -> str:
            return "abc"

    class _StubResolver:
        async def resolve(self) -> str:
            return "_daemon_boot"

    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        state_git_path=Path("/tmp/state.git"),
        proposal_dispatch_interval_s=30,
        policies_ref=_StubRef(),
        operator_session_resolver=_StubResolver(),
    )
    assert sup is not None


def test_both_new_kwargs_default_to_none() -> None:
    """Defaults preserve legacy unit-test construction patterns."""
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
    )
    assert sup._policies_ref is None
    assert sup._operator_session_resolver is None
