"""Supervisor threads the outbound DLP singleton into every ProposalContext.

arch-001 (#173 / PR-S4-2). The ``outbound_dlp`` kwarg is optional (legacy
5-kwarg construction stays valid), but ``_build_proposal_context`` lands
the singleton on the context it builds, and refuses to build one when the
dispatch loop is scheduled yet no scanner was wired — a boot-wiring bug
must surface loudly rather than silently disarm the DLP boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.supervisor.core import Supervisor
from tests.helpers.dlp import identity_outbound_dlp as _identity_dlp


def _make_minimal_session_scope() -> Callable[[], AbstractAsyncContextManager[Any]]:
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=MagicMock())
    cm.__aexit__ = AsyncMock(return_value=None)
    return lambda: cm


def test_outbound_dlp_defaults_to_none() -> None:
    """Legacy construction leaves the scanner unset (no dispatch loop scheduled)."""
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
    )
    assert sup._outbound_dlp is None


def test_build_proposal_context_threads_the_singleton() -> None:
    """The supplied scanner lands on the built ProposalContext."""
    scanner = _identity_dlp()
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        state_git_path=Path("state.git"),
        outbound_dlp=scanner,
    )
    ctx = sup._build_proposal_context()
    assert ctx.outbound_dlp is scanner


def test_build_proposal_context_refuses_when_scanner_unwired() -> None:
    """Scheduled dispatch loop with no scanner is a boot-wiring bug → loud raise."""
    sup = Supervisor(
        session_scope=_make_minimal_session_scope(),
        gate=MagicMock(),
        audit=MagicMock(),
        state_git_path=Path("state.git"),
        # outbound_dlp deliberately omitted.
    )
    with pytest.raises(RuntimeError, match="no outbound DLP scanner was wired"):
        sup._build_proposal_context()
