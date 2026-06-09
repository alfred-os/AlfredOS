"""Minimal :class:`alfred.orchestrator.core.Orchestrator` builder for the
``quarantined_extract`` wrapper tests.

The wrapper under test reads only ``self._quarantined_extractor``; the rest of
the orchestrator's per-turn machinery is irrelevant here. This builder wires
the smallest set of mock dependencies that satisfy ``__init__`` plus the new
additive ``quarantined_extractor=`` kwarg.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.orchestrator.core import Orchestrator


def make_orchestrator(*, quarantined_extractor: Any) -> Orchestrator:
    """Build an orchestrator with mock deps and the supplied extractor."""

    @asynccontextmanager
    async def _scope() -> Any:
        yield MagicMock()

    identity_resolver = MagicMock()
    identity_resolver.get_operator = MagicMock(return_value=MagicMock())

    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()

    return Orchestrator(
        identity_resolver=identity_resolver,
        session_scope=_scope,
        router=MagicMock(),
        budget=MagicMock(),
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        quarantined_extractor=quarantined_extractor,
    )
