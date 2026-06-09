"""The back-compat ``_NoopSemaphore`` async-context path is exercised (Task 61).

The Slice-3 in-process ``AlfredPluginSession`` default dispatch semaphore is a
no-op ``async with`` guard (the per-adapter ``BoundedSemaphore`` is only
allocated by the enforcing ``for_comms_adapter`` factory). Driving a comms
notification through a session built WITHOUT the factory exercises the no-op
``__aenter__`` / ``__aexit__`` so the trust-boundary file stays at 100% line +
branch coverage.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from alfred.plugins.session import _NoopSemaphore

from ._session_builders import INBOUND_PARAMS, build_session


@pytest.mark.asyncio
async def test_noop_semaphore_async_context_is_a_noop() -> None:
    sem = _NoopSemaphore()
    async with sem:
        # Body runs; the no-op guard neither blocks nor raises.
        pass
    # A second entry is equally inert (idempotent, stateless).
    assert await sem.__aenter__() is None
    assert await sem.__aexit__(None, None, None) is None


@pytest.mark.asyncio
async def test_dispatch_runs_under_noop_semaphore_default() -> None:
    """A session built without the factory dispatches under the no-op semaphore."""
    handler = AsyncMock()
    session = build_session(inbound_handler=handler, dispatch_semaphore=_NoopSemaphore())
    await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    handler.process.assert_awaited_once()
