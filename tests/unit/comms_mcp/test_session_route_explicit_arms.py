"""``_route_comms_notification`` match arms are explicit, not catch-all (#152).

Defence-in-depth for CR finding 2: the inner router is gated upstream by
``_COMMS_NOTIFICATION_METHODS`` so an unknown method is not currently reachable
here, but the router must still fail-fast rather than silently coerce any
unhandled method into ``adapter.crashed`` via a ``case _:`` validate-as-crashed.

* ``adapter.crashed`` routes to the crash handler (known-good arm preserved).
* an unhandled method raises a clear :class:`PluginError` naming the method.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from alfred.plugins.errors import PluginError

from ._session_builders import build_session


@pytest.mark.asyncio
async def test_route_crashed_method_reaches_crash_handler() -> None:
    crash_handler = AsyncMock()
    session = build_session(crash_handler=crash_handler)

    await session._route_comms_notification(
        "adapter.crashed",
        {
            "adapter_id": "alfred_comms_test",
            "error_class": "AdapterRuntimeError",
            "detail": "boom",
        },
    )

    crash_handler.process.assert_awaited_once()


@pytest.mark.asyncio
async def test_route_unhandled_method_raises_naming_the_method() -> None:
    crash_handler = AsyncMock()
    session = build_session(crash_handler=crash_handler)

    with pytest.raises(PluginError) as excinfo:
        await session._route_comms_notification("adapter.bogus", {})

    assert "adapter.bogus" in str(excinfo.value)
    crash_handler.process.assert_not_awaited()
