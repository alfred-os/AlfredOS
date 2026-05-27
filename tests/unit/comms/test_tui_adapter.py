"""Tests for ``TuiAdapter`` — the CommsAdapter Protocol wrap around the TUI app.

Covers the constructor inject set, the lifecycle delegation, the
``run()``-before-``start()`` defensive raise, and the health-snapshot
shape. PR D2's Discord adapter will rerun a structurally-identical
suite — keeping these shapes stable is the load-bearing reason the
TuiAdapter exists in Slice 2.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from alfred.comms.adapter import AdapterHealth, CommsAdapter
from alfred.comms.tui_adapter import TuiAdapter


def _build_adapter(**overrides: object) -> TuiAdapter:
    defaults: dict[str, object] = {
        "orchestrator": MagicMock(),
        "identity_resolver": MagicMock(),
        "outbound_dlp": MagicMock(),
        "rate_limiter": MagicMock(),
        "broker": MagicMock(),
        "working_pool": MagicMock(),
    }
    defaults.update(overrides)
    return TuiAdapter(**defaults)  # type: ignore[arg-type]


def test_name_is_tui() -> None:
    adapter = _build_adapter()
    assert adapter.name == "tui"


def test_adapter_satisfies_commsadapter_protocol() -> None:
    adapter = _build_adapter()
    assert isinstance(adapter, CommsAdapter)


@pytest.mark.asyncio
async def test_run_delegates_to_app_run_async() -> None:
    """``run()`` calls ``AlfredTuiApp.run_async()`` exactly once with no args."""
    with patch("alfred.comms.tui_adapter.AlfredTuiApp") as mock_app:
        instance = mock_app.return_value
        instance.run_async = AsyncMock(return_value=None)
        adapter = _build_adapter()
        await adapter.start()
        await adapter.run()
        instance.run_async.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_run_before_start_raises() -> None:
    adapter = _build_adapter()
    with pytest.raises(RuntimeError, match="called before start"):
        await adapter.run()


@pytest.mark.asyncio
async def test_stop_calls_app_exit() -> None:
    with patch("alfred.comms.tui_adapter.AlfredTuiApp") as mock_app:
        instance = mock_app.return_value
        adapter = _build_adapter()
        await adapter.start()
        await adapter.stop()
        instance.exit.assert_called_once()


@pytest.mark.asyncio
async def test_stop_before_start_is_noop() -> None:
    """Idempotent: stop before start does not raise."""
    adapter = _build_adapter()
    await adapter.stop()  # Should not raise.


@pytest.mark.asyncio
async def test_health_before_start_reports_disconnected() -> None:
    adapter = _build_adapter()
    health = adapter.health()
    assert isinstance(health, AdapterHealth)
    assert health.gateway_connected is False
    assert health.last_on_ready_at is None
    assert health.recent_reconnect_count == 0


@pytest.mark.asyncio
async def test_health_after_start_reports_connected() -> None:
    with patch("alfred.comms.tui_adapter.AlfredTuiApp"):
        adapter = _build_adapter()
        await adapter.start()
        health = adapter.health()
        assert health.gateway_connected is True
        assert health.last_on_ready_at is not None
        assert health.recent_reconnect_count == 0


@pytest.mark.asyncio
async def test_restart_rebuilds_app_instance() -> None:
    """Idempotent start: re-start after stop rebuilds the app."""
    with patch("alfred.comms.tui_adapter.AlfredTuiApp") as mock_app:
        adapter = _build_adapter()
        await adapter.start()
        first = mock_app.call_count
        await adapter.stop()
        await adapter.start()
        # Constructor invoked again — Textual App is single-shot.
        assert mock_app.call_count == first + 1


def test_constructor_inject_set_shape() -> None:
    """The canonical inject set documented in the module docstring.

    Pin so PR D2's Discord adapter can reuse the same shape verbatim.
    """
    adapter = _build_adapter()
    # Each attribute is the constructor-provided collaborator.
    for attr in (
        "_orchestrator",
        "_identity_resolver",
        "_outbound_dlp",
        "_rate_limiter",
        "_broker",
        "_working_pool",
    ):
        assert hasattr(adapter, attr)
