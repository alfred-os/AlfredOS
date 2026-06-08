"""Verify the capability-gate sync handshake probe (#174).

core-eng-002 closure: Postgres connectivity is checked HERE (probe c),
not in the snapshot-ref probe (b).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.cli.daemon._daemon_probes import probe_capability_gate_handshake
from alfred.cli.daemon._failures import CapabilityGateHandshakeFailedFailure


@pytest.mark.asyncio
async def test_probe_passes_when_gate_healthy() -> None:
    gate = MagicMock()
    gate.is_backing_store_available = AsyncMock(return_value=True)
    result = await probe_capability_gate_handshake(gate=gate)
    assert result is None


@pytest.mark.asyncio
async def test_probe_refuses_when_gate_unavailable() -> None:
    gate = MagicMock()
    gate.is_backing_store_available = AsyncMock(return_value=False)
    result = await probe_capability_gate_handshake(gate=gate)
    assert isinstance(result, CapabilityGateHandshakeFailedFailure)
    assert result.backing_store_kind == "postgres"


@pytest.mark.asyncio
async def test_probe_refuses_on_gate_exception() -> None:
    gate = MagicMock()
    gate.is_backing_store_available = AsyncMock(side_effect=RuntimeError("pg down"))
    result = await probe_capability_gate_handshake(gate=gate)
    assert isinstance(result, CapabilityGateHandshakeFailedFailure)
    assert result.backing_store_kind == "unknown"
