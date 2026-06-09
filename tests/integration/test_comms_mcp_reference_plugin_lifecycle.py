"""Reference plugin full-lifecycle round-trip (Task 50/53).

Spawns the reference plugin as a subprocess (line-delimited JSON-RPC over
stdin/stdout) and drives the full lifecycle:

* ``lifecycle.start`` -> ``{"ok": true}``;
* an ``inject_inbound`` test trigger -> an ``inbound.message`` notification;
* an ``outbound.message`` request -> ``_OutboundDelivered``;
* ``adapter.health`` -> ``ok=true`` with the buffered outbound counted;
* ``lifecycle.stop`` -> ``flushed_messages`` reports the drained buffer.

This exercises the plugin half of the ADR-0024 wire contract end-to-end. The
host-side ``process_inbound_message`` path is covered by the merge-blocking
``test_comms_mcp_identity_boundary_real.py``; here the plugin's own framing +
the production-gated injector are the surface under test.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

_PLUGIN_DIR = Path(__file__).parents[1].parent / "plugins" / "alfred_comms_test"
_MAIN_PATH = _PLUGIN_DIR / "main.py"
_FRAME_TIMEOUT_S = 5.0


async def _spawn(env_overrides: dict[str, str] | None = None) -> asyncio.subprocess.Process:
    env = {**os.environ, "ALFRED_ENV": "test"}
    if env_overrides:
        env.update(env_overrides)
    return await asyncio.create_subprocess_exec(
        sys.executable,
        str(_MAIN_PATH),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )


async def _send(stdin: asyncio.StreamWriter, frame: dict[str, Any]) -> None:
    stdin.write((json.dumps(frame) + "\n").encode())
    await stdin.drain()


async def _read(stdout: asyncio.StreamReader) -> dict[str, Any]:
    line = await asyncio.wait_for(stdout.readline(), timeout=_FRAME_TIMEOUT_S)
    assert line, "plugin closed stdout before a frame arrived"
    return dict(json.loads(line))


async def _close(proc: asyncio.subprocess.Process) -> None:
    if proc.stdin is not None and not proc.stdin.is_closing():
        proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_FRAME_TIMEOUT_S)
    except TimeoutError:  # pragma: no cover - defensive
        proc.kill()
        await proc.wait()


async def test_full_lifecycle_round_trip() -> None:
    if not _MAIN_PATH.exists():  # pragma: no cover - guarded by manifest test
        pytest.skip("reference plugin missing")
    proc = await _spawn()
    try:
        assert proc.stdin is not None and proc.stdout is not None

        await _send(proc.stdin, {"jsonrpc": "2.0", "id": 1, "method": "lifecycle.start"})
        start = await _read(proc.stdout)
        assert start["result"]["ok"] is True
        assert start["result"]["plugin_version"] == "0.1.0"

        # Inject an inbound — the plugin emits an inbound.message notification.
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "method": "alfred_comms_test/inject_inbound",
                "params": {"content": "hello"},
            },
        )
        inbound = await _read(proc.stdout)
        assert inbound["method"] == "inbound.message"
        assert "id" not in inbound
        assert inbound["params"]["body"] == {"content": "hello"}

        # Deliver an outbound — buffered + reported delivered.
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "outbound.message",
                "params": {"target_platform_id": "discord:1", "body": "ack"},
            },
        )
        outbound = await _read(proc.stdout)
        assert outbound["result"]["outcome"] == "delivered"
        assert outbound["result"]["platform_message_id"]

        # Health reports ok while running.
        await _send(proc.stdin, {"jsonrpc": "2.0", "id": 3, "method": "adapter.health"})
        health = await _read(proc.stdout)
        assert health["result"]["ok"] is True

        # Stop flushes the buffered outbound (1 message) -> flushed_messages == 1.
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "lifecycle.stop",
                "params": {"reason": "shutdown"},
            },
        )
        stop = await _read(proc.stdout)
        assert stop["result"]["ok"] is True
        assert stop["result"]["flushed_messages"] == 1
    finally:
        await _close(proc)


async def test_inject_inbound_refused_in_production() -> None:
    """In production the inject trigger emits the refusal frame + crashes loudly."""
    if not _MAIN_PATH.exists():  # pragma: no cover
        pytest.skip("reference plugin missing")
    proc = await _spawn(env_overrides={"ALFRED_ENV": "production"})
    try:
        assert proc.stdin is not None and proc.stdout is not None
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "method": "alfred_comms_test/inject_inbound",
                "params": {"content": "hello"},
            },
        )
        refusal = await _read(proc.stdout)
        assert refusal["method"] == "comms.test_injection_refused"
        assert refusal["params"]["alfred_env"] == "production"
        # The subprocess crashes loudly after emitting the refusal frame.
        rc = await asyncio.wait_for(proc.wait(), timeout=_FRAME_TIMEOUT_S)
        assert rc != 0
    finally:
        await _close(proc)
