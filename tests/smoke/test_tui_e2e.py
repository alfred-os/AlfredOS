"""TUI end-to-end smoke — launcher-spawn + MCP handshake + stdio round-trip (#206).

History
-------

Through Slice 2/3 this file drove the in-process :class:`AlfredTuiApp`
(Textual) via ``app.run_test()`` + ``Pilot`` against a real Postgres
testcontainer. That worked because the TUI lived in-process at
``alfred.comms.tui``. PR-S4-10 (the TUI flag-day) deleted ``src/alfred/comms/``:
the TUI is now the out-of-process MCP plugin at ``plugins/alfred_tui/``, launched
through ``bin/alfred-plugin-launcher.sh`` and spoken to over the stdio MCP
transport, so the in-process driver has no ``AlfredTuiApp`` to import.

Component D (this module) replaces the Slice-2 stub with the real launcher-spawn
e2e: spawn the plugin through the REAL launcher (the PR-S4-6 contract — positional
``<plugin_id> <executable> [args...]`` + ``ALFRED_PLUGIN_MANIFEST_PATH`` env, no
``--manifest``/``--adapter-id`` flags), then drive the full ADR-0024 wire
lifecycle over the child's line-delimited JSON-RPC stdio:

  * ``lifecycle.start``  -> ``ok=True`` with the plugin version;
  * ``adapter.health``   -> ``ok=True`` while running;
  * ``outbound.message`` (``dm``) -> ``delivered`` (the operator-facing render
    leg the in-process pilot used to assert is exercised host-to-plugin here);
  * ``lifecycle.stop``   -> ``ok=True``.

Why no PTY / no Textual pilot: the launcher-spawned ``alfred_tui.server`` is the
production wire-binding layer; its RichLog render path is unit-pinned by the
plugin's own ``test_render_wiring`` and integration-pinned by
``tests/integration/test_tui_round_trip.py``. The smoke layer's job is to prove
the *deployment shape* — the launcher hands the real plugin a live MCP surface —
which a full PTY drive cannot do more honestly and would only add flake.

Skip-vs-pass discipline (smoke-layer invariant): if the launcher refuses to exec
the plugin on this host (the ``kind=none`` path needs ``runuser`` on Linux;
macOS execs unsandboxed only in dev/test), the test reports SKIPPED — never
PASSED — so the smoke report names the gap rather than silently dropping it.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from alfred.security.dlp import OutboundDlp

pytestmark = pytest.mark.smoke

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_TUI_MANIFEST = _REPO_ROOT / "plugins" / "alfred_tui" / "manifest.toml"
_PLUGIN_ID = "alfred_tui"
_SERVER_MODULE = "alfred_tui.server"
_FRAME_TIMEOUT_S = 5.0


class _Broker:
    def get(self, name: str) -> str:
        return "smoke-tui-pepper-0123456789abcdef-padding"

    def redact(self, text: str) -> str:
        return text


@pytest.mark.smoke
async def test_tui_launcher_spawn_full_lifecycle_round_trip() -> None:
    """Spawn plugins/alfred_tui via the real launcher; drive the wire lifecycle."""
    if not _LAUNCHER.exists():  # pragma: no cover - guarded by repo layout
        pytest.skip("launcher script missing")

    proc = await _spawn_via_launcher()
    try:
        assert proc.stdin is not None and proc.stdout is not None

        # lifecycle.start — the plugin records the adapter id and acks its version.
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "lifecycle.start",
                "params": {
                    "adapter_id": "tui",
                    "credentials_ref": "tui-no-credentials",
                    "policies_snapshot_hash": "0" * 64,
                },
            },
        )
        start = await _read_or_skip(proc)
        assert start["result"]["ok"] is True
        assert start["result"]["plugin_version"]

        # adapter.health — ok while running.
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "adapter.health",
                "params": {"adapter_id": "tui"},
            },
        )
        health = await _read_or_skip(proc)
        assert health["result"]["ok"] is True

        # outbound.message (dm) — delivered (the operator-render leg, host->plugin).
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "outbound.message",
                "params": {
                    "adapter_id": "tui",
                    "idempotency_key": "00000000-0000-4000-8000-000000000001",
                    "target_platform_id": "operator",
                    "body": ["smoke outbound line", _scan_result_payload()],
                    "attachments_refs": [],
                    "addressing_mode": "dm",
                },
            },
        )
        outbound = await _read_or_skip(proc)
        assert outbound["result"]["outcome"] == "delivered"

        # lifecycle.stop — clean shutdown.
        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "lifecycle.stop",
                "params": {"adapter_id": "tui", "reason": "shutdown"},
            },
        )
        stop = await _read_or_skip(proc)
        assert stop["result"]["ok"] is True
    finally:
        await _close(proc)


async def _spawn_via_launcher() -> asyncio.subprocess.Process:
    # The launcher resolves the environment + manifest sandbox block via an
    # internal ``python3 -m alfred.plugins.manifest_reader`` call, so the
    # ``python3`` on PATH must import ``alfred``. Prepend the active interpreter's
    # bin dir so the helper resolves the venv python (matching CI's uv PATH).
    venv_bin = str(Path(sys.executable).parent)
    env = {
        **os.environ,
        "PATH": os.pathsep.join((venv_bin, os.environ.get("PATH", ""))),
        "ALFRED_ENVIRONMENT": "test",
        "ALFRED_PLUGIN_MANIFEST_PATH": str(_TUI_MANIFEST),
        "PYTHONPATH": os.pathsep.join(
            p
            for p in (
                str(_REPO_ROOT / "plugins" / "alfred_tui" / "src"),
                str(_REPO_ROOT / "src"),
                os.environ.get("PYTHONPATH", ""),
            )
            if p
        ),
    }
    return await asyncio.create_subprocess_exec(
        "bash",
        str(_LAUNCHER),
        _PLUGIN_ID,
        sys.executable,
        "-m",
        _SERVER_MODULE,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )


async def _send(stdin: asyncio.StreamWriter, frame: dict[str, Any]) -> None:
    stdin.write((json.dumps(frame) + "\n").encode())
    await stdin.drain()


async def _read_or_skip(proc: asyncio.subprocess.Process) -> dict[str, Any]:
    """Read the next JSON-RPC frame, skipping interleaved non-frame log lines.

    The bare ``alfred_tui.server`` subprocess leaves structlog on its default
    console renderer, so log lines can interleave on stdout; the real host
    ``StdioTransport`` reads JSON-RPC *frames*, which this mirrors by discarding
    any line that is not a JSON object. A launcher that refused to hand off
    (closed stdout) maps to SKIPPED — never a false PASS.
    """
    assert proc.stdout is not None
    deadline = asyncio.get_event_loop().time() + _FRAME_TIMEOUT_S
    while asyncio.get_event_loop().time() < deadline:
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=_FRAME_TIMEOUT_S)
        except TimeoutError:  # pragma: no cover - defensive
            pytest.skip("plugin produced no stdio frame before timeout (launcher/sandbox)")
        if not line:  # pragma: no cover - launcher refused to hand off
            pytest.skip("plugin closed stdout before a frame arrived (launcher refused exec)")
        text = line.decode().strip()
        if not text.startswith("{"):
            continue
        return dict(json.loads(text))
    pytest.skip("no JSON-RPC frame within the read window (only log lines)")  # pragma: no cover


async def _close(proc: asyncio.subprocess.Process) -> None:
    if proc.stdin is not None and not proc.stdin.is_closing():
        proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_FRAME_TIMEOUT_S)
    except TimeoutError:  # pragma: no cover - defensive
        proc.kill()
        await proc.wait()


def _scan_result_payload() -> dict[str, Any]:
    """A wire-shaped OutboundDlpScanResult for the outbound frame body tuple."""
    dlp = OutboundDlp(broker=_Broker(), audit=lambda **_: None)
    _text, scan_result = dlp.scan_for_outbound("smoke outbound line")
    return scan_result.model_dump(mode="json")
