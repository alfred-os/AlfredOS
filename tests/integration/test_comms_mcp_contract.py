"""Spec §9.1 — CommsAdapterMCP reference plugin contract test.

comms-007: Filename matches spec §9.1 line 746 so ADR-0016 cross-references hold.

Validates the comms-MCP wire contract against the in-repo reference plugin
``plugins/alfred_comms_test`` (manifest + line-delimited JSON-RPC echo
server):

1. **Handshake** — the real manifest on disk parses, the session loads via
   the real :class:`AlfredPluginSession.create` factory, and the
   ``plugin.lifecycle.loaded`` audit row lands after
   ``_on_handshake_complete``.
2. **Inbound.message round-trip** — driving the reference plugin as a
   subprocess and sending a ``lifecycle.start`` JSON-RPC frame produces
   BOTH the response and a follow-on ``inbound.message`` notification
   matching the spec §9.1 + comms-001 shape (``platform``,
   ``platform_user_id``, ``content``, ``language``). comms-003: this
   verifies the plugin → host direction, not host → plugin.
3. **adapter.health probe** — after ``lifecycle.start`` flips ``_running``
   true, ``adapter.health`` returns ``{"status": "ok"}``.

Why subprocess pipes for tests 2 and 3
--------------------------------------

The reference plugin and the host's :class:`StdioTransport` use *different*
wire framings: the plugin reads line-delimited JSON (mirroring
``alfred_web_fetch``) and the transport speaks length-prefixed (4-byte BE
header + body). Driving the plugin through ``StdioTransport.dispatch()``
would test the host-side state machine, not the reference plugin. These
tests deliberately bypass the transport and exercise the plugin against
its own framing — line-delimited JSON over stdin/stdout — which is what
the wire contract on the plugin side actually pins (see plugin docstring
in ``plugins/alfred_comms_test/main.py`` §"line-delimited" + comms-002).

This is part 1 of the §9.1 contract test. Part 2 — a smoke test of the
plugin + ``StdioTransport`` once the wire frames converge — is tracked
separately; until then, each side is unit-tested against its own framing.

Marked ``pytest.mark.integration`` because tests 2 + 3 spawn the
reference plugin as a real subprocess. The session-handshake test
(``test_comms_test_plugin_handshake``) does no I/O and is unit-shaped;
it stays in this file for spec-§9.1 locality.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit import audit_row_schemas
from alfred.plugins.session import AlfredPluginSession
from tests.helpers.gates import make_default_test_gate

PLUGIN_DIR: Path = Path(__file__).parent.parent.parent / "plugins" / "alfred_comms_test"
MANIFEST_PATH: Path = PLUGIN_DIR / "manifest.toml"
MAIN_PATH: Path = PLUGIN_DIR / "main.py"

# Bounded so a hung subprocess cannot wedge the CI runner. Five seconds is
# generous for the in-process echo path — the plugin returns within
# microseconds on a healthy box; if a frame has not landed by then the
# subprocess is wedged and the test should fail loud rather than hang.
_PLUGIN_FRAME_TIMEOUT_S: float = 5.0


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    """``MagicMock`` whose ``append_schema`` records calls on ``.calls``.

    Mirrors the unit-level fixture in
    ``tests/unit/plugins/conftest.py``. Inlined here so the integration
    test stays self-contained — the integration conftest spins up a
    Postgres container which is irrelevant to this in-memory audit
    capture path (per-test container would also burn ~5s per test for
    no marginal value).
    """
    writer = MagicMock()
    writer.calls = []
    writer.last_event = None

    async def _capture(**kwargs: Any) -> None:
        writer.calls.append(kwargs)
        # MagicMock attribute writes are typed ``Any`` so this assignment
        # widens ``last_event`` past the initial ``None`` narrowing —
        # callers comparing ``last_event == "plugin.lifecycle.loaded"``
        # under mypy --strict would otherwise see the comparison as
        # unreachable. The explicit local typing keeps the test module
        # strict-clean.
        writer.last_event = kwargs.get("event")

    writer.append_schema = AsyncMock(side_effect=_capture)
    return writer


@pytest.fixture
def fake_gate() -> MagicMock:
    """Capability gate stand-in keyed on an explicit fixture grant.

    CR-149: the previous shape returned ``True`` unconditionally from
    both ``check_plugin_load`` and ``check_content_clearance``, which
    is the "always allow" stub coding-guidelines explicitly forbid.
    A regression in :class:`AlfredPluginSession` that stopped
    consulting the gate would still pass the handshake test because
    the always-allow shim approved every call. PRD §7.1 coverage on
    a trust-boundary path needs the gate to assert against an
    explicit grant policy.

    The fixture grant pins the manifest the reference plugin actually
    ships (``plugin_id="alfred.comms-test"`` at
    ``manifest_tier="user-plugin"``) and refuses anything else. Any
    refactor that calls the gate with a different plugin id or tier
    surfaces here as ``check_plugin_load → False`` rather than
    silently approving the wrong plugin. ``check_content_clearance``
    follows the same principle: only the manifest's declared
    content tier is permitted.
    """
    granted_plugin_id = "alfred.comms-test"
    granted_manifest_tier = "user-plugin"

    def _check_plugin_load(*, plugin_id: str, manifest_tier: str) -> bool:
        return plugin_id == granted_plugin_id and manifest_tier == granted_manifest_tier

    def _check_content_clearance(
        *,
        plugin_id: str,
        content_tier: str,
        **_: object,
    ) -> bool:
        # The reference plugin's manifest declares ``user-plugin`` as
        # its subscriber tier; the corresponding content tier the
        # fixture grant authorises is ``T2`` (the highest non-T3
        # tier a user-plugin may consume). A regression that probes
        # for T3 here is exactly the leak this fixture must catch.
        return plugin_id == granted_plugin_id and content_tier in {"T1", "T2"}

    gate = MagicMock()
    gate.check_plugin_load.side_effect = _check_plugin_load
    gate.check_content_clearance.side_effect = _check_content_clearance
    return gate


# ---------------------------------------------------------------------------
# Test 1 — Handshake against the real reference manifest
# ---------------------------------------------------------------------------


async def test_comms_test_plugin_handshake(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """The reference manifest loads end-to-end via the real session API.

    Exercises:

    * ``AlfredPluginSession.create()`` parses the on-disk
      ``plugins/alfred_comms_test/manifest.toml`` — i.e. the manifest
      shipped to operators — without raising.
    * ``_on_handshake_complete()`` consults the gate and emits
      ``plugin.lifecycle.loaded``.
    * The audit row carries the exact ``plugin_id`` (``alfred.comms-test``)
      and ``manifest_subscriber_tier`` (``user-plugin``) from the manifest,
      pinning that a refactor of the parse path cannot silently drop
      either field.

    Also verifies that the post-PR-S3-7 fixture-parity gate
    (:func:`make_default_test_gate`) accepts the manifest — the
    gate's ``check_plugin_load`` returns True for the
    ``user-plugin`` subscriber tier (operator + user-plugin are
    granted unconditionally by the fixture); pinning the manifest
    against the real fixture catches a regression that would require
    a non-trivial gate change.
    """
    assert MANIFEST_PATH.exists(), (
        f"Reference plugin manifest missing at {MANIFEST_PATH}; comms-MCP §9.1 "
        "contract test cannot run."
    )
    manifest_raw = MANIFEST_PATH.read_text()

    session = await AlfredPluginSession.create(
        manifest_raw=manifest_raw,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
    )
    # ``create()`` only writes on parse failure; ``calls`` stays empty on
    # the happy path. Using ``calls`` rather than ``last_event`` here
    # keeps the assertion symmetric with the post-handshake check below
    # without involving the None-narrow path.
    assert fake_audit_writer.calls == []

    await session._on_handshake_complete()
    assert fake_audit_writer.last_event == "plugin.lifecycle.loaded"
    call = fake_audit_writer.calls[-1]
    assert call["fields"] is audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS
    subject = call["subject"]
    assert subject["plugin_id"] == "alfred.comms-test"
    assert subject["manifest_subscriber_tier"] == "user-plugin"
    assert subject["manifest_version"] == 1
    assert subject["sandbox_profile"] == "user-plugin"

    # CR-149 round-3: pin that ``_on_handshake_complete`` actually
    # consulted the gate. The fixture grant authorises exactly the
    # reference plugin's manifest tier; a regression that drops the
    # gate consult entirely would still pass the audit-row assertions
    # above (because the session would skip the check and go straight
    # to the lifecycle row). Asserting against the mock's call_args
    # closes that bypass — the trust-boundary suite must verify the
    # gate consultation, not just its post-conditions.
    fake_gate.check_plugin_load.assert_called_once_with(
        plugin_id="alfred.comms-test",
        manifest_tier="user-plugin",
    )

    # And the post-PR-S3-7 fixture-parity gate also accepts the
    # manifest (the operator / user-plugin tiers are granted
    # unconditionally; pinning the call site here surfaces any future
    # tightening of the gate's plugin-load semantics).
    real_gate = make_default_test_gate()
    assert real_gate.check_plugin_load(plugin_id="alfred.comms-test", manifest_tier="user-plugin")


# ---------------------------------------------------------------------------
# Test 2 + 3 — Subprocess round-trip against the reference plugin
# ---------------------------------------------------------------------------


async def _send_line(stdin: asyncio.StreamWriter, frame: dict[str, Any]) -> None:
    """Encode + flush one JSON-RPC frame as a single line.

    Mirrors the framing the plugin reads on stdin (``readline``) — a
    single line terminated by ``\n``. ``ensure_ascii=False`` is not used
    because the wire is bytes-encoded with UTF-8 either way and matching
    the plugin's ``json.dumps`` keeps the test framing identical.
    """
    stdin.write((json.dumps(frame) + "\n").encode("utf-8"))
    await stdin.drain()


async def _read_line(stdout: asyncio.StreamReader) -> dict[str, Any]:
    """Read one line from the plugin and decode it as JSON.

    Bounded by :data:`_PLUGIN_FRAME_TIMEOUT_S` so a wedged plugin cannot
    hang the test runner. Raises ``AssertionError`` on EOF rather than
    returning an empty frame — silent EOF in the middle of a contract
    test is a bug, not a tolerable terminal state.
    """
    line = await asyncio.wait_for(stdout.readline(), timeout=_PLUGIN_FRAME_TIMEOUT_S)
    assert line, "plugin closed stdout before a frame arrived"
    return dict(json.loads(line))


async def _spawn_plugin() -> asyncio.subprocess.Process:
    """Spawn the reference plugin as a subprocess speaking on stdin/stdout.

    Uses ``sys.executable`` (the test runner's interpreter) so the
    subprocess inherits the same Python version + virtualenv — the
    plugin has no third-party runtime deps (the ``mcp`` import is probed
    and tolerated absent), so a bare interpreter is enough.

    ``stderr=PIPE`` captures plugin-side tracebacks for the test's
    failure message rather than letting them disappear into the CI log
    noise.
    """
    return await asyncio.create_subprocess_exec(
        sys.executable,
        str(MAIN_PATH),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _close_plugin(proc: asyncio.subprocess.Process) -> None:
    """Best-effort shutdown: close stdin, wait briefly, SIGKILL on hang.

    Mirrors :meth:`StdioTransport.close` semantics so the test doesn't
    leak subprocess handles when an assertion fails mid-flight.
    """
    if proc.stdin is not None and not proc.stdin.is_closing():
        proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_PLUGIN_FRAME_TIMEOUT_S)
    except TimeoutError:  # pragma: no cover — defensive; child should exit on EOF
        proc.kill()
        await proc.wait()


@pytest.mark.integration
async def test_comms_test_plugin_lifecycle_start_emits_inbound_message() -> None:
    """``lifecycle.start`` triggers the plugin → host ``inbound.message`` notification.

    Spec §9.1 + comms-001: the notification payload MUST carry
    ``platform``, ``platform_user_id``, ``content``, and ``language``.
    The plugin emits a fixture frame after the lifecycle response so
    the host observes the response → notification ordering (matches the
    plugin docstring §"comms-003: emit ... after the lifecycle handler
    runs so the host observes the response → notification ordering").

    comms-003: this pins the plugin → host direction. The plugin is the
    origin of the ``inbound.message`` traffic; the host is the
    receiver.
    """
    if not MAIN_PATH.exists():  # pragma: no cover — caught by handshake test
        pytest.skip(f"reference plugin missing at {MAIN_PATH}")

    proc = await _spawn_plugin()
    try:
        assert proc.stdin is not None and proc.stdout is not None

        await _send_line(
            proc.stdin,
            {"jsonrpc": "2.0", "id": 1, "method": "lifecycle.start", "params": {}},
        )

        # The plugin sends two frames in order: the response, then the
        # inbound.message notification. Both are line-delimited; read
        # them sequentially.
        response = await _read_line(proc.stdout)
        assert response.get("id") == 1, f"expected id=1 on lifecycle.start response, got {response}"
        assert response.get("result", {}).get("status") == "started"

        notification = await _read_line(proc.stdout)
        assert notification.get("method") == "inbound.message", (
            f"expected inbound.message notification, got {notification}"
        )
        # Spec §9.1 + comms-001 wire-shape pins.
        assert "id" not in notification, "inbound.message MUST be a notification (no id)"
        params = notification.get("params", {})
        assert params.get("platform") == "test"
        assert params.get("platform_user_id") == "echo-plugin"
        assert params.get("content") == "echo plugin started"
        # BCP-47 language tag (CLAUDE.md i18n rule #3).
        assert params.get("language") == "en-US"
    finally:
        await _close_plugin(proc)


@pytest.mark.integration
async def test_comms_test_plugin_adapter_health_ok_after_start() -> None:
    """``adapter.health`` returns ``status=ok`` once the lifecycle is running.

    The reference plugin's :class:`AdapterHealthResponse`-shaped payload
    reports ``"ok"`` while running and ``"degraded"`` while stopped.
    Driving ``lifecycle.start`` first transitions the state so the
    health probe returns ``"ok"`` — pinning the spec §9.1 + comms-009
    expectation that ``adapter.health`` is consultable post-start and
    reports the Slice-3 narrow ``{"ok", "degraded"}`` Literal.
    """
    if not MAIN_PATH.exists():  # pragma: no cover — caught by handshake test
        pytest.skip(f"reference plugin missing at {MAIN_PATH}")

    proc = await _spawn_plugin()
    try:
        assert proc.stdin is not None and proc.stdout is not None

        # Start, then drain the response + inbound.message notification.
        await _send_line(
            proc.stdin,
            {"jsonrpc": "2.0", "id": 1, "method": "lifecycle.start", "params": {}},
        )
        await _read_line(proc.stdout)  # response
        await _read_line(proc.stdout)  # inbound.message notification

        # Probe health.
        await _send_line(
            proc.stdin,
            {"jsonrpc": "2.0", "id": 2, "method": "adapter.health", "params": {}},
        )
        health = await _read_line(proc.stdout)
        assert health.get("id") == 2
        payload = health.get("result", {})
        assert payload.get("status") == "ok", (
            f"expected status=ok after lifecycle.start, got payload={payload}"
        )
    finally:
        await _close_plugin(proc)
