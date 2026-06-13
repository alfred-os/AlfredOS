"""Runner seq/ack version-gate negotiation (Spec A G2 / ADR-0032) (#237).

The handshake (``lifecycle.start``) advertises ``AlfredSeqAck/1`` in its params;
the runner flips ``transport.enable_seq_ack()`` ONLY when the plugin echoes the
same field in its result. The flip is a TYPED call on the ``_CommsTransportLike``
Protocol — the fake transport here implements ``enable_seq_ack`` explicitly, the
same shape the concrete transports carry.

These cases reuse the runner test's session/handler scaffolding via a thin local
fake transport that records both the sent handshake AND the seq/ack flip.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.cli._launcher_spawn import PluginLaunchSpec
from alfred.comms_mcp.handlers import BindingHandler, CrashHandler, RateLimitHandler
from alfred.plugins.comms_runner import _FIRST_REQUEST_ID, _LIFECYCLE_START_ID, CommsPluginRunner
from alfred.plugins.comms_seq_codec import SEQ_MAGIC, SEQ_VERSION
from alfred.plugins.comms_stdio_transport import CommsStdioTransport
from alfred.plugins.session import AlfredPluginSession
from tests.helpers.gates import make_permissive_fixture_gate

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "alfred_comms_test"

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""


def _handshake_result(*, echo_seq_ack: bool) -> Mapping[str, object]:
    result: dict[str, object] = {"ok": True, "plugin_version": "0.1.0"}
    if echo_seq_ack:
        result["seq_ack"] = {"version": SEQ_VERSION}
    return {"jsonrpc": "2.0", "id": _LIFECYCLE_START_ID, "result": result}


class _GateRecordingTransport:
    """Fake transport that records the handshake send + the seq/ack flip.

    Implements the typed ``_CommsTransportLike`` seam, including the new
    ``enable_seq_ack`` flip (recorded on ``seq_ack_enabled``).
    """

    def __init__(self, inbound: list[Mapping[str, object]]) -> None:
        self._inbound = inbound
        self.sent: list[Mapping[str, object]] = []
        self.seq_ack_enabled = False

    async def spawn(self) -> None:
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:
        return self._inbound.pop(0) if self._inbound else None

    async def close(self) -> None:
        return None

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


def _audit() -> MagicMock:
    from unittest.mock import AsyncMock

    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer


async def _session(transport: Any) -> AlfredPluginSession:
    return await AlfredPluginSession.for_comms_adapter(
        adapter_id=_ADAPTER_ID,
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=make_permissive_fixture_gate(),
        supervisor=MagicMock(),
        inbound_handler=MagicMock(),
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
        transport=transport,
    )


async def _run_handshake(*, echo_seq_ack: bool) -> _GateRecordingTransport:
    transport = _GateRecordingTransport([_handshake_result(echo_seq_ack=echo_seq_ack)])
    session = await _session(transport)
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)
    await runner.start_and_handshake()
    return transport


async def test_handshake_advertises_seq_ack_in_params() -> None:
    transport = await _run_handshake(echo_seq_ack=True)
    start = transport.sent[0]
    params = start["params"]
    assert isinstance(params, Mapping)
    assert params.get("seq_ack") == {"version": SEQ_VERSION}


async def test_both_advertise_flips_transport_on() -> None:
    transport = await _run_handshake(echo_seq_ack=True)
    assert transport.seq_ack_enabled is True


async def test_plugin_silent_stays_off() -> None:
    transport = await _run_handshake(echo_seq_ack=False)
    assert transport.seq_ack_enabled is False


async def test_plugin_wrong_version_stays_off() -> None:
    bad_result = {
        "jsonrpc": "2.0",
        "id": _LIFECYCLE_START_ID,
        "result": {"ok": True, "plugin_version": "0.1.0", "seq_ack": {"version": "9"}},
    }
    transport = _GateRecordingTransport([bad_result])
    session = await _session(transport)
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)
    await runner.start_and_handshake()
    assert transport.seq_ack_enabled is False


async def test_negotiation_does_not_change_id_allocation() -> None:
    """seq is additive: negotiation does not perturb the request-id allocator.

    Drive the REAL runner through ``start_and_handshake()`` with an echoing peer
    (gate flips ON), then assert the runner's ACTUAL post-handshake state rather
    than a tautology: the handshake request carried ``_LIFECYCLE_START_ID``, and
    the runner's next-request-id allocator still sits at ``_FIRST_REQUEST_ID`` —
    so the first ``send_request`` after the handshake will allocate it. The
    lifecycle-start id and the request-id allocator are independent counters; the
    seq/ack gate touches neither.
    """
    transport = _GateRecordingTransport([_handshake_result(echo_seq_ack=True)])
    session = await _session(transport)
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)
    await runner.start_and_handshake()

    # The gate actually flipped (the handshake echoed), so this is not the OFF path.
    assert transport.seq_ack_enabled is True
    # The handshake request carried the lifecycle-start id, unchanged.
    assert transport.sent[0]["id"] == _LIFECYCLE_START_ID
    # The runner's request-id allocator is untouched by negotiation: the next
    # send_request will allocate _FIRST_REQUEST_ID, not some perturbed value.
    assert runner._next_request_id == _FIRST_REQUEST_ID


# ---------------------------------------------------------------------------
# Host-send byte-shape regression: a non-echoing peer must keep the wire PLAIN.
#
# The gate-flip tests above use a fake transport that records frames as mappings,
# so they prove the FLAG flips but NOT what bytes a host ``send()`` then emits.
# The break this regression guards against (PR #262) was exactly that asymmetry:
# the runner always advertises seq/ack, so a peer that ECHOES the capability
# (but cannot deframe) flips the transport gate ON and every subsequent host
# ``send()`` is ``A1``-wrapped — bytes the peer cannot parse. The real-plugin
# integration tests that caught it ``skipif`` on the non-root launcher gate, so
# the break was invisible on the REQUIRED non-root ubuntu gate (#245 paper-gate).
#
# This in-process test (which RUNS on that required gate) wires the REAL
# ``CommsStdioTransport`` through the real ``CommsPluginRunner`` handshake, then
# issues a host ``send()`` and asserts the bytes on the wire:
#
#   * peer does NOT echo  -> gate stays OFF -> PLAIN ADR-0025 bytes (no ``A1``);
#   * peer DOES   echo    -> gate flips ON  -> ``A1`` out-of-band header.
#
# The first case proves "the host never wraps a frame a non-deframing peer can't
# read"; the second proves the test would actually catch a regression that
# flipped the gate, so the first case is not vacuously green.
# ---------------------------------------------------------------------------


class _RecordingStdin:
    """A fake subprocess stdin that records every byte the transport writes."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeProc:
    """Minimal ``asyncio.subprocess.Process`` stand-in: a seeded stdout + a stdin."""

    def __init__(self, *, stdout: asyncio.StreamReader, stdin: _RecordingStdin) -> None:
        self.stdout = stdout
        self.stdin = stdin
        self.returncode: int | None = None


def _stdio_spec() -> PluginLaunchSpec:
    return PluginLaunchSpec(
        plugin_id=_ADAPTER_ID,
        manifest_path=Path("/opt/alfred/manifest.toml"),
        module="alfred_comms_test.main",
        adapter_id=_ADAPTER_ID,
        import_roots=(Path("/opt/alfred/plugins"),),
        inherit_stdio=False,
        sandbox_kind="none",
    )


def _stdout_with_handshake(*, echo_seq_ack: bool) -> asyncio.StreamReader:
    """Seed a stdout reader with ONE plain handshake-ack line, then EOF."""
    result: dict[str, object] = {"ok": True, "plugin_version": "0.1.0"}
    if echo_seq_ack:
        result["seq_ack"] = {"version": SEQ_VERSION}
    ack = {"jsonrpc": "2.0", "id": _LIFECYCLE_START_ID, "result": result}
    reader = asyncio.StreamReader()
    reader.feed_data(json.dumps(ack).encode() + b"\n")
    reader.feed_eof()
    return reader


async def _handshake_real_transport(*, echo_seq_ack: bool) -> tuple[CommsStdioTransport, bytearray]:
    """Run the runner handshake over a REAL stdio transport; return it + stdin bytes.

    The transport's ``_proc`` is pre-seeded (no real subprocess), so ``spawn``
    would double-spawn — the runner's ``start_and_handshake`` calls ``spawn``
    first, so we patch it to a no-op for this hermetic in-process case while the
    rest of the transport (``send`` / ``read_frame`` / ``enable_seq_ack``) is the
    real code under test.
    """
    stdin = _RecordingStdin()
    transport = CommsStdioTransport(adapter_id=_ADAPTER_ID, spec=_stdio_spec())
    transport._proc = _FakeProc(  # type: ignore[assignment]
        stdout=_stdout_with_handshake(echo_seq_ack=echo_seq_ack), stdin=stdin
    )

    async def _noop_spawn() -> None:  # the proc is already wired above
        return None

    transport.spawn = _noop_spawn  # type: ignore[method-assign]
    session = await _session(transport)
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)
    await runner.start_and_handshake()
    return transport, stdin.buffer


async def test_non_echoing_peer_keeps_host_send_plain_adr0025() -> None:
    """A peer that does NOT echo seq/ack -> the host ``send()`` emits PLAIN bytes.

    Proves the host never ``A1``-wraps a frame for a peer that cannot deframe.
    This is the case the reference plugin now hits (its echo was removed in #262).
    """
    transport, _handshake_bytes = await _handshake_real_transport(echo_seq_ack=False)
    frame: Mapping[str, object] = {"jsonrpc": "2.0", "id": 1, "method": "outbound.message"}
    await transport.send(frame)
    # The most recent line on the wire is the host send; it must be PLAIN.
    sent_line = bytes(transport._proc.stdin.buffer).splitlines(keepends=True)[-1]  # type: ignore[union-attr]
    assert not sent_line.startswith(SEQ_MAGIC)
    assert sent_line == json.dumps(frame).encode() + b"\n"


async def test_echoing_peer_flips_gate_so_host_send_is_wrapped() -> None:
    """Negative control: a peer that DOES echo flips the gate, so send is wrapped.

    Without this the plain-bytes assertion above could pass vacuously (e.g. if the
    runner never flipped the gate at all); this proves the test catches the flip.
    """
    transport, _handshake_bytes = await _handshake_real_transport(echo_seq_ack=True)
    frame: Mapping[str, object] = {"jsonrpc": "2.0", "id": 1, "method": "outbound.message"}
    await transport.send(frame)
    sent_line = bytes(transport._proc.stdin.buffer).splitlines(keepends=True)[-1]  # type: ignore[union-attr]
    assert sent_line.startswith(SEQ_MAGIC)
