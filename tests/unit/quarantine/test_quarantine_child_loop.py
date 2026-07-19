"""#340 PR2b golive: the quarantined-child MCP loop (REAL-extraction cutover).

These tests drive the child's REAL length-prefixed JSON-RPC loop
(:func:`alfred.security.quarantine_child.__main__._run_mcp_server`) over fake
in-process stdin/stdout streams — no subprocess, no bwrap, no live LLM. The
deterministic-echo path is DELETED; the extract branch now drives the real
``handle_extract`` -> ``dispatch_extraction`` seam against a brokered ``source``.
These unit tests hold the loop framing + dispatch delegation honest WITHOUT a real
provider by monkeypatching ``dispatch_extraction`` to a canned result (the real
provider round-trip is the Task 14 docker/TLS-stub integration proof):

* ``quarantine.ingest{handle_id, context}`` caches the context (NO reply frame);
* ``quarantine.extract{handle_id, ...}`` on NON-empty content frames the (faked)
  ``dispatch_extraction`` result as ONE reply, then drains leftover sockets;
* ``quarantine.extract`` on EMPTY / popped content short-circuits to a
  ``typed_refusal(reason="cannot_extract")`` frame WITHOUT calling dispatch (spec §8);
* an unknown method is a loud refusal (raises), never a silent skip;
* stdin EOF (empty / truncated) exits the loop cleanly (return, exit 0);
* the fd-3 provider key read happens ONLY in ``main()`` — the loop is fd-3-free
  (sec-007), covered by the sibling skeleton import-hygiene test.
"""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

import pytest

from alfred.security.quarantine_child import __main__ as quarantine_child
from alfred.security.quarantine_child import provider_dispatch as pd

# The canned extraction ``dispatch_extraction`` is faked to return — a
# CommsBodyExtraction-valid ``extracted`` payload plus the child-only ``cost_usd``.
_CANNED_RESULT: dict[str, Any] = {
    "kind": "extracted",
    "data": {"text": "structured value", "intent": "greeting"},
    "extraction_mode": "native_constrained",
    "cost_usd": 0.0,
}


def _frame(method: str, params: dict[str, object]) -> bytes:
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


class _FakeReader:
    """Feeds a fixed byte stream then raises ``IncompleteReadError`` at EOF.

    Mirrors :meth:`asyncio.StreamReader.readexactly`: returns exactly ``n`` bytes
    or raises ``IncompleteReadError`` (partial == EOF mid frame) when the buffer
    is exhausted.
    """

    def __init__(self, data: bytes) -> None:
        self._buf = bytearray(data)

    async def readexactly(self, n: int) -> bytes:
        if len(self._buf) < n:
            partial = bytes(self._buf)
            self._buf.clear()
            raise asyncio.IncompleteReadError(partial, n)
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk


class _FakeWriter:
    """Collects the frames the loop writes + counts ``drain()`` calls."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        self.chunks.append(bytes(data))

    async def drain(self) -> None:
        self.drain_calls += 1

    def joined(self) -> bytes:
        return b"".join(self.chunks)


class _FakeSource:
    """Minimal ``BrokeredProviderSource`` stand-in for the loop tests.

    The loop passes it straight to ``handle_extract`` (which forwards it to the
    faked ``dispatch_extraction``, so ``capabilities()`` / ``bind()`` are never hit
    here) and calls ``drain_leftovers()`` in the extract-branch ``finally``. The
    counter proves the drain fired exactly once per extract, per §6.
    """

    def __init__(self) -> None:
        self.drain_calls = 0

    def drain_leftovers(self) -> None:
        self.drain_calls += 1


def _decode_reply(raw: bytes) -> dict[str, object]:
    length = struct.unpack(">I", raw[:4])[0]
    return json.loads(raw[4 : 4 + length])  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def _extract_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The extract branch reads ``ALFRED_QUARANTINE_MAX_TOKENS`` (spawn env, Task 8)."""
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    quarantine_child._content_cache.clear()


def _fake_dispatch_returning_canned(
    monkeypatch: pytest.MonkeyPatch, captured: dict[str, Any]
) -> None:
    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return dict(_CANNED_RESULT)

    monkeypatch.setattr(pd, "dispatch_extraction", _fake_dispatch)


async def test_ingest_then_extract_frames_dispatch_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-empty content: the loop frames the (faked) ``dispatch_extraction`` result."""
    captured: dict[str, Any] = {}
    _fake_dispatch_returning_canned(monkeypatch, captured)

    reader = _FakeReader(
        _frame("quarantine.ingest", {"handle_id": "h1", "context": "hello over the wire"})
        + _frame(
            "quarantine.extract",
            {"handle_id": "h1", "schema_json": "{}", "schema_version": 1},
        )
    )
    writer = _FakeWriter()
    source = _FakeSource()

    await quarantine_child._run_mcp_server(source, reader=reader, writer=writer)

    reply = _decode_reply(writer.joined())
    assert reply["result"] == _CANNED_RESULT
    # The real T3 bytes flowed through to the dispatcher, and max_tokens came from env.
    assert captured["content"] == b"hello over the wire"
    assert captured["source"] is source
    assert captured["max_tokens"] == 8192
    # §6: the extract branch drains leftover pre-brokered sockets exactly once.
    assert source.drain_calls == 1


async def test_extract_missing_handle_short_circuits_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty content (no prior ingest): short-circuit to ``cannot_extract``, NO dispatch.

    spec §8: an unknown handle pops to ``b""`` and refuses BEFORE any provider call, so
    the child never brokers a socket or pays for 3 doomed attempts. Still ONE framed
    reply (a refusal), and the drain still runs.
    """
    dispatch_calls: list[Any] = []

    async def _boom_dispatch(**kwargs: Any) -> dict[str, Any]:
        dispatch_calls.append(kwargs)
        raise AssertionError("dispatch must not run on empty content (§8 short-circuit)")

    monkeypatch.setattr(pd, "dispatch_extraction", _boom_dispatch)

    reader = _FakeReader(
        _frame(
            "quarantine.extract", {"handle_id": "missing", "schema_json": "{}", "schema_version": 1}
        )
    )
    writer = _FakeWriter()
    source = _FakeSource()

    await quarantine_child._run_mcp_server(source, reader=reader, writer=writer)

    reply = _decode_reply(writer.joined())
    assert reply["result"] == {"kind": "typed_refusal", "reason": "cannot_extract"}
    assert dispatch_calls == []  # dispatch never called
    assert source.drain_calls == 1  # drain still runs in the finally


async def test_second_extract_after_pop_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    """The single-use pop means a SECOND extract on the same handle short-circuits."""
    captured: dict[str, Any] = {}
    _fake_dispatch_returning_canned(monkeypatch, captured)

    reader = _FakeReader(
        _frame("quarantine.ingest", {"handle_id": "h1", "context": "once"})
        + _frame(
            "quarantine.extract", {"handle_id": "h1", "schema_json": "{}", "schema_version": 1}
        )
        + _frame(
            "quarantine.extract", {"handle_id": "h1", "schema_json": "{}", "schema_version": 1}
        )
    )
    writer = _FakeWriter()
    source = _FakeSource()

    await quarantine_child._run_mcp_server(source, reader=reader, writer=writer)

    raw = writer.joined()
    first_len = struct.unpack(">I", raw[:4])[0]
    first = json.loads(raw[4 : 4 + first_len])
    rest = raw[4 + first_len :]
    second_len = struct.unpack(">I", rest[:4])[0]
    second = json.loads(rest[4 : 4 + second_len])

    assert first["result"] == _CANNED_RESULT  # first: real dispatch
    assert second["result"] == {"kind": "typed_refusal", "reason": "cannot_extract"}  # popped
    assert source.drain_calls == 2  # one drain per extract


async def test_unknown_method_refuses_loud() -> None:
    reader = _FakeReader(_frame("quarantine.smuggle", {"handle_id": "h1"}))
    writer = _FakeWriter()

    with pytest.raises(quarantine_child.QuarantineChildProtocolError):
        await quarantine_child._run_mcp_server(_FakeSource(), reader=reader, writer=writer)


async def test_eof_exits_clean() -> None:
    """An empty stream (immediate EOF) returns without writing — clean exit."""
    reader = _FakeReader(b"")
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_FakeSource(), reader=reader, writer=writer)

    assert writer.joined() == b""


async def test_eof_mid_stream_after_ingest_exits_clean() -> None:
    """EOF after a complete ingest (no extract) is a clean loop exit, no reply."""
    reader = _FakeReader(_frame("quarantine.ingest", {"handle_id": "h1", "context": "x"}))
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_FakeSource(), reader=reader, writer=writer)

    assert writer.joined() == b""


async def test_truncated_body_after_valid_header_exits_clean() -> None:
    """A valid header but a short body (host tore the pipe) exits cleanly, no reply.

    The host closing the wire mid-frame must not half-parse — the loop treats a
    truncated body as EOF and returns (exit 0), never crashing on a partial JSON.
    """
    # Header claims 64 bytes; only 3 follow → ``readexactly(64)`` raises EOF.
    reader = _FakeReader(struct.pack(">I", 64) + b"abc")
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_FakeSource(), reader=reader, writer=writer)

    assert writer.joined() == b""


def test_build_provider_returns_factory_from_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_build_provider`` returns a boot-cheap ``_ProviderFactory`` with a key-free repr.

    The frozen factory holds the api key but never exposes it in ``repr`` (HARD #5 /
    no-secret-in-logs), and constructs NO network client at boot (sbx-2026-024 pins the
    no-socket property directly).
    """
    from alfred.security.quarantine_child.brokered_egress import _ProviderFactory

    monkeypatch.setenv("ALFRED_QUARANTINE_MODEL", "claude-test-model")
    monkeypatch.setenv("ALFRED_QUARANTINE_MAX_TOKENS", "8192")
    factory = quarantine_child._build_provider("sk-secret")
    assert isinstance(factory, _ProviderFactory)
    assert "sk-secret" not in repr(factory)


async def test_write_boot_ready_emits_ready_frame_via_writer() -> None:
    """``_write_boot_ready`` writes READY_FRAME through the asyncio writer + drains.

    The ``drain()`` assertion is load-bearing: draining is part of the boot-liveness
    contract (the host must SEE the ready frame, not have it sit in the writer's buffer),
    so a no-op fake would pass even if the readiness flush were removed. Counting the
    call pins that ``_write_boot_ready`` actually flushes exactly once.
    """
    from alfred.security.quarantine_child._handshake import READY_FRAME

    writer = _FakeWriter()  # collects written chunks in .chunks + counts drain() calls
    await quarantine_child._write_boot_ready(writer)
    assert b"".join(writer.chunks) == READY_FRAME
    assert writer.drain_calls == 1
