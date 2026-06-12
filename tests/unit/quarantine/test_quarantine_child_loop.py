"""PR-S4-11c-2b0: the quarantined-child MCP loop (deterministic echo cut).

These tests drive the child's REAL length-prefixed JSON-RPC loop
(:func:`alfred.security.quarantine_child.__main__._run_mcp_server`) over fake
in-process stdin/stdout streams — no subprocess, no bwrap, no LLM. The contract
under proof is the wire peer of the host
:class:`alfred.security.quarantine_transport.QuarantineStdioTransport` and the 2a
in-test ``_EchoingChildDouble``
(``tests/integration/test_quarantine_transport_real.py``):

* ``quarantine.ingest{handle_id, context}`` caches the context (NO reply frame);
* ``quarantine.extract{handle_id, ...}`` pops the cached context single-use and
  replies ONE frame ``{result: {kind: extracted, data: {text: <ctx>, intent:
  greeting}, extraction_mode: native_constrained}}``;
* an unknown method is a loud refusal (raises), never a silent skip;
* stdin EOF exits the loop cleanly (return, exit 0 at the entry point);
* the fd-3 provider key read happens ONLY in ``main()`` — the loop is
  fd-3-free (sec-007), covered by the sibling skeleton import-hygiene test.

PR-S4-11c-2b0 (ADR-0030) moved the child INTO the installed package
(``alfred.security.quarantine_child``) so it ships in the wheel; these tests
import it by its new wheel-path name.
"""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

from alfred.security.quarantine_child import __main__ as quarantine_child


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
    """Collects the frames the loop writes."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.chunks.append(bytes(data))

    async def drain(self) -> None:
        return None

    def joined(self) -> bytes:
        return b"".join(self.chunks)


def _provider() -> object:
    """A deterministic provider sentinel (2b: no LLM)."""
    return quarantine_child._build_provider("sk-fake-key")


def _decode_reply(raw: bytes) -> dict[str, object]:
    length = struct.unpack(">I", raw[:4])[0]
    return json.loads(raw[4 : 4 + length])  # type: ignore[no-any-return]


async def test_ingest_then_extract_echoes_context() -> None:
    reader = _FakeReader(
        _frame("quarantine.ingest", {"handle_id": "h1", "context": "hello over the wire"})
        + _frame(
            "quarantine.extract",
            {"handle_id": "h1", "schema_json": "{}", "schema_version": 1},
        )
    )
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_provider(), reader=reader, writer=writer)

    reply = _decode_reply(writer.joined())
    result = reply["result"]
    assert isinstance(result, dict)
    assert result["kind"] == "extracted"
    assert result["data"] == {"text": "hello over the wire", "intent": "greeting"}
    assert result["extraction_mode"] == "native_constrained"


async def test_extract_pop_is_single_use() -> None:
    """A second extract for the same handle echoes empty (the context was popped)."""
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

    await quarantine_child._run_mcp_server(_provider(), reader=reader, writer=writer)

    raw = writer.joined()
    first_len = struct.unpack(">I", raw[:4])[0]
    first = json.loads(raw[4 : 4 + first_len])
    rest = raw[4 + first_len :]
    second_len = struct.unpack(">I", rest[:4])[0]
    second = json.loads(rest[4 : 4 + second_len])

    assert first["result"]["data"]["text"] == "once"
    assert second["result"]["data"]["text"] == ""


async def test_unknown_method_refuses_loud() -> None:
    reader = _FakeReader(_frame("quarantine.smuggle", {"handle_id": "h1"}))
    writer = _FakeWriter()

    with pytest.raises(quarantine_child.QuarantineChildProtocolError):
        await quarantine_child._run_mcp_server(_provider(), reader=reader, writer=writer)


async def test_eof_exits_clean() -> None:
    """An empty stream (immediate EOF) returns without writing — clean exit."""
    reader = _FakeReader(b"")
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_provider(), reader=reader, writer=writer)

    assert writer.joined() == b""


async def test_eof_mid_stream_after_ingest_exits_clean() -> None:
    """EOF after a complete ingest (no extract) is a clean loop exit, no reply."""
    reader = _FakeReader(_frame("quarantine.ingest", {"handle_id": "h1", "context": "x"}))
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_provider(), reader=reader, writer=writer)

    assert writer.joined() == b""


async def test_truncated_body_after_valid_header_exits_clean() -> None:
    """A valid header but a short body (host tore the pipe) exits cleanly, no reply.

    The host closing the wire mid-frame must not half-parse — the loop treats a
    truncated body as EOF and returns (exit 0), never crashing on a partial JSON.
    """
    # Header claims 64 bytes; only 3 follow → ``readexactly(64)`` raises EOF.
    reader = _FakeReader(struct.pack(">I", 64) + b"abc")
    writer = _FakeWriter()

    await quarantine_child._run_mcp_server(_provider(), reader=reader, writer=writer)

    assert writer.joined() == b""


def test_build_provider_reads_key_without_llm() -> None:
    """``_build_provider`` returns a sentinel and never reaches a network client."""
    provider = quarantine_child._build_provider("sk-secret")
    assert provider is not None
    # The key never lands on the sentinel's public surface.
    assert "sk-secret" not in repr(provider)
