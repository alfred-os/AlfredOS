"""StdioTransport.dispatch returns the correct :data:`DispatchResult` shape.

sec-001 / core-006 fix: ``dispatch()`` must branch on method shape and return
one of three concrete types, *never* unconditionally a :class:`ContentHandle`.

- Control-plane methods (``lifecycle.*``, ``adapter.health``, ``ping``)
  return a :class:`ControlResult` carrying the JSON-RPC ``result`` dict.
  These responses are **never** T3-tagged and **never** written to the
  content store.
- Content-bearing methods (everything else) return a
  :class:`ContentHandle` whose underlying ``TaggedContent[T3]`` lives in
  the transport's content store; the orchestrator never sees raw bytes.
"""

from __future__ import annotations

import json
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.plugins.stdio_transport import StdioTransport
from alfred.plugins.transport import ControlResult
from alfred.security.quarantine import ContentHandle


@pytest.fixture
def passthrough_transport(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> StdioTransport:
    """A transport with a DLP/scanner pair that never refuses or trips.

    Constructed without spawning a real subprocess — ``dispatch`` tests
    patch ``_process`` directly. The dlp is a structural ``scan(text) -> Result``
    fake whose ``.refused`` attribute is always ``False`` so the placeholder-
    frame stage 1 of ``dispatch`` short-circuits to broker substitution.
    """
    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=False, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    return StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/echo",
        args=[],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )


def _wire_subprocess_io(
    transport: StdioTransport, response_payload: dict[str, object]
) -> MagicMock:
    """Patch ``transport._process`` so dispatch reads back ``response_payload``.

    The transport reads its inbound frame via the length-prefixed protocol
    (4-byte BE header + N bytes). Two ``readexactly`` calls satisfy that
    sequence with the framed body of ``response_payload``.
    """
    body = json.dumps(response_payload).encode("utf-8")
    framed = struct.pack(">I", len(body)) + body

    mock_proc = MagicMock()
    mock_proc.stdin.write = MagicMock()
    mock_proc.stdin.drain = AsyncMock()
    mock_proc.stdout.readexactly = AsyncMock(side_effect=[framed[:4], framed[4:]])
    transport._process = mock_proc
    return mock_proc


@pytest.mark.asyncio
async def test_lifecycle_start_returns_control_result(
    passthrough_transport: StdioTransport,
) -> None:
    """Control-plane methods return :class:`ControlResult`, not ContentHandle."""
    _wire_subprocess_io(
        passthrough_transport,
        {"jsonrpc": "2.0", "result": {"status": "ok"}},
    )
    result = await passthrough_transport.dispatch("lifecycle.start", {})
    assert isinstance(result, ControlResult)
    assert result.method == "lifecycle.start"
    assert result.payload == {"status": "ok"}


@pytest.mark.asyncio
async def test_adapter_health_returns_control_result(
    passthrough_transport: StdioTransport,
) -> None:
    """``adapter.health`` is on the control-plane prefix list."""
    _wire_subprocess_io(
        passthrough_transport,
        {"jsonrpc": "2.0", "result": {"healthy": True}},
    )
    result = await passthrough_transport.dispatch("adapter.health", {})
    assert isinstance(result, ControlResult)


@pytest.mark.asyncio
async def test_ping_returns_control_result(
    passthrough_transport: StdioTransport,
) -> None:
    """``ping`` is on the control-plane prefix list."""
    _wire_subprocess_io(
        passthrough_transport,
        {"jsonrpc": "2.0", "result": {}},
    )
    result = await passthrough_transport.dispatch("ping", {})
    assert isinstance(result, ControlResult)


@pytest.mark.asyncio
async def test_web_fetch_returns_content_handle(
    passthrough_transport: StdioTransport,
) -> None:
    """Content-bearing methods return :class:`ContentHandle`.

    The opaque handle holds the source URL (for audit attribution only)
    and a freshly-minted UUID; the actual T3 bytes are held in the content
    store, never returned to the dispatch caller.
    """
    _wire_subprocess_io(
        passthrough_transport,
        {"jsonrpc": "2.0", "result": {"body": "<html>hi</html>"}},
    )
    result = await passthrough_transport.dispatch("web.fetch", {"url": "https://example.com"})
    assert isinstance(result, ContentHandle)
    assert result.source_url.startswith("plugin:test.plugin:")


@pytest.mark.asyncio
async def test_content_handle_response_persists_tagged_in_store(
    passthrough_transport: StdioTransport,
) -> None:
    """rvw-004 fix: the content store receives the TaggedContent[T3] *wrapper*.

    Persisting raw bytes loses the nonce + provenance and silently downgrades
    T3 → untagged on retrieval. The store's recorded value must be a
    ``TaggedContent[T3]`` with ``tier=T3``.
    """
    from alfred.security.tiers import T3, TaggedContent

    _wire_subprocess_io(
        passthrough_transport,
        {"jsonrpc": "2.0", "result": {"body": "abc"}},
    )
    handle = await passthrough_transport.dispatch("web.fetch", {"url": "https://example.com"})
    assert isinstance(handle, ContentHandle)
    stored = passthrough_transport._content_store.get(handle.id)
    assert isinstance(stored, TaggedContent)
    assert stored.tier is T3
