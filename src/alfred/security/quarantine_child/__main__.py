"""Quarantined-LLM child subprocess entry point (PR-S3-4, spec §5.1; #237).

Exposes two JSON-RPC methods consumed by
:class:`alfred.security.quarantine.QuarantinedExtractor` over the host
:class:`alfred.security.quarantine_transport.QuarantineStdioTransport`:

* ``quarantine.ingest(handle_id, context)`` — intake T3 bytes; stores
  them under ``handle_id`` for a single subsequent ``quarantine.extract``
  call.
* ``quarantine.extract(handle_id, schema_json, schema_version, provider)``
  → :data:`alfred.security.quarantine.ExtractionResult` (serialised as
  a discriminated-union JSON object).

**Wheel co-location (PR-S4-11c-2b0, ADR-0030).** This child ships IN the
installed ``alfred`` package (under ``src/alfred/security/quarantine_child``)
and is spawned via ``python -m alfred.security.quarantine_child``. Living in
the wheel means the code is reachable under the bwrap policy's ``/usr`` ro-bind
(site-packages) without widening the sandbox — the prior repo-root
``plugins/alfred_quarantined_llm`` location was wheel-excluded and unreachable
under ``kind="full"``. Imports are bounded to schemas + ``ProviderCapability``
(no privileged ``alfred.audit`` / ``alfred.core`` / ``alfred.memory`` / broker /
orchestrator) — codified by ``test_quarantine_child_import_closure``.

Runs under the ``alfred-quarantine`` OS user per spec §5.2 (UID separation;
the supervisor builds the subprocess argv + env). The provider key is
delivered over fd 3 per spec §5.3 — NEVER read from ``os.environ`` so a
compromised plugin host cannot harvest the key by enumerating its own
environment.

Output discipline: structured JSON only. No free-form text, no tool_call
fields outside the schema. The T3 trust boundary lives in this process;
the orchestrator never sees the raw provider response bytes (spec §6.7).

**Import hygiene (sec-007).** The fd-3 read happens in :func:`main`,
NEVER at module import time. Importing this module in test / mypy / ruff
/ IDE language-server contexts MUST NOT touch fd 3 — those contexts run
with no fd 3 open, and ``os.read(3, ...)`` at module scope would hang
the entire toolchain. The contract: read-fd-3 lives in ``main()``, and
``main()`` runs only under ``if __name__ == "__main__":``.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
import sys
from typing import Any, Protocol, runtime_checkable

# Stdlib-only (import-closure-safe per ADR-0030): pins logging to stderr so the
# child's stdout stays byte-pure for length-prefixed JSON-RPC frames. Called from
# main() before the fd-3 read / loop (BUG-1, PR-S4-11c-2b0).
from alfred._stdio_logging import configure_stderr_logging

# In-process content cache for the Slice-3 skeleton. The production
# implementation (PR-S3-5) replaces this with a Redis-backed
# ContentStore that supports the single-use ``GETDEL`` semantics in
# spec §7.2. The two shapes are write-then-read under the same key, so
# replacing this dict with the Redis client is a closed change.
#
# Module-private so the orchestrator never imports the cache directly —
# all cross-boundary access flows through ``handle_ingest`` /
# ``handle_extract``.
_content_cache: dict[str, bytes] = {}


# ---------------------------------------------------------------------------
# fd-3 provider key read (spec §5.3) — runs in main() only (sec-007).
# ---------------------------------------------------------------------------


# Closed-vocabulary fd-3 framing-error discriminator tags (err-003 fix).
# Printed to stderr before sys.exit(1) so the supervisor's child-died
# notification carries a structured signal naming WHICH framing rule was
# violated. Prior code collapsed all three failure modes into a bare
# ``sys.exit(1)``, leaving operators to guess whether the header was
# short, the body was short, or trailing bytes were present.
_FD3_ERR_SHORT_HEADER = "short_header"
_FD3_ERR_SHORT_BODY = "short_body"
_FD3_ERR_TRAILING_BYTES = "trailing_bytes"


def _emit_fd3_framing_error_and_exit(detail: str) -> None:
    """Print a closed-vocab framing-error tag to stderr, then exit non-zero.

    err-003 fix: keeps the three failure modes distinguishable from the
    supervisor's perspective. The detail tag is one of
    :data:`_FD3_ERR_SHORT_HEADER`, :data:`_FD3_ERR_SHORT_BODY`, or
    :data:`_FD3_ERR_TRAILING_BYTES` — never free-form text, so no
    attacker-controlled bytes can flow into the discriminator (the key
    is never decoded before exit on these paths).
    """
    # The structured marker uses ``=`` separator so the supervisor's
    # stderr scraper can parse it deterministically without word
    # boundary heuristics.
    print(f"plugin.launcher.framing_error={detail}", file=sys.stderr)
    sys.exit(1)


def _read_provider_key_from_fd3() -> str:
    """Read a 4-byte length-prefixed UTF-8 provider key from fd 3.

    Wire format (spec §5.3):

      [ 4-byte big-endian length ][ length-byte UTF-8 key ]

    Any framing error (short read, length lies, trailing bytes) exits the
    subprocess with a non-zero status BEFORE the MCP loop starts so the
    supervisor's child-died notification fires with a clear lifecycle
    state rather than a confused "started but never registered" gap. The
    three failure modes are distinguished via the closed-vocabulary
    stderr tag emitted by :func:`_emit_fd3_framing_error_and_exit`
    (err-003 fix).

    Called ONLY from :func:`main` — invoking this at module import
    time would hang the entire Python toolchain (sec-007). The contract
    is enforced by the test ``test_quarantine_child_module_imports_
    without_reading_fd3``.
    """
    header = os.read(3, 4)
    if len(header) < 4:
        # Fail loud, fail early: the supervisor expects a registered key
        # before it routes any JSON-RPC traffic to this subprocess.
        _emit_fd3_framing_error_and_exit(_FD3_ERR_SHORT_HEADER)
    key_length = struct.unpack(">I", header)[0]
    key_bytes = os.read(3, key_length)
    if len(key_bytes) < key_length:
        _emit_fd3_framing_error_and_exit(_FD3_ERR_SHORT_BODY)
    # Validate fd 3 is empty after reading — trailing bytes mean the
    # supervisor framed the key wrong, which is a class of bug we want to
    # surface immediately, not paper over.
    extra = os.read(3, 1)
    if extra:
        _emit_fd3_framing_error_and_exit(_FD3_ERR_TRAILING_BYTES)
    return key_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# MCP method handlers (the orchestrator-visible surface).
# ---------------------------------------------------------------------------


async def handle_ingest(handle_id: str, context: str) -> None:
    """Store T3 content under ``handle_id`` for one subsequent extract call.

    The Slice-3 skeleton encodes the supplied ``context`` string as UTF-8
    bytes and caches it in-process. PR-S3-5's production ContentStore
    swaps this for the Redis ``SETEX`` half of the single-use GETDEL
    contract (spec §7.2).

    No return value: the orchestrator pre-allocates ``handle_id`` (the
    ContentHandle is constructed at fetch time on the orchestrator side
    in spec §7.3) and trusts that any subsequent extract call against
    the same id reads back the same bytes.
    """
    _content_cache[handle_id] = context.encode()


async def handle_extract(
    *,
    handle_id: str,
    schema_json: str,
    schema_version: int,
    provider: Any,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Dispatch a structured extraction against the cached T3 content.

    Lookup-and-delegate shape: the entry-point's only job is to read the
    bytes for ``handle_id`` out of the content store and forward them to
    :func:`provider_dispatch.dispatch_extraction`, which owns the
    capability-branched (native / JSON-object / prompt-embedded) logic.

    Missing handle id → empty bytes flow forward; the dispatcher's
    retry-exhaustion path turns that into a ``TypedRefusal(reason=
    "cannot_extract")`` so the audit row records ``result="refused"``
    rather than crashing the subprocess. Crashing would skip the audit
    write, which is exactly the failure mode we are not allowed to ship.

    The ``schema_version`` argument is accepted-and-passed-through here;
    enforcement of the ``Literal[1]`` invariant lives on the
    orchestrator side in :meth:`QuarantinedExtractor._validate_schema_
    version` so a bad version refuses BEFORE we pay subprocess-launch
    cost. Re-checking inside the subprocess is defence in depth and
    lands in a later slice.

    ``max_tokens`` is accepted-and-passed-through to
    :func:`provider_dispatch.dispatch_extraction` (P1b, #340); ``None``
    leaves the provider seam's own default in place. PR2b-golive supplies
    the routing.yaml ``max_tokens_per_extraction`` here via the spawn env.

    Imports :mod:`provider_dispatch` inside the function so the child
    module's import-time surface stays minimal — the dispatcher pulls
    in pydantic + the provider SDK shapes, which would otherwise slow
    down every supervisor probe that imports this module just to look
    up ``handle_ingest``. Keeping the ``httpx``/provider-client import
    LAZY (off the module-scope graph) is also load-bearing for the
    go-live egress gate: the live deterministic-echo loop never calls
    ``handle_extract``, so the egress-capable import stays unreachable
    (PR-S4-11c-2b re-pivot).
    """
    # Local import: see docstring rationale above.
    from alfred.security.quarantine_child.provider_dispatch import dispatch_extraction

    # Single-use T3 handle (spec §7.2 GETDEL-equivalent): ``pop`` so the
    # T3-derived bytes are released from the cache the moment the
    # extractor consumes them. Using ``get`` would leave the payload
    # resident in-process and allow replay against the same handle_id
    # on a subsequent extract call — weakening the PRD §7.1 single-
    # consumer boundary intent. The Redis-backed ContentStore (PR-S3-5)
    # uses GETDEL for the same reason.
    content = _content_cache.pop(handle_id, b"")
    return await dispatch_extraction(
        content=content,
        schema_json=schema_json,
        schema_version=schema_version,
        provider=provider,
        max_tokens=max_tokens,
    )


# ---------------------------------------------------------------------------
# Subprocess entry point — fd-3 read + MCP loop. Slice-3 SKELETON.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Wire framing + loop protocol (PR-S4-11c-2b).
#
# DETERMINISTIC ECHO cut: the child runs the REAL length-prefixed JSON-RPC loop
# over fd 0/1 — peer to the host
# :class:`alfred.security.quarantine_transport.QuarantineStdioTransport`'s
# ``_frame`` + the 2a ``_EchoingChildDouble`` — but the extraction itself is a
# deterministic echo (NO LLM call). PR-S4-11c-2c swaps ONLY ``_build_provider``
# (a real Anthropic/DeepSeek client) and the extract branch (a real
# ``dispatch_extraction`` call) for the live model. The echo is NOT a
# host-fabricated extraction (CLAUDE.md hard rule #7): the real bwrapped
# subprocess reads the real wire and produces this reply itself; the host never
# synthesises an extraction on the child's behalf.
# ---------------------------------------------------------------------------

_INGEST_METHOD = "quarantine.ingest"
_EXTRACT_METHOD = "quarantine.extract"

# 4-byte big-endian length prefix — peer to the host transport's framing
# (``struct.pack(">I", ...)`` in quarantine_transport.py).
_LENGTH_HEADER_BYTES = 4


class QuarantineChildProtocolError(Exception):
    """The child received a wire method outside its closed vocabulary.

    A loud refusal (CLAUDE.md hard rule #7): an unknown JSON-RPC method on the
    quarantine wire is never silently skipped — the loop raises, :func:`main`
    prints a closed-vocab marker to stderr (the supervisor captures it) and
    exits non-zero so a wire-contract drift surfaces as a crashed child rather
    than a silently-ignored frame.
    """


class _DeterministicProvider:
    """Provider sentinel for the 2b deterministic-echo cut (NO LLM).

    The fd-3 provider key is still read + scrubbed by :func:`main` before this
    sentinel is built — the real-spawn proof asserts the key was delivered — but
    no network client is constructed. PR-S4-11c-2c replaces this with a real
    Anthropic/DeepSeek client built from the key.

    ``__repr__`` is pinned key-free so a stray ``repr`` of the provider (e.g. in
    a stack trace) can never leak the key the sentinel was built next to.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "_DeterministicProvider()"


@runtime_checkable
class _FrameReader(Protocol):
    """Length-prefixed frame source (``asyncio.StreamReader`` satisfies it)."""

    async def readexactly(self, n: int) -> bytes: ...


@runtime_checkable
class _FrameWriter(Protocol):
    """Length-prefixed frame sink (``asyncio.StreamWriter`` satisfies it)."""

    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...


def _echo_extracted_frame(context: str) -> bytes:
    """Build the ONE length-prefixed reply frame the extract branch emits.

    The ``data.text`` echoes the ingested context so the host's round-trip
    assertion proves the body crossed the wire (not a fixed replay). The shape
    matches the 2a ``_EchoingChildDouble`` byte-for-byte: a
    ``CommsBodyExtraction``-valid ``extracted`` payload.
    """
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "result": {
                "kind": "extracted",
                "data": {"text": context, "intent": "greeting"},
                "extraction_mode": "native_constrained",
            },
        }
    ).encode("utf-8")
    return struct.pack(">I", len(body)) + body


async def main() -> None:  # pragma: no cover - subprocess entry; loop covered via _run_mcp_server
    """Entry point: read provider key from fd 3, then run the MCP server.

    The fd-3 read happens HERE, not at module load time (sec-007). The variable
    is del'd after handing it to the provider builder — best-effort scrub
    (CPython does not guarantee prompt zeroing, but the explicit ``del``
    documents intent and removes the reference from the frame).

    The MCP loop runs over real ``asyncio`` stdio streams (fd 0 / fd 1). The loop
    body itself is injected-stream-testable (:func:`_run_mcp_server` takes the
    reader/writer) so the framing + dispatch are unit-covered without a
    subprocess; ``main`` is the thin real-stdio binding the launcher execs.

    BUG-1 (PR-S4-11c-2b0): stdout carries length-prefixed JSON-RPC reply frames,
    so ALL logging is pinned to stderr BEFORE anything runs — before the fd-3
    read, before the loop, and before the lazy ``provider_dispatch`` import on the
    extract path (which transitively loads the i18n translator and its
    missing-catalog warning on a pip-installed alfred). A log byte on fd 1 would
    corrupt the wire the host transport reads.
    """
    configure_stderr_logging()
    provider_key = _read_provider_key_from_fd3()
    try:
        provider = _build_provider(provider_key)
    finally:
        # del after handoff; in 2b the sentinel holds no key, so this is a
        # forward-looking scrub for the 2c real-client cut.
        del provider_key
    reader = asyncio.StreamReader()
    loop = asyncio.get_running_loop()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    w_transport, w_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
    await _run_mcp_server(provider, reader=reader, writer=writer)


def _build_provider(key: str) -> Any:
    """Construct the provider from the fd-3 key.

    PR-S4-11c-2b: returns a :class:`_DeterministicProvider` sentinel — the key is
    consumed (typed ``str``, so a future implementer cannot silently drop it) but
    NO network client is built and NO LLM is contacted. PR-S4-11c-2c swaps this
    body for a real Anthropic/DeepSeek client built from ``key``.
    """
    del key  # 2b: consumed-but-not-wired; 2c builds the real client from it
    return _DeterministicProvider()


async def _run_mcp_server(provider: Any, *, reader: _FrameReader, writer: _FrameWriter) -> None:
    """Run the length-prefixed JSON-RPC loop over ``reader`` / ``writer``.

    Storeless (the in-proc ``_content_cache`` pop, no Redis): ``quarantine.ingest``
    caches the context under ``handle_id`` and writes NO reply;
    ``quarantine.extract`` pops it single-use and writes ONE
    ``extracted``-kind reply frame echoing the context. An unknown method raises
    :class:`QuarantineChildProtocolError` (loud refusal). stdin EOF (a truncated
    or absent header) ends the loop cleanly — the host closed the pipe, so the
    child returns and :func:`main`'s ``asyncio.run`` exits 0.

    ``provider`` is accepted so the 2c swap (real LLM call in the extract branch)
    is a surgical change — the loop framing + dispatch stay identical.
    """
    del provider  # 2b: the deterministic echo needs no provider; 2c calls it
    while True:
        try:
            header = await reader.readexactly(_LENGTH_HEADER_BYTES)
        except asyncio.IncompleteReadError:
            # EOF (clean or mid-header) — the host closed the wire. Exit the loop.
            return
        length = struct.unpack(">I", header)[0]
        try:
            payload = await reader.readexactly(length)
        except asyncio.IncompleteReadError:
            # A truncated body after a valid header is the host tearing the pipe
            # down; treat it as EOF and exit cleanly rather than half-parsing.
            return
        request = json.loads(payload)
        method = request.get("method")
        params = request.get("params", {})
        if method == _INGEST_METHOD:
            await handle_ingest(str(params["handle_id"]), str(params["context"]))
            # Ingest writes NO reply frame (peer to the host transport, which
            # ships ingest then extract and reads exactly one reply).
            continue
        if method == _EXTRACT_METHOD:
            # PR-S4-11c-2c replaces this deterministic-echo body with a call to
            # ``handle_extract(...)`` (which delegates to ``dispatch_extraction``
            # → the real provider). Keep the loop, ``handle_extract``, and the
            # skeleton/loop tests (test_quarantine_child_loop.py,
            # test_quarantine_plugin_skeleton.py) in sync when that swap lands.
            # Single-use GETDEL-equivalent pop: the context is released the moment
            # the extract consumes it (replay against the same handle echoes "").
            context = _content_cache.pop(str(params["handle_id"]), b"").decode(
                "utf-8", errors="replace"
            )
            writer.write(_echo_extracted_frame(context))
            await writer.drain()
            continue
        # Closed vocabulary — anything else is a loud refusal.
        raise QuarantineChildProtocolError(method if isinstance(method, str) else repr(method))


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    asyncio.run(main())
