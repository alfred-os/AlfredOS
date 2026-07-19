"""Quarantined-LLM child subprocess entry point (PR-S3-4, spec §5.1; #237).

Exposes two JSON-RPC methods consumed by
:class:`alfred.security.quarantine.QuarantinedExtractor` over the host
:class:`alfred.security.quarantine_transport.QuarantineStdioTransport`:

* ``quarantine.ingest(handle_id, context)`` — intake T3 bytes; stores
  them under ``handle_id`` for a single subsequent ``quarantine.extract``
  call.
* ``quarantine.extract(handle_id, schema_json, schema_version, source)``
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
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

# Stdlib-only (import-closure-safe per ADR-0030): pins logging to stderr so the
# child's stdout stays byte-pure for length-prefixed JSON-RPC frames. Called from
# main() before the fd-3 read / loop (BUG-1, PR-S4-11c-2b0).
from alfred._stdio_logging import configure_stderr_logging
from alfred.security.quarantine_child._handshake import READY_FRAME, emit_hello

if TYPE_CHECKING:
    # TYPE-CHECK ONLY: gives ``_build_provider``'s ``-> _ProviderFactory`` annotation a
    # name to resolve under mypy/pyright WITHOUT importing the egress-capable
    # ``brokered_egress`` module at runtime. The real import is LAZY inside
    # ``_build_provider`` / ``main`` (#340 PR2b rev.2 point 2), and this guarded block
    # is nested under an ``ast.If`` — NOT a top-level statement — so the child
    # egress-closure gate (``_module_scope_imports`` walks ``tree.body`` only) never
    # sees it, and the runtime import-closure bound (ADR-0030) is unchanged because
    # ``TYPE_CHECKING`` is ``False`` at runtime.
    from alfred.security.quarantine_child.brokered_egress import _ProviderFactory

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
    source: Any,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Dispatch a structured extraction against the cached T3 content.

    Lookup-and-delegate shape: the entry-point's only job is to read the
    bytes for ``handle_id`` out of the content store and forward them to
    :func:`provider_dispatch.dispatch_extraction`, which owns the
    capability-branched (native / JSON-object / prompt-embedded) logic.

    Empty-content short-circuit (spec §8, #340 PR2b golive): a missing
    handle id (or an ingest of empty bytes) pops to ``b""`` and returns a
    ``TypedRefusal(reason="cannot_extract")`` DIRECTLY — BEFORE any
    ``dispatch_extraction`` call — so the child never brokers a socket or
    pays for 3 doomed provider attempts on content that cannot yield an
    extraction. Returning (not raising) keeps the audit row at
    ``result="refused"`` rather than crashing the subprocess and skipping
    the audit write, which is exactly the failure mode we are not allowed
    to ship (HARD #7).

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
    up ``handle_ingest``. Keeping that import LAZY (off the module-scope
    graph) is load-bearing for the child egress-closure gate: even though
    the live loop NOW calls ``handle_extract`` (#340 PR2b golive), the
    egress-capable transport still lands only inside ``source.bind()`` —
    ``provider_dispatch`` itself is egress-free, and the real Anthropic
    client is assembled over the brokered fd, never at ``__main__`` module
    scope (``test_quarantined_child_has_no_module_scope_egress_import``).
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
    if not content:
        # Empty-content short-circuit (spec §8): no bytes -> no extraction is
        # possible, so refuse WITHOUT brokering a socket or paying for the 3
        # doomed provider attempts dispatch_extraction would otherwise make.
        # Same closed-vocab reason the dispatcher's exhaustion path returns.
        return {"kind": "typed_refusal", "reason": "cannot_extract"}
    return await dispatch_extraction(
        content=content,
        schema_json=schema_json,
        schema_version=schema_version,
        source=source,
        max_tokens=max_tokens,
    )


# ---------------------------------------------------------------------------
# Subprocess entry point — fd-3 read + MCP loop. Slice-3 SKELETON.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Wire framing + loop protocol (#340 PR2b golive).
#
# LIVE EXTRACTION: the child runs the REAL length-prefixed JSON-RPC loop over fd
# 0/1 — peer to the host
# :class:`alfred.security.quarantine_transport.QuarantineStdioTransport`'s
# ``_frame`` — and the extract branch drives the REAL structured extraction
# (``handle_extract`` -> ``dispatch_extraction`` -> the Anthropic SDK over a
# brokered fd). This is the cutover from the prior deterministic-echo loop: the
# real bwrapped subprocess reads the real wire, calls the real model, and frames
# its own reply (CLAUDE.md hard rule #7: the host never synthesises an extraction
# on the child's behalf; raw T3 reaches only this process — HARD #5).
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


@runtime_checkable
class _FrameReader(Protocol):
    """Length-prefixed frame source (``asyncio.StreamReader`` satisfies it)."""

    async def readexactly(self, n: int) -> bytes: ...


@runtime_checkable
class _FrameWriter(Protocol):
    """Length-prefixed frame sink (``asyncio.StreamWriter`` satisfies it)."""

    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...


def _frame_from_result(result: dict[str, Any]) -> bytes:
    """Length-prefix a JSON-RPC ``result`` envelope for one extract reply frame.

    Replaces the deleted echo-frame builder: the child now frames the REAL
    :func:`provider_dispatch.dispatch_extraction` outcome (an ``extracted`` /
    ``typed_refusal`` dict) rather than a synthesised echo. Peer to the host
    transport's ``_decode_result_payload``, which reads ``.get("result")`` — the
    host lifts ``kind`` / ``data`` / ``extraction_mode`` / ``reason`` field-by-field,
    so a child-only ``cost_usd`` key on ``result`` rides along harmlessly.
    """
    body = json.dumps({"jsonrpc": "2.0", "result": result}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def _pin_structlog_to_stderr() -> None:
    """Route structlog output to stderr so no child log ever corrupts the fd-1 wire.

    :func:`configure_stderr_logging` pins STDLIB ``logging`` to stderr, but structlog's
    DEFAULT ``PrintLogger`` writes to ``sys.stdout``. The live extract path now imports
    :mod:`brokered_egress` (whose ``drain_leftovers`` emits a structlog debug) — the
    FIRST structlog emission on the child's live path. Left unpinned, that debug line
    prepends the reply frame and corrupts the wire the host transport reads (the BUG-1
    stdout-purity class; HARD #7). The pre-cutover deterministic-echo child never
    imported structlog on the live path, so this pin is new with the golive cutover.

    Lazy ``import structlog`` (called only from ``main``, never at module import): keeps
    the child's module-scope import surface bounded (ADR-0030) and off the egress-closure
    gate. Global structlog config is process-safe here — the child is a dedicated
    subprocess.
    """
    import structlog

    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))


async def _write_boot_ready(writer: _FrameWriter) -> None:
    """Emit the boot ``ready`` frame via the asyncio ``writer`` — LIVENESS signal (#443).

    Called from ``main`` after the asyncio streams are built and BEFORE the request
    loop is entered: proof the child initialized and is serving.
    """
    writer.write(READY_FRAME)
    await writer.drain()


async def main() -> None:
    """Entry point: read the fd-3 key, build the brokered source, run the MCP server.

    The fd-3 read happens HERE, not at module load time (sec-007). The variable
    is del'd after handing it to the provider builder — best-effort scrub
    (CPython does not guarantee prompt zeroing, but the explicit ``del``
    documents intent and removes the reference from the frame).

    Boot ordering (§20.3.2, pinned by ``test_quarantine_child_boot_ordering``):
    ``configure_stderr_logging`` -> ``_pin_structlog_to_stderr`` (structlog's default
    PrintLogger writes to stdout — pin it to stderr before any child log can corrupt the
    fd-1 wire) -> fd-3 read -> ``emit_hello`` (provenance FIRST,
    before ANY refuse path, so a post-hello refuse is child-authored and the host
    never forges a launcher ``sandbox_refused`` row) -> ``_build_provider`` (the
    §20.2 SECONDARY refuse-boot: an empty key raises ``QuarantineChildBootError``
    strictly AFTER ``emit_hello`` and BEFORE ``ready``) -> reconstruct the
    inherited fd-4 control socket + build the ``BrokeredProviderSource`` -> emit
    ``ready`` -> run the loop. A pre-``emit_hello`` fd-3 framing failure exits with
    ZERO stdout, which the host's sec-001 gate correctly reads as a launcher EOF.

    ``import socket`` is LAZY (here, not module scope): ``socket`` is egress-capable,
    so a module-scope import would trip the child egress-closure gate
    (``test_quarantined_child_has_no_module_scope_egress_import``); ``main()`` is not
    module scope, so the lazy bind keeps the gate green (#340 PR2b rev.2 point 2).

    BUG-1 (PR-S4-11c-2b0): stdout carries length-prefixed JSON-RPC reply frames,
    so ALL logging is pinned to stderr BEFORE anything runs — before the fd-3
    read, before the loop, and before the lazy ``provider_dispatch`` import on the
    extract path (which transitively loads the i18n translator and its
    missing-catalog warning on a pip-installed alfred). A log byte on fd 1 would
    corrupt the wire the host transport reads.
    """
    import socket  # LAZY — see docstring (egress-closure gate); main() is not module scope

    # The inherited one-way core->child control fd (#340 PR2a; ADR-0050). The host
    # spawns with ``control_fd=True`` (Task 8) so fd 4 is a live AF_UNIX end.
    _control_fd = 4

    configure_stderr_logging()
    _pin_structlog_to_stderr()  # structlog default is stdout — pin it before any child log
    provider_key = _read_provider_key_from_fd3()
    emit_hello()  # provenance FIRST (#443): a real exec'd child; pins launcher-vs-child
    try:
        factory = _build_provider(provider_key)  # §20.2 secondary refuse-boot on empty key
    finally:
        del provider_key  # best-effort scrub after handoff to the frozen factory
    # Reconstruct the inherited fd-4 control channel and build the per-attempt
    # provider source BEFORE ``ready`` — a broken control fd refuses boot rather
    # than letting the liveness frame lie (§20.3.2). LAZY import: brokered_egress
    # is the egress-capable module and must stay off __main__'s module-scope graph.
    from alfred.security.quarantine_child.brokered_egress import BrokeredProviderSource

    control_end = socket.socket(fileno=_control_fd, family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    source = BrokeredProviderSource(factory, control_end)
    reader = asyncio.StreamReader()
    loop = asyncio.get_running_loop()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    w_transport, w_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
    await _write_boot_ready(writer)  # liveness: proves initialized + serving (#443)
    await _run_mcp_server(source, reader=reader, writer=writer)


def _build_provider(key: str) -> _ProviderFactory:
    """Build the per-child provider FACTORY from the fd-3 key + spawn-env config.

    Returns a boot-cheap, frozen :class:`_ProviderFactory` — NO socket, NO network:
    the real Anthropic SDK client is assembled per extraction attempt inside
    ``source.bind()`` over a brokered fd, never here. This keeps the child's boot
    path egress-free (``sbx-2026-024``) as defence-in-depth over the ``--unshare-net``
    kernel containment.

    §20.2 SECONDARY refuse-boot (HARD #7): an empty key makes
    ``_ProviderFactory.from_key`` raise :class:`QuarantineChildBootError`, and a
    non-positive ``ALFRED_QUARANTINE_MAX_TOKENS`` raises it here too — both propagate out
    of ``main`` (``asyncio.run`` re-raises) so the child exits non-zero BEFORE writing
    ``ready``: a dead-LLM child must never lie live. The HOST pre-spawn checks (Task 7 key,
    Task 15 budget) are the PRIMARY guards; these are defence-in-depth.

    ``ALFRED_QUARANTINE_MODEL`` / ``ALFRED_QUARANTINE_MAX_TOKENS`` arrive via the
    scrubbed spawn env (Task 8). A missing var is a supervisor-side wiring bug that
    fails loud with ``KeyError`` at boot rather than silently defaulting the model.

    The ``max_tokens > 0`` guard (Task 15, HARD #7) fires HERE — before the request loop
    that calls ``dispatch_extraction`` is ever entered — so a ``<= 0`` budget can never
    reach the retry loop, where the ``CompletionRequest`` ``>0`` validator's
    ``ValidationError`` would be caught as retry-eligible and LAUNDERED into a
    ``cannot_extract`` typed refusal after N doomed attempts.
    """
    from alfred.security.quarantine_child.brokered_egress import (
        QuarantineChildBootError,
        _ProviderFactory,
    )

    model = os.environ["ALFRED_QUARANTINE_MODEL"]
    max_tokens = int(os.environ["ALFRED_QUARANTINE_MAX_TOKENS"])
    if max_tokens <= 0:
        # §20.2 SECONDARY refuse-boot (HARD #7): refuse LOUD at boot rather than let a
        # non-positive budget reach dispatch_extraction, where it would launder into a
        # cannot_extract refusal. Child-subprocess boot diagnostic (NOT t() scope); the
        # value is host-set routing config, non-secret / non-T3.
        raise QuarantineChildBootError(
            f"ALFRED_QUARANTINE_MAX_TOKENS must be > 0, got {max_tokens} — refusing to "
            "boot a child whose every extraction would fail its >0 validator (§20.2)"
        )
    return _ProviderFactory.from_key(key, model=model, max_tokens=max_tokens)


async def _run_mcp_server(source: Any, *, reader: _FrameReader, writer: _FrameWriter) -> None:
    """Run the length-prefixed JSON-RPC loop over ``reader`` / ``writer``.

    Storeless (the in-proc ``_content_cache`` pop, no Redis): ``quarantine.ingest``
    caches the T3 context under ``handle_id`` and writes NO reply;
    ``quarantine.extract`` pops it single-use and runs the REAL structured
    extraction against the brokered ``source`` (:func:`handle_extract` ->
    :func:`provider_dispatch.dispatch_extraction`), then frames the ``extracted`` /
    ``typed_refusal`` result as ONE reply. An unknown method raises
    :class:`QuarantineChildProtocolError` (loud refusal). stdin EOF (a truncated
    or absent header) ends the loop cleanly — the host closed the pipe, so the
    child returns and :func:`main`'s ``asyncio.run`` exits 0.

    ``source`` is the ``BrokeredProviderSource`` (typed ``Any`` for the egress-free
    rationale that types the dispatcher's ``source`` param): it brokers ONE gateway
    socket per retry attempt. After each extract the loop drains any pre-brokered
    sockets an early-success retry never consumed (§6) in a ``finally`` so no fd
    leaks on the persistent child, even if ``handle_extract`` raised.
    """
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
            try:
                result = await handle_extract(
                    handle_id=str(params["handle_id"]),
                    schema_json=str(params["schema_json"]),
                    schema_version=int(params["schema_version"]),
                    source=source,
                    max_tokens=int(os.environ["ALFRED_QUARANTINE_MAX_TOKENS"]),
                )
            finally:
                # Sweep the (N - attempts_used) unused pre-brokered sockets an
                # early-success retry loop never consumed (§6). In a ``finally`` so
                # it runs even if handle_extract raised — no fd leak on the child.
                source.drain_leftovers()
            writer.write(_frame_from_result(result))
            await writer.drain()
            continue
        # Closed vocabulary — anything else is a loud refusal.
        raise QuarantineChildProtocolError(method if isinstance(method, str) else repr(method))


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    asyncio.run(main())
