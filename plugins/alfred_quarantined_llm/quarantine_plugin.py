"""Quarantined-LLM MCP plugin subprocess (PR-S3-4, spec §5.1).

Exposes two JSON-RPC methods consumed by :class:`alfred.plugins.
quarantine_extractor.QuarantinedExtractor` over StdioTransport:

* ``quarantine.ingest(handle_id, context)`` — intake T3 bytes; stores
  them under ``handle_id`` for a single subsequent ``quarantine.extract``
  call.
* ``quarantine.extract(handle_id, schema_json, schema_version, provider)``
  → :data:`alfred.security.quarantine.ExtractionResult` (serialised as
  a discriminated-union JSON object).

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
import os
import struct
import sys
from typing import Any

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
    is enforced by the test ``test_quarantine_plugin_module_imports_
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

    Imports :mod:`provider_dispatch` inside the function so the plugin
    module's import-time surface stays minimal — the dispatcher pulls
    in pydantic + the provider SDK shapes, which would otherwise slow
    down every supervisor probe that imports this module just to look
    up ``handle_ingest``.
    """
    # Local import: see docstring rationale above.
    from plugins.alfred_quarantined_llm.provider_dispatch import dispatch_extraction

    content = _content_cache.get(handle_id, b"")
    return await dispatch_extraction(
        content=content,
        schema_json=schema_json,
        schema_version=schema_version,
        provider=provider,
    )


# ---------------------------------------------------------------------------
# Subprocess entry point — fd-3 read + MCP loop. Slice-3 SKELETON.
# ---------------------------------------------------------------------------


async def main() -> None:  # pragma: no cover - subprocess entry (Task 11 wires loop)
    """Entry point: read provider key from fd 3, then run the MCP server.

    The fd-3 read happens HERE, not at module load time (sec-007). The
    variable is del'd after handing it to the provider builder — best-
    effort scrub (CPython does not guarantee prompt zeroing, but the
    explicit ``del`` documents intent and removes the reference from the
    frame).

    The provider build + MCP server loop are NotImplemented in the
    Slice-3 skeleton; the supervisor cold-start path doesn't exercise
    this entry point until Task 11 wires the recorded fixtures end-to-end.
    """
    provider_key = _read_provider_key_from_fd3()
    try:
        provider = _build_provider(provider_key)
    finally:
        # del after handoff; the only remaining reference is inside
        # the provider client's SDK state.
        del provider_key
    await _run_mcp_server(provider)


def _build_provider(key: str) -> Any:  # pragma: no cover - Task 11 placeholder
    """Construct the provider client from the fd-3 key.

    NotImplementedError in the Slice-3 skeleton — concrete provider
    construction (Anthropic / DeepSeek / OpenAI client builders) lands
    once the recorded fixtures in Task 11b pin the wire format. The
    ``key`` parameter is intentionally consumed (typed ``str``) so a
    future implementer can't silently drop the provider key.
    """
    raise NotImplementedError("_build_provider: Slice-3 final pass (Task 11)")


async def _run_mcp_server(provider: Any) -> None:  # pragma: no cover - Task 11 placeholder
    """Enter the MCP stdio JSON-RPC loop.

    NotImplementedError in the Slice-3 skeleton — the loop body lands
    once the stdio MCP framing crate (PR-S3-3a's StdioTransport peer)
    is wired into the subprocess side. The ``provider`` parameter is
    intentionally consumed so a future implementer can't silently drop
    the provider on the floor.
    """
    raise NotImplementedError("_run_mcp_server: Slice-3 final pass (Task 11)")


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    asyncio.run(main())
