"""Host-side request/response transport carrying a T3 body to the quarantined LLM.

PR-S4-11c-2a (epic #237). This module owns the host half of the
inline-over-wire content path (ADR-0029): the raw T3 inbound body travels to the
(eventually launcher-spawned) quarantined LLM via a ``quarantine.ingest`` request
sent immediately BEFORE the ``quarantine.extract`` request the
:class:`alfred.security.quarantine.QuarantinedExtractor` drives. The child stays
storeless — it caches the ingested body in-process and pops it single-use on
extract; the host owns a single-use staging map that the transport drains when it
ships the ingest.

Three collaborators:

* :class:`QuarantineStagingMap` — the host-side single-use staging store
  (``handle.id -> TaggedContent[T3]``). A second drain of the same id is a loud
  refusal (replay defence — the laundering-window close from ADR-0029).
* :class:`T3BodyRecorder` — the ``record_body`` seam
  :class:`alfred.comms_mcp.bootstrap.CommsExtractorBridge` calls before
  ``extractor.extract``. It tags the inbound body ``TaggedContent[T3]`` via the
  authorised :func:`alfred.security.tiers.tag_t3_with_nonce` boot nonce and stages
  it. A ``None`` nonce is a loud refusal (mirrors StdioTransport's
  ``NonceNotConfigured`` guard); a WRONG nonce surfaces ``tag_t3_with_nonce``'s
  own ``ValueError``.
* :class:`QuarantineStdioTransport` — a :class:`alfred.plugins.transport.PluginTransport`
  driven by the :class:`QuarantinedExtractor`. On ``quarantine.extract`` it drains
  the staged body, sends ``quarantine.ingest{handle_id, context}`` then
  ``quarantine.extract{...}`` over a length-prefixed JSON-RPC child-IO seam, reads
  the reply frame, and returns a :class:`ControlResult`. It does NOT subclass
  :class:`alfred.plugins.stdio_transport.StdioTransport` — its content/control
  branch and direct-exec spawn are the wrong behaviour here; this transport reuses
  only the length-prefix framing convention and is driven against an injected
  child-IO seam so the real launcher-spawn (PR-S4-11c-2b) and the child MCP loop +
  LLM (PR-S4-11c-2c) stay out of scope.
"""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import structlog

from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.plugins.transport import ControlResult
from alfred.security.tiers import T3, tag_t3_with_nonce

if TYPE_CHECKING:
    from alfred.security.quarantine import ContentHandle
    from alfred.security.tiers import CapabilityGateNonce, TaggedContent

_log = structlog.get_logger(__name__)

# Wire method names (ADR-0029). ``quarantine.ingest`` is the NEW forward contract
# PR-S4-11c-2c routes in the child's MCP loop; ``quarantine.extract`` is the
# existing method the QuarantinedExtractor already dispatches.
_INGEST_METHOD = "quarantine.ingest"
_EXTRACT_METHOD = "quarantine.extract"

# 4-byte big-endian length prefix — peer to StdioTransport's framing
# (``struct.pack(">I", ...)`` at stdio_transport.py:467-487,605).
_LENGTH_HEADER_BYTES = 4


class StagingNonceUnconfiguredError(AlfredError):
    """Raised when :class:`T3BodyRecorder` is asked to stage with no nonce.

    Mirrors :class:`alfred.plugins.stdio_transport.NonceNotConfigured`: an
    explicit guard (not ``assert`` — ``python -O`` strips asserts) on the
    trust-boundary path that gates T3 tagging. A silent passthrough would stage
    the inbound body UNTAGGED, which the dual-LLM split forbids (CLAUDE.md hard
    rule #7). Distinct from the ``ValueError`` ``tag_t3_with_nonce`` raises on a
    WRONG nonce: this fires when there is NO nonce to attempt with at all.
    """


class StagingHandleNotConfiguredError(AlfredError):
    """Raised when the staging map is drained for an absent/consumed handle id.

    Single-use invariant (ADR-0029 / spec §7.2): each ``handle.id`` is staged
    once and drained once. A second drain — replay of a consumed T3 body — is a
    loud refusal, never a silent empty value. The same loud-on-replay posture the
    quarantined child enforces with its ``_content_cache.pop`` and the web.fetch
    content store enforces with GETDEL.
    """


@runtime_checkable
class ChildIO(Protocol):
    """The injected child-IO seam :class:`QuarantineStdioTransport` frames over.

    Abstracts the launcher-spawned subprocess pipes (PR-S4-11c-2b) so tests drive
    an in-process child double. ``write_frame`` ships one already-framed
    length-prefixed JSON-RPC request; ``read_frame`` returns the raw bytes of one
    length-prefixed reply frame (header stripped by the caller).
    """

    def write_frame(self, frame: bytes) -> None: ...

    async def read_frame(self) -> bytes: ...

    async def aclose(self) -> None: ...


class QuarantineStagingMap:
    """Host-side single-use staging store: ``handle.id -> TaggedContent[T3]``.

    The host owns the raw T3 body between :class:`T3BodyRecorder` (which stages it)
    and :class:`QuarantineStdioTransport` (which drains it for the
    ``quarantine.ingest`` request). The drain is a single-use ``pop``: a second
    drain of the same id raises :class:`StagingHandleNotConfiguredError` so a
    replay of a consumed body is refused loudly (ADR-0029 laundering-window close).

    Not async-shared across event loops — one map per daemon boot graph, driven by
    a single inbound turn at a time in this cut (the >1-adapter boot refusal in
    ``_commands`` keeps concurrency out of scope for 2a).
    """

    def __init__(self) -> None:
        self._staged: dict[str, TaggedContent[T3]] = {}

    def stage(self, handle_id: str, tagged: TaggedContent[T3]) -> None:
        """Stage a T3-tagged body under ``handle_id`` for a single later drain."""
        self._staged[handle_id] = tagged

    def drain(self, handle_id: str) -> TaggedContent[T3]:
        """Pop and return the staged body for ``handle_id`` (single-use).

        Raises :class:`StagingHandleNotConfiguredError` when ``handle_id`` was
        never staged or has already been drained — the loud refusal that closes
        the replay window.
        """
        try:
            return self._staged.pop(handle_id)
        except KeyError as exc:
            _log.warning(
                "security.quarantine_staging.handle_not_configured",
                handle_id=handle_id,
            )
            raise StagingHandleNotConfiguredError(
                t("security.quarantine_staging.handle_consumed")
            ) from exc


class T3BodyRecorder:
    """The ``record_body`` seam: tag the inbound body T3, stage it under a handle.

    Satisfies :class:`alfred.comms_mcp.bootstrap._BodyRecorderLike`
    (``__call__(*, handle, body) -> None``). The bridge calls this exactly once,
    BEFORE ``extractor.extract``, so the body is staged before the transport's
    ``quarantine.ingest`` drains it.

    Holds the authorised :class:`CapabilityGateNonce` by DI (never re-fetched from
    the module slot) so the gate's ``is``-identity check holds. A ``None`` nonce is
    a loud refusal — the host wires this recorder only on the production path where
    the boot nonce exists; a missing nonce means a wiring bug, not a stage-untagged
    fallback.
    """

    def __init__(self, *, nonce: CapabilityGateNonce | None, staging: QuarantineStagingMap) -> None:
        self._nonce = nonce
        self._staging = staging

    def __call__(self, *, handle: ContentHandle, body: bytes | str | object) -> None:
        """Tag ``body`` T3 under the boot nonce and stage it under ``handle.id``.

        Raises:
            StagingNonceUnconfiguredError: when no nonce is configured — fail
                loud rather than stage untagged (mirrors StdioTransport's
                ``NonceNotConfigured`` guard).
            ValueError: surfaced from :func:`tag_t3_with_nonce` when the held
                nonce is not the authorised slot identity (wrong-nonce path).
        """
        if self._nonce is None:
            _log.error(
                "security.quarantine_staging.nonce_unconfigured",
                handle_id=handle.id,
            )
            raise StagingNonceUnconfiguredError(t("security.quarantine_staging.nonce_unconfigured"))
        # T3 content is a *string* on the TaggedContent model. Decode bytes /
        # stringify mappings with the same ``errors="replace"`` posture the
        # StdioTransport content path uses so a non-UTF-8 body cannot crash the
        # tagging path.
        text = _body_to_text(body)
        tagged = tag_t3_with_nonce(
            text,
            source=f"comms-mcp:inbound:{handle.id}",
            caller_token=self._nonce,
        )
        self._staging.stage(handle.id, tagged)


def _body_to_text(body: bytes | str | object) -> str:
    """Coerce an inbound body to the ``str`` the TaggedContent model requires."""
    if isinstance(body, str):
        return body
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    # A Mapping/structured body — JSON-serialise deterministically. ``default=str``
    # keeps a non-JSON-native value from crashing the tagging path.
    return json.dumps(body, default=str, sort_keys=True)


def _frame(method: str, params: dict[str, object]) -> bytes:
    """Serialise one length-prefixed JSON-RPC request frame.

    Peer to StdioTransport's framing (``struct.pack(">I", len) + body``); the
    request id is omitted because this transport is strictly request/response
    against a single child and matches the reply to the just-sent extract.
    """
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


class QuarantineStdioTransport:
    """Request/response transport from the host to the quarantined LLM child.

    Implements :class:`alfred.plugins.transport.PluginTransport` structurally so
    the real :class:`QuarantinedExtractor` drives it exactly as it would the
    stdio transport. On a ``quarantine.extract`` dispatch it:

    1. Drains the staged T3 body for ``params["handle_id"]`` (single-use; a
       missing/consumed handle raises :class:`StagingHandleNotConfiguredError`).
    2. Sends ``quarantine.ingest{handle_id, context}`` carrying the body inline.
    3. Sends ``quarantine.extract{handle_id, schema_json, schema_version}``.
    4. Reads the reply frame and returns a :class:`ControlResult` — NEVER a
       :class:`ContentHandle` (the regression guard for ``quarantine.py:1038``,
       where a handle trips ``PluginProtocolViolation``).

    Only ``quarantine.extract`` is a supported dispatch method in this cut — any
    other method is a loud :class:`AlfredError` rather than a silent passthrough.
    """

    def __init__(self, *, child_io: ChildIO, staging: QuarantineStagingMap) -> None:
        self._child_io = child_io
        self._staging = staging

    async def dispatch(self, method: str, params: dict[str, object]) -> ControlResult:
        """Dispatch ``quarantine.extract`` via the ingest-then-extract wire.

        ``params`` carries ``handle_id`` (the staged body's key + the wire
        attribution token), ``schema_json`` and ``schema_version`` — exactly the
        shape :meth:`QuarantinedExtractor._extract_body` builds.
        """
        if method != _EXTRACT_METHOD:
            # Closed dispatch vocabulary for this cut — fail loud, never silently
            # forward an unknown method onto the quarantine wire (hard rule #7).
            _log.error("security.quarantine_transport.unsupported_method", method=method)
            raise AlfredError(t("security.quarantine_transport.unsupported_method", method=method))

        handle_id = str(params["handle_id"])
        # Drain BEFORE writing anything to the child: a missing/consumed handle is
        # refused before the wire is touched, so a replay cannot ship a partial
        # ingest then fail.
        tagged = self._staging.drain(handle_id)

        # Inline-over-wire (ADR-0029): ingest carries the raw T3 body; extract
        # carries only the opaque handle id + schema. Ingest goes FIRST so the
        # child has the body cached before it pops it on extract.
        self._child_io.write_frame(
            _frame(_INGEST_METHOD, {"handle_id": handle_id, "context": tagged.content})
        )
        self._child_io.write_frame(
            _frame(
                _EXTRACT_METHOD,
                {
                    "handle_id": handle_id,
                    "schema_json": params["schema_json"],
                    "schema_version": params["schema_version"],
                },
            )
        )

        raw = await self._child_io.read_frame()
        payload = _decode_result_payload(raw)
        # ALWAYS a ControlResult — the QuarantinedExtractor's kind/data/schema
        # guards (quarantine.py:1050-1145) do the lift; this transport never
        # synthesises a ContentHandle or an ExtractionResult on this path.
        return ControlResult(method=_EXTRACT_METHOD, payload=payload)

    async def close(self) -> None:
        """Close the injected child-IO seam (idempotent at the seam level)."""
        await self._child_io.aclose()


def _decode_result_payload(raw: bytes) -> dict[str, object]:
    """Strip the length prefix and return the JSON-RPC ``result`` as a dict.

    ``read_frame`` returns one length-prefixed reply frame (4-byte big-endian
    header + body), peer to the request framing (ADR-0029). The header is stripped
    unconditionally — a frame too short to carry it leaves an empty/garbage body that
    ``json.loads`` rejects loudly (``JSONDecodeError`` propagates into the extractor's
    ``transport_failed`` audit), so a truncated reply never silently mis-parses into an
    empty payload (the slice itself does not raise — the decode does). A non-dict
    ``result`` is returned as an empty dict so the QuarantinedExtractor's OWN
    ``kind``/``data`` guards (quarantine.py:1052/1075) — not this transport —
    classify the laundering attempt as a protocol violation.
    """
    body = raw[_LENGTH_HEADER_BYTES:]
    result = json.loads(body).get("result", {})
    return dict(result) if isinstance(result, dict) else {}


__all__ = [
    "ChildIO",
    "QuarantineStagingMap",
    "QuarantineStdioTransport",
    "StagingHandleNotConfiguredError",
    "StagingNonceUnconfiguredError",
    "T3BodyRecorder",
]
