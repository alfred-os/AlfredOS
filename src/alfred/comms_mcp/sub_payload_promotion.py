"""Host-side sub-payload promotion to ``ContentHandle`` (P1, #206).

The Wave-1 :class:`alfred.comms_mcp.classifiers.discord.DiscordSubPayloadClassifier`
recognises the nine Discord sub-payload kinds and emits opaque
:class:`~alfred.comms_mcp.classifiers.discord.DiscordSubPayload` markers, but it
deliberately does NOT touch the content store — ``classify`` is synchronous and
side-effect-free. This module is the asynchronous HOST step that promotes each
marker to a single-use ``ContentHandle``:

1. run the host-owned :class:`alfred.comms_mcp.inbound_scanner.InboundContentScanner`
   (which dispatches the required classifier set for the adapter kind) to obtain
   the markers;
2. for each marker, **host-mint** a fresh ``uuid4`` ``handle_id`` (the promoter
   never trusts a plugin-supplied id — see ``web_fetch`` spec §3 pre-mint
   contract), write the raw sub-payload bytes to the content store under that id,
   and **rewrite** the body field at the marker's path to
   ``{"$content_handle_id": id}``;
3. return the rewritten body, the emitted handles, and the host-classified kinds.

After promotion the orchestrator only ever holds handle references for the
sub-payloads — the raw (T3) sub-payload bytes live in the content store, single-use,
dereferenced only by the quarantined LLM. This is the load-bearing T3-isolation
boundary: ``process_inbound_message`` calls :meth:`SubPayloadPromoter.promote`
BEFORE ``quarantined_extract`` so no raw sub-payload ever reaches the privileged
orchestrator's view.

The marker ``path`` is the narrow dotted/index DSL the classifier emits
(``embeds[0]`` or ``poll``); :func:`_replace_at_path` honours exactly that shape —
no eval, no arbitrary traversal.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog

from alfred.comms_mcp.classifiers.discord import DiscordSubPayload
from alfred.errors import AlfredError

if TYPE_CHECKING:
    from alfred.comms_mcp.inbound_scanner import InboundContentScanner
    from alfred.security.quarantine import ContentHandle

_log = structlog.get_logger(__name__)


class SubPayloadPromotionError(AlfredError):
    """A promoted sub-payload field could not be rewritten in the inbound body.

    ``marker.path`` is produced by a successful HOST-side classifier match against
    the SAME body, so the field it names is guaranteed to exist when the contract
    holds. If rewrite cannot locate it — a missing key, an out-of-range index, an
    indexed path over a non-list — the classifier and the body have drifted apart.
    This is a trust-boundary failure, not a recoverable case: silently inserting a
    handle reference under a phantom key would leave the real raw (T3) sub-payload
    bytes elsewhere in the promoted body, reaching the privileged orchestrator
    unredacted. The promoter therefore FAILS CLOSED — loud, never a silent no-op.
    """


CONTENT_HANDLE_REF_KEY: Final[str] = "$content_handle_id"
"""The single key a promoted body field carries in place of the raw sub-payload.

Load-bearing: the orchestrator's body-resolution path keys off this exact string
to recognise a handle reference (vs raw content). The leading ``$`` namespaces it
away from any real Discord field name."""


@runtime_checkable
class _ContentStoreLike(Protocol):
    """Structural type for the content store the promoter writes through.

    Matches :class:`alfred.plugins.web_fetch.content_store.ContentStore.write`'s
    host-pre-minted-id contract — the host supplies ``handle_id`` so the store
    never mints internally.
    """

    async def write(self, *, handle_id: str, body: bytes, source_url: str) -> ContentHandle: ...


@dataclass(frozen=True, slots=True)
class PromotedBody:
    """Result of promoting one inbound body's sub-payloads.

    ``body`` is the rewritten body — every recognised sub-payload field replaced
    with a ``{CONTENT_HANDLE_REF_KEY: id}`` reference; the caller's original body
    is never mutated. ``handles`` are the emitted ``ContentHandle`` instances (one
    per promoted sub-payload). ``sub_payload_kinds`` is the HOST-classified kind
    set — the authoritative provenance for the audit row (NOT the plugin-asserted
    ``notification.sub_payload_refs``).
    """

    body: Mapping[str, object]
    handles: tuple[ContentHandle, ...]
    sub_payload_kinds: frozenset[str]


class SubPayloadPromoter:
    """Promotes classified sub-payloads to single-use ``ContentHandle`` refs.

    Constructed per-adapter (the ``adapter_kind`` binds the scanner's required
    classifier set). A ``None`` promoter at the inbound entrypoint means promotion
    is inert — used by the reference plugin whose required classifier set is empty.
    """

    def __init__(
        self,
        *,
        adapter_kind: str,
        scanner: InboundContentScanner,
        content_store: _ContentStoreLike,
    ) -> None:
        self._adapter_kind = adapter_kind
        self._scanner = scanner
        self._content_store = content_store

    async def promote(self, body: Mapping[str, object]) -> PromotedBody:
        """Scan ``body``, promote every recognised sub-payload to a handle ref.

        Returns a :class:`PromotedBody` whose ``body`` is a fresh structure with
        each sub-payload field replaced by a handle reference; the input ``body``
        is left untouched. Bodies with no recognised sub-payloads round-trip
        unchanged with no content-store writes.
        """
        scanned = self._scanner.scan(adapter_kind=self._adapter_kind, body=body)
        markers = [m for m in scanned.sub_payloads if isinstance(m, DiscordSubPayload)]
        if not markers:
            return PromotedBody(body=body, handles=(), sub_payload_kinds=frozenset())

        rewritten = _deep_copy_mapping(body)
        handles: list[ContentHandle] = []
        kinds: set[str] = set()
        for marker in markers:
            handle_id = str(uuid.uuid4())
            handle = await self._content_store.write(
                handle_id=handle_id,
                body=json.dumps(marker.raw, sort_keys=True).encode(),
                source_url=marker.source_url,
            )
            handles.append(handle)
            kinds.add(marker.kind)
            _replace_at_path(rewritten, marker.path, {CONTENT_HANDLE_REF_KEY: handle.id})
            _log.debug(
                "comms_mcp.sub_payload_promoted",
                adapter_kind=self._adapter_kind,
                kind=marker.kind,
                path=marker.path,
                handle_id=handle.id,
            )
        return PromotedBody(
            body=rewritten,
            handles=tuple(handles),
            sub_payload_kinds=frozenset(kinds),
        )


def _deep_copy_mapping(value: Mapping[str, object]) -> dict[str, object]:
    """Recursively copy ``value`` into mutable dicts/lists for in-place rewrite.

    Only mappings and lists are structurally copied; leaves are shared (they are
    replaced wholesale by :func:`_replace_at_path`, never mutated). Keeps the
    caller's original body immutable from the promoter's perspective.
    """
    return {k: _deep_copy_value(v) for k, v in value.items()}


def _deep_copy_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _deep_copy_mapping(value)
    if isinstance(value, list):
        return [_deep_copy_value(item) for item in value]
    return value


def _replace_at_path(body: dict[str, object], path: str, replacement: object) -> None:
    """Replace the value at the classifier's single-segment ``path``.

    The classifier emits exactly one of two path shapes per marker: a bare key
    (``poll``, ``message_reference``) or a single key with a list index
    (``embeds[0]``, ``attachments[1]``). This honours precisely those two forms —
    no nested descent, because no classifier emits a multi-segment path. The path
    is produced by a successful host-side match, so the key/index are known to
    exist when the contract holds; any drift FAILS CLOSED with a typed
    :class:`SubPayloadPromotionError`. Crucially, the bare-key branch must NOT
    silently CREATE an absent key — that would insert a handle ref under a phantom
    field while the real raw sub-payload bytes remained elsewhere in the body
    unredacted (a T3 leak). It refuses instead.
    """
    key, index = _parse_segment(path)
    if key not in body:
        raise SubPayloadPromotionError(f"path {path!r}: key {key!r} absent from body")
    if index is None:
        body[key] = replacement
        return
    target = body[key]
    if not isinstance(target, list):
        raise SubPayloadPromotionError(f"path {path!r}: indexed value is not a list")
    if not 0 <= index < len(target):
        raise SubPayloadPromotionError(f"path {path!r}: index {index} out of range")
    target[index] = replacement


def _parse_segment(segment: str) -> tuple[str, int | None]:
    if segment.endswith("]") and "[" in segment:
        key, _, raw_index = segment.partition("[")
        return key, int(raw_index.rstrip("]"))
    return segment, None


__all__ = [
    "CONTENT_HANDLE_REF_KEY",
    "PromotedBody",
    "SubPayloadPromoter",
    "SubPayloadPromotionError",
]
