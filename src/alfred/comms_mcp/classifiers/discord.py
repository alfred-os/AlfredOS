"""``DiscordSubPayloadClassifier`` — Discord sub-payload recognition (B1, #206).

Discord delivers rich content (embeds, attachments, polls, stickers, interactive
components, message references) inline in the inbound message JSON. Every such
sub-payload is adversary-authorable (any Discord user can craft an embed title or
attachment filename) and therefore **T3**. This host-side classifier recognises
the nine sub-payload kinds enumerated in spec §8.6 / §8.10 and emits one opaque
:class:`DiscordSubPayload` marker per matched sub-payload so the orchestrator
never sees the raw sub-payload bytes inline — the host promotes each marker to a
single-use ``ContentHandle`` downstream (the async content-store write + body
rewrite is a host step, not the synchronous classifier's job).

**Scanner contract (reconciled).** PR-S4-8's
:class:`alfred.comms_mcp.inbound_scanner.InboundContentScanner` constructs a
classifier with no args and calls a SYNCHRONOUS ``classify(body)`` that returns an
iterable of opaque markers (``ScannedInbound.sub_payloads``). This module honours
exactly that surface — ``classify`` is sync and returns ``tuple[DiscordSubPayload,
...]``. The plan pseudocode's ``ScannedFrame`` / inline async content-store write
is NOT the shipped contract; promotion-to-handle is the consuming host step.

**Forward-compat.** Discord's API surface evolves; a future variant may ship a
sub-payload in a materially different shape. A malformed sub-payload (wrong
container type, non-dict element) is logged loudly (``comms_mcp.discord_classifier.malformed``)
and SKIPPED — never raised — so a single odd field cannot crash the inbound scan
for the whole message (spec §8.5 forward-compat note). This is the one deliberate
non-failing skip; every other path is loud.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

import structlog

from alfred.comms_mcp.classifier_registry import register_classifier

_log = structlog.get_logger(__name__)

SubPayloadKind = Literal[
    "embed",
    "attachment",
    "poll",
    "link_unfurl",
    "sticker",
    "voice_message",
    "component",
    "forwarded_ref",
    "pinned_ref",
]
"""The nine Discord sub-payload kinds (spec §8.10 — referenced by the audit
schema's ``sub_payload_kinds`` constant; load-bearing exact set)."""

SUB_PAYLOAD_KINDS: Final[frozenset[str]] = frozenset(
    {
        "embed",
        "attachment",
        "poll",
        "link_unfurl",
        "sticker",
        "voice_message",
        "component",
        "forwarded_ref",
        "pinned_ref",
    }
)


@dataclass(frozen=True, slots=True)
class DiscordSubPayload:
    """An opaque T3 marker for one recognised Discord sub-payload.

    Carries the recognised ``kind``, the dotted ``path`` at which it was found in
    the message body (e.g. ``embeds[0]``), the ``source_url`` audit-attribution
    string (``discord://<path>``), and the ``raw`` sub-payload value. The host
    promotes ``raw`` into a single-use ``ContentHandle`` (writing it to the
    content store + replacing the body field with the handle reference) before
    the orchestrator is reached; the orchestrator only ever holds the handle.
    """

    kind: SubPayloadKind
    path: str
    source_url: str
    raw: Mapping[str, object]


def _walk_path(body: Mapping[str, object], path: str) -> object | None:
    """Resolve a narrow dotted/index path against ``body``; ``None`` if absent.

    The DSL is intentionally tiny — dotted segments with an optional trailing
    ``[index]`` (e.g. ``embeds[0]`` or ``poll``). NO arbitrary code execution, NO
    eval; a missing key, an out-of-range index, or an index applied to a non-list
    all return ``None`` rather than raising. Used by the per-kind matchers and
    pinned directly by ``TestDSL``.
    """
    current: object = body
    for segment in path.split("."):
        key = segment
        index: int | None = None
        if key.endswith("]") and "[" in key:
            key, _, raw_index = key.partition("[")
            try:
                index = int(raw_index.rstrip("]"))
            except ValueError:
                # Malformed selector (``embeds[abc]`` / ``embeds[]``): the DSL
                # contract resolves invalid paths to ``None``, never raises.
                return None
            if index < 0:
                # A negative index would resolve from the END (Python list
                # semantics) — invalid in this DSL; fail closed rather than wrap.
                return None
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
        if index is not None:
            if not isinstance(current, list) or index >= len(current):
                return None
            current = current[index]
    return current


def _marker(kind: SubPayloadKind, path: str, raw: Mapping[str, object]) -> DiscordSubPayload:
    return DiscordSubPayload(kind=kind, path=path, source_url=f"discord://{path}", raw=raw)


@register_classifier(kind="discord", name="discord_sub_payloads")
class DiscordSubPayloadClassifier:
    """Recognise the nine Discord sub-payload kinds; emit one marker each."""

    def classify(self, body: Mapping[str, object]) -> tuple[DiscordSubPayload, ...]:
        """Return one :class:`DiscordSubPayload` marker per matched sub-payload.

        Synchronous + side-effect-free beyond structlog (per the scanner
        contract). Malformed sub-payloads are warned and skipped.
        """
        markers: list[DiscordSubPayload] = []
        markers.extend(self._embeds(body))
        markers.extend(self._attachments(body))
        markers.extend(self._sticker_or_component(body, field="stickers", kind="sticker"))
        markers.extend(self._sticker_or_component(body, field="components", kind="component"))
        markers.extend(self._poll(body))
        markers.extend(self._message_reference(body))
        return tuple(markers)

    def _embeds(self, body: Mapping[str, object]) -> list[DiscordSubPayload]:
        # A Discord embed whose ``type`` is ``"link"`` is a link-unfurl card
        # (link_unfurl); every other embed is a rich ``embed``.
        def kind_of(elem: Mapping[str, object]) -> SubPayloadKind:
            return "link_unfurl" if elem.get("type") == "link" else "embed"

        return self._each_in_list(body, field="embeds", kind_of=kind_of)

    def _attachments(self, body: Mapping[str, object]) -> list[DiscordSubPayload]:
        # An attachment whose ``content_type`` begins ``audio/`` is a Discord
        # voice message (voice_message); every other attachment is an
        # ``attachment``.
        def kind_of(elem: Mapping[str, object]) -> SubPayloadKind:
            content_type = elem.get("content_type")
            if isinstance(content_type, str) and content_type.startswith("audio/"):
                return "voice_message"
            return "attachment"

        return self._each_in_list(body, field="attachments", kind_of=kind_of)

    def _sticker_or_component(
        self, body: Mapping[str, object], *, field: str, kind: SubPayloadKind
    ) -> list[DiscordSubPayload]:
        return self._each_in_list(body, field=field, kind_of=lambda _elem: kind)

    def _each_in_list(
        self,
        body: Mapping[str, object],
        *,
        field: str,
        kind_of: Callable[[Mapping[str, object]], SubPayloadKind],
    ) -> list[DiscordSubPayload]:
        """Emit a marker per dict element of ``body[field]`` (a list field)."""
        value = body.get(field)
        if value is None:
            return []
        if not isinstance(value, list):
            self._warn(field, "container is not a list")
            return []
        markers: list[DiscordSubPayload] = []
        for index, elem in enumerate(value):
            if not isinstance(elem, Mapping):
                self._warn(f"{field}[{index}]", "element is not an object")
                continue
            markers.append(_marker(kind_of(elem), f"{field}[{index}]", elem))
        return markers

    def _poll(self, body: Mapping[str, object]) -> list[DiscordSubPayload]:
        value = body.get("poll")
        if value is None:
            return []
        if not isinstance(value, Mapping):
            self._warn("poll", "poll is not an object")
            return []
        return [_marker("poll", "poll", value)]

    def _message_reference(self, body: Mapping[str, object]) -> list[DiscordSubPayload]:
        # ``message_reference`` underlies both forwarded_ref and pinned_ref. The
        # two are disambiguated by the boolean ``forwarded`` / ``pinned`` flags
        # the inbound emitter sets; a bare reference (an ordinary reply) emits
        # neither — only the two explicitly-flagged forms are promoted.
        value = body.get("message_reference")
        if value is None:
            return []
        if not isinstance(value, Mapping):
            self._warn("message_reference", "message_reference is not an object")
            return []
        if body.get("forwarded") is True:
            return [_marker("forwarded_ref", "message_reference", value)]
        if body.get("pinned") is True:
            return [_marker("pinned_ref", "message_reference", value)]
        return []

    @staticmethod
    def _warn(path: str, reason: str) -> None:
        # Forward-compat skip — loud, never raised (spec §8.5). The word
        # "malformed" is load-bearing: the malformed-path test matches on it.
        _log.warning(
            "comms_mcp.discord_classifier.malformed",
            path=path,
            reason=reason,
        )


__all__ = [
    "SUB_PAYLOAD_KINDS",
    "DiscordSubPayload",
    "DiscordSubPayloadClassifier",
    "SubPayloadKind",
]
