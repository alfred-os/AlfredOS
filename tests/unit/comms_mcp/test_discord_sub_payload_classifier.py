"""``DiscordSubPayloadClassifier`` — nine Discord sub-payload kinds (B1, #206).

The classifier recognises the nine Discord sub-payload kinds (spec §8.6 / §8.10),
emits one opaque T3 sub-payload marker per matched sub-payload, and forward-compat
skips (structlog warn, never raises) on a malformed sub-payload.

**Contract reconciliation.** The shipped PR-S4-8 scanner
(:class:`alfred.comms_mcp.inbound_scanner.InboundContentScanner`) duck-types a
classifier as a no-arg-constructable object with a SYNC
``classify(body) -> Iterable[object]`` returning opaque markers — NOT the async
content-store-writing / body-rewriting ``ScannedFrame`` shape the plan's
pseudocode sketched (the content store's ``write`` is async and the scanner calls
``classify`` synchronously, so promotion-to-ContentHandle is a host step that
consumes these markers, not the classifier's job). These tests pin the real
contract: ``classify`` returns a tuple of :class:`DiscordSubPayload` markers.
"""

from __future__ import annotations

import pytest
from structlog.testing import capture_logs

from alfred.comms_mcp.classifier_registry import get_classifier, register_classifier
from alfred.comms_mcp.classifiers.discord import (
    DiscordSubPayload,
    DiscordSubPayloadClassifier,
    _walk_path,
)

# All nine kinds with a minimal happy-path body fragment for each.
_EMBED = {"title": "hi", "type": "rich"}
_LINK_EMBED = {"title": "unfurl", "type": "link", "url": "https://x"}
_ATTACHMENT = {"id": "1", "filename": "f.png", "content_type": "image/png"}
_VOICE = {"id": "2", "filename": "v.ogg", "content_type": "audio/ogg"}
_POLL = {"question": {"text": "?"}, "answers": []}
_STICKER = {"id": "3", "name": "blob"}
_COMPONENT = {"type": 1, "components": []}
_MSG_REF = {"message_id": "9", "channel_id": "8"}


def _classify(body: dict[str, object]) -> tuple[DiscordSubPayload, ...]:
    return DiscordSubPayloadClassifier().classify(body)


def _kinds(payloads: tuple[DiscordSubPayload, ...]) -> list[str]:
    return [p.kind for p in payloads]


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_classifier_is_registered_under_discord_sub_payloads() -> None:
    # Re-run the canonical import-time registration before asserting (idempotent
    # no-op on the same class object): a sibling suite test
    # (test_classifier_registry_import_registration) reloads the registry module,
    # replacing the global _REGISTRY dict and dropping every classifier
    # registered by another module. Re-registering the SAME class restores the
    # entry order-independently — a reload would mint a new class object and trip
    # the registry's different-class collision guard.
    register_classifier(kind="discord", name="discord_sub_payloads")(DiscordSubPayloadClassifier)
    assert (
        get_classifier(kind="discord", name="discord_sub_payloads") is DiscordSubPayloadClassifier
    )


# --------------------------------------------------------------------------- #
# Happy paths — one populated sub-payload of each kind
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("body", "kind", "expected_path"),
    [
        ({"content": "x", "embeds": [_EMBED]}, "embed", "embeds[0]"),
        ({"content": "x", "embeds": [_LINK_EMBED]}, "link_unfurl", "embeds[0]"),
        ({"content": "x", "attachments": [_ATTACHMENT]}, "attachment", "attachments[0]"),
        ({"content": "x", "attachments": [_VOICE]}, "voice_message", "attachments[0]"),
        ({"content": "x", "poll": _POLL}, "poll", "poll"),
        ({"content": "x", "stickers": [_STICKER]}, "sticker", "stickers[0]"),
        ({"content": "x", "components": [_COMPONENT]}, "component", "components[0]"),
        (
            {"content": "x", "message_reference": _MSG_REF, "forwarded": True},
            "forwarded_ref",
            "message_reference",
        ),
        (
            {"content": "x", "message_reference": _MSG_REF, "pinned": True},
            "pinned_ref",
            "message_reference",
        ),
    ],
)
def test_each_kind_emits_one_marker(body: dict[str, object], kind: str, expected_path: str) -> None:
    payloads = _classify(body)
    assert _kinds(payloads) == [kind]
    marker = payloads[0]
    assert marker.kind == kind
    assert marker.path == expected_path
    assert marker.source_url == f"discord://{expected_path}"
    # The raw sub-payload value rides on the marker (host promotes it to a
    # ContentHandle downstream) — the orchestrator never sees it inline.
    assert marker.raw is not None


# --------------------------------------------------------------------------- #
# Malformed paths — wrong type / missing nested field → warn + skip (no raise)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body",
    [
        {"content": "x", "embeds": "not-a-list"},
        {"content": "x", "embeds": ["not-a-dict"]},
        {"content": "x", "attachments": {"oops": "dict-not-list"}},
        {"content": "x", "attachments": [123]},
        {"content": "x", "poll": "not-a-dict"},
        {"content": "x", "stickers": "not-a-list"},
        {"content": "x", "components": 99},
        {"content": "x", "message_reference": "not-a-dict", "forwarded": True},
        {"content": "x", "message_reference": ["bad"], "pinned": True},
    ],
)
def test_malformed_sub_payload_warns_and_skips(body: dict[str, object]) -> None:
    with capture_logs() as logs:
        payloads = _classify(body)
    # No marker emitted for the malformed shape — forward-compat skip, no crash.
    assert payloads == ()
    assert any(
        entry.get("event") == "comms_mcp.discord_classifier.malformed"
        and entry.get("log_level") == "warning"
        for entry in logs
    )


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #


def test_multiple_embeds_each_get_a_marker() -> None:
    body = {"content": "x", "embeds": [_EMBED, dict(_EMBED, title="two")]}
    payloads = _classify(body)
    assert _kinds(payloads) == ["embed", "embed"]
    assert [p.path for p in payloads] == ["embeds[0]", "embeds[1]"]


def test_empty_arrays_emit_no_markers() -> None:
    body = {"content": "x", "embeds": [], "attachments": [], "stickers": []}
    assert _classify(body) == ()


def test_no_sub_payload_fields_emit_no_markers() -> None:
    body = {"content": "plain text", "id": "1", "author": {"id": "7"}}
    assert _classify(body) == ()


def test_non_sub_payload_fields_are_not_in_markers() -> None:
    # The classifier must not invent markers from ordinary fields.
    body = {"content": "x", "id": "1", "author": {"id": "7"}, "embeds": [_EMBED]}
    payloads = _classify(body)
    assert _kinds(payloads) == ["embed"]


def test_mixed_embed_and_link_unfurl_disambiguate() -> None:
    body = {"content": "x", "embeds": [_EMBED, _LINK_EMBED]}
    payloads = _classify(body)
    assert _kinds(payloads) == ["embed", "link_unfurl"]


def test_mixed_attachment_and_voice_disambiguate() -> None:
    body = {"content": "x", "attachments": [_ATTACHMENT, _VOICE]}
    payloads = _classify(body)
    assert _kinds(payloads) == ["attachment", "voice_message"]


def test_bare_message_reference_without_flag_emits_nothing() -> None:
    # An ordinary reply carries message_reference but neither the forwarded nor
    # the pinned flag — it is not a promoted sub-payload kind.
    body = {"content": "x", "message_reference": _MSG_REF}
    assert _classify(body) == ()


# --------------------------------------------------------------------------- #
# DSL — the narrow path walker (index access, no eval)
# --------------------------------------------------------------------------- #


class TestDSL:
    def test_walk_top_level_object(self) -> None:
        assert _walk_path({"poll": _POLL}, "poll") == _POLL

    def test_walk_list_index(self) -> None:
        assert _walk_path({"embeds": [_EMBED]}, "embeds[0]") == _EMBED

    def test_walk_missing_key_returns_none(self) -> None:
        assert _walk_path({"content": "x"}, "embeds[0]") is None

    def test_walk_out_of_range_index_returns_none(self) -> None:
        assert _walk_path({"embeds": []}, "embeds[0]") is None

    def test_walk_index_on_non_list_returns_none(self) -> None:
        assert _walk_path({"embeds": "x"}, "embeds[0]") is None

    def test_walk_malformed_index_returns_none(self) -> None:
        # A non-numeric index (``embeds[abc]``) must fail closed to ``None`` — the
        # DSL contract says invalid selectors resolve to nothing, not raise.
        assert _walk_path({"embeds": [_EMBED]}, "embeds[abc]") is None

    def test_walk_empty_index_returns_none(self) -> None:
        assert _walk_path({"embeds": [_EMBED]}, "embeds[]") is None

    def test_walk_negative_index_returns_none(self) -> None:
        # ``embeds[-1]`` must NOT resolve from the end — a negative selector is
        # invalid in this DSL and must fail closed rather than wrap.
        assert _walk_path({"embeds": [_EMBED]}, "embeds[-1]") is None
