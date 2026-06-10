"""``binding_emitter`` relays a host-issued verification phrase (Task G2, #206).

Per closure sec-4 the plugin is the **receive-side** of binding: it does NOT mint
verification phrases (the host issues ``secrets.token_urlsafe(24)`` and owns the
phrase↔platform_user_id table + replay refusal). The emitter exists to relay an
inbound that carries a host-issued phrase back to the host as a
``BindingRequestNotification`` so the host can complete the bind.

To avoid the plugin re-deciding "is this a binding attempt" (a host concern), the
emitter is injected with a ``phrase_matcher`` predicate (host-defined) and an
``is_bound`` predicate. It emits ONLY when the text matches AND the user is
unbound; the phrase is carried byte-exactly.

Behaviour pinned here:

1. Matching phrase from an unbound user → one ``adapter.binding_request`` with
   the phrase carried byte-exactly + public-only ``platform_metadata``.
2. Matching phrase from an ALREADY-BOUND user → no notification.
3. Non-matching text → no notification.
4. ``platform_metadata`` carries only public profile fields; private fields
   (``email`` / ``phone``) are never populated even if offered.
5. The relayed ``verification_phrase`` equals the inbound text byte-for-byte (no
   in-plugin minting, no normalisation).
"""

from __future__ import annotations

from collections.abc import Mapping

from plugins.alfred_discord.binding_emitter import BindingEmitter, PlatformProfile

_ADAPTER = "discord"
# A host-issued token_urlsafe(24)-shaped phrase (sec-4): NOT plugin-minted.
_HOST_PHRASE = "Zx9_aB3cD-Ef7gH1iJ2kL4mN6oP8qR0sT"


class _RecordingSink:
    def __init__(self) -> None:
        self.frames: list[Mapping[str, object]] = []

    async def emit(self, frame: Mapping[str, object]) -> None:
        self.frames.append(frame)


def _profile() -> PlatformProfile:
    return PlatformProfile(
        username="newcomer",
        display_name="New Comer",
        avatar_hash="abc123",
        joined_at="2026-06-01T00:00:00Z",
    )


def _emitter(sink: _RecordingSink, *, bound: bool, matches: bool) -> BindingEmitter:
    return BindingEmitter(
        adapter_id=_ADAPTER,
        sink=sink,
        phrase_matcher=lambda _text: matches,
        is_bound=lambda _user: bound,
    )


async def test_matching_phrase_unbound_user_emits_binding_request() -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink, bound=False, matches=True)
    await emitter.maybe_emit(platform_user_id="111", text=_HOST_PHRASE, profile=_profile())
    assert len(sink.frames) == 1
    frame = sink.frames[0]
    assert frame["method"] == "adapter.binding_request"
    params = frame["params"]
    assert isinstance(params, Mapping)
    assert params["platform_user_id"] == "111"
    assert params["verification_phrase"] == _HOST_PHRASE


async def test_matching_phrase_bound_user_does_not_emit() -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink, bound=True, matches=True)
    await emitter.maybe_emit(platform_user_id="111", text=_HOST_PHRASE, profile=_profile())
    assert sink.frames == []


async def test_non_matching_text_does_not_emit() -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink, bound=False, matches=False)
    await emitter.maybe_emit(
        platform_user_id="111", text="just a normal message", profile=_profile()
    )
    assert sink.frames == []


async def test_metadata_carries_only_public_fields() -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink, bound=False, matches=True)
    await emitter.maybe_emit(platform_user_id="111", text=_HOST_PHRASE, profile=_profile())
    params = sink.frames[0]["params"]
    assert isinstance(params, Mapping)
    metadata = params["platform_metadata"]
    assert isinstance(metadata, Mapping)
    assert set(metadata) == {"username", "display_name", "avatar_hash", "joined_at"}
    assert "email" not in metadata
    assert "phone" not in metadata


async def test_phrase_relayed_byte_exact() -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink, bound=False, matches=True)
    tricky = "  alfred-Fox-Violet-with-trailing  "
    # phrase_matcher accepts; the emitter must relay the text VERBATIM (the host
    # correlates against its pending-bindings table — no in-plugin normalisation).
    await emitter.maybe_emit(platform_user_id="111", text=tricky, profile=_profile())
    params = sink.frames[0]["params"]
    assert isinstance(params, Mapping)
    assert params["verification_phrase"] == tricky
