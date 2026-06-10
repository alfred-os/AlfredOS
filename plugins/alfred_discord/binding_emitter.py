"""Relay a host-issued verification phrase as ``adapter.binding_request`` (#206).

Closure **sec-4** is load-bearing: the verification phrase is HOST-supplied. The
host mints it (``secrets.token_urlsafe(24)`` — 192 bits, NOT plugin-minted),
binds it to a ``platform_user_id`` at issuance, and owns the replay/takeover
refusal (a valid-shape phrase from a *different* platform_user_id is refused
host-side). The plugin's :class:`BindingEmitter` is the **receive-side**: it
relays an inbound that carries a host-issued phrase back to the host so the host
can complete the bind. It NEVER generates a phrase and NEVER normalises one — it
carries the inbound text byte-for-byte so the host's correlation against its
pending-bindings table is exact.

To keep the "is this a binding attempt?" decision host-owned (the plugin cannot
see the pending-bindings table), the emitter is injected with two host-defined
predicates:

* ``phrase_matcher(text) -> bool`` — does this inbound text look like a phrase
  the host issued? (The host owns the shape; the plugin does not hardcode it.)
* ``is_bound(platform_user_id) -> bool`` — is this user already bound? (An
  already-bound user's matching text is regular traffic, not a bind.)

``platform_metadata`` is a frozen :class:`PlatformProfile` carrying ONLY public
Discord profile fields — private fields (``email`` / ``phone``) cannot be set on
it by construction, so no private datum can leak through the binding frame even
if discord.py surfaces it.

Wiring status (#235). The :class:`BindingEmitter` is TESTED but NOT constructed
by the gateway in this PR, so ``adapter.binding_request`` is dead in production
until the PR-S4-10 flag-day wires it into the live gateway. See
``docs/subsystems/comms.md`` (Slice-4 wiring-status note) and issue #235.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass

import structlog

from alfred.comms_mcp.protocol import BindingRequestNotification
from plugins.alfred_discord.notifications import (
    NOTIFY_BINDING,
    NotificationSink,
    notification_frame,
)

_log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class PlatformProfile:
    """Public-only Discord profile fields carried in a binding request.

    Frozen + a closed field set: ``email`` / ``phone`` are NOT members, so a
    private datum cannot be threaded into the binding frame by construction
    (closure G2 test 4). Every field is a public-facing profile attribute.
    """

    username: str
    display_name: str
    avatar_hash: str
    joined_at: str


class BindingEmitter:
    """Receive-side binding relay — emits a host-issued phrase, never mints one."""

    def __init__(
        self,
        *,
        adapter_id: str,
        sink: NotificationSink,
        phrase_matcher: Callable[[str], bool],
        is_bound: Callable[[str], bool],
    ) -> None:
        self._adapter_id = adapter_id
        self._sink = sink
        self._phrase_matcher = phrase_matcher
        self._is_bound = is_bound

    async def maybe_emit(
        self, *, platform_user_id: str, text: str, profile: PlatformProfile
    ) -> bool:
        """Relay ``text`` as a binding request iff it is a phrase from an unbound user.

        Returns ``True`` when a notification was emitted. The phrase is carried
        VERBATIM (no minting, no normalisation) so the host correlation is exact.
        """
        if self._is_bound(platform_user_id):
            return False
        if not self._phrase_matcher(text):
            return False

        notification = BindingRequestNotification(
            adapter_id=self._adapter_id,
            platform_user_id=platform_user_id,
            verification_phrase=text,
            platform_metadata=asdict(profile),
        )
        frame = notification_frame(NOTIFY_BINDING, notification.model_dump(mode="json"))
        await self._sink.emit(frame)
        _log.info("comms.binding.relayed", adapter=self._adapter_id)
        return True


__all__ = ["BindingEmitter", "PlatformProfile"]
