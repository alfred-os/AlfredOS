"""``client_handshake`` — the gateway's client-leg HOST handshake (Spec A G3-3b-2b / ADR-0031).

The ``alfred-gateway`` is the HOST on its CLIENT leg: it stands in for the daemon
toward an UNMODIFIED TUI. It SENDS ``lifecycle.start`` to the dialed-in TUI FIRST
and reads the TUI's result — the mirror image of the core leg (where the gateway
is the PEER and RECEIVES ``lifecycle.start``). This is the SEND side of
:meth:`alfred.plugins.comms_runner.CommsPluginRunner._handshake`, WITHOUT a
session/capability gate (the gateway is not a plugin runner; it just opens the
client wire).

**Minimal shape (Spec A G3-3b-2b, Task 0).** Because ``LifecycleStartRequest``'s
``credentials_ref`` / ``policies_snapshot_hash`` are now OPTIONAL, the gateway
sends the SAME minimal ``{adapter_id, seq_ack}`` the runner does — no sentinel
credentials, no boot epoch (the epoch is a CORE-leg concern; the TUI never sees
it).

**Fail-loud (CLAUDE.md hard rule #7).** A clean EOF before the ack, a not-ok /
malformed result, or a hostile peer that floods more than
:data:`_MAX_PRE_ACK_FRAMES` non-matching frames before the ack all raise
:class:`GatewayHandshakeError` — never a silent no-op, never an infinite drain.

**Half-negotiation is corruption (security L1).** ``enable_seq_ack`` is called
ONLY when the TUI ECHOES the matching wire version; a result that omits the echo
leaves the leg plain ADR-0025. The real operator-local TUI returns
``seq_ack=None``.

**Stricter than the runner's ack check (deliberate hardening).** The runner
accepts a loose ``result.get("ok")``; this leg instead validates the result via
:class:`LifecycleStartResult` (``plugin_version`` required, ``extra="forbid"``) —
the correct hardening for the attacker-reachable client leg, where a malformed or
smuggled-field result must fail closed rather than be read positionally.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Protocol, runtime_checkable

import structlog
from pydantic import ValidationError

from alfred.comms_mcp.protocol import LifecycleStartResult
from alfred.errors import AlfredError
from alfred.plugins.comms_seq_codec import SEQ_VERSION

log = structlog.get_logger(__name__)

# The JSON-RPC id the gateway stamps on its ``lifecycle.start`` request; the TUI
# echoes it on the result frame so the host matches the ack. Mirrors the runner's
# ``_LIFECYCLE_START_ID`` (both 0 — the handshake is the first request on a leg).
_CLIENT_LIFECYCLE_START_ID: Final[int] = 0

# The wire ``adapter_id`` the TUI accepts. The TUI is keyed ``tui`` on its wire —
# NOT ``gateway`` (which is the gateway's OWN identity toward the core, not toward
# its client). A mismatched id would fail the TUI's ``AdapterId`` validation.
_CLIENT_ADAPTER_ID: Final[str] = "tui"

# The bounded cap on pre-ack non-matching frames the host warn-and-drops before
# the ack (security M1). The runner drains pre-ack frames UNBOUNDED; the gateway
# faces an attacker-reachable client leg, so a torn / hostile peer that never
# sends the ack must NOT spin forever — exceeding the cap fails closed.
_MAX_PRE_ACK_FRAMES: Final[int] = 8


@runtime_checkable
class _ClientHandshakeTransport(Protocol):
    """Structural seam for the client-leg transport the handshake drives.

    Mirrors :class:`alfred.gateway.core_link._CommsTransportLike` (and the shared
    runner seam) but binds ONLY the three awaitables + the sync seq/ack flip this
    SEND-side handshake touches. Re-declared locally so this module owns the exact
    shape it depends on (a test drives it with an in-memory frame queue).
    """

    async def send(self, frame: Mapping[str, object]) -> None: ...

    async def read_frame(self) -> Mapping[str, object] | None: ...

    def enable_seq_ack(self) -> None: ...


class GatewayHandshakeError(AlfredError):
    """The client-leg HOST handshake failed (fail-loud, CLAUDE.md hard rule #7).

    Raised on a clean EOF before the ack, a not-ok / malformed
    ``lifecycle.start`` result, or a peer that floods more than
    :data:`_MAX_PRE_ACK_FRAMES` non-matching frames before the ack. Mirrors the
    runner's ``PluginError`` handshake-failure arm — an unusable client handshake
    is never a silent no-op. A programmer/operator-facing f-string (NOT a ``t()``
    string), matching :class:`alfred.gateway.core_link.GatewayCoreLinkError`.
    """


async def client_handshake(transport: _ClientHandshakeTransport) -> bool:
    """Send ``lifecycle.start`` to the dialed-in TUI, await the ack, negotiate seq/ack.

    Sends the minimal ``{adapter_id, seq_ack}`` request (no credentials, no
    epoch), then reads frames until the one whose ``id`` matches the request —
    warn-and-dropping at most :data:`_MAX_PRE_ACK_FRAMES` non-matching pre-ack
    frames. Validates the result via :class:`LifecycleStartResult` (a not-ok /
    missing ``plugin_version`` / non-mapping result is a fail-closed reject).

    Returns ``client_seq_enabled``: ``True`` (and flips the transport's seq/ack
    header on) iff the TUI ECHOED the matching wire version; ``False`` for the
    plain leg the real TUI returns (``seq_ack=None``).

    Raises :class:`GatewayHandshakeError` on a clean EOF before the ack, a
    malformed/not-ok result, or a pre-ack flood exceeding the cap (fail-loud,
    CLAUDE.md hard rule #7).
    """
    await transport.send(
        {
            "jsonrpc": "2.0",
            "id": _CLIENT_LIFECYCLE_START_ID,
            "method": "lifecycle.start",
            "params": {
                "adapter_id": _CLIENT_ADAPTER_ID,
                "seq_ack": {"version": SEQ_VERSION},
            },
        }
    )

    dropped = 0
    while True:
        frame = await transport.read_frame()
        if frame is None:
            log.error("gateway.client_link.handshake_eof", adapter_id=_CLIENT_ADAPTER_ID)
            raise GatewayHandshakeError(
                f"client link closed before lifecycle.start ack (adapter_id={_CLIENT_ADAPTER_ID!r})"
            )
        frame_id = frame.get("id")
        # ``frame.get("id") == _CLIENT_LIFECYCLE_START_ID`` ALONE would also match
        # ``{"id": false, ...}`` because ``False == 0`` in Python — a non-conformant
        # frame would be treated as the ack. Guard the int type (and exclude ``bool``,
        # an int subclass) so only a genuine integer ``0`` is the ack; a boolean id is
        # warn-dropped as a pre-ack frame within the cap.
        if type(frame_id) is int and frame_id == _CLIENT_LIFECYCLE_START_ID:
            return _negotiate_from_result(transport, frame.get("result"))
        # A non-matching frame before the ack is not expected on a conformant TUI
        # wire (the TUI answers lifecycle.start before emitting anything else);
        # warn (not debug) so a peer that front-runs the ack is operator-visible.
        # The frame is dropped — keep reading for the ack, but BOUNDED: a hostile
        # peer that never sends the ack must not spin the host forever (M1).
        dropped += 1
        if dropped > _MAX_PRE_ACK_FRAMES:
            log.error(
                "gateway.client_link.pre_ack_flood",
                adapter_id=_CLIENT_ADAPTER_ID,
                dropped=dropped,
            )
            raise GatewayHandshakeError(
                f"client link flooded {dropped} pre-ack frames "
                f"(cap={_MAX_PRE_ACK_FRAMES}, adapter_id={_CLIENT_ADAPTER_ID!r})"
            )
        log.warning(
            "gateway.client_link.pre_ack_frame_ignored",
            adapter_id=_CLIENT_ADAPTER_ID,
        )


def _negotiate_from_result(transport: _ClientHandshakeTransport, result: object) -> bool:
    """Validate the ack ``result`` and flip seq/ack iff the peer echoed the version.

    Validates via :class:`LifecycleStartResult` (so a not-ok / missing
    ``plugin_version`` / non-mapping result fails closed). Enables seq/ack ONLY
    when the TUI echoed the matching wire version — half-negotiation is a
    corruption surface (security L1).
    """
    try:
        validated = LifecycleStartResult.model_validate(result)
    except ValidationError as exc:
        log.error("gateway.client_link.handshake_malformed_result", adapter_id=_CLIENT_ADAPTER_ID)
        raise GatewayHandshakeError(
            f"client lifecycle.start result malformed (adapter_id={_CLIENT_ADAPTER_ID!r})"
        ) from exc
    if not validated.ok:
        log.error("gateway.client_link.handshake_not_ok", adapter_id=_CLIENT_ADAPTER_ID)
        raise GatewayHandshakeError(
            f"client lifecycle.start not ok (adapter_id={_CLIENT_ADAPTER_ID!r})"
        )
    if validated.seq_ack is not None and validated.seq_ack.version == SEQ_VERSION:
        transport.enable_seq_ack()
        return True
    return False


__all__ = [
    "GatewayHandshakeError",
    "client_handshake",
]
