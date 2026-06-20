"""G6-3 credential wire frames — the heaviest trust boundary in Spec B (#288).

The real core-injects-at-spawn credential path replaces the G6-2 fake credential
seam. On each (re)spawn the gateway sends a :class:`SpawnRequest` to the core over
the trusted ADR-0031 leg; the core's ``CoreAdapterCredentialResolver`` resolves the
platform credential from the secret broker and returns a :class:`SpawnGrant`; the
gateway delivers the plaintext to the bwrap child over fd 3 (the
``deliver_provider_key_via_fd3`` discipline), then drops its reference.

**This module is the SHARED envelope** between the gateway client and the daemon
route (precedent: ``gateway/_control_frames.py`` + ``comms_mcp/protocol.py``) so
the two ends cannot drift. The two methods are a request/response pair on the leg:

* ``gateway.adapter.spawn_request`` — gateway -> core, id-correlated.
* ``core.adapter.spawn_grant`` — core -> gateway, the FIRST core->gateway RESPONSE
  frame on this leg (a third frame class alongside the opaque T3 payload units and
  the fire-and-forget status notifications).

**The credential is structurally un-loggable (correction S-C3).**
:attr:`SpawnGrant.credential_material` is ``Field(repr=False)`` and
:meth:`SpawnGrant.__repr__` / :meth:`SpawnGrant.__str__` elide it, so
``log.info(frame)`` / f-strings / exception args are safe BY DEFAULT — a future
edit that logs a grant cannot leak the credential. The broker's ``redact()`` does
NOT help here (it only knows registered secret values; the wire-delivered cred is
not registered at the gateway).

**Honest str-residency scope (maintainer C1, option (a)).** The credential is
carried as a ``str`` end-to-end (matching ``SecretBroker.get() -> str`` and the
already-shipped quarantine fd-3 path). An immutable ``str`` cannot be zeroed; the
ONLY verifiably-zeroed object in the pipeline is the ephemeral ``writev`` bytearray
*inside* the reused :func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3`,
which overwrites its own buffer with NUL the instant the write returns. The brief
str-residency window between the broker read and the fd-3 write is microseconds and
is mitigated (not eliminated) the same way the quarantine path is. A cross-cutting
``SecretBroker.get_bytes`` + bytes-end-to-end that upgrades BOTH the quarantine and
the adapter cred paths together is a SEPARATE future hardening — NOT in G6-3.

**Anti-forgery / epoch + dedup.** The dedup/replay key is ``(adapter_id,
host_restart_seq, epoch)``. The per-core-boot ``epoch`` is load-bearing:
``host_restart_seq`` (= the gateway's ``_AdapterRun.restart_count``) resets on a
gateway restart, so ``(adapter_id, host_restart_seq)`` alone is replayable across a
gateway bounce — only the epoch disambiguates. Both frames are frozen +
``extra="forbid"`` + closed-vocab ``adapter_id`` so a smuggled / typo'd field is a
loud ``ValidationError`` at the boundary. These frames carry NO T3 message body.
"""

from __future__ import annotations

from typing import Final

from pydantic import ConfigDict, Field

from alfred.comms_mcp.protocol import AdapterId, _WireModel

# The request/response method names on the trusted leg. They live HERE, next to the
# models, so BOTH the gateway client (sender) and the daemon route (responder) import
# the SAME constant — the audit-event-name and the wire-method-name cannot drift
# (the no-drift discipline the lifecycle frames use). ``gateway.adapter.*`` keeps the
# request inside the namespace the core's session router already owns; the grant is a
# RESPONSE the gateway's ``_consume_frame`` routes to its pending waiter.
GATEWAY_ADAPTER_SPAWN_REQUEST: Final[str] = "gateway.adapter.spawn_request"
CORE_ADAPTER_SPAWN_GRANT: Final[str] = "core.adapter.spawn_grant"

# A correlation id is a 32-hex token (``uuid4().hex``) — same shape as the per-boot
# epoch, pinned so a malformed id fails validation loudly at the boundary.
_CORRELATION_ID_PATTERN: Final[str] = r"^[0-9a-f]{32}$"
_EPOCH_PATTERN: Final[str] = r"^[0-9a-f]{32}$"


class SpawnRequest(_WireModel):
    """Gateway -> core: resolve the platform credential for one adapter (re)spawn.

    ``request_id`` correlates the response :class:`SpawnGrant` back to this
    outstanding request (the leg has no JSON-RPC id correlation today — Task 2.5
    builds it). ``host_restart_seq`` is the gateway's per-adapter incarnation
    (``_AdapterRun.restart_count``); ``epoch`` is the per-core-boot value sourced
    LIVE from ``GatewayCoreLink.current_core_epoch()`` at spawn time (correction
    H1 — never the construction-time snapshot).
    """

    request_id: str = Field(min_length=32, max_length=32, pattern=_CORRELATION_ID_PATTERN)
    adapter_id: AdapterId
    host_restart_seq: int = Field(ge=0)
    epoch: str = Field(min_length=32, max_length=32, pattern=_EPOCH_PATTERN)


class SpawnGrant(_WireModel):
    """Core -> gateway: the resolved platform credential for one spawn.

    A RESPONSE to a gateway-initiated :class:`SpawnRequest` (a precondition the
    gateway consumes), NOT a core directive — the gateway decides whether/when to
    spawn. ``credential_material`` is the PLAINTEXT platform credential carried over
    the trusted leg only; it is ``repr=False`` and elided from every string form
    (see the module docstring). The grant echoes the request's ``request_id`` +
    ``(adapter_id, host_restart_seq, epoch)`` so the gateway can refuse a
    mismatched/forged/unsolicited grant (adversarial e).
    """

    # ``extra="forbid"`` is inherited from ``_WireModel``; re-pin ``frozen`` so the
    # ``__repr__`` override below cannot be read as a mutability relaxation.
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str = Field(min_length=32, max_length=32, pattern=_CORRELATION_ID_PATTERN)
    adapter_id: AdapterId
    host_restart_seq: int = Field(ge=0)
    epoch: str = Field(min_length=32, max_length=32, pattern=_EPOCH_PATTERN)
    # ``repr=False`` keeps the credential out of Pydantic's default ``__repr__`` /
    # ``__str__`` — but a frozen ``_WireModel`` would still let a future custom
    # ``__repr__`` see it via ``self.credential_material``, so the overrides below
    # build the safe string EXPLICITLY (never touching the field). ``min_length=1``
    # refuses an empty credential at the boundary (a placeholder/unset value never
    # reaches fd-3 silently).
    credential_material: str = Field(min_length=1, repr=False)

    def __repr__(self) -> str:
        """A credential-free repr (correction S-C3 — safe to log by default).

        Renders ONLY the non-secret routing metadata; the credential is replaced by
        a fixed marker. Built without referencing ``self.credential_material`` so the
        plaintext can never reach a string surface via this method.
        """
        return (
            f"SpawnGrant(request_id={self.request_id!r}, adapter_id={self.adapter_id!r}, "
            f"host_restart_seq={self.host_restart_seq!r}, epoch={self.epoch!r}, "
            f"credential_material=<elided>)"
        )

    __str__ = __repr__


__all__ = [
    "CORE_ADAPTER_SPAWN_GRANT",
    "GATEWAY_ADAPTER_SPAWN_REQUEST",
    "SpawnGrant",
    "SpawnRequest",
]
