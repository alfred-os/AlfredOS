"""``GatewayAdapterCredentialClient`` — the gateway-side credential acquirer (G6-3).

The gateway half of the heaviest trust boundary in Spec B (#288). On each adapter
(re)spawn the supervisor calls :meth:`acquire_and_deliver`, which:

1. mints a correlation ``request_id`` and builds a
   :class:`alfred.comms_mcp.adapter_credential_protocol.SpawnRequest` (the ``epoch``
   is sourced LIVE at the call site — correction H1 — by the supervisor);
2. runs the ``spawn_request -> spawn_grant`` round-trip over the trusted core leg
   (:meth:`alfred.gateway.core_link.GatewayCoreLink.request_spawn_grant`);
3. VERIFIES the grant echoes the outstanding request's ``(request_id, adapter_id,
   host_restart_seq, epoch)`` — a mismatched/forged grant is REFUSED (adversarial e);
4. delivers ``grant.credential_material`` to the child's fd-3 WRITE END via the reused
   :func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3` (atomic
   ``writev`` of a length-prefixed frame; the library builds + zeroes its OWN buffer
   and closes ``write_fd`` itself).

**Fail-closed + loud + no-continue (CLAUDE.md hard rule #7).** Every failure — a
grant refusal, a leg drop, a reply timeout, a mismatched grant, an fd-3 write fault —
raises a loud :class:`AdapterCredentialError` (or the typed
:class:`CredentialLegDownError` the supervisor's AWAITING_CORE consumes) and aborts
the spawn. NEVER log-and-continue. On any pre-delivery failure the client CLOSES
``write_fd`` itself (no leaked descriptor) — the library only owns the close once the
delivery is reached.

**The credential is never retained (correction A-H2 / maintainer C1).** The
credential lives only in the ephemeral grant frame returned by the round-trip; the
client passes it STRAIGHT to the delivery fn (which owns + zeroes the only mutable
copy) and holds NO instance-level credential field. ``acquire_and_deliver`` allocates
nothing credential-bearing on ``self``, so two adapters' spawns share no buffer
identity. The credential is a ``str`` end-to-end (honest str-residency scope — see
``adapter_credential_protocol``); it is NEVER logged (the grant frame is repr-safe,
and this module logs only routing ids / reasons).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Callable
from typing import Protocol
from uuid import uuid4

import structlog

from alfred.comms_mcp.adapter_credential_protocol import SpawnGrant, SpawnRequest
from alfred.comms_mcp.adapter_credential_resolver import AdapterCredentialError
from alfred.supervisor.fd3_key_delivery import (
    ProviderKeyDeliveryError,
    deliver_provider_key_via_fd3,
)

log = structlog.get_logger(__name__)


class _CredentialLegLike(Protocol):
    """The core-leg seam the client drives (the credential round-trip half)."""

    async def request_spawn_grant(
        self, request: SpawnRequest, *, timeout: float = ...
    ) -> SpawnGrant: ...


class GatewayAdapterCredentialClient:
    """Acquire one adapter's platform credential and deliver it over fd 3 (G6-3).

    Construct one per gateway process, holding the core leg. The fd-3 delivery fn is
    injectable ONLY so the per-adapter-isolation unit tests can substitute a fake
    sink; production always uses the reused
    :func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3`.
    """

    def __init__(
        self,
        *,
        core_link: _CredentialLegLike,
        deliver: Callable[..., None] = deliver_provider_key_via_fd3,
    ) -> None:
        self._core_link = core_link
        self._deliver = deliver

    async def acquire_and_deliver(
        self, *, adapter_id: str, host_restart_seq: int, write_fd: int, epoch: str
    ) -> None:
        """Run the round-trip + verify the grant + deliver the credential over fd 3.

        ``write_fd`` is the WRITE end of the pipe whose READ end is the child's fd 3
        (the child factory creates it and passes it here — Task 5a). The delivery fn
        closes ``write_fd`` itself; this method closes it on EVERY pre-delivery
        failure so the descriptor never leaks (CLAUDE.md hard rule #7).
        """
        # The SpawnRequest construction lives INSIDE the try that owns the _close_fd
        # cleanup: a validation fault while building the request (e.g. a future field
        # tightening) must NOT leak write_fd — the round-trip is simply never reached.
        # The round-trip itself: a CredentialLegDownError propagates UNWRAPPED (the
        # supervisor's AWAITING_CORE consumes it as the link-down signal); any OTHER
        # failure (reply timeout, etc.) is wrapped as AdapterCredentialError. A
        # CancelledError (cancellation during the core-grant await) MUST propagate but
        # MUST NOT leak the fd. On ANY raise before delivery, close write_fd ourselves —
        # the delivery was never reached, so the library never closed it.
        try:
            request = SpawnRequest(
                request_id=uuid4().hex,
                adapter_id=adapter_id,
                host_restart_seq=host_restart_seq,
                epoch=epoch,
            )
            grant = await self._core_link.request_spawn_grant(request)
        except AdapterCredentialError:
            # The leg-down error is rooted at AlfredError but is NOT an
            # AdapterCredentialError; only a genuine credential refusal arrives here.
            self._close_fd(write_fd)
            raise
        except asyncio.CancelledError:
            # Cancellation must PROPAGATE (never swallowed) — but the fd must not leak:
            # close it, then re-raise so the supervisor's structured-concurrency
            # cancellation continues to unwind.
            self._close_fd(write_fd)
            raise
        except Exception as exc:
            self._close_fd(write_fd)
            # CredentialLegDownError is re-raised UNWRAPPED so the supervisor can
            # distinguish link-down (await-core) from a hard refusal; every other
            # round-trip fault becomes a loud AdapterCredentialError abort.
            from alfred.gateway.core_link import CredentialLegDownError

            if isinstance(exc, CredentialLegDownError):
                raise
            log.warning(
                "gateway.adapter.credential_roundtrip_failed",
                adapter_id=adapter_id,
                host_restart_seq=host_restart_seq,
                error_class=type(exc).__name__,
            )
            raise AdapterCredentialError(
                adapter_id=adapter_id, reason="grant_roundtrip_failed"
            ) from exc

        self._verify_grant(grant, request, write_fd)

        # Deliver the plaintext over fd 3. The library builds + zeroes its OWN bytearray
        # and closes write_fd on success AND on its own refusal — so we do NOT close it
        # here. A ProviderKeyDeliveryError (partial write / EAGAIN / OSError) is a loud
        # fail-closed abort: wrap it (do NOT reuse the fd3 subsystem's exception type).
        try:
            self._deliver(write_fd=write_fd, key=grant.credential_material)
        except ProviderKeyDeliveryError as exc:
            log.error(
                "gateway.adapter.credential_delivery_failed",
                adapter_id=adapter_id,
                host_restart_seq=host_restart_seq,
                reason=exc.reason,
            )
            raise AdapterCredentialError(
                adapter_id=adapter_id, reason="delivery_failed"
            ) from None  # ``from None``: the chained exc carries no secret, but the
            # closed-vocab reason is the whole story — keep the trace minimal.

    def _verify_grant(self, grant: SpawnGrant, request: SpawnRequest, write_fd: int) -> None:
        """Refuse a grant that does not echo the outstanding request (adversarial e).

        The grant MUST match the request's ``(request_id, adapter_id,
        host_restart_seq, epoch)`` exactly — a forged/stale grant (wrong epoch, wrong
        adapter, wrong incarnation, or an out-of-band id) is REFUSED loud and the
        spawn aborts; the credential is never written to fd 3. Closes ``write_fd``
        (the delivery is never reached on a refusal).
        """
        if (
            grant.request_id == request.request_id
            and grant.adapter_id == request.adapter_id
            and grant.host_restart_seq == request.host_restart_seq
            and grant.epoch == request.epoch
        ):
            return
        self._close_fd(write_fd)
        log.warning(
            "gateway.adapter.credential_grant_mismatch",
            adapter_id=request.adapter_id,
            host_restart_seq=request.host_restart_seq,
        )
        raise AdapterCredentialError(adapter_id=request.adapter_id, reason="grant_mismatch")

    @staticmethod
    def _close_fd(write_fd: int) -> None:
        """Close ``write_fd`` on a pre-delivery failure (no leaked descriptor)."""
        with contextlib.suppress(OSError):
            os.close(write_fd)


__all__ = [
    "GatewayAdapterCredentialClient",
]
