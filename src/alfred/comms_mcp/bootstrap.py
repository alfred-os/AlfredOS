"""Concrete seam bridges assembling the comms-MCP host (PR-S4-8, #152).

Wave 2 shipped the inbound path against three injected Protocol seams; this
module supplies the **concrete** adapters the comms host wires at boot, bridging
each seam onto the real Slice-3 surface:

* :class:`CommsExtractorBridge` adapts the body-shaped
  ``_OrchestratorLike.quarantined_extract`` seam onto the real handle-shaped
  :meth:`alfred.security.quarantine.QuarantinedExtractor.extract` — raw body ->
  :class:`ContentHandle` -> ``extract(handle, schema)``. The canonical
  ``user_id`` is accepted by the seam (the inbound entrypoint passes it) but is
  NEVER threaded into the extractor call: the extractor surface has no user-id
  parameter, so the identity invariant (spec §8.2 last paragraph — the canonical
  id never crosses outward) holds by construction.
* :class:`SyncIdentityResolverBridge` adapts the async
  ``_IdentityResolverLike.resolve`` seam onto the real **sync**
  :meth:`alfred.identity.resolver.IdentityResolver.resolve(platform, platform_id)`.
  The :class:`Platform` enum ships ``TUI``/``DISCORD`` (Slice-2); the native
  ``tui``/``discord`` adapter kinds map 1:1, and the reference adapter kind
  ``alfred_comms_test`` keeps the legacy ``Platform.DISCORD`` placeholder, all
  via :data:`_ADAPTER_KIND_TO_PLATFORM`.
* :class:`SupervisorBreakerTripper` adapts the handlers' ``trip_comms_breaker``
  seam onto :meth:`alfred.supervisor.core.Supervisor.trip_breaker`.

Keeping the bridges here (not inside the inbound path) means the trust-tier
enforcement stays at the orchestrator/inbound edge while the wiring that knows
about ``ContentHandle`` minting, the sync resolver, and the supervisor lives in
one assembled-at-boot module the integration test drives end-to-end.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, Literal, Protocol, runtime_checkable

from alfred.comms_mcp.errors import UnknownAdapterKindError
from alfred.comms_mcp.inbound import ResolvedInbound
from alfred.identity.models import Platform
from alfred.security.quarantine import ContentHandle, ExtractionSchema

if TYPE_CHECKING:
    from alfred.identity.models import User
    from alfred.security.quarantine import ExtractionResult, QuarantinedExtractor
    from alfred.supervisor.core import Supervisor, TripBreakerReason


@runtime_checkable
class _SyncResolverLike(Protocol):
    """Structural type for the real sync :class:`IdentityResolver`."""

    def resolve(self, platform: Platform, platform_id: str) -> User | None: ...


@runtime_checkable
class _BodyRecorderLike(Protocol):
    """Records a T3 inbound body under a handle for the extractor to dereference."""

    def __call__(
        self, *, handle: ContentHandle, body: bytes | str | Mapping[str, object]
    ) -> None: ...


@runtime_checkable
class _SupervisorTripLike(Protocol):
    """Structural type for the supervisor breaker-trip façade.

    ``reason`` is the real :data:`alfred.supervisor.core.TripBreakerReason`
    Literal — the bridge maps the handlers' open-vocab seam reason onto it (see
    :meth:`SupervisorBreakerTripper.trip_comms_breaker`).
    """

    async def trip_breaker(self, *, component_id: str, reason: TripBreakerReason) -> None: ...


# Default persona for an inbound message until the Slice-5 persona registry lands
# (matches the orchestrator's single-persona pin).
_DEFAULT_PERSONA = "alfred"

# Adapter-kind -> Platform mapping. The Slice-2 ``Platform`` enum ships
# ``TUI``/``DISCORD``. The native ``tui``/``discord`` adapter kinds map 1:1 onto
# their owning platform; the reference plugin's ``alfred_comms_test`` kind has no
# native member, so it keeps the legacy ``DISCORD`` placeholder for the resolver
# lookup (the reference-plugin integration test binds its synthetic user under
# that platform).
_ADAPTER_KIND_TO_PLATFORM: Mapping[str, Platform] = {
    "tui": Platform.TUI,
    "discord": Platform.DISCORD,
    "alfred_comms_test": Platform.DISCORD,
}


class CommsBodyExtraction(ExtractionSchema):
    """Schema the comms inbound body is quarantine-extracted to.

    A deliberately minimal v1 schema: the quarantined LLM lifts the platform
    body's plain text into ``text`` plus a coarse ``intent`` bucket. The host
    never reads the raw T3 body directly — it reads this structured, DLP-scanned
    result. The schema MUST keep ``schema_version: ClassVar[Literal[1]] = 1``
    (enforced by :meth:`ExtractionSchema.__init_subclass__`).
    """

    schema_version: ClassVar[Literal[1]] = 1

    text: str
    intent: str


class CommsExtractorBridge:
    """Body-shaped seam over the real handle-shaped :class:`QuarantinedExtractor`.

    Satisfies the orchestrator's body-shaped ``QuarantinedExtractorLike`` seam
    (``extract(body, *, canonical_user_id, source_tier)``) by minting an opaque
    :class:`ContentHandle`, recording the T3 body under the handle id, and
    delegating to the real ``extract(handle, schema)``. The ``canonical_user_id``
    is accepted but never forwarded into the extractor call — the wire carries
    only the opaque handle id (spec §8.2 identity invariant).

    ``record_body`` is the injected T3-recording seam: the host wires a function
    that tags the body ``TaggedContent[T3]`` (via the capability-gate nonce path)
    and writes it to the content store the extractor's transport reads. Keeping it
    injected means the bridge never holds a gate nonce itself — the authorised T3
    tagging stays at the host boundary that owns the gate. When ``record_body`` is
    ``None`` the body is not recorded (the unit-test path where the extractor is
    a recorded fixture that does not dereference the handle).
    """

    def __init__(
        self,
        *,
        extractor: QuarantinedExtractor,
        record_body: _BodyRecorderLike | None = None,
    ) -> None:
        self._extractor = extractor
        self._record_body = record_body

    async def extract(
        self,
        *,
        body: bytes | str | Mapping[str, object],
        canonical_user_id: str,
        source_tier: Literal["T3"],
    ) -> ExtractionResult:
        """Record ``body`` under a fresh handle and delegate to the extractor.

        ``source_tier`` is pinned ``"T3"`` by the orchestrator wrapper before this
        bridge is reached; ``canonical_user_id`` is intentionally unused here —
        it stays host-side and never crosses into the quarantine wire (the
        parameter exists only to satisfy the seam the inbound path calls).
        """
        del canonical_user_id, source_tier  # host-side only; never wired outward
        handle = ContentHandle(
            id=uuid.uuid4().hex,
            # Forensic-attribution only; never readable content. The opaque
            # marker keeps the raw body off the handle's audit surface.
            source_url="comms-mcp://inbound",
            fetch_timestamp=datetime.now(UTC),
        )
        if self._record_body is not None:
            self._record_body(handle=handle, body=body)
        return await self._extractor.extract(handle, CommsBodyExtraction)


class SyncIdentityResolverBridge:
    """Async seam over the real **sync** :class:`IdentityResolver`.

    Adapts ``resolve(*, adapter_id, platform_user_id) -> ResolvedInbound | None``
    (async, the inbound seam) onto the sync
    ``IdentityResolver.resolve(platform, platform_id) -> User | None`` by mapping
    the adapter kind onto a :class:`Platform` member and wrapping the resolved
    ``User`` into the frozen :class:`ResolvedInbound` the inbound path consumes.
    The canonical id (``User.slug``) is the only identity token that leaves this
    bridge; nothing else about the ORM row escapes.
    """

    def __init__(self, *, resolver: _SyncResolverLike) -> None:
        self._resolver = resolver

    async def resolve(self, *, adapter_id: str, platform_user_id: str) -> ResolvedInbound | None:
        try:
            platform = _ADAPTER_KIND_TO_PLATFORM[adapter_id]
        except KeyError as exc:
            # An unmapped adapter kind must fail loud — silently defaulting to
            # DISCORD would resolve the user against the wrong platform's
            # binding table. The native ``tui``/``discord`` kinds map 1:1; the
            # ``alfred_comms_test -> DISCORD`` placeholder is the only non-native
            # mapping the reference plugin relies on.
            raise UnknownAdapterKindError(
                f"no Platform mapping for adapter_id {adapter_id!r}"
            ) from exc
        # The real resolver is synchronous + holds a per-instance LRU; the call
        # is in-process and fast (no I/O on a cache hit), so a direct call inside
        # the async seam is correct — there is no blocking-call-in-async concern
        # the way a network round-trip would raise.
        user = self._resolver.resolve(platform, platform_user_id)
        if user is None:
            return None
        return ResolvedInbound(
            canonical_user_id=user.slug,
            persona=_DEFAULT_PERSONA,
            language=user.language,
            adapter_id=adapter_id,
        )


class SupervisorBreakerTripper:
    """Breaker seam over :meth:`Supervisor.trip_breaker`.

    The handlers' ``_BreakerTripperLike`` seam (``trip_comms_breaker``) is wired
    here onto the real reason-checked supervisor façade. The comms-adapter
    component id is the ``adapter_id`` so the breaker the supervisor trips is the
    one keyed to this adapter.
    """

    def __init__(self, *, supervisor: _SupervisorTripLike) -> None:
        self._supervisor = supervisor

    async def trip_comms_breaker(self, *, adapter_id: str, reason: str) -> None:
        """Trip the comms-adapter breaker, mapping the seam reason onto the façade.

        Foundation gap (handlers <-> supervisor reason vocabulary). The handlers'
        ``_BreakerTripperLike`` seam carries an open-vocab ``reason`` (e.g.
        ``"comms.rate_limit.exhausted"`` from the platform-rate-limit handler),
        but :meth:`Supervisor.trip_breaker` accepts only the closed
        :data:`TripBreakerReason` Literal (``comms_handler_repeated_failures`` /
        ``plugin_lifecycle_crash``). Any comms-side breaker trip that is NOT the
        dispatcher's repeated-handler-failure path is a self-reported adapter
        fault, so it maps onto ``plugin_lifecycle_crash``; the open-vocab reason
        survives forensically on the rate-limit handler's own
        ``COMMS_RATE_LIMIT_SIGNAL_FIELDS`` audit row. The unused ``reason`` arg is
        retained on the seam so PR-S4-9 can widen the Literal additively without a
        signature change here.
        """
        del reason  # see docstring — mapped onto the closed supervisor vocabulary
        await self._supervisor.trip_breaker(
            component_id=f"comms.{adapter_id}", reason="plugin_lifecycle_crash"
        )


def build_supervisor_breaker_tripper(*, supervisor: Supervisor) -> SupervisorBreakerTripper:
    """Construct the breaker tripper from a real :class:`Supervisor`."""
    return SupervisorBreakerTripper(supervisor=supervisor)


__all__ = [
    "CommsBodyExtraction",
    "CommsExtractorBridge",
    "SupervisorBreakerTripper",
    "SyncIdentityResolverBridge",
    "build_supervisor_breaker_tripper",
]
