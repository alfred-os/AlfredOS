"""§4.3 T3 egress-response quarantine-extract wrapper (Spec C G7-2c-1, #333).

This module is the C2 half of the G7-2c decomposition.  C1 (``relay_client.py``)
fires the request through the gateway relay and returns either a ``Fired``
(raw T3 response) or ``Deduplicated`` (the stored T2 from a prior call).  C2 owns
the boundary crossing: it turns raw T3 bytes into a T2 ``ExtractionResult`` via the
ONE sanctioned gate-checked seam — ``quarantined_to_structured`` — and records the
post-extraction T2 in the dedup ledger so a future replay can short-circuit.

Trust-boundary invariants enforced here
---------------------------------------
1. Raw T3 bytes (``EgressResponse.body``) are NEVER passed to the orchestrator.
   The orchestrator receives only the ``ExtractionResult`` out of
   ``quarantined_to_structured``.
2. On a ``Deduplicated`` hit the stored T2 is replayed directly — the extractor is
   NOT called (HARD rule #5: replay must not re-enter raw-T3 ingestion).
3. The ledger stores ``result.model_dump_json()`` (post-extraction T2), NEVER the
   raw T3 body.  ``_EXTRACTION_RESULT_ADAPTER`` deserialises on replay so the
   orchestrator always sees a typed ``ExtractionResult``.
4. A gate denial in ``quarantined_to_structured`` raises ``AlfredError`` BEFORE
   ``record_response`` is reached — the ledger row stays ``committed_no_response``
   (a deliberate at-most-once firewall).

No ``canonical_user_id`` parameter
------------------------------------
The per-user rate-limiter premise assumes a turn-user context that is not yet
available on this path.  Threading one here is dead plumbing until epic #339
supplies a real turn-user.  See TODO: #339 below.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, cast

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from alfred.egress.egress_id import TurnEgressContext, compute_egress_id, compute_request_descriptor
from alfred.egress.relay_client import Deduplicated, Fired, RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.security.quarantine import (
    ContentHandle,
    ExtractionResult,
    ExtractionSchema,
    quarantined_to_structured,
)
from alfred.security.quarantine_transport import T3BodyRecorder

if TYPE_CHECKING:
    from alfred.hooks.capability import CapabilityGate
    from alfred.security.quarantine import QuarantinedExtractor

# ---------------------------------------------------------------------------
# Module-level TypeAdapter for ExtractionResult replay deserialisation.
#
# ``ExtractionResult = Extracted | TypedRefusal`` is a plain union (core-011).
# The discriminator field ``kind`` drives the parse so the correct branch is
# selected without an isinstance walk.  Built once at import time (expensive
# for Pydantic v2; avoid per-call construction).
# ---------------------------------------------------------------------------
_EXTRACTION_RESULT_ADAPTER: TypeAdapter[ExtractionResult] = TypeAdapter(
    Annotated[ExtractionResult, Field(discriminator="kind")]
)


# ---------------------------------------------------------------------------
# EgressExtractOutcome — the only value the orchestrator receives from this path
# ---------------------------------------------------------------------------


class EgressExtractOutcome(BaseModel):
    """The orchestrator-visible outcome of one mode-(b) tool-egress call.

    ``result`` is structurally T2 (``Extracted | TypedRefusal``) — the orchestrator
    NEVER sees raw T3 bytes.  ``deduplicated`` distinguishes a fresh extraction from
    a ledger replay.  ``language`` carries the BCP-47 tag from the calling context
    (or the stored tag on replay).  ``status`` is the upstream HTTP response code on
    a fresh ``Fired`` extraction, or ``None`` on a ``Deduplicated`` replay (the
    original status is not stored in the ledger).
    """

    result: ExtractionResult
    deduplicated: bool
    language: str | None
    status: int | None
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Default post-fire hook — a module-level no-op so production is unaffected.
#
# The barrier seam is injected in tests to simulate a process kill after the
# external call fires (fire_count increments) but before record_response runs.
# The module-level default ensures the parameter is never required and the
# production path is never altered by an unconfigured seam.
# ---------------------------------------------------------------------------


def _schema_identity(schema: type[ExtractionSchema]) -> str:
    """Stable, fully-qualified identity string for an ExtractionSchema subclass.

    Combines the module path, qualified class name, and schema_version so that
    a schema rename, move, or version bump all produce a distinct identity —
    folded into the egress-id body hash (C6 / G7-2.5 Task 1).
    """
    return f"{schema.__module__}.{schema.__qualname__}:v{schema.schema_version}"


async def _noop() -> None:
    """No-op async hook; the production default for post_fire_hook."""
    return


# ---------------------------------------------------------------------------
# EgressResponseExtractor
# ---------------------------------------------------------------------------


class EgressResponseExtractor:
    """Gate-checked wrapper that converts a mode-(b) relay outcome to T2.

    Wraps ``RelayEgressClient`` (C1) with the §4.3 quarantine-extract boundary:

    *  ``Fired(response)``  → mint ``ContentHandle``, record body T3 via
       ``T3BodyRecorder``, call ``quarantined_to_structured`` (gate-first), write
       ``result.model_dump_json()`` to the ledger, return T2 outcome.
    *  ``Deduplicated(stored_t2, lang)``  → deserialise the stored T2 and return
       it immediately — no extract, no ledger write (HARD rule #5).

    See module docstring for the full invariant list.

    # TODO: #339 — supply ``canonical_user_id`` from the real turn-user once the
    # LLM tool-calling subsystem lands; on this path it is dead plumbing.
    """

    def __init__(
        self,
        *,
        relay_client: RelayEgressClient,
        gate: CapabilityGate,
        extractor: QuarantinedExtractor,
        recorder: T3BodyRecorder,
        post_fire_hook: Callable[[], Awaitable[None]] = _noop,
    ) -> None:
        self._relay_client = relay_client
        self._gate = gate
        self._extractor = extractor
        self._recorder = recorder
        self._post_fire_hook = post_fire_hook

    async def handle(
        self,
        *,
        raw_request: _RawToolRequest,
        ctx: TurnEgressContext,
        call_index: int,
        schema: type[ExtractionSchema],
        language: str | None = None,
    ) -> EgressExtractOutcome:
        """Execute one egress call and return a T2 extraction outcome.

        Steps (``Fired`` branch):
        1. Fire through the relay (C1 ledger commit + gateway round-trip).
        2. Mint ``ContentHandle``; stage raw T3 body via ``recorder``.
        3. Call ``quarantined_to_structured`` (gate-first).  A denial raises
           ``AlfredError`` — let it propagate; do NOT reach step 4.
        4. Recompute ``egress_id`` (pure function of ``ctx`` + ``call_index``).
        5. Record post-extraction T2 in the ledger.
        6. Return ``EgressExtractOutcome(result=result, deduplicated=False)``.

        Steps (``Deduplicated`` branch):
        1. Deserialise ``stored_t2`` via ``_EXTRACTION_RESULT_ADAPTER``.
        2. Return immediately — extractor and ledger are NOT touched.
        """
        # C6 (G7-2.5 Task 1): fold method + url + schema identity into the ledger
        # integrity hash so a divergent URL/schema replayed at the same egress-id
        # fires EgressIdIntegrityError (Spec C §5).  The descriptor is a fixed-width
        # sha256 hex string — prepending it to the redacted body in C1 cannot introduce
        # a separator-collision.
        request_descriptor = compute_request_descriptor(
            method=raw_request.method,
            url=raw_request.url,
            schema_id=_schema_identity(schema),
        )
        outcome = await self._relay_client.fire(
            raw_request=raw_request,
            ctx=ctx,
            call_index=call_index,
            request_descriptor=request_descriptor,
        )

        if isinstance(outcome, Deduplicated):
            # Replay: return the stored T2 directly.  The extractor must NOT be
            # called — re-tagging raw T3 on replay violates HARD rule #5.
            # status=None: the original upstream HTTP status is not stored in the
            # ledger (only the post-extraction T2 is persisted).
            stored_result = _EXTRACTION_RESULT_ADAPTER.validate_json(outcome.stored_t2)
            return EgressExtractOutcome(
                result=stored_result,
                deduplicated=True,
                language=outcome.language,
                status=None,
            )

        # outcome is Fired — raw T3 bytes in outcome.response.body.
        outcome = cast(  # type: ignore[redundant-cast]  # cast not assert: asserts stripped under -O; mirrors relay_client.py
            Fired, outcome
        )

        # Barrier seam (C4 / §4.3): invoked after the external call has fired
        # (intent is committed_no_response, fire_count incremented) and BEFORE
        # record_response.  In production this is _noop (no cost).  Tests inject
        # a hook that raises to simulate a process kill mid-window and prove the
        # at-most-once invariant — a subsequent replay of the same (ctx,
        # call_index) must see IntentInDoubt and refuse to re-fire.
        await self._post_fire_hook()

        # Step 2: mint an opaque ContentHandle and stage the raw T3 body.
        # The orchestrator never touches outcome.response.body directly.
        handle = ContentHandle(
            id=str(uuid.uuid4()),
            source_url=raw_request.url,
            fetch_timestamp=datetime.now(UTC),
        )
        self._recorder(handle=handle, body=outcome.response.body)

        # Step 3: gate-checked T3 → T2 extraction.  A gate denial raises
        # AlfredError here; we let it propagate without calling record_response —
        # the ledger row stays committed_no_response (at-most-once firewall).
        result = await quarantined_to_structured(
            handle,
            schema,
            extractor=self._extractor,
            gate=self._gate,
        )

        # Step 4: recompute egress_id — pure, matches the id C1 committed.
        egress_id = compute_egress_id(ctx, call_index=call_index)

        # Step 5: record post-extraction T2 (NEVER raw T3 body).
        # Use self._relay_client.ledger to enforce the single-ledger invariant:
        # C1 committed the intent via this same ledger instance (M8).
        await self._relay_client.ledger.record_response(
            egress_id=egress_id,
            response=result.model_dump_json(),
            language=language,
        )

        return EgressExtractOutcome(
            result=result,
            deduplicated=False,
            language=language,
            status=outcome.response.status,
        )


__all__ = [
    "EgressExtractOutcome",
    "EgressResponseExtractor",
]
