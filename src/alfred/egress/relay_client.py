"""In-core ledger-wrapped mode-(b) tool-egress relay client (Spec C G7-2c-1, #333).

The connectivity-free core cannot open external sockets directly (HARD rule #9 /
CLAUDE.md §Security rules). For inspectable tool egress it speaks a
length-prefixed JSON-frame protocol over raw asyncio to the gateway's
``EgressRelay`` server (gateway-side G7-2b). This module is the in-core
counterpart — C1 in the G7-2c decomposition.

Design summary (§4.2 mode-(b) flow, this file):

1. Core-side DLP stage (scan_for_outbound) redacts the body BEFORE it ever
   reaches the network — the gateway re-runs its own DLP stages on the
   already-redacted text (defence in depth).
2. The egress-id ledger (commit_intent) stamps a durable intent row BEFORE
   the fire (commit-then-fire: a later exception cannot unwind the intent).
3. The client honours the tri-state ledger reply:
   - IntentFresh → fire.
   - IntentReplayComplete → short-circuit with the stored T2 (NO re-fire, NO
     re-extract — HARD rule #5).
   - IntentInDoubt + idempotent=True → refire with Idempotency-Key header
     (manifest-declared safe); + idempotent=False → refuse (EgressInDoubtError).
4. Every refusal path (deny, io-down, in-doubt) writes exactly one durable
   audit row (HARD rule #7) via AuditWriter.append_schema BEFORE raising.
5. Concurrency is bounded by an asyncio.Semaphore; the client holds no
   core_link / seq-ack reference and must NOT head-of-line the comms relay (§6).

C1 returns ``Fired(response)`` with raw T3 bytes untouched inside
``EgressResponse.body``; C2 mints the ContentHandle. C1 never
decodes or inspects the body.
"""

from __future__ import annotations

import asyncio
import contextlib
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, cast

import pydantic

from alfred.audit.audit_row_schemas import EGRESS_RELAY_REFUSED_FIELDS
from alfred.egress.egress_id import (
    TurnEgressContext,
    compute_egress_body_hash,
    compute_egress_id,
)
from alfred.egress.errors import (
    EgressDeniedError,
    EgressInDoubtError,
    RelayIOPlaneUnavailableError,
)
from alfred.egress.relay_protocol import (
    EgressRelayReply,
    EgressRequest,
    EgressResponse,
    FrameTooLargeError,
    _RawToolRequest,
    read_frame,
    write_frame,
)
from alfred.memory.egress_idempotency import (
    EgressIdempotencyStore,
    IntentFresh,
    IntentInDoubt,
    IntentReplayComplete,
)

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.security.dlp import OutboundDlp

# Default per-call timeout (seconds). Wide enough for a slow upstream but bounded
# so a stalled gateway connection cannot park a turn forever. Operators with
# high-latency origins should tune via action-deadline (spec §10.5) rather than
# raising this — the per-relay deadline is a local network bound, not an end-to-end
# application timeout.
# AUDIT INTERACTION (#347 blocker 2): the enriched in_doubt/ledger_state web.fetch
# timeout row is only produced when the action-deadline is the TIGHTER bound. If
# action-deadline is raised above this per-call timeout, THIS timeout fires first
# and surfaces RelayIOPlaneUnavailableError (a generic fault row), not the enriched
# timeout row. So raise action-deadline and this timeout together, not one alone.
_DEFAULT_PER_CALL_TIMEOUT: float = 30.0

# Default maximum frame size (bytes). 64 MiB is generous for a tool response;
# the gateway enforces its own response_too_large deny BEFORE this limit bites,
# so in practice the cap is a defence-in-depth guard against a malformed gateway
# or a proxy that streams an unbounded body before the deny frame is ready.
_DEFAULT_MAX_FRAME_LEN: int = 64 * 1024 * 1024  # 64 MiB

# Stable closed-vocab audit event name (never localised — audit tokens are English).
_AUDIT_EVENT: Final[str] = "security.egress_relay_refused"
_AUDIT_SCHEMA_NAME: Final[str] = "EGRESS_RELAY_REFUSED_FIELDS"

# A request_descriptor MUST be a 64-char lowercase-hex sha256 digest
# (compute_request_descriptor). The C6 integrity contract requires the
# (method, url, schema_id) identity to be folded into the body hash; a
# malformed/empty descriptor would let a caller bypass it (G7-2.5 C6).
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")
_DESCRIPTOR_LEN: Final[int] = 64


def _require_request_descriptor(request_descriptor: str) -> None:
    """Fail loud (ValueError) unless ``request_descriptor`` is a 64-char lowercase-hex digest.

    A non-conforming descriptor is a programming-contract violation: C2 must
    compute it via :func:`~alfred.egress.egress_id.compute_request_descriptor`.
    Refusing here closes the C6 bypass an empty/short descriptor would open
    (the old ``request_descriptor=""`` default).
    """
    if len(request_descriptor) != _DESCRIPTOR_LEN or any(
        c not in _HEX_DIGITS for c in request_descriptor
    ):
        raise ValueError(
            "request_descriptor must be a 64-char lowercase-hex sha256 digest "
            "(compute_request_descriptor) — the C6 integrity contract requires it"
        )


@dataclass(frozen=True)
class Fired:
    """The relay forwarded the request; carries the raw T3 upstream response."""

    response: EgressResponse


@dataclass(frozen=True)
class Deduplicated:
    """The ledger had a completed response; the request was NOT re-fired.

    ``stored_t2`` is the previously stored (already-extracted) T2 string from the
    ledger. C2 consumes it directly — no re-extraction of raw T3 bytes.
    """

    stored_t2: str
    language: str | None


RelayOutcome = Fired | Deduplicated


class RelayEgressClient:
    """Ledger-wrapped, DLP-redacting mode-(b) tool-egress relay client.

    Speaks the framed JSON wire (``relay_protocol.py``) to the gateway's
    ``EgressRelay`` over raw asyncio (NOT httpx — HARD rule #9 + the import-guard
    invariant; this file must NOT appear in ``_CONSTRUCT_ALLOWLIST``).
    """

    def __init__(
        self,
        *,
        relay_url: str,
        core_dlp: OutboundDlp,
        ledger: EgressIdempotencyStore,
        audit_writer: AuditWriter,
        concurrency: int,
        open_connection: Callable[
            [str, int], Any
        ] = asyncio.open_connection,  # injectable raw-asyncio dialer for tests
        per_call_timeout: float = _DEFAULT_PER_CALL_TIMEOUT,
        max_frame_len: int = _DEFAULT_MAX_FRAME_LEN,
    ) -> None:
        # Parse the relay URL once at construction; the dialer reuses host+port for
        # every fire (urllib.parse.urlsplit handles both tcp:// and http:// forms).
        parsed = urllib.parse.urlsplit(relay_url)
        if parsed.hostname is None or parsed.port is None:
            raise ValueError("relay_url must include a hostname and explicit port")
        self._relay_host: str = parsed.hostname
        self._relay_port: int = parsed.port

        if concurrency <= 0:
            raise ValueError("concurrency must be > 0")
        # concurrency is an explicit required arg — a deliberate per-wiring-site
        # HoL-capacity decision (no hidden default).
        self._core_dlp = core_dlp
        self._ledger = ledger
        self._audit_writer = audit_writer
        self._semaphore = asyncio.Semaphore(concurrency)
        self._open_connection = open_connection
        self._per_call_timeout = per_call_timeout
        self._max_frame_len = max_frame_len

    @property
    def ledger(self) -> EgressIdempotencyStore:
        """The idempotency ledger this client commits intents to.

        C2 (EgressResponseExtractor) uses this to call record_response
        against the SAME ledger instance as C1's commit_intent — enforcing
        the single-ledger invariant via the API, not caller discipline.
        """
        return self._ledger

    @staticmethod
    def _destination_for_audit(url: str) -> str:
        """Extract the bare host authority for audit rows (payload-blind).

        Returns the hostname (or netloc) ONLY — never a path or query —
        so malformed URLs cannot sneak body content into the durable
        audit row or the EgressInDoubtError message (HARD rules #5/#7).
        """
        parsed = urllib.parse.urlsplit(url)
        return parsed.hostname or parsed.netloc or "<invalid-url>"

    async def fire(
        self,
        *,
        raw_request: _RawToolRequest,
        ctx: TurnEgressContext,
        call_index: int,
        request_descriptor: str,
    ) -> RelayOutcome:
        """Execute one egress call through the gateway relay.

        ``request_descriptor`` is REQUIRED (no default): a 64-char lowercase-hex
        sha256 digest C2 computes via ``compute_request_descriptor`` from
        ``(method, url, schema_id)``. A malformed/empty value fails loud
        (``ValueError``) — closing the C6 bypass an empty default would open.

        See module docstring for the exact flow. Raises:
        - ``ValueError`` — request_descriptor is not a 64-char lowercase-hex digest.
        - ``EgressIdIntegrityError`` — same logical slot, different body hash
          (let it propagate; the ledger detected a non-deterministic re-run).
        - ``EgressInDoubtError`` — in-doubt + non-idempotent (refused by policy).
        - ``IOPlaneUnavailableError`` — gateway unreachable, truncated frame, or
          timeout.
        - ``EgressDeniedError`` — gateway deny frame (allowlist / DLP / SSRF).
        """
        # Step 0: contract guard — a bad descriptor cannot fold the C6 identity in.
        _require_request_descriptor(request_descriptor)

        # Step 1: Core-side DLP pass (stage 1+2+3 with broker).
        scanned = self._core_dlp.scan_for_outbound(raw_request.body)
        redacted_text: str = scanned[0]

        # Step 2: Deterministic dedup key + integrity body-hash.
        # ``request_descriptor`` is a fixed-width (64-char) sha256 hex string computed
        # by C2 from (method, url, schema_id); the redacted request HEADERS are folded
        # in too, so a divergent method/url/schema OR a divergent-header replay at the
        # same (ctx, call_index) fires EgressIdIntegrityError (Spec C §5 / G7-2.5 C6).
        # The headers folded are the pre-Idempotency-Key ``raw_request.headers`` so a
        # legitimate idempotent refire (which only ADDS the key) keeps a stable hash.
        egress_id = compute_egress_id(ctx, call_index=call_index)
        body_hash = compute_egress_body_hash(
            request_descriptor=request_descriptor,
            headers=raw_request.headers,
            redacted_body=redacted_text,
        )

        # Step 3: Commit intent durably BEFORE the fire (commit-then-fire).
        # EgressIdIntegrityError propagates if the same id arrives with a
        # different body hash (non-deterministic re-run — HARD rule #7).
        intent = await self._ledger.commit_intent(
            egress_id=egress_id,
            adapter_id=ctx.adapter_id,
            inbound_id=ctx.inbound_id,
            session_id=ctx.session_id,
            call_index=call_index,
            body_hash=body_hash,
        )

        # Step 4: Intent dispatch.
        if isinstance(intent, IntentReplayComplete):
            # Stored T2 — no dial, no re-extract (HARD rule #5).
            return Deduplicated(stored_t2=intent.response, language=intent.language)

        if isinstance(intent, IntentInDoubt):
            if not raw_request.idempotent:
                # Default policy: refuse. A non-idempotent re-fire risks a double
                # side-effect (spec §5 H3). Write the durable audit row FIRST.
                destination = self._destination_for_audit(raw_request.url)
                # Audit-failure is fail-loud (HARD rule #7): if _audit_refused raises,
                # let it propagate — a broken audit write is more severe than the
                # I/O outage it records.
                await self._audit_refused(
                    destination=destination,
                    reason="egress_in_doubt",
                    egress_id=egress_id,
                    result="in_doubt",
                )
                raise EgressInDoubtError(destination=destination, egress_id=egress_id)
            # Idempotent refire: forward egress_id as the remote Idempotency-Key
            # header so the upstream server can dedup the HTTP-level request.
            # Drop any pre-existing idempotency-key (case-insensitive) before
            # setting the canonical one — HTTP header names are case-insensitive,
            # and keeping a lower-case duplicate creates two conflicting values.
            forwarded_headers: Mapping[str, str] = {
                k: v for k, v in raw_request.headers.items() if k.lower() != "idempotency-key"
            }
            forwarded_headers = {**forwarded_headers, "Idempotency-Key": egress_id}
        else:
            # IntentFresh — forward the original headers, no Idempotency-Key.
            intent = cast(  # type: ignore[redundant-cast]  # cast not assert: asserts stripped under -O (mirrors the Fired cast above)
                IntentFresh, intent
            )
            forwarded_headers = raw_request.headers

        # Step 5: Fire under concurrency bound and per-call timeout.
        return await self._do_fire(
            raw_request=raw_request,
            redacted_text=redacted_text,
            egress_id=egress_id,
            forwarded_headers=forwarded_headers,
        )

    async def _do_fire(
        self,
        *,
        raw_request: _RawToolRequest,
        redacted_text: str,
        egress_id: str,
        forwarded_headers: Mapping[str, str],
    ) -> Fired:
        """Open the gateway relay connection, exchange one frame pair, return Fired.

        All I/O errors (OSError, IncompleteReadError, TimeoutError,
        FrameTooLargeError, JSON/validation errors) map to IOPlaneUnavailableError
        with a durable audit row before the raise.
        """
        destination = self._destination_for_audit(raw_request.url)

        request = EgressRequest(
            method=raw_request.method,
            url=raw_request.url,
            headers=forwarded_headers,
            body=redacted_text,
            egress_id=egress_id,
        )

        reply: EgressRelayReply
        writer: Any = None
        async with self._semaphore:
            try:
                async with asyncio.timeout(self._per_call_timeout):
                    reader, writer = await self._open_connection(self._relay_host, self._relay_port)
                    await write_frame(writer, request.model_dump_json().encode("utf-8"))
                    raw = await read_frame(reader, max_len=self._max_frame_len)
                # Parse outside the timeout so a slow Pydantic parse never
                # triggers a spurious TimeoutError, but still within the
                # semaphore so the connection is closed before the slot
                # is released (the finally below closes the writer).
                reply = EgressRelayReply.model_validate_json(raw)
            except (
                OSError,
                asyncio.IncompleteReadError,
                FrameTooLargeError,
                pydantic.ValidationError,
            ) as exc:
                # A precise, closed set of the genuinely-expected I/O + parse
                # faults — NOT a bare `except Exception`. A programming bug
                # (AttributeError/TypeError) in the fire block must propagate
                # loud, not be silently mapped to an I/O outage (HARD rule #7).
                # Coverage:
                # - OSError: connect failure (and its TimeoutError /
                #   asyncio.TimeoutError subclasses from asyncio.timeout, in
                #   3.11+).
                # - asyncio.IncompleteReadError: EOF mid-frame (truncated read).
                # - FrameTooLargeError (a ValueError): oversized frame header.
                # - pydantic.ValidationError: malformed reply frame
                #   (model_validate_json on non-conforming JSON).
                detail = f"{type(exc).__name__}: {exc}"
                # Audit-failure is fail-loud (HARD rule #7): if _audit_refused raises,
                # let it propagate — a broken audit write is more severe than the
                # I/O outage it records.
                await self._audit_refused(
                    destination=destination,
                    reason="io_plane_unavailable",
                    egress_id=egress_id,
                    result="io_plane_unavailable",
                )
                raise RelayIOPlaneUnavailableError(detail=detail) from exc
            finally:
                if writer is not None:
                    writer.close()
                    # Teardown-only cleanup swallow: wait_closed() can stall
                    # on a half-open socket or unresponsive peer, which would
                    # (a) hold _semaphore past the per-call budget and (b) mask
                    # the typed IOPlaneUnavailableError/EgressDeniedError by
                    # raising during exception unwinding. This is deliberate —
                    # NOT a trust-boundary exception swallow (HARD rule #7).
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(writer.wait_closed(), self._per_call_timeout)

        if reply.deny_reason is not None:
            reason_token = str(reply.deny_reason)
            await self._audit_refused(
                destination=destination,
                reason=reason_token,
                egress_id=egress_id,
                result="denied",
            )
            raise EgressDeniedError(destination=destination, deny_reason=reason_token)

        # reply.response is guaranteed non-None by EgressRelayReply's
        # exactly-one model_validator (response set iff deny_reason is None);
        # we have already returned on the deny_reason branch above. Narrow with
        # cast, NOT an assert (stripped under -O) and NOT an `if None: raise`
        # (an uncoverable branch that breaks the 100% branch gate). Mirrors
        # PostgresEgressIdempotencyStore's cast(str, row.response).
        return Fired(response=cast(EgressResponse, reply.response))

    async def _audit_refused(
        self,
        *,
        destination: str,
        reason: str,
        egress_id: str,
        result: str,
    ) -> None:
        """Write the durable refusal audit row (HARD rule #7, non-skippable).

        Payload-blind: destination host authority, closed-vocab reason token, and
        the egress_id (already public sha256 hex) only — no body, no header values.
        """
        await self._audit_writer.append_schema(
            fields=EGRESS_RELAY_REFUSED_FIELDS,
            schema_name=_AUDIT_SCHEMA_NAME,
            event=_AUDIT_EVENT,
            actor_user_id=None,
            persona_id=None,
            subject={
                "destination": destination,
                "reason": reason,
                "egress_id": egress_id,
            },
            trust_tier_of_trigger="T3",
            result=result,
            cost_estimate_usd=0.0,
            trace_id=egress_id,
        )


__all__ = ["Deduplicated", "Fired", "RelayEgressClient", "RelayOutcome"]
