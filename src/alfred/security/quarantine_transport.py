"""Host-side request/response transport carrying a T3 body to the quarantined LLM.

PR-S4-11c-2a (epic #237). This module owns the host half of the
inline-over-wire content path (ADR-0029): the raw T3 inbound body travels to the
(eventually launcher-spawned) quarantined LLM via a ``quarantine.ingest`` request
sent immediately BEFORE the ``quarantine.extract`` request the
:class:`alfred.security.quarantine.QuarantinedExtractor` drives. The child stays
storeless — it caches the ingested body in-process and pops it single-use on
extract; the host owns a single-use staging map that the transport drains when it
ships the ingest.

Three collaborators:

* :class:`QuarantineStagingMap` — the host-side single-use staging store
  (``handle.id -> TaggedContent[T3]``). A second drain of the same id is a loud
  refusal (replay defence — the laundering-window close from ADR-0029).
* :class:`T3BodyRecorder` — the ``record_body`` seam
  :class:`alfred.comms_mcp.bootstrap.CommsExtractorBridge` calls before
  ``extractor.extract``. It tags the inbound body ``TaggedContent[T3]`` via the
  authorised :func:`alfred.security.tiers.tag_t3_with_nonce` boot nonce and stages
  it. A ``None`` nonce is a loud refusal (mirrors StdioTransport's
  ``NonceNotConfigured`` guard); a WRONG nonce surfaces ``tag_t3_with_nonce``'s
  own ``ValueError``.
* :class:`QuarantineStdioTransport` — a :class:`alfred.plugins.transport.PluginTransport`
  driven by the :class:`QuarantinedExtractor`. On ``quarantine.extract`` it drains
  the staged body, sends ``quarantine.ingest{handle_id, context}`` then
  ``quarantine.extract{...}`` over a length-prefixed JSON-RPC child-IO seam, reads
  the reply frame, and returns a :class:`ControlResult`. It does NOT subclass
  :class:`alfred.plugins.stdio_transport.StdioTransport` — its content/control
  branch and direct-exec spawn are the wrong behaviour here; this transport reuses
  only the length-prefix framing convention and is driven against an injected
  child-IO seam so the real launcher-spawn (PR-S4-11c-2b) and the child MCP loop +
  LLM (PR-S4-11c-2c) stay out of scope.
"""

from __future__ import annotations

import asyncio
import json
import struct
import uuid
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import structlog

from alfred.egress.control_fd_broker import ControlFdBrokerError
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.plugins.transport import ControlResult
from alfred.security.quarantine import BROKER_SOCKET_COUNT
from alfred.security.quarantine_child_io import QuarantineChildSpawnError
from alfred.security.tiers import T3, tag_t3_with_nonce

if TYPE_CHECKING:
    from alfred.egress.broker_audit import EgressBrokerAuditor
    from alfred.security.quarantine import ContentHandle
    from alfred.security.tiers import CapabilityGateNonce, TaggedContent

_log = structlog.get_logger(__name__)

# Wire method names (ADR-0029). ``quarantine.ingest`` is the NEW forward contract
# PR-S4-11c-2c routes in the child's MCP loop; ``quarantine.extract`` is the
# existing method the QuarantinedExtractor already dispatches.
_INGEST_METHOD = "quarantine.ingest"
_EXTRACT_METHOD = "quarantine.extract"

# 4-byte big-endian length prefix — peer to StdioTransport's framing
# (``struct.pack(">I", ...)`` at stdio_transport.py:467-487,605).
_LENGTH_HEADER_BYTES = 4

# The closed-vocab :class:`alfred.security.quarantine.TypedRefusalReason` a broker
# failure lifts to (golive spec §7/§21, HARD #7). A ``ControlFdBrokerError`` means
# the child could not be handed a live gateway socket — the provider egress is
# unreachable, so this maps to ``provider_unavailable`` (the SAME reason the child
# dispatcher returns on ``ProviderUnavailableError``). The FORENSIC record of *why*
# (the closed broker ``reason`` + destination) is the durable ``egress.broker.refused``
# row (``record_broker_failure``); the orchestrator-visible outcome is a graceful
# typed refusal, NEVER a raw ``ControlFdBrokerError`` (HARD #7). ``transport_failed``
# is an audit-result value, not a ``TypedRefusalReason`` — the two are distinct.
_BROKER_FAILURE_REFUSAL_REASON = "provider_unavailable"
# The unresolved-destination sentinel for the failure row when a ``ControlFdBrokerError``
# somehow carries no ``destination`` (defensive — every broker-path error stamps one).
_UNRESOLVED_DESTINATION = "<unresolved>"

# The generic member of the CLOSED ``EGRESS_BROKER_REFUSED_REASONS`` vocabulary
# (``ControlFdBrokerError.__init__``'s own default). Used for the two broker-preamble failures
# the broker itself never raises a specific code for: the preamble deadline (A7) and the
# pre-connect misconfiguration errors (``IOPlaneUnavailableError`` /
# ``QuarantineChildSpawnError``, A4). Deliberately NOT new vocabulary members: that frozenset is
# AST-drift-guarded against ``ControlFdBrokerError``'s literals
# (``tests/unit/audit/test_egress_broker_reason_vocab.py``), so growing it for a CALLER's
# convenience would either break the guard or force a fake raise site in the broker. The
# specific cause is preserved in the loud structlog event at each call site instead.
_GENERIC_BROKER_REFUSAL_REASON = "control_fd_broker_failed"

# Bound on the per-extraction broker preamble — the ``broker_sockets`` batch PLUS its
# ``egress.broker.connected`` audit rows (golive spec §17, review item A7).
#
# WHY IT MUST EXIST: unbounded, the preamble sits entirely OUTSIDE the §17 timeout nesting.
# Under gateway degradation the outer ``action_deadline`` fires mid-preamble and the extraction
# dies as an anonymous deadline kill — the graceful ``provider_unavailable`` refusal and the
# ``egress.broker.refused`` forensic row (the very artefacts this path exists to produce) are
# never reached.
#
# THE ARITHMETIC: the preamble is SEQUENTIAL with the ``read_frame`` bound, not nested inside
# it, so both must fit within the outer deadline:
#
#     preamble(4) + host_read(25) = 29 < action_deadline(30)          [success path]
#     preamble(4) + refusal(<=11) = 15 < action_deadline(30)          [refusal path]
#
# which preserves the documented nesting ``action_deadline(30) > host_read(25) >
# gateway_handshake(22) > child_budget(20) > sdk_read(8)`` — pinned by
# ``test_broker_preamble_bound_nests_under_the_action_deadline`` and the §17 hierarchy suite.
#
# The refusal leg previously read "failure-row write(<=5)" with NOTHING pinning the 5: the
# whole fail-closed path (revoke + row) ran outside every ceiling, and the reap underneath was
# SIGTERM-only with an unbounded ``wait()``. A child declining to die blew the action_deadline
# AND starved ``record_broker_failure``. Every term is now a real constant, not prose.
#
# WHY 4s IS AMPLE: with the CONNECT phase now gathered (A1) the batch costs ONE connect RTT to a
# co-located gateway (sub-millisecond on a docker network), N local AF_UNIX ``sendmsg`` calls
# (microseconds), and N+1 audit appends (single-digit ms). 4s is ~3 orders of magnitude of
# headroom. It does mean this bound, not ``control_fd_broker._CONNECT_TIMEOUT_S`` (10s), is the
# effective connect ceiling on the golive path — deliberate: 10s of connect latency is already a
# dead extraction, and refusing at 4s buys the forensics.
_BROKER_PREAMBLE_TIMEOUT_S = 4.0

# Bound on the child teardown inside a revoke. Covers the two-stage reap
# (``_REAP_TOTAL_GRACE_S``, ~2s) plus the best-effort stderr drain
# (``_STDERR_DRAIN_TIMEOUT_S``, 2s) with ~1s of slack. Its job is to stop a wedged teardown
# consuming the whole refusal budget and starving the audit row that follows it.
_REVOKE_TIMEOUT_S = 5.0

# Bound on the ENTIRE fail-closed refusal path: revoke (<=5) + the durable
# ``egress.broker.refused`` row (bounded independently at
# ``broker_audit._AUDIT_AWAIT_TIMEOUT_S``, 5s). This is the constant the nesting arithmetic
# above cites, so the refusal leg is pinned by code rather than asserted in a comment.
#
# STRICTLY GREATER than 5 + 5, so the INNER bound always wins the worst case. At exactly 10
# the two would expire on the same tick and an anonymous outer cancel could pre-empt the
# auditor's own specific ``egress.broker.audit_write_timeout`` error — losing the one log
# line that says WHICH stage hung. This bound is the backstop, not the reporter.
_BROKER_REFUSAL_TIMEOUT_S = 11.0


class StagingNonceUnconfiguredError(AlfredError):
    """Raised when :class:`T3BodyRecorder` is asked to stage with no nonce.

    Mirrors :class:`alfred.plugins.stdio_transport.NonceNotConfigured`: an
    explicit guard (not ``assert`` — ``python -O`` strips asserts) on the
    trust-boundary path that gates T3 tagging. A silent passthrough would stage
    the inbound body UNTAGGED, which the dual-LLM split forbids (CLAUDE.md hard
    rule #7). Distinct from the ``ValueError`` ``tag_t3_with_nonce`` raises on a
    WRONG nonce: this fires when there is NO nonce to attempt with at all.
    """


class StagingHandleNotConfiguredError(AlfredError):
    """Raised when the staging map is drained for an absent/consumed handle id.

    Single-use invariant (ADR-0029 / spec §7.2): each ``handle.id`` is staged
    once and drained once. A second drain — replay of a consumed T3 body — is a
    loud refusal, never a silent empty value. The same loud-on-replay posture the
    quarantined child enforces with its ``_content_cache.pop`` and the web.fetch
    content store enforces with GETDEL.
    """


@runtime_checkable
class ChildIO(Protocol):
    """The injected child-IO seam :class:`QuarantineStdioTransport` frames over.

    Abstracts the launcher-spawned subprocess pipes (PR-S4-11c-2b) so tests drive
    an in-process child double. ``write_frame`` ships one already-framed
    length-prefixed JSON-RPC request; ``read_frame`` returns the raw bytes of one
    length-prefixed reply frame (header stripped by the caller). ``broker_sockets``
    hands the child ``count`` pre-connected gateway sockets over the fd-4 control
    channel BEFORE the extract frame (connect-defer, #340 golive Task 9): a partial
    connect failure sends nothing and raises :class:`ControlFdBrokerError`.
    """

    def write_frame(self, frame: bytes) -> None: ...

    async def read_frame(self) -> bytes: ...

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]: ...

    async def aclose(self) -> None: ...


class QuarantineStagingMap:
    """Host-side single-use staging store: ``handle.id -> TaggedContent[T3]``.

    The host owns the raw T3 body between :class:`T3BodyRecorder` (which stages it)
    and :class:`QuarantineStdioTransport` (which drains it for the
    ``quarantine.ingest`` request). The drain is a single-use ``pop``: a second
    drain of the same id raises :class:`StagingHandleNotConfiguredError` so a
    replay of a consumed body is refused loudly (ADR-0029 laundering-window close).

    Not async-shared across event loops — one map per daemon boot graph, driven by
    a single inbound turn at a time in this cut (the >1-adapter boot refusal in
    ``_commands`` keeps concurrency out of scope for 2a).
    """

    def __init__(self) -> None:
        self._staged: dict[str, TaggedContent[T3]] = {}

    def stage(self, handle_id: str, tagged: TaggedContent[T3]) -> None:
        """Stage a T3-tagged body under ``handle_id`` for a single later drain."""
        self._staged[handle_id] = tagged

    def drain(self, handle_id: str) -> TaggedContent[T3]:
        """Pop and return the staged body for ``handle_id`` (single-use).

        Raises :class:`StagingHandleNotConfiguredError` when ``handle_id`` was
        never staged or has already been drained — the loud refusal that closes
        the replay window.
        """
        try:
            return self._staged.pop(handle_id)
        except KeyError as exc:
            _log.warning(
                "security.quarantine_staging.handle_not_configured",
                handle_id=handle_id,
            )
            raise StagingHandleNotConfiguredError(
                t("security.quarantine_staging.handle_consumed")
            ) from exc

    def discard(self, handle_id: str) -> None:
        """Drop any staged body for ``handle_id`` — a NON-logging, never-raising no-op.

        Distinct from :meth:`drain`: ``drain`` is the single-use consume path whose
        absence is a loud replay refusal (warning + raise). ``discard`` is the
        cleanup path for a body whose extraction never completed (gate-deny,
        extract failure, cancellation) — an absent handle is the EXPECTED
        happy-path case (a successful extract already drained it), so it must NOT
        emit ``security.quarantine_staging.handle_not_configured`` (false security
        noise on the C9 happy-path cleanup).
        """
        self._staged.pop(handle_id, None)


class T3BodyRecorder:
    """The ``record_body`` seam: tag the inbound body T3, stage it under a handle.

    Satisfies :class:`alfred.comms_mcp.bootstrap._BodyRecorderLike`
    (``__call__(*, handle, body) -> None``). The bridge calls this exactly once,
    BEFORE ``extractor.extract``, so the body is staged before the transport's
    ``quarantine.ingest`` drains it.

    Holds the authorised :class:`CapabilityGateNonce` by DI (never re-fetched from
    the module slot) so the gate's ``is``-identity check holds. A ``None`` nonce is
    a loud refusal — the host wires this recorder only on the production path where
    the boot nonce exists; a missing nonce means a wiring bug, not a stage-untagged
    fallback.
    """

    def __init__(self, *, nonce: CapabilityGateNonce | None, staging: QuarantineStagingMap) -> None:
        self._nonce = nonce
        self._staging = staging

    def __call__(self, *, handle: ContentHandle, body: bytes | str | object) -> None:
        """Tag ``body`` T3 under the boot nonce and stage it under ``handle.id``.

        Raises:
            StagingNonceUnconfiguredError: when no nonce is configured — fail
                loud rather than stage untagged (mirrors StdioTransport's
                ``NonceNotConfigured`` guard).
            ValueError: surfaced from :func:`tag_t3_with_nonce` when the held
                nonce is not the authorised slot identity (wrong-nonce path).
        """
        if self._nonce is None:
            _log.error(
                "security.quarantine_staging.nonce_unconfigured",
                handle_id=handle.id,
            )
            raise StagingNonceUnconfiguredError(t("security.quarantine_staging.nonce_unconfigured"))
        # T3 content is a *string* on the TaggedContent model. Decode bytes /
        # stringify mappings with the same ``errors="replace"`` posture the
        # StdioTransport content path uses so a non-UTF-8 body cannot crash the
        # tagging path.
        text = _body_to_text(body)
        tagged = tag_t3_with_nonce(
            text,
            source=f"comms-mcp:inbound:{handle.id}",
            caller_token=self._nonce,
        )
        self._staging.stage(handle.id, tagged)

    def discard_staged(self, handle_id: str) -> None:
        """Discard any staged T3 body for *handle_id*.

        Drain-and-discard a staged body whose extraction never completed
        (gate-deny before extract, an extract failure mid-flight, OR a
        ``CancelledError`` from Task 6's action-deadline) so it cannot
        orphan in the unbounded staging map (G7-2.5 C9).

        Idempotent: a no-op when a successful extract already drained the
        handle (the normal happy-path exit) or when the handle was never
        staged.  Delegates to :meth:`QuarantineStagingMap.discard` (a
        non-logging ``pop(..., None)``) so the C9 happy-path cleanup does NOT
        emit a false ``security.quarantine_staging.handle_not_configured``
        warning — the ``except BaseException`` block in
        :meth:`EgressResponseExtractor.handle` can call this unconditionally
        without a prior existence check.
        """
        self._staging.discard(handle_id)


def _body_to_text(body: bytes | str | object) -> str:
    """Coerce an inbound body to the ``str`` the TaggedContent model requires."""
    if isinstance(body, str):
        return body
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    # A Mapping/structured body — JSON-serialise deterministically. ``default=str``
    # keeps a non-JSON-native value from crashing the tagging path.
    return json.dumps(body, default=str, sort_keys=True)


def _frame(method: str, params: dict[str, object]) -> bytes:
    """Serialise one length-prefixed JSON-RPC request frame.

    Peer to StdioTransport's framing (``struct.pack(">I", len) + body``); the
    request id is omitted because this transport is strictly request/response
    against a single child and matches the reply to the just-sent extract.
    """
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode("utf-8")
    return struct.pack(">I", len(body)) + body


class QuarantineStdioTransport:
    """Request/response transport from the host to the quarantined LLM child.

    Implements :class:`alfred.plugins.transport.PluginTransport` structurally so
    the real :class:`QuarantinedExtractor` drives it exactly as it would the
    stdio transport. On a ``quarantine.extract`` dispatch it:

    1. Drains the staged T3 body for ``params["handle_id"]`` (single-use; a
       missing/consumed handle raises :class:`StagingHandleNotConfiguredError`).
    2. Sends ``quarantine.ingest{handle_id, context}`` carrying the body inline.
    3. Sends ``quarantine.extract{handle_id, schema_json, schema_version}``.
    4. Reads the reply frame and returns a :class:`ControlResult` — NEVER a
       :class:`ContentHandle` (the regression guard for ``quarantine.py:1038``,
       where a handle trips ``PluginProtocolViolation``).

    Only ``quarantine.extract`` is a supported dispatch method in this cut — any
    other method is a loud :class:`AlfredError` rather than a silent passthrough.
    """

    def __init__(
        self,
        *,
        child_io: ChildIO,
        staging: QuarantineStagingMap,
        broker_auditor: EgressBrokerAuditor,
    ) -> None:
        self._child_io = child_io
        self._staging = staging
        # Serialises ``dispatch`` against the ONE long-lived child. Nothing else does:
        # ``adapter_ids`` is a list and ``supervise_all`` runs a runner per adapter, so the
        # shipped Discord+TUI config makes concurrent dispatch reachable in principle. Today's
        # serialisation is emergent, not guaranteed — and the failure mode is not a crash but a
        # SILENT cross-user T3 disclosure: two dispatches interleaving write_frame/read_frame on
        # one child cross their replies, so user A's extraction returns user B's T3 body.
        #
        # Constructed here rather than lazily because a Lock created outside a running loop is
        # loop-agnostic in modern CPython, and a lazy "create on first use" would itself race.
        self._dispatch_lock = asyncio.Lock()
        # REQUIRED (no default). An ``EgressBrokerAuditor | None = None`` default was
        # fail-OPEN: a caller that forgot the auditor silently lost every durable
        # ``egress.broker.*`` row while the broker kept handing live gateway sockets to a T3
        # child. Audit-log writes are non-skippable (CLAUDE.md HARD #5), so the wiring mistake
        # must be a construction-time TypeError, not a runtime audit hole.
        self._broker_auditor = broker_auditor

    async def dispatch(self, method: str, params: dict[str, object]) -> ControlResult:
        """Dispatch ``quarantine.extract`` via the ingest-then-extract wire.

        ``params`` carries ``handle_id`` (the staged body's key + the wire
        attribution token), ``schema_json`` and ``schema_version`` — exactly the
        shape :meth:`QuarantinedExtractor._extract_body` builds.
        """
        if method != _EXTRACT_METHOD:
            # Closed dispatch vocabulary for this cut — fail loud, never silently
            # forward an unknown method onto the quarantine wire (hard rule #7).
            _log.error("security.quarantine_transport.unsupported_method", method=method)
            raise AlfredError(t("security.quarantine_transport.unsupported_method", method=method))

        # Held across the WHOLE wire exchange — broker preamble, both writes, and the read.
        # A narrower critical section would still let a second dispatch's frames land between
        # this one's, which is the crossing itself.
        async with self._dispatch_lock:
            return await self._dispatch_locked(params)

    async def _dispatch_locked(self, params: dict[str, object]) -> ControlResult:
        """The single-child wire exchange. Caller MUST hold ``_dispatch_lock``."""
        handle_id = str(params["handle_id"])
        # Drain BEFORE writing anything to the child: a missing/consumed handle is
        # refused before the wire is touched, so a replay cannot ship a partial
        # ingest then fail.
        tagged = self._staging.drain(handle_id)

        refusal = await self._run_broker_preamble()
        if refusal is not None:
            return refusal

        # Inline-over-wire (ADR-0029): ingest carries the raw T3 body; extract
        # carries only the opaque handle id + schema. Ingest goes FIRST so the
        # child has the body cached before it pops it on extract.
        self._child_io.write_frame(
            _frame(_INGEST_METHOD, {"handle_id": handle_id, "context": tagged.content})
        )
        self._child_io.write_frame(
            _frame(
                _EXTRACT_METHOD,
                {
                    "handle_id": handle_id,
                    "schema_json": params["schema_json"],
                    "schema_version": params["schema_version"],
                },
            )
        )

        raw = await self._child_io.read_frame()
        payload = _decode_result_payload(raw)
        # ALWAYS a ControlResult — the QuarantinedExtractor's kind/data/schema
        # guards (quarantine.py:1050-1145) do the lift; this transport never
        # synthesises a ContentHandle or an ExtractionResult on this path.
        return ControlResult(method=_EXTRACT_METHOD, payload=payload)

    async def _run_broker_preamble(self) -> ControlResult | None:
        """Broker N gateway sockets + write their audit rows. ``None`` == proceed to the wire.

        Brokers ``BROKER_SOCKET_COUNT`` one-shot gateway sockets up-front (spec §6,
        connect-defer) BEFORE the ingest/extract writes, so all N ``sendmsg``s enqueue into the
        child's fd-4 buffer ahead of the extract frame and the child's post-read drain is
        race-free. Returns a typed-refusal :class:`ControlResult` on any broker failure — a raw
        broker error NEVER reaches the orchestrator (HARD #7).

        Three invariants beyond the happy path:

        **The whole preamble is BOUNDED** (:data:`_BROKER_PREAMBLE_TIMEOUT_S`, review item A7).
        Unbounded it sits outside the §17 timeout nesting, so a degraded gateway kills the
        extraction on the outer ``action_deadline`` before the graceful refusal + forensic row
        are ever produced.

        **Only OUR deadline is treated as a deadline.** The ``except TimeoutError`` arm is gated
        on the timeout context's ``.expired()``, because ``EgressBrokerAuditor`` raises
        ``TimeoutError`` in its own right when its bounded ``append_schema`` hangs. Ungated,
        this arm caught a FAILED, NON-SKIPPABLE AUDIT WRITE and returned a graceful typed
        refusal — precisely the laundering HARD #5 forbids and the third bullet below
        disclaims. A callee's ``TimeoutError`` revokes (the sockets are already queued) and
        then propagates.

        **Any failure that could leave fds in the child REVOKES the capability** (A2/A3) by
        tearing the child down. Three arcs reach it:

        * a SEND-phase partial failure (``exc.delivered > 0``): connect-defer makes the CONNECT
          half all-or-nothing but cannot make the SEND half atomic, so k-1 live sockets sit in
          the child's SCM_RIGHTS queue that no drain will reclaim (the drain only runs in the
          extract branch's ``finally``, and this path writes no extract frame);
        * the preamble deadline: the delivery count is unknowable, so revoke conservatively;
        * a post-broker exception — an audit-row write that raises or a fail-closed hookpoint
          that denies (A3). The sockets are ALREADY queued at that point, so without the revoke
          the child would hold live provider-reachable fds with NO durable audit row and NO
          teardown: an un-recorded, un-revoked capability grant. The exception still propagates
          (a failed audit write is loud — HARD #5 — never laundered into a soft refusal); the
          revoke merely happens first.

        A ``delivered == 0`` broker failure (the COMMON gateway-down case) deliberately does NOT
        revoke: nothing reached the child, so there is no capability to revoke and no desynced
        queue, and killing the child would turn a transient outage into a hard-down quarantine
        path.
        """
        # Groups every ``egress.broker.*`` row this extraction writes (it becomes each row's
        # ``trace_id``) and salts each socket's ``egress_id``. Without it the N success rows
        # carried one identical id — all N share a destination — so an audit consumer could not
        # tell 1 extraction x N sockets from N extractions x 1 socket and the ADR-0040 residual
        # (vii) counts inflated N-fold. A fresh uuid rather than ``handle_id``: the handle is a
        # capability token for the staged T3 body and does not belong in an audit row.
        extraction_id = str(uuid.uuid4())
        try:
            async with asyncio.timeout(_BROKER_PREAMBLE_TIMEOUT_S) as preamble_deadline:
                destinations = await self._child_io.broker_sockets(BROKER_SOCKET_COUNT)
                for ordinal, (host, port) in enumerate(destinations):
                    await self._broker_auditor.record_broker_success(
                        destination=f"{host}:{port}",
                        extraction_id=extraction_id,
                        socket_ordinal=ordinal,
                    )
        except TimeoutError:
            if not preamble_deadline.expired():
                # NOT our deadline — a ``TimeoutError`` raised BY the callee. The auditor
                # raises exactly that when its own bounded ``append_schema`` hangs, so
                # catching it here silently converted a FAILED, NON-SKIPPABLE AUDIT WRITE
                # into a graceful typed refusal. HARD #5: a failed audit write is loud and
                # is never laundered. Let it propagate.
                #
                # Revoke FIRST. A sibling ``except`` clause does not catch a re-raise from
                # inside this handler, so the A3 arm below would be skipped — and by this
                # point the sockets are already queued in the child. Propagating without the
                # revoke would leave a T3 child holding live provider-reachable fds with no
                # durable row and no teardown: the exact un-recorded, un-revoked capability
                # grant A3 exists to prevent.
                await self._revoke_child_capability()
                raise
            _log.error(
                "security.quarantine_transport.broker_preamble_deadline_exceeded",
                timeout_s=_BROKER_PREAMBLE_TIMEOUT_S,
            )
            return await self._refuse_broker(
                extraction_id=extraction_id,
                destination=_UNRESOLVED_DESTINATION,
                reason=_GENERIC_BROKER_REFUSAL_REASON,
                revoke=True,  # conservative: we cannot know how many fds reached the child
            )
        except ControlFdBrokerError as exc:
            return await self._refuse_broker(
                extraction_id=extraction_id,
                destination=exc.destination or _UNRESOLVED_DESTINATION,
                reason=exc.reason,
                revoke=exc.delivered > 0,
            )
        except (IOPlaneUnavailableError, QuarantineChildSpawnError) as exc:
            # Both escape ``broker_sockets`` strictly BEFORE any connect — an unset/malformed
            # proxy URL (``_resolve_proxy_addr``) or an IO built without a control-end/egress
            # config. Nothing was delivered, so no revoke. Previously these propagated RAW past
            # the ``except ControlFdBrokerError`` narrowing, bypassing the typed refusal (A4).
            _log.error(
                "security.quarantine_transport.broker_unconfigured",
                error_class=type(exc).__name__,
            )
            return await self._refuse_broker(
                extraction_id=extraction_id,
                destination=_UNRESOLVED_DESTINATION,
                reason=_GENERIC_BROKER_REFUSAL_REASON,
                revoke=False,
            )
        except BaseException:
            # A3: the sockets are already in the child's queue. Revoke BEFORE the exception
            # propagates — deliberately ``BaseException`` so a ``CancelledError`` (an outer
            # action-deadline firing mid-preamble) revokes too: that path also writes no extract
            # frame, so the child would keep un-drained live fds. Mirrors the
            # ``_await_boot_handshake`` teardown discipline in ``quarantine_child_io``.
            await self._revoke_child_capability()
            raise
        return None

    async def _refuse_broker(
        self, *, extraction_id: str, destination: str, reason: str, revoke: bool
    ) -> ControlResult:
        """Revoke (if the child holds fds), persist the refusal row, return the typed refusal.

        Revoke-FIRST ordering is deliberate: if the durable ``egress.broker.refused`` write
        itself fails it propagates loudly (HARD #5 — audit writes are non-skippable), and the
        capability must already be revoked by then rather than left live behind a raised error.
        """
        async with asyncio.timeout(_BROKER_REFUSAL_TIMEOUT_S):
            if revoke:
                await self._revoke_child_capability()
            await self._broker_auditor.record_broker_failure(
                destination=destination, reason=reason, extraction_id=extraction_id
            )
        return _broker_failure_refusal()

    async def _revoke_child_capability(self) -> None:
        """Tear the quarantine child down, revoking every fd already in its SCM_RIGHTS queue.

        Killing the child is what makes the connect-defer invariant TRUE rather than merely
        narrower: it revokes the granted capability and discards the desynced socket queue
        atomically, in one step the kernel guarantees.

        **Operational consequence (tracked):** the child is spawned exactly ONCE, at daemon boot
        (``_build_comms_inbound_extractor``); there is no respawn scheduler. After a revoke,
        subsequent extractions degrade GRACEFULLY rather than crashing — the control-parent
        socket is closed, so ``_send_one`` fails immediately with ``sendmsg_failed`` and every
        later dispatch returns this same ``provider_unavailable`` typed refusal plus its own
        ``egress.broker.refused`` row — but the quarantine path stays down until the daemon is
        restarted. That is the correct fail-closed trade against leaving un-revoked gateway
        capability in a T3-holding child.

        A teardown that itself fails is logged LOUD with an explicit ``error_class`` and
        swallowed (never silent — HARD #7): it must not preempt the caller's graceful typed
        refusal, which is the orchestrator's only clean exit from this path.
        """
        _log.error("security.quarantine_transport.capability_revoked")
        try:
            async with asyncio.timeout(_REVOKE_TIMEOUT_S):
                await self._child_io.aclose()
        except TimeoutError:
            # BOUNDED because the caller still has an audit row to write. Unbounded, a child
            # that declines to die starved ``record_broker_failure`` entirely — the refusal
            # that triggered this teardown produced no forensic row at all. The SIGKILL
            # escalation underneath (``_terminate_and_reap``) means reaching this is already
            # an OS-level anomaly, so it is an ERROR, not a warning.
            _log.error(
                "security.quarantine_transport.revoke_deadline_exceeded",
                timeout_s=_REVOKE_TIMEOUT_S,
            )
        except Exception as exc:
            _log.error(
                "security.quarantine_transport.capability_revoke_failed",
                error_class=type(exc).__name__,
            )

    async def close(self) -> None:
        """Close the injected child-IO seam (idempotent at the seam level)."""
        await self._child_io.aclose()


def _broker_failure_refusal() -> ControlResult:
    """The ``ControlResult`` a broker failure lifts to — a graceful typed refusal (HARD #7).

    The payload is the SAME ``{"kind": "typed_refusal", "reason": ...}`` wire shape the child
    normally sends over the wire, so :meth:`QuarantinedExtractor._extract_body` lifts it into a
    :class:`alfred.security.quarantine.TypedRefusal` (``result="refused"``) — a legitimate
    orchestrator outcome the caller branches on, never a raised ``ControlFdBrokerError``. The
    durable forensic record of the broker failure is the separate ``egress.broker.refused`` audit
    row (see :meth:`QuarantineStdioTransport.dispatch`); this outcome carries no T3-derived bytes.
    """
    return ControlResult(
        method=_EXTRACT_METHOD,
        payload={"kind": "typed_refusal", "reason": _BROKER_FAILURE_REFUSAL_REASON},
    )


def _decode_result_payload(raw: bytes) -> dict[str, object]:
    """Strip the length prefix and return the JSON-RPC ``result`` as a dict.

    ``read_frame`` returns one length-prefixed reply frame (4-byte big-endian
    header + body), peer to the request framing (ADR-0029). The header is stripped
    unconditionally — a frame too short to carry it leaves an empty/garbage body that
    ``json.loads`` rejects loudly (``JSONDecodeError`` propagates into the extractor's
    ``transport_failed`` audit), so a truncated reply never silently mis-parses into an
    empty payload (the slice itself does not raise — the decode does). A non-dict
    ``result`` is returned as an empty dict so the QuarantinedExtractor's OWN
    ``kind``/``data`` guards (quarantine.py:1052/1075) — not this transport —
    classify the laundering attempt as a protocol violation.
    """
    body = raw[_LENGTH_HEADER_BYTES:]
    result = json.loads(body).get("result", {})
    return dict(result) if isinstance(result, dict) else {}


__all__ = [
    "ChildIO",
    "QuarantineStagingMap",
    "QuarantineStdioTransport",
    "StagingHandleNotConfiguredError",
    "StagingNonceUnconfiguredError",
    "T3BodyRecorder",
]
