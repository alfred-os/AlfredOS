"""Adversarial: the gateway-forwarded inbound RECEIVE trust boundary (Spec B G6-7-4).

**Threat model** (ADR-0039 / #309 / §3.3). The ``alfred-gateway`` is the
network-facing front door; it forwards a hosted adapter child's ``inbound.message``
to the connectivity-free CORE as a JSON-RPC ``gateway.adapter.inbound`` notification
whose ``params`` is a :class:`GatewayAdapterInboundEnvelope` (``{adapter_id, body}``).
The opaque ``body`` is T3 the gateway NEVER parses (hard rule #5); the core re-parses
it core-side (the trusted boundary). This is the highest-value trust seam in the
system — untrusted T3 crossing from the network-facing gateway into the trusted core
— so an adversary has five distinct levers, every one of which MUST be neutralised at
the core's :class:`GatewayForwardedInboundReceiver` (the K4 admission + re-parse +
wire_seq-rebind + dispatched-edge pipeline):

* **C1 wiring regression (the real bug this file gates)** — the forward must ride as
  a JSON-RPC NOTIFICATION (method ``gateway.adapter.inbound``), NOT a bare envelope
  object: a frame with no ``method`` is a RESPONSE frame the daemon pump silently
  drops (``_resolve_pending`` -> no awaiter -> ignored). The af9c3b5e fix made the
  gateway emit a notification frame; case (1) drives a REAL
  ``forward_adapter_inbound``-produced frame through the ACTUAL ``read_frame`` ->
  :meth:`CommsPluginRunner.pump` -> ``_wire_seq_of`` -> ``_route_notification`` chain
  and proves it REACHES the receiver (not dropped) AND that the dispatched
  notification's ``wire_seq`` equals the leg-frame seq (the fold -> lift -> rebind
  chain). A unit test that calls ``_route_notification`` directly does NOT catch a
  ``_pump`` mis-discrimination — only an end-to-end pump drive does.

* **Forged unknown adapter (K4)** — an ENVELOPE ``adapter_id`` naming a kind NOT in
  the per-adapter collaborator registry is a loud ``unknown_adapter`` refusal, never
  default-routed, never dispatched. It must ACK-to-DRAIN the leg seq (ARCH-309-3) so
  a contiguous-seq leg's high-water is NOT wedged (a wedge = the gateway replays the
  forged frame forever).

* **Envelope/body ``adapter_id`` disagreement (F3)** — the body stays the sole G0
  authority; an envelope routing id that disagrees with the body it wraps is a
  forged-body/valid-leg mismatch -> ``envelope_body_mismatch`` refusal + ack-to-drain.

* **Malformed body** — a body that is not a valid ``InboundMessageNotification``
  (non-JSON / non-object / missing field / ``extra_forbidden`` top-level key) is a
  ``body_malformed`` drop + ack-to-drain. CANARY-ABSENCE: a high-entropy secret /
  canary planted in the body MUST NOT appear in ANY signed audit row OR ANY captured
  structlog line (spec §3.3 — no T3 leak; the structural summary is leak-safe and the
  ``extra_forbidden`` key is redacted to ``<redacted-t3-key>``).

* **Body-smuggled ``wire_seq``** — the host-authoritative leg-carrier seq (ADR-0032)
  is rebound from the REAL leg frame; a value smuggled into the untrusted T3 body is
  scrubbed (re-parse -> ``None``) then replaced with the real leg seq, never trusted.

* **Dispatch-failure replay (ADR-0039 item 4)** — a dispatch failure leaves the frame
  UN-committed / UN-observed so the forwarding leg replays it; after a SUCCESS, the
  same inbound re-delivered is a ``replay_observed`` clean drop, NOT re-dispatched.

* **Audit-unwritable does NOT drain** — a failed signed-audit write on a drop
  disposition is non-skippable (hard rules #5/#7): ``observe`` is NOT called (an
  un-recorded drop is never silently drained) and the typed
  :class:`ForwardedInboundAuditWriteError` PROPAGATES (the disposition escalates a
  restart) rather than silently swallowing the lost security signal.

NON-ROOT, no-Postgres, in-process (the gating non-root CI lane): the e2e case drives
the runner's pump over an IN-MEMORY transport that yields the framed bytes (so it
exercises the real ``read_frame`` / ``_wire_seq_of`` / ``_route_notification`` path);
every other case drives the receiver with the same injected fakes the unit tests use
(idempotency store, ack tracker, collaborators). Standalone adversarial module — a
receive-boundary integrity property, not a corpus content payload.

KNOWN-THIS-SLICE PROPERTY (case 7): a deterministically-failing (poison) frame
replays UNBOUNDEDLY in G6-7-4 — the un-observed-on-failure behaviour is what lets the
leg replay, and the poison CEILING (a bound on the replay count) is G6-7-5's job. This
module's gateway-leg drive is therefore TEST-ONLY-resumable until G6-7-5 lands the
ceiling; case 7 pins the unbounded-replay property explicitly so a future ceiling does
not silently regress the un-observed-on-failure contract it builds on.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import structlog.testing

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.errors import ForwardedInboundAuditWriteError
from alfred.comms_mcp.forwarded_inbound_receiver import (
    GatewayForwardedInboundReceiver,
    _ForwardedCollaborators,
)
from alfred.comms_mcp.inbound import _PreResolutionLimiter
from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_INBOUND
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_seq_codec import WIRE_SEQ_FRAME_KEY
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

pytestmark = pytest.mark.asyncio

# The ADMITTED adapter kind for the cases that drive the REAL dispatched-edge
# pipeline (``process_inbound_message``, no injected fake dispatch). ``alfred_comms_test``
# has an EMPTY required-classifier set (``REQUIRED_CLASSIFIERS_BY_KIND``), so a ``None``
# sub-payload promoter is correct and the M2 fail-closed guard does not trip — unlike
# ``discord``, which requires ``discord_sub_payloads`` and would need a real promoter.
# The unit tests use ``discord`` only because they inject a fake ``dispatch``; these
# adversarial cases exercise the real pipeline, so the plain-text reference kind fits.
_ADAPTER_ID = "alfred_comms_test"

# A valid closed-vocab ``AdapterId`` KIND that is NOT in the test registry — the K4
# unknown-adapter (registry-miss) lever. It passes the wire ``AdapterId`` validator
# (so the refusal is the receiver's K4 registry-miss, NOT an off-vocab ValidationError —
# that off-vocab path is its own unit-test case), but names no registered collaborator.
_UNREGISTERED_KIND = "tui"

# A high-entropy synthetic canary planted in malformed-body cases. NOT a real
# secret — but shaped so that if ANY substring of it lands on a signed audit row or
# a structlog line, the T3-leak assertion fails loud. Assembled inline (no concern of
# GitHub push-protection here, it is plainly synthetic) but kept distinctive so a
# partial leak (a fragment) is still caught by the substring scan.
_CANARY = "CANARY-7f3a9e2b4c6d8a1f-DLP-TRIPWIRE-do-not-log-этот-секрет"


# --------------------------------------------------------------------------- #
# Shared fakes — the same shapes the unit/dispatched-edge tests use, so these
# cases exercise the REAL receiver + REAL pipeline with deps mocked (no Postgres).
# --------------------------------------------------------------------------- #


class _SpyAckTracker:
    """Records ``observe(seq)`` so drain occurrence / high-water advance is assertable."""

    def __init__(self) -> None:
        self.observed: list[int] = []

    def observe(self, seq: int) -> None:
        self.observed.append(seq)


class _NeverCommittedStore:
    """A store whose key is never durable — the happy/dispatch path needs only a read."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        return True

    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        return False


class _ReplayableStore:
    """``commit_once`` wins once per (adapter_id, inbound_id); ``has_committed`` reflects it.

    Drives the dispatch-failure-replay case: a first SUCCESS commits the key; a later
    re-delivery reads ``has_committed -> True`` and the dispatched edge short-circuits
    to a clean replay drop (no re-dispatch).
    """

    def __init__(self) -> None:
        self._committed: set[tuple[str, str]] = set()

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        key = (adapter_id, inbound_id)
        if key in self._committed:
            return False
        self._committed.add(key)
        return True

    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        return (adapter_id, inbound_id) in self._committed


class _RaisingAuditWriter:
    """An audit writer whose ``append_schema`` always raises (drop-path failure).

    Proves a failed signed-audit write happens BEFORE (and short-circuits) the drain
    ``observe`` — the receiver wraps it in ``ForwardedInboundAuditWriteError``.
    """

    def __init__(self) -> None:
        self.append_schema_calls = 0

    async def append_schema(self, **kwargs: Any) -> None:
        self.append_schema_calls += 1
        raise RuntimeError("signed audit write failed")


def _discord_collaborators(
    *, orchestrator: SpyOrchestrator | None = None
) -> _ForwardedCollaborators:
    """The K4-admitted collaborator set for ``_ADAPTER_ID`` (the real pipeline runs).

    ``sub_payload_promoter`` is ``None``: ``_ADAPTER_ID`` (``alfred_comms_test``) has an
    EMPTY required-classifier set, so the M2 fail-closed promoter guard does not trip and
    the real ``process_inbound_message`` runs with no promotion (plain-text only).
    """
    return _ForwardedCollaborators(
        # Mirrors the daemon's _build_forwarded_inbound_registry: a None promoter is
        # valid for an empty-required-classifier kind (the daemon uses the same ignore).
        sub_payload_promoter=None,  # type: ignore[arg-type]
        resolver_bridge=SpyIdentityResolver(returns=make_resolved(adapter_id=_ADAPTER_ID)),
        orchestrator=orchestrator if orchestrator is not None else SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        secret_broker=SpySecretBroker(),
        # ONE long-lived limiter (sec-003) — the real pipeline calls check_and_record.
        pre_resolution_limiter=_PreResolutionLimiter(),
    )


def _build_receiver(
    *,
    audit_writer: Any,
    idempotency_store: Any,
    ack_tracker: _SpyAckTracker | None = None,
    orchestrator: SpyOrchestrator | None = None,
) -> GatewayForwardedInboundReceiver:
    """A REAL receiver over the REAL dispatched-edge pipeline (deps mocked, no DB)."""
    receiver = GatewayForwardedInboundReceiver(
        registry={_ADAPTER_ID: _discord_collaborators(orchestrator=orchestrator)},
        idempotency_store=idempotency_store,
        audit_writer=audit_writer,
    )
    if ack_tracker is not None:
        receiver.set_ack_tracker(ack_tracker)
    return receiver


def _discord_body(
    *,
    adapter_id: str = _ADAPTER_ID,
    inbound_id: str | None = None,
    smuggled_wire_seq: int | None = None,
    content: str = "hello there",
) -> str:
    """A well-formed ``InboundMessageNotification`` body serialized to a JSON str.

    The gateway forwards a ``str`` body (``forward_adapter_inbound``), so this mirrors
    the wire shape the core re-parses. ``smuggled_wire_seq`` plants a body-derived seq
    the receiver MUST scrub-then-rebind; ``content`` carries arbitrary T3 text.
    """
    notification = make_notification(
        adapter_id=adapter_id,
        inbound_id=inbound_id,
        body={"content": content},
        wire_seq=smuggled_wire_seq,
    )
    dumped: str = notification.model_dump_json()
    return dumped


def _inbound_params(*, adapter_id: str, body: bytes | str) -> dict[str, Any]:
    """The wire ``params`` of a ``gateway.adapter.inbound`` notification frame."""
    return {"adapter_id": adapter_id, "body": body}


@pytest.fixture(autouse=True)
def _reset_audit_hash() -> Any:
    """Isolate the module-level comms audit-hash broker between tests."""
    audit_hash.reset_for_test()
    yield
    audit_hash.reset_for_test()


# --------------------------------------------------------------------------- #
# In-memory transport + a real-pump harness for the C1 e2e case.
# --------------------------------------------------------------------------- #


class _ScriptedTransport:
    """An in-memory ``_CommsTransportLike`` that replays a fixed frame script.

    ``read_frame`` pops the next scripted frame and finally returns ``None`` (clean
    EOF) so :meth:`CommsPluginRunner.pump` exits. This is the SEAM the seq-enabled
    socket carrier satisfies in production — it lets the pump exercise the real
    ``read_frame`` -> ``_wire_seq_of`` -> ``_route_notification`` chain without a
    socket / subprocess (non-root, no Postgres). ``spawn``/``send``/``close`` are
    no-ops; ``enable_seq_ack`` is unused (pump is driven directly, skipping handshake).
    """

    def __init__(self, frames: list[Mapping[str, object]]) -> None:
        self._frames = list(frames)
        self.closed = False

    async def spawn(self) -> None:  # pragma: no cover - pump() skips spawn
        return None

    async def send(self, frame: Mapping[str, object]) -> None:  # pragma: no cover
        return None

    async def read_frame(self) -> Mapping[str, object] | None:
        if self._frames:
            return self._frames.pop(0)
        return None  # clean EOF -> pump exits

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:  # pragma: no cover - handshake not driven
        return None


def _forwarded_frame(*, params: Mapping[str, object], wire_seq: int | None) -> dict[str, Any]:
    """The JSON-RPC ``gateway.adapter.inbound`` NOTIFICATION frame the pump reads.

    Byte-for-byte the frame ``GatewayCoreLink.forward_adapter_inbound`` produces
    (``{jsonrpc, method, params}`` — a NOTIFICATION, no ``id``), with the
    seq-enabled socket carrier's reserved out-of-band wire-seq folded under
    :data:`WIRE_SEQ_FRAME_KEY` exactly as ``read_frame`` delivers it. ``_wire_seq_of``
    lifts that key in the pump; a ``None`` seq omits it (a plain/stdio frame).
    """
    frame: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": GATEWAY_ADAPTER_INBOUND,
        "params": dict(params),
    }
    if wire_seq is not None:
        frame[WIRE_SEQ_FRAME_KEY] = wire_seq
    return frame


def _gateway_leg_runner(
    *, transport: _ScriptedTransport, receiver: GatewayForwardedInboundReceiver
) -> CommsPluginRunner:
    """A daemon gateway-leg runner: real receiver threaded into the default disposition.

    Mirrors the daemon's Task-5 wiring (``_commands.py``): a HOST runner over the
    gateway leg with a ``forwarded_inbound_receiver`` injected, so the constructed
    :class:`SessionDispatchDisposition` routes ``gateway.adapter.inbound`` to the
    receiver. The session is a stand-in the receiver intercepts BEFORE touching (the
    forwarded path never reaches ``_on_post_handshake_method``); wiring it proves the
    interception, not the session refusal.
    """
    session = MagicMock()
    session._on_post_handshake_method = AsyncMock()
    session._supervisor = MagicMock()
    session._supervisor.request_plugin_restart = AsyncMock()
    return CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        # The concrete receiver's set_ack_tracker is narrower (_AckTrackerLike) than the
        # _ForwardedReceiverLike Protocol's (object) — a benign method-arg variance the
        # daemon's own wiring also satisfies structurally; the receive() contract matches.
        forwarded_inbound_receiver=receiver,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# 1 — REAL e2e: a forwarded notification frame REACHES the receiver through the
#     actual read_frame -> pump -> route chain, with the leg seq rebound (C1 guard).
# --------------------------------------------------------------------------- #


async def test_e2e_forwarded_frame_reaches_receiver_via_real_pump() -> None:
    """The C1 regression guard: drive a REAL forwarded frame through the pump.

    Builds the exact JSON-RPC ``gateway.adapter.inbound`` NOTIFICATION frame the
    gateway emits (with the carrier seq folded under ``_wire_seq``), feeds it through
    a scripted ``read_frame``, and runs :meth:`CommsPluginRunner.pump`. The frame MUST
    reach the receiver and dispatch (NOT be silently dropped as a response frame — the
    C1 defect), AND the dispatched notification's ``wire_seq`` MUST equal the leg-frame
    seq (the fold -> lift -> rebind chain), never the body-smuggled value nor ``None``.
    """
    orch = SpyOrchestrator()
    receiver = _build_receiver(
        audit_writer=SpyAuditWriter(),
        idempotency_store=_NeverCommittedStore(),
        ack_tracker=_SpyAckTracker(),
        orchestrator=orch,
    )
    # The body smuggles wire_seq=999; the REAL leg-frame seq is 5. The fold -> lift ->
    # rebind chain must dispatch with 5.
    body = _discord_body(smuggled_wire_seq=999, content="e2e through the real pump")
    frame = _forwarded_frame(params=_inbound_params(adapter_id=_ADAPTER_ID, body=body), wire_seq=5)
    transport = _ScriptedTransport([frame])
    runner = _gateway_leg_runner(transport=transport, receiver=receiver)

    # Drive the REAL single-reader pump: read_frame -> _wire_seq_of -> _route_notification
    # -> disposition -> receiver -> dispatched-edge pipeline. NOT _route_notification
    # injected directly (that would not catch a _pump response-frame mis-drop — C1).
    await runner.pump()

    # The frame REACHED dispatch (not dropped as a response frame): the real pipeline
    # ran the orchestrator extract/ingest/dispatch sequence exactly once.
    assert orch.dispatch_calls == 1
    assert orch.call_order == ["extract", "ingest", "dispatch"]
    # The dispatched body is the forwarded T3 content, re-parsed core-side.
    assert orch.last_extract_kwargs["body"] == {"content": "e2e through the real pump"}
    # The wire_seq was the REAL leg seq (5), never the smuggled 999, never None.
    assert orch.last_extract_kwargs["source_tier"] == "T3"
    # The transport was torn down cleanly on EOF (no FD leak).
    assert transport.closed is True


async def test_e2e_dispatched_notification_carries_real_leg_seq_not_body_value() -> None:
    """The dispatched edge observes the REAL leg seq, never the body-smuggled one.

    A direct corollary of the fold -> lift -> rebind chain: the durable-intake ack
    tracker ``observe``s the leg-frame seq (5), proving the dispatched-edge ``observe``
    used the rebound host-authoritative value, never the body's smuggled 999.
    """
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        audit_writer=SpyAuditWriter(),
        idempotency_store=_NeverCommittedStore(),
        ack_tracker=ack,
    )
    body = _discord_body(smuggled_wire_seq=999)
    frame = _forwarded_frame(params=_inbound_params(adapter_id=_ADAPTER_ID, body=body), wire_seq=5)
    runner = _gateway_leg_runner(transport=_ScriptedTransport([frame]), receiver=receiver)

    await runner.pump()

    # The dispatched-edge observe drained the REAL leg seq (5) — never the smuggled 999.
    assert ack.observed == [5]


# --------------------------------------------------------------------------- #
# 2 — Forged unknown adapter (K4): refuse, ack-to-drain, high-water advances,
#     NOT dispatched, never default-routed.
# --------------------------------------------------------------------------- #


async def test_forged_unknown_adapter_refused_drained_high_water_advances() -> None:
    """A forged ENVELOPE adapter (a kind NOT in the registry) is a K4 refusal.

    ``_UNREGISTERED_KIND`` (``"tui"``) is a valid ``AdapterId`` KIND but is NOT in the
    registry (which holds only ``_ADAPTER_ID``) -> ``unknown_adapter`` refusal. It is
    NOT dispatched, never default-routed, and the leg seq is ACK-drained so the
    contiguous high-water ADVANCES past it (the tracker is NOT wedged — a wedge = the
    gateway replays the forged frame forever).
    """
    orch = SpyOrchestrator()
    audit = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        audit_writer=audit,
        idempotency_store=_NeverCommittedStore(),
        ack_tracker=ack,
        orchestrator=orch,
    )

    await receiver.receive(
        params=_inbound_params(adapter_id=_UNREGISTERED_KIND, body=b"never-parsed"),
        wire_seq=11,
    )

    # NOT dispatched, never default-routed to the admitted collaborator pipeline.
    assert orch.dispatch_calls == 0
    rows = audit.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["adapter_id"] == _UNREGISTERED_KIND
    assert rows[0]["reason"] == "unknown_adapter"
    assert rows[0]["result"] == "refused"
    assert rows[0]["trust_tier_of_trigger"] == "T3"
    # Drained: the contiguous high-water ADVANCES past the forged frame (not wedged).
    assert ack.observed == [11]


# --------------------------------------------------------------------------- #
# 3 — Envelope/body adapter_id disagreement (F3): refuse, ack-to-drain.
# --------------------------------------------------------------------------- #


async def test_envelope_body_adapter_id_disagreement_refused_and_drained() -> None:
    """Envelope says ``_ADAPTER_ID`` (registry hit) but the body claims ``discord`` (F3).

    The body is the sole G0 authority; an envelope routing id that disagrees with the
    body it wraps is a forged-body/valid-leg mismatch -> ``envelope_body_mismatch``
    refusal + ack-to-drain. The valid-leg registry hit does NOT let the disagreement
    through.
    """
    orch = SpyOrchestrator()
    audit = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        audit_writer=audit,
        idempotency_store=_NeverCommittedStore(),
        ack_tracker=ack,
        orchestrator=orch,
    )

    await receiver.receive(
        params=_inbound_params(adapter_id=_ADAPTER_ID, body=_discord_body(adapter_id="discord")),
        wire_seq=13,
    )

    assert orch.dispatch_calls == 0
    rows = audit.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["adapter_id"] == _ADAPTER_ID
    assert rows[0]["reason"] == "envelope_body_mismatch"
    assert rows[0]["result"] == "refused"
    assert ack.observed == [13]


# --------------------------------------------------------------------------- #
# 4 — Malformed body: drop, ack-to-drain, + CANARY-ABSENCE (no T3 leak).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"not-json-at-all", id="non_json"),
        pytest.param(b'"a-bare-json-string"', id="non_object"),
        pytest.param(b'{"adapter_id": "discord"}', id="missing_required_field"),
    ],
)
async def test_malformed_body_dropped_drained_no_canary_leak(body: bytes) -> None:
    """A body that fails ``InboundMessageNotification`` validation is dropped + drained.

    Covers non-JSON, a non-object top-level, and a missing-required-field body. Each is
    a ``body_malformed`` drop carrying ONLY the closed-vocab reason (never ``str(exc)``,
    never the body), followed by an ack-to-drain. CANARY-ABSENCE: a high-entropy canary
    embedded in the malformed body MUST NOT appear in ANY signed audit row OR ANY
    captured structlog line (spec §3.3 — the leak-safe structural summary may aid an
    operator, but the raw T3 never lands).
    """
    audit = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        audit_writer=audit, idempotency_store=_NeverCommittedStore(), ack_tracker=ack
    )
    # Plant the canary INSIDE the malformed body so a naive "echo the body" bug leaks it.
    poisoned = body.replace(b"discord", b"discord", 1) + b" " + _CANARY.encode("utf-8")

    with structlog.testing.capture_logs() as logs:
        await receiver.receive(
            params=_inbound_params(adapter_id=_ADAPTER_ID, body=poisoned),
            wire_seq=17,
        )

    rows = audit.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["adapter_id"] == _ADAPTER_ID
    assert rows[0]["reason"] == "body_malformed"
    assert rows[0]["result"] == "dropped"
    assert ack.observed == [17]  # drained
    # CANARY-ABSENCE: no fragment of the canary on ANY signed audit row...
    for row in audit.schema_rows:
        assert _CANARY not in str(row)
        assert "CANARY" not in str(row)
    # ...nor on ANY captured structlog line (the leak-safe structural summary only).
    for entry in logs:
        assert _CANARY not in str(entry)
        assert "CANARY" not in str(entry)


async def test_malformed_body_extra_forbidden_key_redacted_no_canary_leak() -> None:
    """An ``extra_forbidden`` TOP-LEVEL key (its NAME is attacker T3) is redacted.

    The ``extra_forbidden`` error's ``loc`` ENDS in the attacker-supplied extra-key
    NAME — itself T3 — so the re-parse redacts it to ``<redacted-t3-key>``. A canary
    used AS the extra key MUST NOT survive onto a signed audit row or a structlog line.
    """
    audit = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        audit_writer=audit, idempotency_store=_NeverCommittedStore(), ack_tracker=ack
    )
    # A structurally-valid notification with one EXTRA top-level key whose NAME is the
    # canary — _WireModel is extra="forbid", so this is a body_malformed drop and the
    # offending key name (T3) must be redacted, never echoed.
    base = json.loads(_discord_body())
    base[_CANARY] = "x"
    poisoned = json.dumps(base).encode("utf-8")

    with structlog.testing.capture_logs() as logs:
        await receiver.receive(
            params=_inbound_params(adapter_id=_ADAPTER_ID, body=poisoned),
            wire_seq=19,
        )

    rows = audit.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["reason"] == "body_malformed"
    assert ack.observed == [19]
    for row in audit.schema_rows:
        assert _CANARY not in str(row)
    for entry in logs:
        assert _CANARY not in str(entry)


# --------------------------------------------------------------------------- #
# 5 — Body-smuggled wire_seq scrubbed + real leg seq rebound (receiver-level).
# --------------------------------------------------------------------------- #


async def test_body_smuggled_wire_seq_scrubbed_and_real_leg_seq_rebound() -> None:
    """The body carries ``wire_seq=999``; the REAL leg frame carries seq=3.

    The dispatched notification's ``wire_seq`` MUST be 3 (the real leg-carrier seq the
    receiver rebinds out-of-band), never 999 (smuggled into the untrusted T3 body and
    scrubbed to ``None`` by the re-parse) nor ``None``. Proven at the dispatch edge: the
    ack tracker ``observe``s 3.
    """
    ack = _SpyAckTracker()
    orch = SpyOrchestrator()
    receiver = _build_receiver(
        audit_writer=SpyAuditWriter(),
        idempotency_store=_NeverCommittedStore(),
        ack_tracker=ack,
        orchestrator=orch,
    )

    await receiver.receive(
        params=_inbound_params(adapter_id=_ADAPTER_ID, body=_discord_body(smuggled_wire_seq=999)),
        wire_seq=3,
    )

    assert orch.dispatch_calls == 1
    assert ack.observed == [3]  # the REAL leg seq, never the smuggled 999 nor None


# --------------------------------------------------------------------------- #
# 6 — Dispatch-failure replay: a failed dispatch re-dispatches; after success a
#     re-delivery is replay_observed + drained, NOT re-dispatched.
# --------------------------------------------------------------------------- #


class _FailThenSucceedOrchestrator(SpyOrchestrator):
    """``dispatch`` raises on the FIRST call, then succeeds on every later call.

    Drives the ADR-0039 item-4 replay contract: the first dispatch failure leaves the
    frame un-committed / un-observed (the leg replays it); the re-delivery succeeds.
    """

    def __init__(self, *, call_order: list[str] | None = None) -> None:
        super().__init__(call_order=call_order)
        self._failed_once = False

    async def dispatch(self, ingested: object) -> None:
        self.call_order.append("dispatch")
        self.dispatch_calls += 1
        if not self._failed_once:
            self._failed_once = True
            raise RuntimeError("transient dispatch fault")


async def test_dispatch_failure_replays_then_success_then_replay_observed() -> None:
    """Three deliveries of the SAME inbound across a transient dispatch fault.

    1. delivery #1 — dispatch RAISES -> NOT committed, NOT observed (the leg replays);
    2. delivery #2 (the replay) — dispatch SUCCEEDS -> committed + observed once;
    3. delivery #3 (a second replay) — ``has_committed`` is True -> ``replay_observed``
       clean drop, NOT re-dispatched (the dispatch spy count does not advance).
    """
    store = _ReplayableStore()
    audit = SpyAuditWriter()
    ack = _SpyAckTracker()
    orch = _FailThenSucceedOrchestrator()
    receiver = _build_receiver(
        audit_writer=audit, idempotency_store=store, ack_tracker=ack, orchestrator=orch
    )
    params = _inbound_params(adapter_id=_ADAPTER_ID, body=_discord_body(inbound_id="poison-7"))

    # Delivery #1 — dispatch raises. The receiver does NOT swallow a non-audit fault;
    # it propagates (the disposition's catch-and-continue is the leg-replay recovery).
    with pytest.raises(RuntimeError, match="transient dispatch fault"):
        await receiver.receive(params=params, wire_seq=20)
    assert orch.dispatch_calls == 1
    assert ack.observed == []  # NOT observed — the leg will replay
    assert audit.rows_with_schema("COMMS_INBOUND_DISPATCH_FAILED_FIELDS")

    # Delivery #2 — the replay re-dispatches (un-committed) and now succeeds: commit +
    # observe happen on the dispatched edge.
    await receiver.receive(params=params, wire_seq=21)
    assert orch.dispatch_calls == 2
    assert ack.observed == [21]

    # Delivery #3 — has_committed is now True: a clean replay_observed drop, NOT
    # re-dispatched (the spy count stays at 2). Still drained (the tail must trim).
    await receiver.receive(params=params, wire_seq=22)
    assert orch.dispatch_calls == 2  # NOT re-dispatched
    assert ack.observed == [21, 22]  # replay still drains its seq
    assert audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")


# --------------------------------------------------------------------------- #
# 7 — Documented known-this-slice property: a poison frame replays UNBOUNDEDLY
#     in G6-7-4 (the bound is G6-7-5). Pin the un-observed-on-failure contract.
# --------------------------------------------------------------------------- #


class _AlwaysFailOrchestrator(SpyOrchestrator):
    """``dispatch`` ALWAYS raises — a deterministically-failing (poison) frame."""

    async def dispatch(self, ingested: object) -> None:
        self.call_order.append("dispatch")
        self.dispatch_calls += 1
        raise RuntimeError("poison frame")


async def test_poison_frame_replays_unboundedly_this_slice() -> None:
    """KNOWN-THIS-SLICE (G6-7-4): a deterministically-failing frame replays unboundedly.

    The poison CEILING (a bound on the replay count) is G6-7-5's job. Here we pin the
    behaviour G6-7-4 actually ships and the ceiling will build on: EVERY delivery of a
    deterministically-failing frame raises, NEVER commits, NEVER observes — so the
    forwarding leg replays it forever. The gateway leg is therefore TEST-ONLY-resumable
    until G6-7-5 lands the ceiling; if a future change makes this frame stop replaying
    WITHOUT a deliberate ceiling, this test fails loud and surfaces the regression.
    """
    store = _ReplayableStore()
    ack = _SpyAckTracker()
    orch = _AlwaysFailOrchestrator()
    receiver = _build_receiver(
        audit_writer=SpyAuditWriter(),
        idempotency_store=store,
        ack_tracker=ack,
        orchestrator=orch,
    )
    params = _inbound_params(adapter_id=_ADAPTER_ID, body=_discord_body(inbound_id="poison-loop"))

    # Re-deliver the SAME poison frame several times: each raises, none commits, none
    # observes — an unbounded replay (no ceiling this slice).
    for seq in range(5):
        with pytest.raises(RuntimeError, match="poison frame"):
            await receiver.receive(params=params, wire_seq=seq)

    assert orch.dispatch_calls == 5  # re-dispatched EVERY time (no short-circuit)
    assert ack.observed == []  # NEVER observed — the high-water never advances past it


# --------------------------------------------------------------------------- #
# 8 — Audit-unwritable does NOT drain: the signed drop-audit write raises ->
#     observe NOT called, the typed marker propagates (escalation, not silent drain).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("adapter_id", "body"),
    [
        pytest.param(_UNREGISTERED_KIND, b"never-parsed", id="unknown_adapter"),
        pytest.param(_ADAPTER_ID, None, id="envelope_body_mismatch"),
        pytest.param(_ADAPTER_ID, b"not-json", id="body_malformed"),
    ],
)
async def test_audit_unwritable_on_drop_does_not_drain_and_propagates(
    adapter_id: str, body: bytes | None
) -> None:
    """A failed signed-audit write on a drop disposition is non-skippable.

    Across all three terminal drops (unknown adapter / envelope-body mismatch /
    malformed body): the signed-audit write raises -> ``observe`` is NOT called (an
    un-recorded drop is NEVER silently drained) and the typed
    :class:`ForwardedInboundAuditWriteError` PROPAGATES (the disposition escalates a
    restart) rather than swallowing the lost security signal (hard rules #5/#7).
    """
    audit = _RaisingAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        audit_writer=audit, idempotency_store=_NeverCommittedStore(), ack_tracker=ack
    )
    # The mismatch case needs a body whose adapter_id disagrees with the envelope.
    drop_body: bytes | str = _discord_body(adapter_id="discord") if body is None else body

    with pytest.raises(ForwardedInboundAuditWriteError) as excinfo:
        await receiver.receive(
            params=_inbound_params(adapter_id=adapter_id, body=drop_body), wire_seq=31
        )

    # The raw backend error is chained as the cause (no T3 on the marker)...
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    # ...the drop was NOT drained (never ACK an un-recorded drop)...
    assert ack.observed == []
    # ...and the audit write was attempted exactly once (it raised, short-circuiting).
    assert audit.append_schema_calls == 1
