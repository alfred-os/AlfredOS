"""Unit tests for the quarantine request/response transport + staging seam.

PR-S4-11c-2a (epic #237). The host-side wire that carries a T3 inbound body to
the (eventually launcher-spawned) quarantined LLM. Host-only: no subprocess, no
bwrap, no real LLM — the child is an in-test length-prefixed double.

What is under test (ADR-0029):

* :class:`QuarantineStdioTransport` sends ``quarantine.ingest{handle_id, context}``
  THEN ``quarantine.extract{handle_id, ...}`` in that order, over a length-prefixed
  JSON-RPC child-IO seam, and returns a :class:`ControlResult` (NOT a
  :class:`ContentHandle` — the regression guard for ``quarantine.py:1038``).
* The host single-use staging map + the ``record_body`` seam: tags the inbound body
  ``TaggedContent[T3]`` via the boot nonce, stages it under ``handle.id``, and the
  transport drains it single-use (replay refused).
* The missing-nonce / wrong-nonce fail-loud posture.
* :class:`CommsExtractorBridge` calls ``record_body`` exactly once BEFORE
  ``extractor.extract``.
"""

from __future__ import annotations

import asyncio
import json
import struct
import time
from typing import TYPE_CHECKING, Any

import pytest

import alfred.security.quarantine_transport as transport_mod
from alfred.egress.control_fd_broker import ControlFdBrokerError
from alfred.plugins.transport import ControlResult
from alfred.security.quarantine import ContentHandle
from alfred.security.quarantine_transport import (
    ChildIO,
    QuarantineStagingMap,
    QuarantineStdioTransport,
    StagingHandleNotConfiguredError,
    StagingNonceUnconfiguredError,
    T3BodyRecorder,
    _decode_result_payload,
)
from alfred.security.tiers import T3, CapabilityGateNonce

if TYPE_CHECKING:
    from collections.abc import Sequence


# ---------------------------------------------------------------------------
# Test child double — a length-prefixed JSON-RPC peer that records the frames
# it receives in order and replies to ``quarantine.extract`` with a recorded
# ``extracted`` payload. Mirrors the child's ingest/extract single-use cache.
# ---------------------------------------------------------------------------


def _frame(obj: dict[str, Any]) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack(">I", len(body)) + body


class _RecordingChildIO:
    """In-process child-IO double for :class:`QuarantineStdioTransport`.

    Records every request method/params in receive order; replies to
    ``quarantine.extract`` with a ``CommsBodyExtraction``-valid ``extracted``
    payload, echoing the most-recently-ingested ``context`` into ``data.text``
    so the integration-shaped assertion can prove the body reached the child.
    """

    def __init__(self) -> None:
        self.received: list[tuple[str, dict[str, Any]]] = []
        self._ingested: dict[str, str] = {}
        self._pending_reply: bytes | None = None
        self.closed = False
        self.brokered: list[int] = []
        self.aborted = False

    def abort(self) -> None:
        # #472 finding 2: the synchronous last-resort revoke. Subclasses that need to
        # observe it inherit this; the cancel/timeout arms call it via _abort_child_now.
        self.aborted = True

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        # Benign in-process double: records the requested count and returns that many
        # (host, port) destinations, mirroring a successful connect-defer batch.
        self.brokered.append(count)
        return [("gw", 8889)] * count

    def write_frame(self, frame: bytes) -> None:
        length = struct.unpack(">I", frame[:4])[0]
        obj = json.loads(frame[4 : 4 + length])
        method = obj["method"]
        params = obj["params"]
        self.received.append((method, params))
        if method == "quarantine.ingest":
            # Single-use cache, mirroring quarantine_plugin.handle_ingest.
            self._ingested[params["handle_id"]] = params["context"]
        elif method == "quarantine.extract":
            # Pop single-use, mirroring quarantine_plugin.handle_extract.
            context = self._ingested.pop(params["handle_id"], "")
            self._pending_reply = _frame(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "kind": "extracted",
                        "data": {"text": context, "intent": "greeting"},
                        "extraction_mode": "native_constrained",
                    },
                }
            )

    async def read_frame(self) -> bytes:
        if self._pending_reply is None:  # pragma: no cover - defensive
            raise AssertionError("read_frame called with no pending reply")
        reply = self._pending_reply
        self._pending_reply = None
        return reply

    async def aclose(self) -> None:
        self.closed = True


class _ContentHandleReturningChildIO(_RecordingChildIO):
    """A child that replies with a frame the transport must NOT lift to a handle.

    The transport's contract is to return a :class:`ControlResult` regardless of
    payload — this double proves the transport never synthesises a
    :class:`ContentHandle` (the regression guard for ``quarantine.py:1038``,
    where a ``ContentHandle`` trips ``PluginProtocolViolation``).
    """


def _make_handle() -> ContentHandle:
    from datetime import UTC, datetime

    return ContentHandle(
        id="deadbeef",
        source_url="comms-mcp://inbound",
        fetch_timestamp=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# #340 golive Task 9: connect-defer broker-N-then-write + typed-refusal on failure.
# ---------------------------------------------------------------------------


def _extracted_reply_frame(text: str = "x") -> bytes:
    return _frame(
        {
            "jsonrpc": "2.0",
            "result": {
                "kind": "extracted",
                "data": {"text": text, "intent": "greeting"},
                "extraction_mode": "native_constrained",
            },
        }
    )


class _OrderRecordingChildIO:
    """A ChildIO double that records the ORDER of broker_sockets vs write_frame.

    The load-bearing invariant (spec §6, connect-defer): ``dispatch`` must broker
    all N sockets BEFORE it writes the ingest/extract frames, so every ``sendmsg``
    enqueues into the child's fd-4 buffer ahead of the extract frame (race-free
    drain).
    """

    def __init__(self) -> None:
        self.order: list[str] = []

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        self.order.append(f"broker:{count}")
        return [("gw", 8889)] * count

    def write_frame(self, frame: bytes) -> None:
        self.order.append("write")

    async def read_frame(self) -> bytes:
        self.order.append("read")
        return _extracted_reply_frame()

    async def aclose(self) -> None:  # pragma: no cover - not exercised here
        return None

    def abort(self) -> None:  # pragma: no cover - not exercised here (never reaches revoke)
        return None


@pytest.mark.asyncio
async def test_dispatch_brokers_n_before_writing() -> None:
    """``dispatch`` brokers ``BROKER_SOCKET_COUNT`` sockets BEFORE any frame write."""
    from alfred.security.quarantine import BROKER_SOCKET_COUNT

    staging = QuarantineStagingMap()
    nonce = CapabilityGateNonce()
    staging.stage("deadbeef", _tag(nonce, "hello there"))
    child = _OrderRecordingChildIO()
    transport = QuarantineStdioTransport(
        child_io=child, staging=staging, broker_auditor=_RecordingAuditor()
    )

    await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )

    assert child.order[0] == f"broker:{BROKER_SOCKET_COUNT}"
    assert "write" in child.order
    assert child.order.index(f"broker:{BROKER_SOCKET_COUNT}") < child.order.index("write")


class _RecordingAuditor:
    """A fake :class:`EgressBrokerAuditor` recording success/failure row calls."""

    def __init__(self) -> None:
        self.successes: list[str] = []
        self.failures: list[tuple[str, str]] = []
        self.success_ids: list[tuple[str, int]] = []
        self.failure_ids: list[str] = []

    async def record_broker_success(
        self, *, destination: str, extraction_id: str, socket_ordinal: int
    ) -> None:
        self.successes.append(destination)
        self.success_ids.append((extraction_id, socket_ordinal))

    async def record_broker_failure(
        self, *, destination: str, reason: str, extraction_id: str
    ) -> None:
        self.failures.append((destination, reason))
        self.failure_ids.append(extraction_id)


class _RaisingChildIO(_RecordingChildIO):
    """A ChildIO double whose ``broker_sockets`` raises a caller-supplied error.

    Typed ``BaseException`` (not ``ControlFdBrokerError``) so the A4 cases can drive the
    ``IOPlaneUnavailableError`` / ``QuarantineChildSpawnError`` arms that used to escape raw.
    """

    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self._error = error

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        raise self._error


class _StallingChildIO(_RecordingChildIO):
    """A ChildIO double whose ``broker_sockets`` outlives the preamble bound (A7).

    Sleeps well past ``_BROKER_PREAMBLE_TIMEOUT_S`` — a stand-in for a degraded gateway whose
    CONNECT never completes. The ``asyncio.sleep`` is cancellable, so the bound tears it down
    promptly and the test costs the bound, not the sleep.
    """

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        import asyncio

        await asyncio.sleep(3600)
        raise AssertionError("unreachable: the preamble bound must fire first")


class _CloseRaisingChildIO(_RaisingChildIO):
    """A ChildIO double whose ``aclose`` itself fails — the loud-teardown-failure path."""

    async def aclose(self) -> None:
        raise OSError("teardown failed")


class _HangingCloseChildIO(_RaisingChildIO):
    """A ChildIO double whose ``aclose`` never returns — a child ignoring its teardown.

    The fail-closed path's own worst case: the broker already failed, so the transport is
    trying to revoke, and the revoke itself wedges.
    """

    async def aclose(self) -> None:
        import asyncio

        await asyncio.sleep(3600)
        raise AssertionError("unreachable: the revoke bound must fire first")


@pytest.mark.parametrize(
    "double",
    [
        _RecordingChildIO,
        _ContentHandleReturningChildIO,
        _OrderRecordingChildIO,
        _RaisingChildIO,
        _StallingChildIO,
        _CloseRaisingChildIO,
        _HangingCloseChildIO,
    ],
)
def test_every_transport_childio_double_satisfies_the_protocol(double: type) -> None:
    """Every ChildIO double in this module implements the FULL Protocol — incl. ``abort``.

    #472 finding 2 review (core lane): neither ``mypy``/``pyright`` (they don't type-check
    ``tests/``) nor the one ``issubclass`` site in test_quarantine_child_io.py enforces that
    these doubles keep pace with the Protocol. Without this guard, a double missing the new
    ``abort`` method would take ``_abort_child_now``'s ``capability_abort_failed`` arm and a
    revoke test could pass while proving nothing (the negative log-assertions in the arm tests
    are the companion protection). ``@runtime_checkable`` ``issubclass`` checks method presence.
    """
    assert issubclass(double, ChildIO)


async def _dispatch_extract(transport: QuarantineStdioTransport) -> Any:
    return await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )


def _staged_transport(child: Any, *, auditor: Any = None) -> QuarantineStdioTransport:
    staging = QuarantineStagingMap()
    staging.stage("deadbeef", _tag(CapabilityGateNonce(), "hello there"))
    return QuarantineStdioTransport(child_io=child, staging=staging, broker_auditor=auditor)


@pytest.mark.asyncio
async def test_dispatch_broker_failure_returns_typed_refusal_not_raised() -> None:
    """A broker ``ControlFdBrokerError`` becomes a ``provider_unavailable`` typed refusal (HARD #7).

    The orchestrator NEVER sees a raw ``ControlFdBrokerError`` — ``dispatch`` returns a
    ``ControlResult`` whose ``typed_refusal`` payload ``QuarantinedExtractor`` lifts to a graceful
    refusal, and ``record_broker_failure`` is called ONCE with the real closed-vocab reason +
    the error's destination.
    """
    auditor = _RecordingAuditor()
    child = _RaisingChildIO(ControlFdBrokerError("gateway_unreachable", destination="gw:8889"))
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert isinstance(result, ControlResult)
    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert child.received == []  # broker-before-write: no ingest/extract frame was sent
    assert auditor.failures == [("gw:8889", "gateway_unreachable")]
    assert auditor.successes == []


@pytest.mark.asyncio
async def test_dispatch_broker_failure_unresolved_destination_fallback() -> None:
    """A ``ControlFdBrokerError`` with no ``destination`` records the ``<unresolved>`` sentinel."""
    auditor = _RecordingAuditor()
    child = _RaisingChildIO(ControlFdBrokerError("control_fd_broker_failed"))
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert result.payload["reason"] == "provider_unavailable"
    assert auditor.failures == [("<unresolved>", "control_fd_broker_failed")]


@pytest.mark.asyncio
async def test_dispatch_broker_failure_row_precedes_the_typed_refusal() -> None:
    """The refusal row is DURABLE before the refusal is returned (HARD #5: non-skippable).

    Replaces the former ``without_auditor`` case: the auditor is now a required constructor
    argument (A5), so there is no auditor-less path left to cover. What still needs pinning is
    that the durable row is written on the way OUT — a refusal returned before its forensic row
    would leave the operator with a refused extraction and no record of which destination
    failed.
    """
    auditor = _RecordingAuditor()
    child = _RaisingChildIO(
        ControlFdBrokerError("sendmsg_failed", destination="gw:8889", delivered=0)
    )
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert auditor.failures == [("gw:8889", "sendmsg_failed")]


@pytest.mark.asyncio
async def test_hanging_revoke_still_writes_the_refusal_row() -> None:
    """A wedged teardown must NOT swallow the ``egress.broker.refused`` row.

    The fail-closed path was itself unbounded: ``_refuse_broker`` -> ``_revoke_child_capability``
    ran OUTSIDE every ceiling, and the reap underneath was SIGTERM-only with an unbounded
    ``wait()``. A child that declines to die therefore hung dispatch past the outer
    ``action_deadline`` AND starved ``record_broker_failure`` — no forensic row for the very
    failure that triggered the teardown. The revoke is best-effort; the row is not.
    """
    auditor = _RecordingAuditor()
    child = _HangingCloseChildIO(
        ControlFdBrokerError("sendmsg_failed", destination="gw:8889", delivered=1)  # revoke=True
    )
    transport = _staged_transport(child, auditor=auditor)
    started = time.monotonic()

    result = await _dispatch_extract(transport)

    elapsed = time.monotonic() - started
    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert auditor.failures == [("gw:8889", "sendmsg_failed")]  # the row SURVIVED the hang
    assert elapsed < transport_mod._BROKER_REFUSAL_TIMEOUT_S, (
        f"refusal path took {elapsed:.2f}s — the bound did not apply"
    )


@pytest.mark.asyncio
async def test_hanging_revoke_is_logged_loudly() -> None:
    """A revoke that outruns its bound is loud, never silent (HARD #7)."""
    import structlog.testing

    child = _HangingCloseChildIO(
        ControlFdBrokerError("sendmsg_failed", destination="gw:8889", delivered=1)
    )
    transport = _staged_transport(child, auditor=_RecordingAuditor())

    with structlog.testing.capture_logs() as logs:
        await _dispatch_extract(transport)

    assert [
        e for e in logs if e["event"] == "security.quarantine_transport.revoke_deadline_exceeded"
    ]


@pytest.mark.asyncio
async def test_audit_write_timeout_is_not_laundered_into_a_typed_refusal() -> None:
    """A ``TimeoutError`` from the AUDIT WRITE must propagate, not become a soft refusal.

    ``_run_broker_preamble`` wraps ``broker_sockets`` + the N ``record_broker_success`` calls in
    one ``asyncio.timeout``, then catches bare ``TimeoutError``. But ``EgressBrokerAuditor``
    raises ``TimeoutError`` itself when its bounded ``append_schema`` hangs — so a FAILED,
    NON-SKIPPABLE AUDIT WRITE was being caught by the deadline arm and converted into a graceful
    ``provider_unavailable`` refusal. That is exactly the laundering HARD #5 forbids, and it
    contradicts this module's own docstring ("never laundered into a soft refusal").

    The two are told apart by the timeout context's ``.expired()``: only a genuinely expired
    preamble is a deadline; anything else is the callee's own error.
    """
    auditor = _RaisingAuditor(TimeoutError("append_schema hung"))
    transport = _staged_transport(_RecordingChildIO(), auditor=auditor)

    with pytest.raises(TimeoutError):
        await _dispatch_extract(transport)


@pytest.mark.asyncio
async def test_concurrent_dispatches_are_serialised_against_the_single_child() -> None:
    """Two concurrent dispatches must NOT interleave on the one persistent child.

    Nothing serialised ``dispatch`` against the single long-lived child. ``adapter_ids`` is a
    list and ``supervise_all`` runs one runner per adapter, so the shipped Discord+TUI config
    makes concurrent dispatch reachable in principle — today's serialisation is EMERGENT, not
    asserted. If it ever breaks, two dispatches interleave ``write_frame``/``read_frame`` on
    one child and the replies cross: user A's extraction returns user B's T3 content. That is
    a cross-user T3 disclosure, so the invariant is pinned rather than assumed.

    Without the lock this fails as ``assert 'body B' == 'body A'`` — the disclosure, live.
    """

    class _YieldingChildIO(_RecordingChildIO):
        """Yields to the loop mid-dispatch — where an unserialised second dispatch cuts in.

        ``_pending_reply`` is a SINGLE slot, which is a faithful model of the single
        long-lived child: one reply channel. An interleaved second dispatch overwrites it,
        so the first dispatch reads the second one's T3 body. Rather than raise on an empty
        slot, this returns a sentinel so the assertion lands on the security property
        (whose body came back) instead of on fixture mechanics.
        """

        async def read_frame(self) -> bytes:
            await asyncio.sleep(0)  # the interleaving window
            if self._pending_reply is None:
                return _frame(
                    {
                        "jsonrpc": "2.0",
                        "result": {
                            "kind": "extracted",
                            "data": {"text": "<CROSSED>", "intent": "greeting"},
                            "extraction_mode": "native_constrained",
                        },
                    }
                )
            return await super().read_frame()

    child = _YieldingChildIO()
    staging = QuarantineStagingMap()
    staging.stage("A", _tag(CapabilityGateNonce(), "body A"))
    staging.stage("B", _tag(CapabilityGateNonce(), "body B"))
    transport = QuarantineStdioTransport(
        child_io=child, staging=staging, broker_auditor=_RecordingAuditor()
    )

    async def _one(handle_id: str) -> str:
        result = await transport.dispatch(
            "quarantine.extract",
            {"handle_id": handle_id, "schema_json": "{}", "schema_version": 1},
        )
        text = result.payload["data"]["text"]  # type: ignore[index,call-overload]
        return str(text)

    async with asyncio.TaskGroup() as tg:
        task_a = tg.create_task(_one("A"))
        task_b = tg.create_task(_one("B"))

    # THE invariant: each dispatch gets back the body IT staged. Interleaved, A reads the
    # reply B just overwrote — a cross-user T3 disclosure.
    assert task_a.result() == "body A", "dispatch A received another user's T3 body"
    assert task_b.result() == "body B", "dispatch B received another user's T3 body"


# ---------------------------------------------------------------------------
# #340 review batch A — broker transport invariants (A2/A3/A4/A5/A7).
# ---------------------------------------------------------------------------


class _RaisingAuditor(_RecordingAuditor):
    """An auditor whose ``record_broker_success`` fails (a hung/failed durable write)."""

    def __init__(self, error: BaseException | None = None) -> None:
        super().__init__()
        self._error = error or RuntimeError("append_schema failed")

    async def record_broker_success(
        self, *, destination: str, extraction_id: str, socket_ordinal: int
    ) -> None:
        raise self._error


@pytest.mark.asyncio
async def test_send_phase_partial_failure_tears_down_the_child() -> None:
    """A2: a broker failure AFTER the first successful ``sendmsg`` revokes the capability.

    Connect-defer only makes the CONNECT half all-or-nothing. When ``_send_one`` fails on
    socket k of N, k-1 fds are ALREADY in the child's SCM_RIGHTS queue — and because the
    refusal writes NO extract frame, the child's ``drain_leftovers()`` ``finally`` (its only
    reclaim path) never runs. Those live gateway-reachable sockets would otherwise sit in a
    T3-holding child indefinitely, un-drained and recorded by an audit row that says the
    broker REFUSED. Tearing the child down revokes the capability and discards the desynced
    queue atomically, making the connect-defer invariant TRUE rather than merely narrower.
    """
    auditor = _RecordingAuditor()
    child = _RaisingChildIO(
        ControlFdBrokerError("short_data_send", destination="gw:8889", delivered=1)
    )
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert child.closed is True  # the capability is revoked, not merely refused
    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert auditor.failures == [("gw:8889", "short_data_send")]
    assert child.received == []  # still no ingest/extract frame on the wire


@pytest.mark.asyncio
async def test_connect_phase_failure_leaves_the_child_alive() -> None:
    """A2 boundary: the COMMON gateway-down case (``delivered == 0``) must NOT tear down.

    Connect-defer guarantees nothing reached the child, so there is no un-revoked capability
    and no desynced queue. Killing the child here would turn a transient, self-healing gateway
    outage into a hard-down quarantine path — the teardown is scoped to the case that actually
    granted a capability.
    """
    auditor = _RecordingAuditor()
    child = _RaisingChildIO(
        ControlFdBrokerError("gateway_unreachable", destination="gw:8889", delivered=0)
    )
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert child.closed is False
    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert auditor.failures == [("gw:8889", "gateway_unreachable")]


@pytest.mark.asyncio
async def test_post_broker_audit_failure_tears_down_the_child_and_propagates() -> None:
    """A3: broker-then-audit ordering — a failed success-row write must revoke first.

    ``broker_sockets`` puts N live gateway sockets in the child's queue BEFORE
    ``record_broker_success`` is awaited. If that await raises (audit-write timeout,
    ``append_schema`` failure, fail-closed hookpoint) the extract frame is never written, so
    no drain runs and the ``transport_failed`` path never calls ``aclose()`` — leaving live
    provider-reachable fds in a T3-holding child with NO durable audit row and NO teardown.
    The exception still PROPAGATES (a failed audit write is loud, never laundered into a soft
    refusal — HARD #5/#7); the teardown just happens first.
    """
    child = _RecordingChildIO()
    transport = _staged_transport(child, auditor=_RaisingAuditor())

    with pytest.raises(RuntimeError, match="append_schema failed"):
        await _dispatch_extract(transport)

    assert child.closed is True
    assert child.received == []  # no ingest/extract frame followed the failed audit


@pytest.mark.asyncio
async def test_broker_preamble_is_bounded_and_refuses_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A7: the per-extraction broker preamble is bounded by the §17 nesting budget.

    Unbounded, the preamble sits entirely outside the timeout hierarchy: under gateway
    degradation the outer 30s ``action_deadline`` fires before the graceful
    ``provider_unavailable`` + ``egress.broker.refused`` forensics are ever reached. The bound
    makes the refusal reachable. Because a deadline cannot tell us how many fds reached the
    child, it revokes conservatively.
    """
    import alfred.security.quarantine_transport as qt

    # Shrink the real bound rather than waiting it out: the invariant under test is that a
    # bound EXISTS and refuses gracefully, not its numeric value (pinned separately by
    # ``test_broker_preamble_bound_nests_under_the_action_deadline``).
    monkeypatch.setattr(qt, "_BROKER_PREAMBLE_TIMEOUT_S", 0.01)
    auditor = _RecordingAuditor()
    child = _StallingChildIO()
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert child.closed is True  # conservative revoke — delivery count is unknowable
    assert auditor.failures == [("<unresolved>", "control_fd_broker_failed")]
    assert child.received == []


@pytest.mark.asyncio
async def test_broker_preamble_bound_nests_under_the_action_deadline() -> None:
    """A7 arithmetic: preamble + host read-frame must fit INSIDE the action deadline.

    The preamble is SEQUENTIAL with (not nested inside) the ``read_frame`` bound, so for
    ``action_deadline`` to remain the dominating outer bound the two must sum below it:
    ``_BROKER_PREAMBLE_TIMEOUT_S + _READ_FRAME_TIMEOUT_S < action_deadline``. Drawn from LIVE
    constants so a drift in ANY term trips this guard.
    """
    from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
    from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S
    from alfred.security.quarantine_transport import _BROKER_PREAMBLE_TIMEOUT_S

    host_side_worst_case = _BROKER_PREAMBLE_TIMEOUT_S + _READ_FRAME_TIMEOUT_S
    assert host_side_worst_case < float(_DEFAULT_ACTION_DEADLINE_SECONDS)


@pytest.mark.asyncio
async def test_io_plane_unavailable_becomes_a_typed_refusal() -> None:
    """A4: ``IOPlaneUnavailableError`` must not escape ``dispatch`` raw.

    ``broker_sockets`` raises it for an unset/malformed proxy URL (via ``_resolve_proxy_addr``),
    strictly BEFORE any connect — so nothing was delivered and the child stays alive.
    """
    from alfred.egress.errors import IOPlaneUnavailableError

    auditor = _RecordingAuditor()
    child = _RaisingChildIO(IOPlaneUnavailableError(detail="proxy url unset"))
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert child.closed is False  # pre-connect failure — no capability was granted
    assert auditor.failures == [("<unresolved>", "control_fd_broker_failed")]


@pytest.mark.asyncio
async def test_child_spawn_error_becomes_a_typed_refusal() -> None:
    """A4: ``QuarantineChildSpawnError`` (the unconfigured-broker guard) must not escape raw."""
    from alfred.security.quarantine_child_io import QuarantineChildSpawnError

    auditor = _RecordingAuditor()
    child = _RaisingChildIO(QuarantineChildSpawnError("broker unconfigured"))
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    assert child.closed is False
    assert auditor.failures == [("<unresolved>", "control_fd_broker_failed")]


def test_broker_auditor_is_a_required_constructor_argument() -> None:
    """A5: the auditor has no default — omitting it is a TypeError, not a silent audit hole.

    A ``broker_auditor: EgressBrokerAuditor | None = None`` default is fail-OPEN: a caller that
    forgets it silently loses every durable ``egress.broker.*`` row while the broker keeps
    handing live gateway sockets to a T3 child. Audit writes are non-skippable (HARD #5).
    """
    with pytest.raises(TypeError):
        QuarantineStdioTransport(child_io=_RecordingChildIO(), staging=QuarantineStagingMap())  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_teardown_failure_is_loud_and_does_not_mask_the_refusal() -> None:
    """HARD #7: a teardown that itself fails is logged LOUD, never silently swallowed.

    The refusal must still reach the orchestrator — a failed revoke must not convert a graceful
    typed refusal into an unhandled exception.
    """
    import structlog

    auditor = _RecordingAuditor()
    child = _CloseRaisingChildIO(
        ControlFdBrokerError("short_data_send", destination="gw:8889", delivered=2)
    )
    transport = _staged_transport(child, auditor=auditor)

    with structlog.testing.capture_logs() as logs:
        result = await _dispatch_extract(transport)

    assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}
    events = [entry["event"] for entry in logs]
    assert "security.quarantine_transport.capability_revoke_failed" in events


@pytest.mark.asyncio
async def test_dispatch_broker_success_records_one_success_row_per_destination() -> None:
    """On full-batch success, ``record_broker_success`` is called once per brokered destination."""
    from alfred.security.quarantine import BROKER_SOCKET_COUNT

    auditor = _RecordingAuditor()
    child = _RecordingChildIO()  # its broker_sockets returns count copies of ("gw", 8889)
    transport = _staged_transport(child, auditor=auditor)

    result = await _dispatch_extract(transport)

    assert isinstance(result, ControlResult)
    assert result.payload["kind"] == "extracted"
    assert auditor.successes == ["gw:8889"] * BROKER_SOCKET_COUNT
    assert auditor.failures == []


# ---------------------------------------------------------------------------
# 1 + 2: transport ordering + ControlResult (not ContentHandle).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_sends_ingest_then_extract_in_order() -> None:
    """The transport drains the staged body, sends ingest THEN extract."""
    staging = QuarantineStagingMap()
    nonce = CapabilityGateNonce()
    staging.stage("deadbeef", _tag(nonce, "hello there"))
    child = _RecordingChildIO()
    transport = QuarantineStdioTransport(
        child_io=child, staging=staging, broker_auditor=_RecordingAuditor()
    )

    result = await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )

    methods = [m for m, _ in child.received]
    assert methods == ["quarantine.ingest", "quarantine.extract"]
    ingest_params = child.received[0][1]
    assert ingest_params["handle_id"] == "deadbeef"
    assert ingest_params["context"] == "hello there"
    assert isinstance(result, ControlResult)
    assert result.method == "quarantine.extract"
    assert result.payload["kind"] == "extracted"


@pytest.mark.asyncio
async def test_dispatch_returns_control_result_not_content_handle() -> None:
    """Regression guard: the transport returns ControlResult, never ContentHandle.

    ``QuarantinedExtractor._extract_body`` (quarantine.py:1038) raises
    ``PluginProtocolViolation`` if it gets a ``ContentHandle`` instead of a
    ``ControlResult``. The transport must therefore never lift content into a
    handle on this path.
    """
    staging = QuarantineStagingMap()
    nonce = CapabilityGateNonce()
    staging.stage("deadbeef", _tag(nonce, "body"))
    child = _ContentHandleReturningChildIO()
    transport = QuarantineStdioTransport(
        child_io=child, staging=staging, broker_auditor=_RecordingAuditor()
    )

    result = await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )

    # Exactly a ControlResult — NOT a ContentHandle. The QuarantinedExtractor's
    # ``isinstance(result_raw, ControlResult)`` guard (quarantine.py:1038) trips
    # ``PluginProtocolViolation`` on a ContentHandle, so the transport must return
    # the control shape on this path. ``type() is`` (not ``isinstance``) so the
    # check is meaningful even though the static return type is ControlResult.
    assert type(result) is ControlResult
    assert not isinstance(result, ContentHandle)  # type: ignore[unreachable]


@pytest.mark.asyncio
async def test_close_delegates_to_child_io() -> None:
    """``close`` closes the injected child-IO seam."""
    child = _RecordingChildIO()
    transport = QuarantineStdioTransport(
        child_io=child, staging=QuarantineStagingMap(), broker_auditor=_RecordingAuditor()
    )
    await transport.close()
    assert child.closed is True


# ---------------------------------------------------------------------------
# 3 + 4: record_body T3 staging + missing/wrong nonce fail-loud.
# ---------------------------------------------------------------------------


def _tag(nonce: CapabilityGateNonce, text: str) -> Any:
    """Tag ``text`` T3 under a registered ``nonce`` (test helper)."""
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        from alfred.security.tiers import tag_t3_with_nonce

        return tag_t3_with_nonce(text, source="test", caller_token=nonce)
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


def test_record_body_stages_t3_under_handle_id(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """``record_body`` tags the body T3 and stages it under ``handle.id``.

    The ``authorized_t3_nonce`` fixture registers the nonce as the live slot, so
    ``tag_t3_with_nonce`` accepts it as ``caller_token``.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    handle = _make_handle()

    recorder(handle=handle, body="attack")

    tagged = staging.drain("deadbeef")
    assert tagged.tier is T3
    assert tagged.content == "attack"


def test_record_body_missing_nonce_raises_loud(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A recorder built with a ``None`` nonce refuses to stage — no silent
    untagged write (mirrors StdioTransport's NonceNotConfigured pattern)."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=None, staging=staging)
    handle = _make_handle()

    with pytest.raises(StagingNonceUnconfiguredError):
        recorder(handle=handle, body="attack")
    # Nothing was staged — the refusal happened before any write.
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("deadbeef")


def test_record_body_wrong_nonce_surfaces_value_error() -> None:
    """4b: a WRONG (unregistered) nonce surfaces ``tag_t3_with_nonce``'s ValueError.

    No fixture registers the recorder's nonce, so the live slot is whatever the
    process holds (not this object); ``tag_t3_with_nonce`` raises
    ``ValueError(security.tag_t3_unauthorized)``.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=CapabilityGateNonce(), staging=staging)
    handle = _make_handle()

    with pytest.raises(ValueError, match="tag_t3_unauthorized"):
        recorder(handle=handle, body="attack")


# ---------------------------------------------------------------------------
# 5: staging map single-use.
# ---------------------------------------------------------------------------


def test_staging_map_single_use(authorized_t3_nonce: CapabilityGateNonce) -> None:
    """A second drain of the same handle id fails — single-use (replay refused)."""
    staging = QuarantineStagingMap()
    staging.stage("h1", _tag(authorized_t3_nonce, "once"))

    first = staging.drain("h1")
    assert first.content == "once"
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("h1")


def test_staging_drain_missing_handle_raises() -> None:
    """Draining an unstaged handle id is a loud refusal, not an empty value."""
    staging = QuarantineStagingMap()
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("never-staged")


@pytest.mark.asyncio
async def test_dispatch_replay_after_consume_refused(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A second dispatch against a consumed handle id fails — the staging map
    drained it on the first call (laundering-window close)."""
    staging = QuarantineStagingMap()
    staging.stage("deadbeef", _tag(authorized_t3_nonce, "body"))
    child = _RecordingChildIO()
    transport = QuarantineStdioTransport(
        child_io=child, staging=staging, broker_auditor=_RecordingAuditor()
    )

    await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )
    with pytest.raises(StagingHandleNotConfiguredError):
        await transport.dispatch(
            "quarantine.extract",
            {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
        )


# ---------------------------------------------------------------------------
# 6: CommsExtractorBridge calls record_body exactly once BEFORE extract.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bridge_calls_record_body_once_before_extract() -> None:
    """``CommsExtractorBridge`` records the body exactly once, before extract."""
    from alfred.comms_mcp.bootstrap import CommsBodyExtraction, CommsExtractorBridge
    from alfred.security.quarantine import Extracted

    order: list[str] = []
    record_calls: list[Sequence[object]] = []
    sentinel = Extracted(
        data={"text": "x", "intent": "greeting"},  # type: ignore[arg-type]
        extraction_mode="native_constrained",
    )

    class _SpyRecorder:
        def __call__(self, *, handle: ContentHandle, body: object) -> None:
            order.append("record")
            record_calls.append((handle, body))

    class _SpyExtractor:
        async def extract(self, handle: ContentHandle, schema: type) -> Extracted:
            order.append("extract")
            assert schema is CommsBodyExtraction
            return sentinel

    bridge = CommsExtractorBridge(
        extractor=_SpyExtractor(),  # type: ignore[arg-type]
        record_body=_SpyRecorder(),
    )
    result = await bridge.extract(body="hello", canonical_user_id="u1", source_tier="T3")

    assert result is sentinel
    assert order == ["record", "extract"]
    assert len(record_calls) == 1


# ---------------------------------------------------------------------------
# Body coercion + fail-loud edges (full-coverage of the trust-boundary file).
# ---------------------------------------------------------------------------


def test_record_body_bytes_decoded_to_t3_text(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A ``bytes`` body is decoded (errors=replace) before T3 tagging."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    recorder(handle=_make_handle(), body=b"raw \xff bytes")
    tagged = staging.drain("deadbeef")
    assert tagged.tier is T3
    assert tagged.content == "raw � bytes"


def test_record_body_mapping_serialised_deterministically(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A structured (Mapping) body is JSON-serialised (sorted) before tagging."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    recorder(handle=_make_handle(), body={"b": 2, "a": 1})
    tagged = staging.drain("deadbeef")
    assert tagged.content == '{"a": 1, "b": 2}'


@pytest.mark.asyncio
async def test_dispatch_unsupported_method_fails_loud() -> None:
    """A non-``quarantine.extract`` dispatch method is a loud refusal."""
    from alfred.errors import AlfredError

    transport = QuarantineStdioTransport(
        child_io=_RecordingChildIO(),
        staging=QuarantineStagingMap(),
        broker_auditor=_RecordingAuditor(),
    )
    with pytest.raises(AlfredError, match="unsupported wire method"):
        await transport.dispatch("quarantine.ingest", {"handle_id": "x"})


@pytest.mark.asyncio
async def test_dispatch_non_dict_result_yields_empty_payload(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A non-dict ``result`` frame yields an empty payload dict.

    The transport does NOT classify it — it returns an empty payload so the
    QuarantinedExtractor's own kind/data guards trip the protocol violation.
    """
    staging = QuarantineStagingMap()
    staging.stage("deadbeef", _tag(authorized_t3_nonce, "body"))

    class _NonDictResultChild(_RecordingChildIO):
        def write_frame(self, frame: bytes) -> None:
            length = struct.unpack(">I", frame[:4])[0]
            obj = json.loads(frame[4 : 4 + length])
            if obj["method"] == "quarantine.extract":
                self._pending_reply = _frame({"jsonrpc": "2.0", "result": "not-a-dict"})

    transport = QuarantineStdioTransport(
        child_io=_NonDictResultChild(), staging=staging, broker_auditor=_RecordingAuditor()
    )
    result = await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )
    assert result.payload == {}


def test_decode_result_payload_truncated_frame_raises_loud() -> None:
    """A reply frame too short to carry the length header fails LOUD, never empty.

    A malicious/buggy child (adversary-facing once 2b spawns the real subprocess)
    could send a truncated frame. The decode must NOT silently mis-parse it into an
    empty payload (which would let the laundering attempt slip past as a benign
    no-op) — stripping the 4-byte header off a sub-4-byte frame yields an empty
    body that ``json.loads`` rejects, so the failure propagates into the
    extractor's ``transport_failed`` audit (CLAUDE.md hard rule #7).
    """
    with pytest.raises(json.JSONDecodeError):
        _decode_result_payload(b"\x00\x01")  # 2 bytes — shorter than the 4-byte header


# ---------------------------------------------------------------------------
# 9: discard_staged — C9 drain-on-error, no orphaned T3 body (G7-2.5 Task 3)
# ---------------------------------------------------------------------------


def test_t3_body_recorder_discard_staged(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """``discard_staged`` removes a staged T3 body; subsequent drain raises; idempotent.

    Verifies three properties required by C9 (G7-2.5 Task 3):
    1. After staging a body via the recorder, ``discard_staged`` removes it so
       a follow-up ``staging.drain`` raises ``StagingHandleNotConfiguredError``
       (the staged entry is gone, not a silent no-op).
    2. A second call to ``discard_staged`` is a no-op — it does NOT raise even
       though the handle has already been drained/discarded.  This makes the
       ``except BaseException`` block in ``egress_response_extract.handle``
       safe to call unconditionally without checking first.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    handle = _make_handle()

    recorder(handle=handle, body="attack payload")

    # Confirm the body is staged before the discard.
    assert handle.id in staging._staged

    # Discard the staged body.
    recorder.discard_staged(handle.id)

    # After discard the staging map must be empty — the body cannot orphan.
    assert handle.id not in staging._staged

    # A subsequent drain must raise (the entry was removed, not silently zeroed).
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain(handle.id)

    # A second discard is a no-op — must not raise even though handle is gone.
    recorder.discard_staged(handle.id)


def test_staging_map_discard_is_silent_non_raising_no_op(
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``QuarantineStagingMap.discard`` removes a present handle and is a no-op
    (never raises) on an absent one — and, unlike ``drain``, it is NON-logging."""
    import alfred.security.quarantine_transport as qt

    warnings: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        qt._log,
        "warning",
        lambda *a, **k: warnings.append((a, k)),  # type: ignore[arg-type]
    )

    staging = QuarantineStagingMap()
    staging.stage("h1", _tag(authorized_t3_nonce, "body"))

    # Present handle → removed.
    staging.discard("h1")
    assert "h1" not in staging._staged
    # drain() on an absent handle raises AND logs — that's the loud/expected drain
    # contract, not what we're testing here.  Clear captured warnings before the
    # critical discard() assertion so drain's noise doesn't pollute it.
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("h1")
    warnings.clear()

    # Absent handle → silent no-op (no raise, no warning).
    staging.discard("never-staged")
    assert warnings == [], (
        "discard() on an absent handle must NOT emit "
        "security.quarantine_staging.handle_not_configured (NON-logging contract)"
    )


def test_discard_staged_on_drained_handle_emits_no_warning(
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C9 happy-path: ``discard_staged`` on an already-drained handle emits NO
    ``security.quarantine_staging.handle_not_configured`` warning and does not raise.

    The OutboundDlp extractor drains the staged body on the success path; C9's
    unconditional ``except BaseException`` cleanup then calls ``discard_staged`` on
    the already-gone handle. Routing that through the loud ``drain`` (old behaviour)
    logged a warning + would have raised — false security noise on a benign cleanup.
    ``discard`` is silent.
    """
    import alfred.security.quarantine_transport as qt

    warnings: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        qt._log,
        "warning",
        lambda *a, **k: warnings.append((a, k)),  # type: ignore[arg-type]
    )

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    handle = _make_handle()
    recorder(handle=handle, body="attack payload")

    # Simulate the success path: the extractor already drained the body.
    staging.drain(handle.id)
    assert warnings == [], "the happy-path drain itself must not warn"

    # C9 cleanup on the already-drained handle: silent + no raise.
    recorder.discard_staged(handle.id)
    assert warnings == [], (
        "discard_staged on an already-drained handle must NOT emit "
        "security.quarantine_staging.handle_not_configured (false security noise)"
    )
