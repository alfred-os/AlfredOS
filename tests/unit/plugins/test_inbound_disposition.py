"""``InboundDisposition`` seam + ``SessionDispatchDisposition`` default (G6-7-2, #309).

The pump's per-notification routing is factored behind an injectable
:class:`alfred.plugins.inbound_disposition.InboundDisposition`. The DEFAULT
:class:`alfred.plugins.inbound_disposition.SessionDispatchDisposition` carries the
verbatim routing the runner used to inline (``_route_notification`` +
``_route_spawn_request``). These cases drive ``dispatch`` /
``_route_spawn_request`` DIRECTLY to cover every arm, then a seam test proves the
runner builds the default by identity and routes the pump through an injected spy.

The fakes mirror ``test_comms_runner.py`` / ``test_comms_runner_credential_route.py``
(recording session, fake resolver, sending transport) so the disposition's
behaviour is pinned identically to the pre-refactor runner.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import pytest
import structlog.testing
from sqlalchemy.exc import SQLAlchemyError

from alfred.comms_mcp.adapter_credential_protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    GATEWAY_ADAPTER_SPAWN_REQUEST,
    SpawnGrant,
    SpawnRequest,
)
from alfred.comms_mcp.adapter_credential_resolver import (
    AdapterCredentialAuditWriteError,
    AdapterCredentialError,
)
from alfred.comms_mcp.adapter_status_observer import AdapterStatusAuditWriteError
from alfred.comms_mcp.errors import ForwardedInboundAuditWriteError
from alfred.comms_mcp.handlers import BindingHandler, CrashHandler, RateLimitHandler
from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_INBOUND
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.inbound_disposition import (
    InboundDisposition,
    SessionDispatchDisposition,
)
from alfred.plugins.session import AlfredPluginSession
from tests.helpers.gates import make_permissive_fixture_gate

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "discord"
_EPOCH = "0123456789abcdef0123456789abcdef"
_REQ_ID = "11111111111111111111111111111111"
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


class _SendingTransport:
    """In-memory transport recording every ``send`` (mirrors the credential-route fake)."""

    def __init__(self) -> None:
        self.sent: list[Mapping[str, object]] = []

    async def spawn(self) -> None:  # pragma: no cover - unused
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:  # pragma: no cover
        return None

    async def close(self) -> None:  # pragma: no cover
        return None

    def enable_seq_ack(self) -> None:  # pragma: no cover
        return None


class _FakeResolver:
    """Records every resolved request; optionally raises a wired exception."""

    def __init__(self, *, raise_with: BaseException | None = None) -> None:
        self.requests: list[SpawnRequest] = []
        self._raise_with = raise_with

    async def resolve(self, request: SpawnRequest) -> SpawnGrant:
        self.requests.append(request)
        if self._raise_with is not None:
            raise self._raise_with
        return SpawnGrant(
            request_id=request.request_id,
            adapter_id=request.adapter_id,
            host_restart_seq=request.host_restart_seq,
            epoch=request.epoch,
            credential_material=_SENTINEL_CRED,
        )


def _request_params() -> dict[str, object]:
    return SpawnRequest(
        request_id=_REQ_ID, adapter_id=_ADAPTER_ID, host_restart_seq=0, epoch=_EPOCH
    ).model_dump()


def _disposition(
    *,
    session: Any,
    resolver: Any,
    send_notification: Any | None = None,
    request_restart: Any | None = None,
    forwarded_inbound_receiver: Any | None = None,
) -> SessionDispatchDisposition:
    return SessionDispatchDisposition(
        session=session,
        credential_resolver=resolver,
        adapter_id=_ADAPTER_ID,
        send_notification=send_notification or AsyncMock(),
        request_restart=request_restart or AsyncMock(),
        forwarded_inbound_receiver=forwarded_inbound_receiver,
    )


def _recording_session() -> MagicMock:
    session = MagicMock()
    session._on_post_handshake_method = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# (1) non-spawn notification -> the session arm runs with the right args
# ---------------------------------------------------------------------------


async def test_non_spawn_notification_routes_to_session_with_wire_seq() -> None:
    session = _recording_session()
    disposition = _disposition(session=session, resolver=None)

    result = await disposition.dispatch("inbound.message", {"adapter_id": _ADAPTER_ID}, wire_seq=7)

    assert result is None
    session._on_post_handshake_method.assert_awaited_once_with(
        "inbound.message", {"adapter_id": _ADAPTER_ID}, wire_seq=7
    )


# ---------------------------------------------------------------------------
# (2) spawn-request + resolver -> resolver called, grant sent
# ---------------------------------------------------------------------------


async def test_spawn_request_resolved_and_grant_sent() -> None:
    session = _recording_session()
    send = AsyncMock()
    resolver = _FakeResolver()
    disposition = _disposition(session=session, resolver=resolver, send_notification=send)

    result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert result is None
    assert len(resolver.requests) == 1
    send.assert_awaited_once()
    method, params = send.call_args.args
    assert method == CORE_ADAPTER_SPAWN_GRANT
    assert params["request_id"] == _REQ_ID
    assert params["credential_material"] == _SENTINEL_CRED
    # The session dispatch was intercepted (the credential request never reached it).
    session._on_post_handshake_method.assert_not_awaited()


# ---------------------------------------------------------------------------
# (3) malformed SpawnRequest -> loud drop, no grant, no raise
# ---------------------------------------------------------------------------


async def test_malformed_spawn_request_drops_loud_no_grant() -> None:
    session = _recording_session()
    send = AsyncMock()
    resolver = _FakeResolver()
    disposition = _disposition(session=session, resolver=resolver, send_notification=send)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, {"bogus": "x"})

    assert result is None
    assert resolver.requests == []
    send.assert_not_awaited()
    assert any(rec.get("event") == "comms.runner.spawn_request_malformed" for rec in log_records), (
        log_records
    )


# ---------------------------------------------------------------------------
# (4) AdapterCredentialError -> loud drop, no grant, no raise
# ---------------------------------------------------------------------------


async def test_credential_refusal_drops_loud_no_grant() -> None:
    session = _recording_session()
    send = AsyncMock()
    resolver = _FakeResolver(
        raise_with=AdapterCredentialError(adapter_id=_ADAPTER_ID, reason="missing_secret")
    )
    disposition = _disposition(session=session, resolver=resolver, send_notification=send)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert result is None
    assert len(resolver.requests) == 1
    send.assert_not_awaited()
    assert any(rec.get("event") == "comms.runner.spawn_request_refused" for rec in log_records), (
        log_records
    )


# ---------------------------------------------------------------------------
# (5) AdapterCredentialAuditWriteError -> escalates (restart requested), no grant
# ---------------------------------------------------------------------------


async def test_credential_audit_write_failure_escalates_restart() -> None:
    session = _recording_session()
    send = AsyncMock()
    restart = AsyncMock()
    resolver = _FakeResolver(
        raise_with=AdapterCredentialAuditWriteError("credential audit write failed")
    )
    disposition = _disposition(
        session=session, resolver=resolver, send_notification=send, request_restart=restart
    )

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert result is None
    send.assert_not_awaited()
    restart.assert_awaited_once_with(reason="credential_audit_unwritable")
    assert any(
        rec.get("event") == "comms.runner.credential_audit_unwritable"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (6) (5) + the restart request itself raises -> logged second loud row, no raise
# ---------------------------------------------------------------------------


async def test_credential_audit_restart_request_failure_stays_loud() -> None:
    session = _recording_session()
    restart = AsyncMock(side_effect=RuntimeError("restart bus down"))
    resolver = _FakeResolver(
        raise_with=AdapterCredentialAuditWriteError("credential audit write failed")
    )
    disposition = _disposition(session=session, resolver=resolver, request_restart=restart)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert result is None
    events = {rec.get("event") for rec in log_records}
    assert "comms.runner.credential_audit_unwritable" in events
    assert any(
        rec.get("event") == "comms.runner.credential_audit_restart_request_failed"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (7) grant send-fault (OSError / CommsProtocolError) -> loud drop, no raise
# ---------------------------------------------------------------------------


async def test_grant_send_fault_drops_loud_no_leak() -> None:
    session = _recording_session()
    send = AsyncMock(side_effect=BrokenPipeError("peer gone"))
    resolver = _FakeResolver()
    disposition = _disposition(session=session, resolver=resolver, send_notification=send)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert result is None
    assert len(resolver.requests) == 1  # the resolver resolved; the SEND failed
    assert any(rec.get("event") == "comms.runner.spawn_grant_send_failed" for rec in log_records), (
        log_records
    )
    assert _SENTINEL_CRED not in repr(log_records)


# ---------------------------------------------------------------------------
# (8) AdapterStatusAuditWriteError from the session arm -> restart requested
# ---------------------------------------------------------------------------


async def test_status_audit_write_failure_escalates_restart() -> None:
    session = _recording_session()
    session._on_post_handshake_method = AsyncMock(
        side_effect=AdapterStatusAuditWriteError("status audit write failed")
    )
    restart = AsyncMock()
    disposition = _disposition(session=session, resolver=None, request_restart=restart)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(
            "gateway.adapter.up", {"adapter_id": _ADAPTER_ID, "epoch": "a" * 32}
        )

    assert result is None
    restart.assert_awaited_once_with(reason="status_audit_unwritable")
    assert any(
        rec.get("event") == "comms.runner.status_audit_unwritable"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (9) (8) + the restart request raises -> logged second loud row, no raise
# ---------------------------------------------------------------------------


async def test_status_audit_restart_request_failure_stays_loud() -> None:
    session = _recording_session()
    session._on_post_handshake_method = AsyncMock(
        side_effect=AdapterStatusAuditWriteError("status audit write failed")
    )
    restart = AsyncMock(side_effect=RuntimeError("restart bus down"))
    disposition = _disposition(session=session, resolver=None, request_restart=restart)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(
            "gateway.adapter.up", {"adapter_id": _ADAPTER_ID, "epoch": "a" * 32}
        )

    assert result is None
    events = {rec.get("event") for rec in log_records}
    assert "comms.runner.status_audit_unwritable" in events
    assert any(
        rec.get("event") == "comms.runner.status_audit_restart_request_failed"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (10) blanket Exception from the session arm -> swallowed, no raise
# ---------------------------------------------------------------------------


async def test_handler_exception_swallowed_and_continues() -> None:
    session = _recording_session()
    session._on_post_handshake_method = AsyncMock(side_effect=RuntimeError("handler boom"))
    disposition = _disposition(session=session, resolver=None)

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch("inbound.message", {"adapter_id": _ADAPTER_ID})

    assert result is None
    assert any(
        rec.get("event") == "comms.runner.handler_failed_continuing" for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (11) spawn-request method but resolver is None -> falls through to the session
# ---------------------------------------------------------------------------


async def test_spawn_request_without_resolver_falls_through_to_session() -> None:
    session = _recording_session()
    send = AsyncMock()
    disposition = _disposition(session=session, resolver=None, send_notification=send)

    result = await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert result is None
    send.assert_not_awaited()
    # Not intercepted: the session dispatch WAS invoked (fall-through).
    session._on_post_handshake_method.assert_awaited_once()


async def test_route_spawn_request_called_directly_resolves_and_sends() -> None:
    # Direct ``_route_spawn_request`` call covers the method without going through
    # ``dispatch``'s method gate.
    session = _recording_session()
    send = AsyncMock()
    resolver = _FakeResolver()
    disposition = _disposition(session=session, resolver=resolver, send_notification=send)

    result = await disposition._route_spawn_request(_request_params())

    assert result is None
    send.assert_awaited_once()


# ---------------------------------------------------------------------------
# (12) the default disposition satisfies the runtime-checkable Protocol
# ---------------------------------------------------------------------------


async def test_session_dispatch_disposition_is_an_inbound_disposition() -> None:
    session = _recording_session()
    disposition = _disposition(session=session, resolver=None)
    assert isinstance(disposition, InboundDisposition)


async def test_audit_write_failure_with_sqlalchemy_error_escalates_no_leak() -> None:
    # The FULL resolver (not a fake) wraps a raw SQLAlchemyError into the typed marker;
    # the disposition recognises it and escalates without leaking the credential.
    from datetime import UTC, datetime

    from alfred.comms_mcp.adapter_credential_resolver import CoreAdapterCredentialResolver

    class _Broker:
        def get(self, name: str) -> str:
            return _SENTINEL_CRED

    class _FailingAudit:
        async def append_schema(self, **kwargs: object) -> None:
            raise SQLAlchemyError("db down")

    session = _recording_session()
    send = AsyncMock()
    restart = AsyncMock()
    resolver = CoreAdapterCredentialResolver(
        broker=_Broker(),  # type: ignore[arg-type]
        audit=_FailingAudit(),  # type: ignore[arg-type]
        now=lambda: datetime.now(UTC),
    )
    disposition = _disposition(
        session=session, resolver=resolver, send_notification=send, request_restart=restart
    )

    with structlog.testing.capture_logs() as log_records:
        await disposition.dispatch(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    restart.assert_awaited_once()
    send.assert_not_awaited()
    assert _SENTINEL_CRED not in repr(log_records)


# ---------------------------------------------------------------------------
# (13) gateway.adapter.inbound + receiver -> receiver.receive, session NOT called
# ---------------------------------------------------------------------------


class _FakeForwardedReceiver:
    """Records every ``receive(params, wire_seq)``; optionally raises a wired exc."""

    def __init__(self, *, raise_with: BaseException | None = None) -> None:
        self.calls: list[tuple[object, int | None]] = []
        self._raise_with = raise_with

    async def receive(self, *, params: object, wire_seq: int | None) -> None:
        self.calls.append((params, wire_seq))
        if self._raise_with is not None:
            raise self._raise_with

    def set_ack_tracker(self, ack_tracker: object) -> None:  # pragma: no cover - unused
        return None


async def test_forwarded_inbound_routes_to_receiver_not_session() -> None:
    session = _recording_session()
    receiver = _FakeForwardedReceiver()
    disposition = _disposition(session=session, resolver=None, forwarded_inbound_receiver=receiver)
    params = {"adapter_id": _ADAPTER_ID, "body": b"opaque-t3"}

    result = await disposition.dispatch(GATEWAY_ADAPTER_INBOUND, params, wire_seq=7)

    assert result is None
    assert receiver.calls == [(params, 7)]
    # Intercepted before the session: the gateway.adapter.* prefix never reached the
    # AdapterStatusObserver unknown_method refusal.
    session._on_post_handshake_method.assert_not_awaited()


# ---------------------------------------------------------------------------
# (14) gateway.adapter.inbound + NO receiver -> falls through to the session
# ---------------------------------------------------------------------------


async def test_forwarded_inbound_without_receiver_falls_through_to_session() -> None:
    # A daemon-spawned stdio leg (or a session lacking the gateway role) has no
    # receiver: the frame is NOT silently special-cased away — it falls through to
    # the session, which (on a comms session) hits the gateway.adapter.* prefix ->
    # AdapterStatusObserver unknown_method LOUD refusal (fail-closed).
    session = _recording_session()
    disposition = _disposition(session=session, resolver=None)
    params = {"adapter_id": _ADAPTER_ID, "body": b"opaque-t3"}

    result = await disposition.dispatch(GATEWAY_ADAPTER_INBOUND, params, wire_seq=7)

    assert result is None
    session._on_post_handshake_method.assert_awaited_once_with(
        GATEWAY_ADAPTER_INBOUND, params, wire_seq=7
    )


# ---------------------------------------------------------------------------
# (15) receiver audit-write failure (SQLAlchemyError) -> LOUD escalation, no swallow
# ---------------------------------------------------------------------------


async def test_forwarded_inbound_audit_write_failure_escalates_restart() -> None:
    session = _recording_session()
    restart = AsyncMock()
    receiver = _FakeForwardedReceiver(
        raise_with=ForwardedInboundAuditWriteError("forwarded audit write failed")
    )
    disposition = _disposition(
        session=session,
        resolver=None,
        request_restart=restart,
        forwarded_inbound_receiver=receiver,
    )

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(
            GATEWAY_ADAPTER_INBOUND,
            {"adapter_id": _ADAPTER_ID, "body": b"opaque-t3"},
            wire_seq=7,
        )

    assert result is None
    restart.assert_awaited_once_with(reason="forwarded_inbound_audit_unwritable")
    # The non-skippable failed-audit-write is LOUD (error), NEVER downgraded to the
    # blanket catch-and-continue warning.
    assert any(
        rec.get("event") == "comms.runner.forwarded_inbound_audit_unwritable"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records
    assert not any(
        rec.get("event") == "comms.runner.handler_failed_continuing" for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (16) (15) + the restart request itself raises -> logged second loud row, no raise
# ---------------------------------------------------------------------------


async def test_forwarded_inbound_audit_restart_request_failure_stays_loud() -> None:
    session = _recording_session()
    restart = AsyncMock(side_effect=RuntimeError("restart bus down"))
    receiver = _FakeForwardedReceiver(
        raise_with=ForwardedInboundAuditWriteError("forwarded audit write failed")
    )
    disposition = _disposition(
        session=session,
        resolver=None,
        request_restart=restart,
        forwarded_inbound_receiver=receiver,
    )

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(
            GATEWAY_ADAPTER_INBOUND,
            {"adapter_id": _ADAPTER_ID, "body": b"opaque-t3"},
            wire_seq=7,
        )

    assert result is None
    events = {rec.get("event") for rec in log_records}
    assert "comms.runner.forwarded_inbound_audit_unwritable" in events
    assert any(
        rec.get("event") == "comms.runner.forwarded_inbound_audit_restart_request_failed"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (17) receiver ordinary fault -> blanket catch-and-continue (NOT the loud arm)
# ---------------------------------------------------------------------------


async def test_forwarded_inbound_ordinary_fault_is_caught_and_continues() -> None:
    session = _recording_session()
    restart = AsyncMock()
    receiver = _FakeForwardedReceiver(raise_with=RuntimeError("dispatch boom"))
    disposition = _disposition(
        session=session,
        resolver=None,
        request_restart=restart,
        forwarded_inbound_receiver=receiver,
    )

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(
            GATEWAY_ADAPTER_INBOUND,
            {"adapter_id": _ADAPTER_ID, "body": b"opaque-t3"},
            wire_seq=7,
        )

    assert result is None
    # An ordinary (non-audit-write) fault from the receive is NOT a non-skippable
    # security event: it falls to the blanket catch-and-continue, no restart.
    restart.assert_not_awaited()
    assert any(
        rec.get("event") == "comms.runner.handler_failed_continuing" for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# (18) receiver RAW SQLAlchemyError (non-audit DB fault) -> catch-and-continue, NO restart
# ---------------------------------------------------------------------------


async def test_forwarded_inbound_raw_sqlalchemy_error_replays_no_restart() -> None:
    """A raw ``SQLAlchemyError`` from the receiver is a leg-replay fault, NOT a restart.

    The plan-review defect: on the forwarded path a raw ``SQLAlchemyError`` also comes
    from NON-audit sources (``has_committed`` / ``commit_once`` / ``orchestrator.dispatch``)
    whose designed recovery is leg replay (catch-and-continue, ADR-0039 item 4), not the
    audit-unwritable RESTART escalation. Only a signed-audit-write failure — wrapped in
    the typed ``ForwardedInboundAuditWriteError`` marker AT THE WRITE SITE — escalates.
    A raw ``SQLAlchemyError`` therefore falls to the blanket catch-and-continue: NO
    restart (no restart-storm risk on a transient DB blip), and it is NOT mislabelled
    "audit_unwritable".
    """
    session = _recording_session()
    restart = AsyncMock()
    receiver = _FakeForwardedReceiver(raise_with=SQLAlchemyError("transient db blip"))
    disposition = _disposition(
        session=session,
        resolver=None,
        request_restart=restart,
        forwarded_inbound_receiver=receiver,
    )

    with structlog.testing.capture_logs() as log_records:
        result = await disposition.dispatch(
            GATEWAY_ADAPTER_INBOUND,
            {"adapter_id": _ADAPTER_ID, "body": b"opaque-t3"},
            wire_seq=7,
        )

    assert result is None
    # A raw SQLAlchemyError is the leg-replay recovery, NOT the loud restart escalation.
    restart.assert_not_awaited()
    assert any(
        rec.get("event") == "comms.runner.handler_failed_continuing" for rec in log_records
    ), log_records
    # And it is NEVER mislabelled as the audit-unwritable security event.
    assert not any(
        rec.get("event") == "comms.runner.forwarded_inbound_audit_unwritable" for rec in log_records
    ), log_records


# ---------------------------------------------------------------------------
# Seam: the runner builds the default by identity and routes the pump through it
# ---------------------------------------------------------------------------

_RUNNER_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

_RUNNER_ADAPTER_ID = "alfred_comms_test"

_HANDSHAKE_OK: Mapping[str, object] = {
    "jsonrpc": "2.0",
    "id": 0,
    "result": {"ok": True, "plugin_version": "0.1.0"},
}


class _RunnerFakeTransport:
    """A scripted in-memory transport (mirrors test_comms_runner's _FakeTransport)."""

    def __init__(self, inbound: list[Any]) -> None:
        self._inbound = inbound
        self.sent: list[Mapping[str, object]] = []
        self.spawned = False
        self.closed = False

    async def spawn(self) -> None:
        self.spawned = True

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:
        if not self._inbound:
            return None
        item = self._inbound.pop(0)
        if callable(item):
            return item()  # type: ignore[no-any-return]
        return item

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:  # pragma: no cover - no seq_ack echo here
        return None


class _RecordingHandler:
    def __init__(self) -> None:
        self.processed: list[object] = []

    async def process(self, notification: object) -> None:
        self.processed.append(notification)


def _audit() -> MagicMock:
    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer


async def _make_runner_session(transport: Any, inbound_handler: Any) -> AlfredPluginSession:
    return await AlfredPluginSession.for_comms_adapter(
        adapter_id=_RUNNER_ADAPTER_ID,
        manifest_raw=_RUNNER_MANIFEST,
        audit_writer=_audit(),
        gate=make_permissive_fixture_gate(),
        supervisor=MagicMock(),
        inbound_handler=inbound_handler,
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
        transport=transport,  # type: ignore[arg-type]
    )


def _inbound_frame() -> Mapping[str, object]:
    return {
        "jsonrpc": "2.0",
        "method": "inbound.message",
        "params": {
            "adapter_id": _RUNNER_ADAPTER_ID,
            "inbound_id": "frame-disposition-1",
            "platform_user_id": "discord:42",
            "body": {"content": "hello"},
            "sub_payload_refs": [],
            "received_at": "2026-06-10T00:00:00+00:00",
            "addressing_signal": "dm",
        },
    }


async def test_runner_builds_default_session_dispatch_disposition() -> None:
    transport = _RunnerFakeTransport([])
    inbound_handler = _RecordingHandler()
    session = await _make_runner_session(transport, inbound_handler)
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_RUNNER_ADAPTER_ID)

    assert isinstance(runner._inbound_disposition, SessionDispatchDisposition)


class _SpyDisposition:
    """Records the (method, params, wire_seq) of every dispatched notification."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object, int | None]] = []

    async def dispatch(self, method: str, params: object, *, wire_seq: int | None = None) -> None:
        self.calls.append((method, params, wire_seq))


async def test_injected_disposition_receives_pump_notification() -> None:
    transport = _RunnerFakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    inbound_handler = _RecordingHandler()
    session = await _make_runner_session(transport, inbound_handler)
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    spy = _SpyDisposition()
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_RUNNER_ADAPTER_ID,
        inbound_disposition=spy,
    )

    await runner.run()

    # The notification routed to the SPY, not the session's post-handshake recorder.
    assert len(spy.calls) == 1
    method, params, wire_seq = spy.calls[0]
    assert method == "inbound.message"
    assert isinstance(params, Mapping)
    assert wire_seq is None
    assert inbound_handler.processed == []
    assert transport.closed is True


class _RaisingDisposition:
    """A disposition that BREAKS the never-raise contract on every dispatch."""

    async def dispatch(self, method: str, params: object, *, wire_seq: int | None = None) -> None:
        raise RuntimeError("contract violation")


async def test_injected_disposition_contract_violation_is_loud_not_silent() -> None:
    """A disposition that violates the never-raise contract is caught + audited loud.

    ``_route_notification`` is now a bare ``await self._inbound_disposition.dispatch(...)``
    on an INJECTABLE seam. The default ``SessionDispatchDisposition`` provably never
    raises, but a future G6-7-3 forward-runner disposition that breaks the contract
    would otherwise leak its exception into the fire-and-forget dispatch task as a
    GC-time "Task exception was never retrieved" warning — a SILENT failure at this
    I/O boundary (CLAUDE.md hard rule #7). The runner's backstop turns it into a LOUD
    audited row and lets the pump SURVIVE.
    """
    transport = _RunnerFakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    inbound_handler = _RecordingHandler()
    session = await _make_runner_session(transport, inbound_handler)
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_RUNNER_ADAPTER_ID,
        inbound_disposition=_RaisingDisposition(),
    )

    # Track every fire-and-forget task the pump spawns so we can assert NONE retained
    # an unretrieved exception (mirrors test_comms_runner's no-leak pattern).
    spawned: list[asyncio.Task[object]] = []
    real_ensure_future = asyncio.ensure_future

    def _tracking_ensure_future(coro: Any, **kwargs: Any) -> asyncio.Task[object]:
        task = real_ensure_future(coro, **kwargs)
        spawned.append(task)
        return task

    with (
        mock.patch.object(asyncio, "ensure_future", _tracking_ensure_future),
        structlog.testing.capture_logs() as log_records,
    ):
        # The pump must SURVIVE the contract violation: run() completes, no raise.
        await runner.run()

    # (b) the contract violation was audited LOUD with adapter_id + notification_method.
    assert any(
        rec.get("event") == "comms.runner.disposition_contract_violation"
        and rec.get("log_level") == "error"
        and rec.get("adapter_id") == _RUNNER_ADAPTER_ID
        and rec.get("notification_method") == "inbound.message"
        for rec in log_records
    ), log_records

    # (c) the dispatch task(s) completed WITHOUT a leaked, unretrieved exception:
    # the backstop swallowed-and-audited rather than re-raising, so no task carries
    # an exception that would warn at GC time.
    dispatch_tasks = [t for t in spawned if t.done() and not t.cancelled()]
    assert dispatch_tasks, "expected at least one fire-and-forget dispatch task"
    for task in dispatch_tasks:
        assert task.exception() is None, task

    # (a) the pump survived to clean EOF and tore the transport down.
    assert transport.closed is True
