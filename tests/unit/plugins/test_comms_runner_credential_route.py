"""Runner-side credential request/response routing (G6-3 Task 6, #288).

The daemon (HOST runner) receives ``gateway.adapter.spawn_request`` on the leg and
must RESPOND with ``core.adapter.spawn_grant`` — the credential round-trip's core
half. The runner owns ``send_notification`` + the transport (the session does not),
so the resolver routing lives in :meth:`CommsPluginRunner._route_notification`,
intercepted BEFORE the session dispatch (a ``gateway.adapter.*`` method would
otherwise hit the status observer's ``unknown_method`` refusal).

* a valid request -> ``resolver.resolve`` -> a ``core.adapter.spawn_grant`` frame on
  the transport (echoing the request's correlation keys);
* a malformed request -> loud drop, NO grant frame (fail-closed);
* a refusal (``AdapterCredentialError``) -> loud drop, NO grant frame (the resolver
  already audited the refusal — the gateway's bounded await times out fail-closed).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
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
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_stdio_transport import CommsProtocolError

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "discord"
_EPOCH = "0123456789abcdef0123456789abcdef"
_REQ_ID = "11111111111111111111111111111111"
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


class _SendingTransport:
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


def _runner(transport: Any, resolver: Any, *, supervisor: Any | None = None) -> CommsPluginRunner:
    session = MagicMock()
    session._on_post_handshake_method = AsyncMock()
    # ``_request_restart`` reads ``session._supervisor`` — give it an AsyncMock
    # ``request_plugin_restart`` so the escalation arm's restart request is awaitable +
    # assertable (the SEC-1 / ERR-G63-01 escalation pattern).
    if supervisor is None:
        supervisor = MagicMock()
        supervisor.request_plugin_restart = AsyncMock()
    session._supervisor = supervisor
    return CommsPluginRunner(
        session=session,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        credential_resolver=resolver,
    )


def _request_params() -> dict[str, object]:
    return SpawnRequest(
        request_id=_REQ_ID, adapter_id=_ADAPTER_ID, host_restart_seq=0, epoch=_EPOCH
    ).model_dump()


async def test_spawn_request_is_resolved_and_grant_sent_back() -> None:
    transport = _SendingTransport()
    resolver = _FakeResolver()
    runner = _runner(transport, resolver)

    await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    # The resolver saw the request; a grant frame went back on the transport.
    assert len(resolver.requests) == 1
    grants = [f for f in transport.sent if f.get("method") == CORE_ADAPTER_SPAWN_GRANT]
    assert len(grants) == 1
    grant_params = grants[0]["params"]
    assert isinstance(grant_params, dict)
    assert grant_params["request_id"] == _REQ_ID
    assert grant_params["credential_material"] == _SENTINEL_CRED
    # The session dispatch was NOT invoked for the credential request (intercepted).
    runner._session._on_post_handshake_method.assert_not_awaited()


async def test_malformed_spawn_request_is_dropped_no_grant() -> None:
    transport = _SendingTransport()
    resolver = _FakeResolver()
    runner = _runner(transport, resolver)

    await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, {"bogus": "x"})

    assert resolver.requests == []  # never reached the resolver
    assert [f for f in transport.sent if f.get("method") == CORE_ADAPTER_SPAWN_GRANT] == []


async def test_refused_spawn_request_sends_no_grant() -> None:
    transport = _SendingTransport()
    resolver = _FakeResolver(
        raise_with=AdapterCredentialError(adapter_id=_ADAPTER_ID, reason="missing_secret")
    )
    runner = _runner(transport, resolver)

    # The runner must NOT crash on a refusal (it runs fire-and-forget) and must send
    # NO grant frame — the resolver already audited; the gateway's bounded await
    # times out fail-closed.
    await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert len(resolver.requests) == 1
    assert [f for f in transport.sent if f.get("method") == CORE_ADAPTER_SPAWN_GRANT] == []


async def test_credential_never_logged_when_grant_sent() -> None:
    transport = _SendingTransport()
    resolver = _FakeResolver()
    runner = _runner(transport, resolver)

    # Use ``structlog.testing.capture_logs`` for parity with the other sentinel sweeps
    # (the runner logs through structlog, not stdlib logging).
    with structlog.testing.capture_logs() as log_records:
        await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert _SENTINEL_CRED not in repr(log_records)


async def test_no_resolver_wired_falls_through_to_session() -> None:
    # Defensive: with NO resolver wired, a spawn_request is NOT intercepted — it falls
    # through to the session (which routes it to the status observer's refusal). The
    # runner must not crash.
    transport = _SendingTransport()
    runner = _runner(transport, resolver=None)

    await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    # No grant sent; the session dispatch WAS invoked (fall-through).
    assert [f for f in transport.sent if f.get("method") == CORE_ADAPTER_SPAWN_GRANT] == []
    runner._session._on_post_handshake_method.assert_awaited_once()


# --- Fix 1 (ERR-G63-01): a failed signed-audit write ESCALATES, not swallowed -----


async def test_credential_audit_write_failure_escalates_loud_not_swallowed() -> None:
    """ERR-G63-01 (#288): a failed signed-audit write on the credential-grant path is
    a non-skippable security event — it must ESCALATE (a ``log.error`` row + a restart
    request), NOT vanish into the fire-and-forget dispatch task as a GC-time warning.

    The resolver raises the DISTINCT ``AdapterCredentialAuditWriteError`` when its
    ``append_schema`` fails (e.g. a ``SQLAlchemyError``). The runner's
    ``_route_spawn_request`` recognises it and runs the SAME SEC-1 escalation arm the
    status path uses — it must NOT fall through to a silent loud-drop and it must send
    NO grant.
    """
    supervisor = MagicMock()
    supervisor.request_plugin_restart = AsyncMock()
    transport = _SendingTransport()
    resolver = _FakeResolver(
        raise_with=AdapterCredentialAuditWriteError("credential audit write failed")
    )
    runner = _runner(transport, resolver, supervisor=supervisor)

    with structlog.testing.capture_logs() as log_records:
        # The escalation IS the teardown — the fire-and-forget body returns normally.
        await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    # A loud log.error row was emitted...
    assert any(
        rec.get("event") == "comms.runner.credential_audit_unwritable"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records
    # ...AND a restart was requested with the closed-vocab reason.
    supervisor.request_plugin_restart.assert_awaited_once()
    _, kwargs = supervisor.request_plugin_restart.call_args
    assert kwargs["reason"] == "credential_audit_unwritable"
    assert kwargs["adapter_id"] == _ADAPTER_ID
    # NO grant frame left the gateway (the audit of the release failed).
    assert [f for f in transport.sent if f.get("method") == CORE_ADAPTER_SPAWN_GRANT] == []


async def test_credential_audit_write_failure_with_sqlalchemy_error_escalates() -> None:
    """A raw ``SQLAlchemyError`` from the resolver's real ``append_schema`` must reach
    the runner as the typed marker (the resolver wraps it) → the runner escalates.

    This drives the FULL resolver (not a fake) so the wrap-at-the-resolver +
    escalate-at-the-runner contract is exercised end-to-end on the core leg.
    """
    from datetime import UTC, datetime

    from alfred.comms_mcp.adapter_credential_resolver import CoreAdapterCredentialResolver

    class _Broker:
        def get(self, name: str) -> str:
            return _SENTINEL_CRED

    class _FailingAudit:
        async def append_schema(self, **kwargs: object) -> None:
            raise SQLAlchemyError("db down")

    supervisor = MagicMock()
    supervisor.request_plugin_restart = AsyncMock()
    transport = _SendingTransport()
    resolver = CoreAdapterCredentialResolver(
        broker=_Broker(),  # type: ignore[arg-type]
        audit=_FailingAudit(),  # type: ignore[arg-type]
        now=lambda: datetime.now(UTC),
    )
    runner = _runner(transport, resolver, supervisor=supervisor)

    with structlog.testing.capture_logs() as log_records:
        await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    supervisor.request_plugin_restart.assert_awaited_once()
    assert [f for f in transport.sent if f.get("method") == CORE_ADAPTER_SPAWN_GRANT] == []
    # The credential never leaked into any escalation log.
    assert _SENTINEL_CRED not in repr(log_records)


async def test_credential_audit_restart_request_failure_stays_loud_no_leak() -> None:
    """If the ERR-G63-01 restart REQUEST itself raises, stay loud + don't propagate.

    The audit-write failure is already escalated loudly. A failing restart request
    logs a SECOND loud row and returns (the body is fire-and-forget; propagating would
    only leak an unretrieved-task-exception warning).
    """
    supervisor = MagicMock()
    supervisor.request_plugin_restart = AsyncMock(side_effect=RuntimeError("restart bus down"))
    transport = _SendingTransport()
    resolver = _FakeResolver(
        raise_with=AdapterCredentialAuditWriteError("credential audit write failed")
    )
    runner = _runner(transport, resolver, supervisor=supervisor)

    with structlog.testing.capture_logs() as log_records:
        # Must NOT raise even though the restart request raises.
        await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    events = {rec.get("event") for rec in log_records}
    assert "comms.runner.credential_audit_unwritable" in events
    assert "comms.runner.credential_audit_restart_request_failed" in events
    assert any(
        rec.get("event") == "comms.runner.credential_audit_restart_request_failed"
        and rec.get("log_level") == "error"
        for rec in log_records
    ), log_records


# --- Fix 3 (HIGH): a send fault after a valid grant is a loud drop, no leak --------


async def test_grant_send_fault_is_loud_drop_no_crash_no_leak() -> None:
    """The credential-grant send-fault loud-drop (comms_runner.py ~899-902).

    A transport whose ``send`` raises AFTER a valid grant is resolved must NOT crash
    the fire-and-forget body, must leave NO grant frame on the wire, and must NEVER log
    the credential — only the routing id. This is the previously-uncovered arm that
    held ``comms_runner.py`` at 99% (the required plugins 100% gate).
    """

    class _FaultingTransport:
        def __init__(self) -> None:
            self.sent: list[Mapping[str, object]] = []

        async def spawn(self) -> None:  # pragma: no cover - unused
            return None

        async def send(self, frame: Mapping[str, object]) -> None:
            # A broken pipe on a gapped leg (a known transport-fault-family error).
            raise BrokenPipeError("peer gone")

        async def read_frame(self) -> Mapping[str, object] | None:  # pragma: no cover
            return None

        async def close(self) -> None:  # pragma: no cover
            return None

        def enable_seq_ack(self) -> None:  # pragma: no cover
            return None

    transport = _FaultingTransport()
    resolver = _FakeResolver()
    runner = _runner(transport, resolver)

    with structlog.testing.capture_logs() as log_records:
        # No crash even though the grant send raises.
        await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    # The resolver DID resolve a grant (it was the SEND that failed)...
    assert len(resolver.requests) == 1
    # ...but nothing landed on the wire, and a loud-drop row was emitted with the
    # routing id only — never the credential.
    assert any(rec.get("event") == "comms.runner.spawn_grant_send_failed" for rec in log_records), (
        log_records
    )
    assert _SENTINEL_CRED not in repr(log_records)


async def test_grant_send_fault_protocol_error_is_loud_drop() -> None:
    """A ``CommsProtocolError`` (reframe-ceiling) on the grant send is also a loud drop
    in the narrowed transport-fault family — no crash, no grant, no leak."""

    class _ProtocolFaultTransport(_SendingTransport):
        async def send(self, frame: Mapping[str, object]) -> None:
            raise CommsProtocolError("reframe ceiling exceeded")

    transport = _ProtocolFaultTransport()
    resolver = _FakeResolver()
    runner = _runner(transport, resolver)

    with structlog.testing.capture_logs() as log_records:
        await runner._route_notification(GATEWAY_ADAPTER_SPAWN_REQUEST, _request_params())

    assert any(rec.get("event") == "comms.runner.spawn_grant_send_failed" for rec in log_records), (
        log_records
    )
    assert _SENTINEL_CRED not in repr(log_records)
