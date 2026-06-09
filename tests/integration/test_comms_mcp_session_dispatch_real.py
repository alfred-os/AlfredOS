"""Session dispatch arm audit rows land in real Postgres (Tasks 53/54).

Drives the comms-wired :class:`AlfredPluginSession` (built via the enforcing
``for_comms_adapter`` factory) through a real :class:`AuditWriter` backed by a
Postgres testcontainer:

* an unknown notification method emits ``COMMS_UNKNOWN_NOTIFICATION_FIELDS`` and
  calls ``Supervisor.request_plugin_restart`` (Task 53 / Critical 6 — never a
  silent drop);
* three handler failures inside the 5-minute window emit
  ``COMMS_HANDLER_FAILED_FIELDS`` each, and the 3rd trips the breaker via
  ``Supervisor.trip_breaker`` (Task 54 / err-007).

The supervisor itself is a separate subsystem (own integration coverage); here a
recording stand-in captures the two calls the dispatch arm makes so the
end-to-end audit-row persistence + the supervisor hand-off are both asserted
against real DB writes. The capability gate is the real permissive FIXTURE gate
(CLAUDE.md hard rule #2 — never an always-allow shim).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.models import AuditEntry, Base
from alfred.plugins.session import AlfredPluginSession
from tests.helpers.gates import make_permissive_fixture_gate

pytestmark = pytest.mark.integration

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.comms-test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

_INBOUND_PARAMS: dict[str, Any] = {
    "adapter_id": "alfred_comms_test",
    "platform_user_id": "discord:123",
    "body": {"content": "hi"},
    "sub_payload_refs": [],
    "received_at": "2026-06-07T12:00:00Z",
    "addressing_signal": "dm",
}


class _RecordingSupervisor:
    """Captures the dispatch arm's supervisor hand-offs."""

    def __init__(self) -> None:
        self.restart_calls: list[dict[str, str]] = []
        self.trip_calls: list[dict[str, str]] = []

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None:
        self.restart_calls.append({"adapter_id": adapter_id, "reason": reason})

    async def trip_breaker(self, *, component_id: str, reason: str) -> None:
        self.trip_calls.append({"component_id": component_id, "reason": reason})


@asynccontextmanager
async def _audit_writer(postgres_url: str) -> AsyncIterator[tuple[AuditWriter, Any]]:
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        yield AuditWriter(session_factory=session_scope), sm
    finally:
        await engine.dispose()


async def _build_session(
    audit: AuditWriter, supervisor: _RecordingSupervisor, inbound_handler: Any
) -> AlfredPluginSession:
    return await AlfredPluginSession.for_comms_adapter(
        adapter_id="alfred_comms_test",
        manifest_raw=_MANIFEST,
        audit_writer=audit,
        gate=make_permissive_fixture_gate(),
        supervisor=supervisor,  # type: ignore[arg-type]
        inbound_handler=inbound_handler,
        binding_handler=_AsyncNoop(),
        rate_limit_handler=_AsyncNoop(),
        crash_handler=_AsyncNoop(),
    )


class _AsyncNoop:
    async def process(self, _notification: object) -> None:
        return None


class _FailingHandler:
    async def process(self, _notification: object) -> None:
        raise RuntimeError("deterministic handler failure")


async def _rows_with_event(sm: Any, event: str) -> list[AuditEntry]:
    async with sm() as session:
        result = await session.execute(select(AuditEntry).where(AuditEntry.event == event))
        return list(result.scalars().all())


async def test_unknown_notification_audits_and_requests_restart(postgres_url: str) -> None:
    async with _audit_writer(postgres_url) as (audit, sm):
        supervisor = _RecordingSupervisor()
        session = await _build_session(audit, supervisor, _AsyncNoop())

        await session._on_post_handshake_method(method="totally.unknown", params={"k": "v"})

        rows = await _rows_with_event(sm, "comms.unknown.notification")
        assert len(rows) == 1
        assert rows[0].subject["method"] == "totally.unknown"
        assert supervisor.restart_calls == [
            {"adapter_id": "alfred_comms_test", "reason": "unknown_notification"}
        ]


async def test_three_handler_failures_trip_breaker(postgres_url: str) -> None:
    async with _audit_writer(postgres_url) as (audit, sm):
        supervisor = _RecordingSupervisor()
        session = await _build_session(audit, supervisor, _FailingHandler())

        for _ in range(3):
            with pytest.raises(RuntimeError, match="deterministic handler failure"):
                await session._on_post_handshake_method(
                    method="inbound.message", params=_INBOUND_PARAMS
                )

        failed_rows = await _rows_with_event(sm, "comms.handler.failed")
        assert len(failed_rows) == 3
        # The 3rd failure tripped the breaker exactly once.
        assert supervisor.trip_calls == [
            {"component_id": "alfred_comms_test", "reason": "comms_handler_repeated_failures"}
        ]


async def test_two_handler_failures_do_not_trip(postgres_url: str) -> None:
    async with _audit_writer(postgres_url) as (audit, _sm):
        supervisor = _RecordingSupervisor()
        session = await _build_session(audit, supervisor, _FailingHandler())

        for _ in range(2):
            with pytest.raises(RuntimeError):
                await session._on_post_handshake_method(
                    method="inbound.message", params=_INBOUND_PARAMS
                )

        assert supervisor.trip_calls == []
