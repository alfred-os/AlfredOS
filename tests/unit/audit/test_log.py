"""Tests for the slice 1 audit log writer.

The writer takes a ``session_factory`` (async context manager factory) and
owns its own transaction inside ``.append()``. The fixtures here build a
factory that yields a single shared session-mock so the assertions can
inspect what was added/flushed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit import audit_row_schemas
from alfred.audit.log import AuditWriter


def _mock_session() -> AsyncMock:
    """AsyncMock with `add` as a sync MagicMock to match SQLAlchemy's API.

    `AsyncSession.add` is sync; only `flush`/`commit`/`execute` are async.
    Without this, `AsyncMock` would coerce `add` to async and emit a
    RuntimeWarning about an un-awaited coroutine.
    """
    session = AsyncMock()
    session.add = MagicMock()
    return session


def _factory_for(session: AsyncMock):  # type: ignore[no-untyped-def]
    """Wrap a single session-mock in an async-context-manager factory.

    Mirrors the shape of ``alfred.memory.db.build_session_scope``'s output:
    a zero-arg callable returning an async context manager that yields the
    session.
    """

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncMock]:
        yield session

    return _scope


@pytest.mark.asyncio
class TestAuditWriter:
    async def test_append_persists_required_fields(self) -> None:
        session = _mock_session()
        writer = AuditWriter(session_factory=_factory_for(session))
        await writer.append(
            event="provider.call",
            actor_user_id="operator",
            subject={"provider": "deepseek", "model": "deepseek-chat"},
            trust_tier_of_trigger="T2",
            result="success",
            cost_estimate_usd=0.0001,
            trace_id="abc-123",
        )
        assert session.add.call_count == 1
        added = session.add.call_args[0][0]
        assert added.event == "provider.call"
        assert added.subject["provider"] == "deepseek"
        assert added.result == "success"
        assert added.trust_tier_of_trigger == "T2"
        session.flush.assert_awaited_once()

    async def test_append_raises_on_persistence_failure(self) -> None:
        session = _mock_session()
        session.flush.side_effect = RuntimeError("db down")
        writer = AuditWriter(session_factory=_factory_for(session))
        with pytest.raises(RuntimeError, match="db down"):
            await writer.append(
                event="provider.call",
                actor_user_id="operator",
                subject={},
                trust_tier_of_trigger="T2",
                result="success",
                cost_estimate_usd=0.0,
                trace_id="abc",
            )


# --- append_schema helper (Cluster 4, rvw-001) ---


def _make_writer() -> tuple[AuditWriter, AsyncMock]:
    """Return (writer, session_mock) for testing."""
    session_mock = AsyncMock()
    session_mock.add = MagicMock()
    session_mock.flush = AsyncMock()
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=session_mock)
    cm.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=cm)
    return AuditWriter(session_factory=factory), session_mock


@pytest.mark.asyncio
async def test_append_schema_accepts_fields_kwarg() -> None:
    """append_schema() forwards all required append() kwargs plus field set."""
    writer, session_mock = _make_writer()
    await writer.append_schema(
        fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
        event="plugin.lifecycle.loaded",
        actor_user_id=None,
        subject={
            "plugin_id": "alfred-web-fetch",
            "manifest_subscriber_tier": "system",
            "manifest_version": 1,
            "sandbox_profile": "unsandboxed",
            "exit_code": None,
            "signal": None,
            "restart_count": 0,
            "breaker_state": "CLOSED",
            "correlation_id": "trace-abc",
        },
        trust_tier_of_trigger="T0",
        result="loaded",
        cost_estimate_usd=0.0,
        trace_id="trace-abc",
    )
    assert session_mock.add.called


@pytest.mark.asyncio
async def test_append_schema_rejects_subject_missing_field() -> None:
    """append_schema() raises ValueError when subject dict is missing a declared field."""
    writer, _ = _make_writer()
    with pytest.raises(ValueError, match="missing required fields"):
        await writer.append_schema(
            fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
            event="plugin.lifecycle.loaded",
            actor_user_id=None,
            subject={"plugin_id": "alfred-web-fetch"},  # missing all other fields
            trust_tier_of_trigger="T0",
            result="loaded",
            cost_estimate_usd=0.0,
            trace_id="trace-abc",
        )


def test_all_audit_row_schema_fields_live_in_known_subject_space() -> None:
    """Every field name in every constant is a non-empty string with no whitespace.

    This is the AuditEntry column-space guard (Cluster 4): no constant may
    introduce a field name that is empty, contains whitespace (would break
    SQL/JSON key hygiene), or starts with an underscore (private convention).
    It cannot verify against the JSON subject dict at import time — that
    verification is the append_schema() runtime check — but it guards against
    typo-introduced field names that would fail silently.
    """
    import re

    valid_field = re.compile(r"^[a-z][a-z0-9_]*$")
    constant_names = [
        name
        for name in dir(audit_row_schemas)
        if name.isupper() and isinstance(getattr(audit_row_schemas, name), frozenset)
    ]
    assert len(constant_names) >= 17, f"Expected >=17 constants, got {len(constant_names)}"
    for name in constant_names:
        for field in getattr(audit_row_schemas, name):
            assert valid_field.match(field), (
                f"{name} member {field!r} fails snake_case field-name rule; "
                "all audit subject dict keys must be lowercase snake_case"
            )
