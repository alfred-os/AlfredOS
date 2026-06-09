"""Unknown post-handshake method → audit row + restart request, no raise (Task 38).

Critical 6: an unknown notification is NOT silently dropped. The dispatcher
emits ``COMMS_UNKNOWN_NOTIFICATION_FIELDS`` (with secret-shaped tokens scrubbed
from ``method_redacted_params``) and calls ``request_plugin_restart`` — and the
path handles the case directly, it does not raise.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.unit.comms_mcp._inbound_spies import SpyAuditWriter

from ._session_builders import build_session


@pytest.mark.asyncio
async def test_unknown_method_audits_and_requests_restart() -> None:
    supervisor = AsyncMock()
    audit = SpyAuditWriter()
    session = build_session(supervisor=supervisor, audit_writer=audit)

    await session._on_post_handshake_method(method="some.unknown.thing", params={"x": 1})

    rows = audit.rows_with_schema("COMMS_UNKNOWN_NOTIFICATION_FIELDS")
    assert len(rows) == 1
    assert rows[0]["method"] == "some.unknown.thing"
    supervisor.request_plugin_restart.assert_awaited_once_with(
        adapter_id=session._effective_adapter_id, reason="unknown_notification"
    )


@pytest.mark.asyncio
async def test_unknown_method_does_not_raise() -> None:
    session = build_session(supervisor=AsyncMock())
    # No exception — the case is handled directly (spec §8.4).
    await session._on_post_handshake_method(method="bogus.method", params=None)


@pytest.mark.asyncio
async def test_unknown_method_redacts_secret_shaped_params() -> None:
    audit = SpyAuditWriter()
    session = build_session(supervisor=AsyncMock(), audit_writer=audit)

    await session._on_post_handshake_method(
        method="bogus.method",
        params={"token": "sk-ABCDEFGHIJKLMNOPQRSTUVWX", "n": 7},
    )

    rows = audit.rows_with_schema("COMMS_UNKNOWN_NOTIFICATION_FIELDS")
    redacted = rows[0]["method_redacted_params"]
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in str(redacted)
    assert redacted["n"] == 7  # non-string value passes through


@pytest.mark.asyncio
async def test_unknown_method_redacts_nested_secret_shaped_params() -> None:
    """A secret nested at any depth in an unknown-method param is scrubbed.

    Top-level-only redaction (CR #232) let a credential smuggled into a nested
    dict / list value pass through into ``method_redacted_params`` unredacted —
    a T3 plugin payload leaking a secret into audit storage (CLAUDE.md hard
    rule 1). The redactor recurses through dicts, lists, and tuples.
    """
    audit = SpyAuditWriter()
    session = build_session(supervisor=AsyncMock(), audit_writer=audit)
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"  # noqa: S105 — synthetic API-key shape

    await session._on_post_handshake_method(
        method="bogus.method",
        params={
            "envelope": {"auth": {"bearer": secret}},
            "tokens": ["clean", secret, {"deep": [secret]}],
            "n": 7,
        },
    )

    rows = audit.rows_with_schema("COMMS_UNKNOWN_NOTIFICATION_FIELDS")
    redacted = rows[0]["method_redacted_params"]
    assert secret not in str(redacted)
    assert redacted["envelope"]["auth"]["bearer"] == "[REDACTED:api-key-shape]"
    assert redacted["tokens"][0] == "clean"
    assert redacted["tokens"][1] == "[REDACTED:api-key-shape]"
    assert redacted["tokens"][2]["deep"][0] == "[REDACTED:api-key-shape]"
    assert redacted["n"] == 7


@pytest.mark.asyncio
async def test_unknown_method_no_supervisor_still_audits() -> None:
    # A session with no supervisor wired (defensive) still emits the audit row
    # — the restart request is simply skipped.
    audit = SpyAuditWriter()
    session = build_session(supervisor=None, audit_writer=audit)
    session._supervisor = None
    await session._on_post_handshake_method(method="bogus.method", params={})
    assert len(audit.rows_with_schema("COMMS_UNKNOWN_NOTIFICATION_FIELDS")) == 1
