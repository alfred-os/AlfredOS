"""sandbox_info post-handshake handshake (PR-S4-6 arch-3).

After the handshake a plugin may report its effective sandbox posture via a
``sandbox_info`` method. The Supervisor compares the plugin-reported
``effective_sandbox_kind`` against the manifest's declared ``sandbox.kind``;
a mismatch (a kind:none plugin claiming kind:full, or vice versa) is a lie
about its own isolation and triggers ``SandboxInfoHandshakeMismatch`` + a
session teardown (kill + quarantine audit row).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit import audit_row_schemas
from alfred.plugins.errors import SandboxInfoHandshakeMismatch
from alfred.plugins.session import AlfredPluginSession

_NONE_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.test-plugin"
subscriber_tier = "system"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

_FULL_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.test-plugin"
subscriber_tier = "system"
sandbox_profile = "user-plugin"

[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = "config/sandbox/foo.linux.bwrap.policy"
"""


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    writer = MagicMock()
    writer.calls = []
    writer.last_event = None

    async def _append_schema(**kwargs):
        writer.calls.append(kwargs)
        writer.last_event = kwargs.get("event")

    writer.append_schema = AsyncMock(side_effect=_append_schema)
    return writer


@pytest.fixture
def fake_gate() -> MagicMock:
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    return gate


async def _make_session(manifest: str, audit, gate, transport):
    session = await AlfredPluginSession.create(
        manifest_raw=manifest,
        audit_writer=audit,
        gate=gate,
        transport=transport,
    )
    await session._on_handshake_complete()
    return session


@pytest.mark.asyncio
async def test_sandbox_info_match_is_noop(fake_audit_writer, fake_gate) -> None:
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await _make_session(_NONE_MANIFEST, fake_audit_writer, fake_gate, transport)
    # Plugin reports the truth (kind:none) → no teardown, no kill.
    await session._on_post_handshake_method("sandbox_info", {"effective_sandbox_kind": "none"})
    transport.kill.assert_not_awaited()


@pytest.mark.asyncio
async def test_sandbox_info_lie_triggers_teardown(fake_audit_writer, fake_gate) -> None:
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await _make_session(_NONE_MANIFEST, fake_audit_writer, fake_gate, transport)
    # kind:none plugin claims kind:full → mismatch → teardown.
    with pytest.raises(SandboxInfoHandshakeMismatch) as exc_info:
        await session._on_post_handshake_method("sandbox_info", {"effective_sandbox_kind": "full"})
    assert exc_info.value.declared == "none"
    assert exc_info.value.reported == "full"
    transport.kill.assert_awaited_once()
    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"


@pytest.mark.asyncio
async def test_sandbox_info_missing_field_triggers_teardown(fake_audit_writer, fake_gate) -> None:
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await _make_session(_FULL_MANIFEST, fake_audit_writer, fake_gate, transport)
    # A sandbox_info with no effective_sandbox_kind cannot be verified — a
    # plugin that won't attest its posture is refused.
    with pytest.raises(SandboxInfoHandshakeMismatch):
        await session._on_post_handshake_method("sandbox_info", {})
    transport.kill.assert_awaited_once()


@pytest.mark.asyncio
async def test_sandbox_info_quarantine_row_shape(fake_audit_writer, fake_gate) -> None:
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await _make_session(_NONE_MANIFEST, fake_audit_writer, fake_gate, transport)
    with pytest.raises(SandboxInfoHandshakeMismatch):
        await session._on_post_handshake_method("sandbox_info", {"effective_sandbox_kind": "full"})
    call = fake_audit_writer.calls[-1]
    assert call["fields"] is audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS
    assert call["subject"]["quarantine_reason"].startswith("sandbox_info")


@pytest.mark.asyncio
async def test_non_sandbox_info_method_unaffected(fake_audit_writer, fake_gate) -> None:
    # A benign non-disallowed method with no params is still a no-op.
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await _make_session(_NONE_MANIFEST, fake_audit_writer, fake_gate, transport)
    await session._on_post_handshake_method("lifecycle.ping")
    transport.kill.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_params", [[], ["effective_sandbox_kind"], "full", 7, 0, ""])
async def test_sandbox_info_non_object_params_fails_closed(
    fake_audit_writer, fake_gate, bad_params
) -> None:
    """A sandbox_info whose params is not a JSON object is a lie (CR #229 R2 f-3).

    Hard rule #7 (fail-closed): a malformed ``params`` (list/string/number,
    truthy or falsy) must reach quarantine + teardown + the typed mismatch —
    NOT raise an ``AttributeError`` before the audit row writes. Treating a
    non-object params as an honest "<missing>" attestation closes the drift.
    """
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await _make_session(_NONE_MANIFEST, fake_audit_writer, fake_gate, transport)
    with pytest.raises(SandboxInfoHandshakeMismatch):
        await session._on_post_handshake_method("sandbox_info", bad_params)
    transport.kill.assert_awaited_once()
    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"


@pytest.mark.asyncio
async def test_sandbox_info_mismatch_propagates_even_if_teardown_raises(
    fake_audit_writer, fake_gate
) -> None:
    """A teardown kill error must not swallow the typed mismatch (CR #229 R2 f-4).

    If ``_quarantine_teardown`` re-raises a kill failure, the caller must STILL
    see :class:`SandboxInfoHandshakeMismatch` — a sandbox-attestation lie always
    surfaces the typed mismatch so the supervisor's spawn path refuses the
    session. The kill error is chained, never the surfaced exception.
    """
    transport = MagicMock()
    transport.kill = AsyncMock(side_effect=OSError("kill syscall failed"))
    session = await _make_session(_NONE_MANIFEST, fake_audit_writer, fake_gate, transport)
    with pytest.raises(SandboxInfoHandshakeMismatch) as exc_info:
        await session._on_post_handshake_method("sandbox_info", {"effective_sandbox_kind": "full"})
    assert exc_info.value.declared == "none"
    assert exc_info.value.reported == "full"
    # The audit row still landed (try/finally) and records the kill failure.
    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
    assert fake_audit_writer.calls[-1]["subject"]["kill_succeeded"] is False
