"""Post-handshake `alfred/hooks.register` attack (spec §4.6, §12.2, §12.3).

A plugin subprocess completes the manifest handshake legitimately (so
the capability gate has approved its declared ``subscriber_tier``),
then sends an inbound JSON-RPC frame with method
``alfred/hooks.register``. If accepted, the plugin silently installs
a hook subscription the operator never granted — a tier-laundering
attack that elevates the plugin's effective subscriber-tier without
re-consulting the gate.

Defence under test
==================

:meth:`AlfredPluginSession._on_post_handshake_method` enforces:

1. **SIGKILL first.** ``await transport.kill()`` runs BEFORE the audit
   row writes. The row's ``signal='SIGKILL'`` claim is only true when
   the kill actually landed (sec-013 / core-007 ordering).
2. **Audit row guaranteed.** The emit lives in a ``try/finally`` so the
   operator sees ``plugin.lifecycle.quarantined`` even when the kill
   itself fails (rvw-pre-flight). The ``kill_succeeded`` field reflects
   the actual outcome — operators distinguish "kill landed cleanly"
   from "quarantine intent logged but subprocess was already dead".
3. **No hook registered.** The handler never reaches the registry; the
   adversarial assertion confirms ``HookRegistry._hookpoints`` is
   unchanged by the attack attempt.

YAML payload
============

The companion YAML payload (``tl_post_handshake_hook_register.yaml``,
id ``tl-2026-004``) declares the corpus-level contract: the corpus
README is the source of truth for which attacks the slice owns, and
this module is the live executable assertion. ID ``tl-2026-003``
belongs to ``tl_gc_traversal_out_of_scope.yaml`` — CR on PR #140
caught the prior docstring drift.

sec-015 fix
===========

The tests assert (a) the quarantine row was written, (b)
``transport.kill()`` was called (SIGKILL actually issued), and (c) no
hookpoint was registered despite the attack — strengthening the
original "audit row was written" assertion to pin all three failure
modes the original plan-review pass flagged.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
import yaml

from alfred.audit import audit_row_schemas
from alfred.hooks.registry import HookRegistry, get_registry
from alfred.plugins.session import AlfredPluginSession
from tests.adversarial.payload_schema import AdversarialPayload

_VALID_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.compromised-plugin"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    """``AuditWriter`` stand-in that records the last event + every call.

    Mirrors ``tests/unit/plugins/conftest.py::fake_audit_writer`` so the
    adversarial test asserts the same contract the unit-test layer does.
    """
    writer = MagicMock()
    writer.calls = []
    writer.last_event = None

    async def _capture(**kwargs: object) -> None:
        writer.calls.append(kwargs)
        writer.last_event = kwargs.get("event")

    writer.append_schema = AsyncMock(side_effect=_capture)
    return writer


@pytest.fixture
def fake_gate() -> MagicMock:
    """Capability gate stand-in that approves the load.

    The attack is post-handshake by definition — the gate must have
    already approved the plugin's load. A refusal here would mean the
    test exercises the wrong failure mode.
    """
    gate = MagicMock()
    gate.check_plugin_load.return_value = True
    gate.check_content_clearance.return_value = True
    return gate


@pytest.fixture
def mock_transport() -> MagicMock:
    """Transport stub whose ``kill()`` is an awaitable returning True.

    A successful kill is the happy-path defence: SIGKILL landed, the
    audit row claims ``signal='SIGKILL'`` truthfully. The failure-mode
    tests below override the return value to exercise the
    ``kill_succeeded=False`` branch.
    """
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    return transport


@pytest_asyncio.fixture
async def session_post_handshake(
    fake_audit_writer: MagicMock,
    fake_gate: MagicMock,
    mock_transport: MagicMock,
) -> tuple[AlfredPluginSession, MagicMock, MagicMock]:
    """Build a session that has completed the handshake.

    Both :meth:`AlfredPluginSession.create` (rvw-cr-round-1) and
    :meth:`_on_handshake_complete` are async (Cluster-4: awaited audit
    emits), so the fixture must itself be async — :func:`pytest_asyncio.fixture`
    drives the event loop.
    """
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
        transport=mock_transport,
    )
    await session._on_handshake_complete()
    return session, fake_audit_writer, mock_transport


@pytest.mark.asyncio
async def test_post_handshake_hook_register_quarantines_plugin(
    session_post_handshake: tuple[AlfredPluginSession, MagicMock, MagicMock],
) -> None:
    """The attack triggers ``plugin.lifecycle.quarantined``.

    Asserts the audit row landed with the right schema fields, the
    forensic ``signal='SIGKILL'`` claim, ``kill_succeeded=True``, and
    ``breaker_state='OPEN'`` so post-incident analysis can correlate
    the quarantine across the audit graph.
    """
    session, audit, _transport = session_post_handshake
    await session._on_post_handshake_method("alfred/hooks.register")

    assert audit.last_event == "plugin.lifecycle.quarantined"
    call = audit.calls[-1]
    assert call["fields"] is audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS
    assert call["schema_name"] == "PLUGIN_LIFECYCLE_QUARANTINED_FIELDS"
    subject = call["subject"]
    assert subject["quarantine_reason"] == "protocol_violation"
    assert subject["signal"] == "SIGKILL"
    assert subject["kill_succeeded"] is True
    assert subject["breaker_state"] == "OPEN"
    assert subject["plugin_id"] == "alfred.compromised-plugin"
    # Symmetric key-set validation against the frozenset constant.
    assert set(subject.keys()) == audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS


@pytest.mark.asyncio
async def test_post_handshake_hook_register_sigkill_issued(
    session_post_handshake: tuple[AlfredPluginSession, MagicMock, MagicMock],
) -> None:
    """SIGKILL must actually be issued — not just claimed in the audit row.

    sec-013 / sec-015: the row says ``signal='SIGKILL'`` only when the
    kill was delivered, so the assertion pins both invariants — the
    audit claim AND the underlying syscall — in the same test path.
    """
    session, _audit, transport = session_post_handshake
    await session._on_post_handshake_method("alfred/hooks.register")
    transport.kill.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_post_handshake_hook_register_does_not_install_hookpoint(
    session_post_handshake: tuple[AlfredPluginSession, MagicMock, MagicMock],
) -> None:
    """No new hookpoint is registered despite the attack attempt.

    Reads the global :class:`HookRegistry` before and after the call.
    The session has no path that would write to ``_hookpoints``; the
    invariant survives because routing the disallowed method goes
    straight to the quarantine branch.
    """
    registry: HookRegistry = get_registry()
    hooks_before = set(registry._hookpoints.keys())
    session, _audit, _transport = session_post_handshake
    await session._on_post_handshake_method("alfred/hooks.register")
    hooks_after = set(registry._hookpoints.keys())
    assert hooks_after == hooks_before


@pytest.mark.asyncio
async def test_allowed_post_handshake_method_does_not_quarantine(
    session_post_handshake: tuple[AlfredPluginSession, MagicMock, MagicMock],
) -> None:
    """A legitimate post-handshake method must not trigger kill or audit.

    Negative control: ensures the disallowed-set match is exact — a
    typo or substring match would over-trigger the quarantine path and
    DoS the plugin pool. ``lifecycle.stop`` is the canonical legitimate
    shutdown signal a plugin sends, so it stands in for "any non-attack
    method".
    """
    session, audit, transport = session_post_handshake
    last_event_before = audit.last_event
    await session._on_post_handshake_method("lifecycle.stop")
    transport.kill.assert_not_awaited()
    assert audit.last_event == last_event_before


@pytest.mark.asyncio
async def test_kill_failure_still_emits_quarantine_row(
    fake_audit_writer: MagicMock,
    fake_gate: MagicMock,
) -> None:
    """When ``transport.kill()`` returns False, the audit row still lands.

    Try/finally guarantee (rvw-pre-flight): the operator must see the
    quarantine event regardless of kill outcome. ``kill_succeeded`` and
    ``quarantine_reason`` reflect the actual outcome so post-incident
    analysis can distinguish the two cases.
    """
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=False)
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
        transport=transport,
    )
    await session._on_handshake_complete()
    await session._on_post_handshake_method("alfred/hooks.register")

    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
    subject = fake_audit_writer.calls[-1]["subject"]
    assert subject["kill_succeeded"] is False
    assert subject["signal"] is None
    assert "kill failed" in subject["quarantine_reason"]


def test_yaml_payload_exists_for_post_handshake_hook_register() -> None:
    """The companion YAML payload exists and parses through the schema.

    Each pytest-module adversarial test has a paired YAML payload that
    declares the corpus-level contract. The corpus conftest validates
    every YAML at collection time; this test pins the *existence* of
    this slice's payload so a future rename of the YAML file is caught
    by the test rather than a silent corpus-drift.
    """
    payload_path = Path(__file__).parent / "tl_post_handshake_hook_register.yaml"
    assert payload_path.exists(), "tl-2026-004 YAML payload must exist"
    data = yaml.safe_load(payload_path.read_text())
    payload = AdversarialPayload.model_validate(data)
    assert payload.id == "tl-2026-004"
    assert payload.category == "tier_laundering"
    assert payload.ingestion_path == "stdio_transport.inbound"
    assert payload.expected_outcome == "audit_row_emitted"
