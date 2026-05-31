"""``AlfredPluginSession`` manifest handshake + lifecycle audit (spec §4.2, §4.6, §4.7).

These tests exercise the three trust-boundary contracts the session owns:

* **``create()`` is the only public construction path.** A synchronous
  ``__init__`` cannot ``await`` the ``plugin.lifecycle.load_refused``
  audit emit on manifest-version mismatch, so the public factory MUST be
  async (rvw-cr-round-1). Direct ``AlfredPluginSession(...)`` is internal.
* **``_on_handshake_complete`` emits ``plugin.lifecycle.loaded``** after a
  successful capability-gate check, and ``plugin.lifecycle.load_refused``
  when the gate denies the load.
* **``_on_post_handshake_method`` quarantines on a disallowed JSON-RPC
  method.** Spec §4.6: a plugin sending ``alfred/hooks.register`` after
  handshake is trying to silently install a hook subscription. Defence is
  ``SIGKILL via transport.kill()`` FIRST, then audit row (the row claims
  the subprocess is dead — make it true before writing). The emit lives
  in a ``try/finally`` so operators see the quarantine event even if the
  kill itself fails (kill_succeeded=False).

Cluster 4 invariant: every audit emit uses ``await append_schema(...)``
with the relevant ``*_FIELDS`` frozenset + ``schema_name`` literal and
the typed ``subject={}`` dict — matching the
``StdioTransport.dispatch`` pattern Batch 2 established.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.audit import audit_row_schemas
from alfred.plugins.errors import (
    ManifestError,
    ManifestTierError,
    ManifestVersionError,
    PluginError,
)
from alfred.plugins.session import AlfredPluginSession

_VALID_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.test-plugin"
subscriber_tier = "system"
sandbox_profile = "user-plugin"
"""


_VERSION_MISMATCH_MANIFEST = """
[alfred]
manifest_version = 2

[plugin]
id = "alfred.test-plugin"
subscriber_tier = "system"
sandbox_profile = "user-plugin"
"""


@pytest.fixture
def fake_gate() -> MagicMock:
    """Capability gate stand-in: ``check_plugin_load`` returns True.

    Real :class:`alfred.hooks.capability.CapabilityGate` requires a
    persisted grant. Tests use a structural mock so the handshake test
    is not coupled to grant-table fixtures.
    """
    gate = MagicMock()
    gate.check_plugin_load.return_value = True
    gate.check_content_clearance.return_value = True
    return gate


@pytest.fixture
def refusing_gate() -> MagicMock:
    """Capability gate that refuses ``check_plugin_load``."""
    gate = MagicMock()
    gate.check_plugin_load.return_value = False
    gate.check_content_clearance.return_value = False
    return gate


@pytest.mark.asyncio
async def test_create_returns_session_on_valid_manifest(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """``create()`` succeeds when manifest_version=1 and tier is valid."""
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
    )
    assert session is not None
    # No audit emit yet — handshake hasn't completed.
    assert fake_audit_writer.last_event is None


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_version_mismatch(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Version mismatch raises ``ManifestVersionError`` and emits an audit row.

    The async factory awaits ``append_schema`` for the
    ``plugin.lifecycle.load_refused`` row BEFORE re-raising so the
    audit row lands even though the construction fails (rvw-cr-round-1).
    """
    with pytest.raises(ManifestVersionError):
        await AlfredPluginSession.create(
            manifest_raw=_VERSION_MISMATCH_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"
    # The forensic call recorded the schema name + the frozenset constant.
    call = fake_audit_writer.calls[-1]
    assert call["fields"] is audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS
    assert call["schema_name"] == "PLUGIN_LIFECYCLE_FIELDS"
    subject: dict[str, Any] = call["subject"]
    # plugin_id must be the best-effort extract from the raw TOML —
    # err-017 fix: the row carries an identifiable plugin id even though
    # the strict parse failed.
    assert subject["plugin_id"] == "alfred.test-plugin"
    assert subject["manifest_version"] == 2
    # subject keyset matches the frozenset exactly (symmetric validation).
    assert set(subject.keys()) == audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS


@pytest.mark.asyncio
async def test_create_load_refused_uses_sha256_when_plugin_id_unparseable(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """When the manifest has no recoverable ``id``, the audit row uses a sha256 sentinel.

    err-017 fix: keep an identifiable plugin label on the audit row so
    post-incident analysis can correlate the failed manifest blob to
    its source.
    """
    manifest = """
[alfred]
manifest_version = 99

[plugin]
subscriber_tier = "system"
sandbox_profile = "user-plugin"
"""
    with pytest.raises(ManifestVersionError):
        await AlfredPluginSession.create(
            manifest_raw=manifest,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    subject = fake_audit_writer.calls[-1]["subject"]
    assert subject["plugin_id"].startswith("unknown(sha256=")
    assert subject["manifest_version"] == 99


@pytest.mark.asyncio
async def test_handshake_complete_emits_loaded(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Successful gate check → ``plugin.lifecycle.loaded`` audit row."""
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
    )
    await session._on_handshake_complete()
    assert fake_audit_writer.last_event == "plugin.lifecycle.loaded"
    call = fake_audit_writer.calls[-1]
    subject = call["subject"]
    assert subject["plugin_id"] == "alfred.test-plugin"
    assert subject["manifest_subscriber_tier"] == "system"
    assert subject["manifest_version"] == 1
    assert subject["breaker_state"] == "CLOSED"
    assert subject["signal"] is None
    assert subject["exit_code"] is None
    # Symmetric — frozenset matches subject keys exactly.
    assert set(subject.keys()) == audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS
    # check_plugin_load actually consulted the gate.
    fake_gate.check_plugin_load.assert_called_once_with(
        plugin_id="alfred.test-plugin", manifest_tier="system"
    )


@pytest.mark.asyncio
async def test_handshake_complete_emits_load_refused_when_gate_denies(
    fake_audit_writer: MagicMock, refusing_gate: MagicMock
) -> None:
    """Gate denial → ``plugin.lifecycle.load_refused`` + ``PluginError`` raise."""
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=refusing_gate,
    )
    with pytest.raises(PluginError):
        await session._on_handshake_complete()
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"


@pytest.mark.asyncio
async def test_post_handshake_hook_register_triggers_sigkill_then_audit(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """``alfred/hooks.register`` post-handshake → ``transport.kill()`` then quarantine row.

    sec-013 / core-007 ordering: the SIGKILL is delivered BEFORE the
    audit row is written, so the row's ``signal='SIGKILL'`` claim is
    true at write time.
    """
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
        transport=transport,
    )
    await session._on_handshake_complete()
    await session._on_post_handshake_method("alfred/hooks.register")

    transport.kill.assert_awaited_once()
    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
    call = fake_audit_writer.calls[-1]
    assert call["fields"] is audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS
    assert call["schema_name"] == "PLUGIN_LIFECYCLE_QUARANTINED_FIELDS"
    subject = call["subject"]
    assert subject["quarantine_reason"] == "protocol_violation"
    assert subject["signal"] == "SIGKILL"
    assert subject["kill_succeeded"] is True
    assert subject["breaker_state"] == "OPEN"
    assert subject["trip_count"] == 1
    assert set(subject.keys()) == audit_row_schemas.PLUGIN_LIFECYCLE_QUARANTINED_FIELDS


@pytest.mark.asyncio
async def test_post_handshake_hook_register_emits_audit_even_when_kill_fails(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Kill failure (subprocess already dead) → row still lands with ``kill_succeeded=False``.

    The try/finally pattern guarantees the operator sees the quarantine
    event regardless of kill outcome (rvw-pre-flight fix).
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


@pytest.mark.asyncio
async def test_post_handshake_hook_register_emits_audit_when_kill_raises(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """An unexpected exception from ``kill()`` still produces the audit row.

    The ``try/finally`` around the audit emit fires before the exception
    re-raises so the operator-visible record of the quarantine attempt
    survives the failure mode.
    """

    class _BoomError(RuntimeError):
        pass

    transport = MagicMock()
    transport.kill = AsyncMock(side_effect=_BoomError("transport pipe closed"))
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
        transport=transport,
    )
    await session._on_handshake_complete()
    with pytest.raises(_BoomError):
        await session._on_post_handshake_method("alfred/hooks.register")
    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
    assert fake_audit_writer.calls[-1]["subject"]["kill_succeeded"] is False


@pytest.mark.asyncio
async def test_post_handshake_allowed_method_does_not_quarantine(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """A non-disallowed method must not fire kill or write a quarantine row."""
    transport = MagicMock()
    transport.kill = AsyncMock()
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
        transport=transport,
    )
    await session._on_handshake_complete()
    last_event = fake_audit_writer.last_event
    await session._on_post_handshake_method("lifecycle.stop")
    transport.kill.assert_not_awaited()
    # last_event should still be the loaded row from before the call.
    assert fake_audit_writer.last_event == last_event


@pytest.mark.asyncio
async def test_post_handshake_hook_register_without_transport_still_emits_row(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """No transport handle (callers may not have one) → kill skipped, row emitted.

    The quarantine path is best-effort about the kill step; the audit
    row is the load-bearing invariant. A None transport falls through to
    ``kill_succeeded=False`` and still writes the row.
    """
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
        transport=None,
    )
    await session._on_handshake_complete()
    await session._on_post_handshake_method("alfred/hooks.register")
    assert fake_audit_writer.last_event == "plugin.lifecycle.quarantined"
    assert fake_audit_writer.calls[-1]["subject"]["kill_succeeded"] is False


@pytest.mark.asyncio
async def test_handshake_complete_is_idempotent_no_double_emit(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """A second call to ``_on_handshake_complete`` after success is a no-op.

    Prevents the supervisor accidentally double-logging ``loaded`` if the
    handshake-driving code retries.
    """
    session = await AlfredPluginSession.create(
        manifest_raw=_VALID_MANIFEST,
        audit_writer=fake_audit_writer,
        gate=fake_gate,
    )
    await session._on_handshake_complete()
    first_call_count = len(fake_audit_writer.calls)
    await session._on_handshake_complete()
    assert len(fake_audit_writer.calls) == first_call_count


# ---------------------------------------------------------------------------
# CR-PR-140 F5 — load_refused row must land for EVERY manifest parse failure.
# ---------------------------------------------------------------------------
#
# The original ``create()`` only caught ``ManifestVersionError`` and
# ``ManifestTierError``. Other parse failures (malformed TOML, missing
# fields, invalid types, unknown subscriber_tier label) raised plain
# ``ManifestError`` and skipped the ``plugin.lifecycle.load_refused``
# audit emit — violating the refused-load contract in PRD §4.2 (an
# operator could not distinguish "we never received the manifest" from
# "we received it and refused it for shape reasons"). These tests pin
# the broader contract.


_MALFORMED_TOML_MANIFEST = "this is not valid TOML ::: ===\n[unclosed"


_MISSING_PLUGIN_TABLE_MANIFEST = """
[alfred]
manifest_version = 1
"""


_MISSING_PLUGIN_ID_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
subscriber_tier = "system"
sandbox_profile = "user-plugin"
"""


_UNKNOWN_SUBSCRIBER_TIER_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.weird-tier-plugin"
subscriber_tier = "made-up-tier"
sandbox_profile = "user-plugin"
"""


_INVALID_SANDBOX_PROFILE_TYPE_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.bad-sandbox-type"
subscriber_tier = "system"
sandbox_profile = 42
"""


_CONTENT_TRUST_TIER_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.tier-laundering-attempt"
subscriber_tier = "T3"
sandbox_profile = "user-plugin"
"""


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_malformed_toml(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Malformed TOML → ``ManifestError`` AND ``plugin.lifecycle.load_refused`` row.

    CR PR #140 F5 fix: previously the narrower ``except`` skipped this
    path. The forensic ``plugin_id`` falls back to the sha256 sentinel
    because the raw TOML is unparseable so the id-regex extractor
    typically misses too.
    """
    with pytest.raises(ManifestError):
        await AlfredPluginSession.create(
            manifest_raw=_MALFORMED_TOML_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"
    call = fake_audit_writer.calls[-1]
    assert call["fields"] is audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS
    subject = call["subject"]
    # ``got`` is absent on plain ManifestError so the helper records -1.
    assert subject["manifest_version"] == -1


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_missing_plugin_table(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """No ``[plugin]`` table → audit row lands.

    CR PR #140 F5 fix.
    """
    with pytest.raises(ManifestError):
        await AlfredPluginSession.create(
            manifest_raw=_MISSING_PLUGIN_TABLE_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_missing_plugin_id(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Missing ``[plugin] id`` → audit row lands with sha256 sentinel.

    CR PR #140 F5 fix.
    """
    with pytest.raises(ManifestError):
        await AlfredPluginSession.create(
            manifest_raw=_MISSING_PLUGIN_ID_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"
    subject = fake_audit_writer.calls[-1]["subject"]
    # No id to extract → sha256 sentinel.
    assert subject["plugin_id"].startswith("unknown(sha256=")


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_unknown_subscriber_tier(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Unknown ``subscriber_tier`` label (not T0-T3, not in valid set) → row lands.

    CR PR #140 F5 fix. Note this is distinct from the
    ``ManifestTierError`` path (which fires on T0-T3 confusion); a
    label outside the closed vocabulary raises plain ``ManifestError``.
    """
    with pytest.raises(ManifestError):
        await AlfredPluginSession.create(
            manifest_raw=_UNKNOWN_SUBSCRIBER_TIER_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"
    subject = fake_audit_writer.calls[-1]["subject"]
    # The forensic id extractor recovers the id even though the strict
    # parse failed on the tier.
    assert subject["plugin_id"] == "alfred.weird-tier-plugin"


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_invalid_sandbox_profile_type(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """Non-string ``sandbox_profile`` → audit row lands.

    CR PR #140 F5 fix.
    """
    with pytest.raises(ManifestError):
        await AlfredPluginSession.create(
            manifest_raw=_INVALID_SANDBOX_PROFILE_TYPE_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"


@pytest.mark.asyncio
async def test_create_emits_load_refused_on_content_trust_tier_in_subscriber_field(
    fake_audit_writer: MagicMock, fake_gate: MagicMock
) -> None:
    """T0-T3 in ``subscriber_tier`` → ``ManifestTierError`` AND audit row.

    Defence-in-depth pin: the broader ``except ManifestError`` introduced
    in the F5 fix still covers the tier-laundering subclass. A regression
    that re-narrowed the catch would break this assertion.
    """
    with pytest.raises(ManifestTierError):
        await AlfredPluginSession.create(
            manifest_raw=_CONTENT_TRUST_TIER_MANIFEST,
            audit_writer=fake_audit_writer,
            gate=fake_gate,
        )
    assert fake_audit_writer.last_event == "plugin.lifecycle.load_refused"
    subject = fake_audit_writer.calls[-1]["subject"]
    assert subject["plugin_id"] == "alfred.tier-laundering-attempt"
