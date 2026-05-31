"""StdioTransport outbound DLP: scans placeholder frame BEFORE substitution.

arch-001 / sec-010 invariant (also ADR-0017): the outbound DLP pass sees
the JSON-RPC frame *with the* ``{{secret:*}}`` *placeholders still in
place* — the broker only substitutes real values *after* DLP has cleared
the frame. Routing plaintext secrets through the DLP regex/NER chain
creates a secret-sink class of attack: rule-trip logs would carry the
secret, ReDoS payloads could be staged via secret values, and
downstream classifiers turn into an exfil channel.

Coverage for this file pins the *order* (DLP-before-substitute), the
*refusal path* (audit row written via ``append_schema`` with
``DLP_OUTBOUND_REFUSED_FIELDS`` *before* raising ``DlpOutboundRefusedError``),
and the *placeholder-not-substituted* invariant (DLP sees the
``{{secret:*}}`` token, never the real value).

CR Cluster 1 fix: refusal raises ``DlpOutboundRefusedError`` (not
generic ``PluginError``) so audit consumers can distinguish DLP refusals
from sandbox or manifest failures (arch-006 / err-011).
"""

from __future__ import annotations

import json
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from alfred.audit import audit_row_schemas
from alfred.plugins.errors import DlpOutboundRefusedError
from alfred.plugins.stdio_transport import StdioTransport


@pytest.fixture
def transport_with_refusing_dlp(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> StdioTransport:
    """A transport whose DLP refuses every outbound frame.

    The refusing DLP returns a Result with ``refused=True`` and a closed-
    vocabulary ``rule_matched`` so the audit row carries a forensic-
    safe rule identifier.
    """
    refusing_dlp = MagicMock()
    refusing_dlp.scan.return_value = MagicMock(refused=True, rule_matched="test_rule")
    scanner = MagicMock()
    scanner.scan.return_value = None
    return StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=refusing_dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )


@pytest.mark.asyncio
async def test_outbound_dlp_refusal_emits_audit_row(
    transport_with_refusing_dlp: StdioTransport, fake_audit_writer: MagicMock
) -> None:
    """DLP refusal writes a ``security.dlp_outbound_refused`` audit row.

    arch-006 / err-011: the exception is :class:`DlpOutboundRefusedError`
    (not generic ``PluginError``) so audit consumers can branch on it
    distinctly from manifest / sandbox failures.
    """
    with pytest.raises(DlpOutboundRefusedError):
        await transport_with_refusing_dlp.dispatch("web.fetch", {"url": "https://example.com"})
    assert fake_audit_writer.last_event == "security.dlp_outbound_refused"


@pytest.mark.asyncio
async def test_outbound_dlp_audit_row_uses_schema_fields(
    transport_with_refusing_dlp: StdioTransport, fake_audit_writer: MagicMock
) -> None:
    """The DLP-refusal audit row passes the schema_name + frozenset fields.

    Cluster 4 fix: ``append_schema`` is the typed helper that validates
    subject keys against ``DLP_OUTBOUND_REFUSED_FIELDS`` so a typo'd
    field name fails CI rather than silently shadowing the real field.
    """
    with pytest.raises(DlpOutboundRefusedError):
        await transport_with_refusing_dlp.dispatch("web.fetch", {"url": "https://example.com"})
    assert len(fake_audit_writer.calls) == 1
    call_kwargs = fake_audit_writer.calls[0]
    assert call_kwargs["fields"] is audit_row_schemas.DLP_OUTBOUND_REFUSED_FIELDS
    assert call_kwargs["schema_name"] == "DLP_OUTBOUND_REFUSED_FIELDS"
    subject = call_kwargs["subject"]
    # Every key in the constant must be present (symmetric validation).
    assert set(subject.keys()) == audit_row_schemas.DLP_OUTBOUND_REFUSED_FIELDS
    assert subject["scan_rule_matched"] == "test_rule"
    assert subject["direction"] == "outbound"
    assert subject["wire"] == "stdio_transport.outbound"
    assert subject["field_name"] == "frame"


@pytest.mark.asyncio
async def test_outbound_dlp_refusal_exception_carries_forensic_attrs(
    transport_with_refusing_dlp: StdioTransport,
) -> None:
    """The raised exception carries plugin_id + rule_matched.

    Both are closed-vocabulary safe-for-audit fields. The exception
    contract is part of the security review surface — downstream
    handlers branch on these attributes.
    """
    with pytest.raises(DlpOutboundRefusedError) as excinfo:
        await transport_with_refusing_dlp.dispatch("web.fetch", {"url": "https://example.com"})
    assert excinfo.value.plugin_id == "test.plugin"
    assert excinfo.value.rule_matched == "test_rule"


@pytest.mark.asyncio
async def test_dlp_sees_placeholder_frame_not_substituted_value(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """arch-001 invariant: DLP scans the ``{{secret:*}}`` placeholder.

    The DLP fake captures every bytes argument; the test asserts the
    placeholder string is present AND the substituted secret value is
    absent. The broker is wired to substitute the placeholder for a
    real secret-shaped value — the test would FAIL (substituted value
    visible in DLP capture) if dispatch ever inverted the order.

    Plain language: "DLP must never see a real secret. The broker
    runs after DLP has cleared the frame."
    """
    scanned_frames: list[bytes] = []
    dlp = MagicMock()

    def _capture_and_pass(frame: bytes) -> MagicMock:
        scanned_frames.append(frame)
        return MagicMock(refused=False, rule_matched=None)

    dlp.scan.side_effect = _capture_and_pass

    # Broker substitutes the placeholder for a secret-shaped value.
    substituted_params = {
        "url": "https://example.com",
        "cookie": "sk-supersecret-value",
    }
    fake_broker.substitute = AsyncMock(return_value=substituted_params)

    scanner = MagicMock()
    scanner.scan.return_value = None

    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    original_params = {
        "url": "https://example.com",
        "cookie": "{{secret:cookie:example.com}}",
    }

    response = json.dumps({"jsonrpc": "2.0", "result": {"status": "ok"}}).encode("utf-8")
    response_frame = struct.pack(">I", len(response)) + response

    with patch.object(transport, "_process") as mock_proc:
        mock_proc.stdin.write = MagicMock()
        mock_proc.stdin.drain = AsyncMock()
        mock_proc.stdout.readexactly = AsyncMock(
            side_effect=[response_frame[:4], response_frame[4:]]
        )
        await transport.dispatch("lifecycle.start", original_params)

    assert len(scanned_frames) == 1
    scanned_text = scanned_frames[0].decode("utf-8", errors="replace")
    assert "{{secret:cookie:example.com}}" in scanned_text, (
        "DLP must see placeholder frame, not substituted value"
    )
    assert "sk-supersecret-value" not in scanned_text, (
        "DLP must NOT see the substituted secret value"
    )


@pytest.mark.asyncio
async def test_outbound_dlp_called_before_subprocess_write(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """``dlp.scan`` runs before ``subprocess.stdin.write``.

    Plain ordering assertion — the DLP gate sits in front of the wire.
    A future refactor that moves the write before the scan would slip
    the placeholder frame straight onto the wire (which is fine for the
    placeholder itself, but the test pins the gate position so the
    invariant survives changes to the surrounding code).
    """
    call_order: list[str] = []
    dlp = MagicMock()

    def _record_dlp(_: bytes) -> MagicMock:
        call_order.append("dlp")
        return MagicMock(refused=False, rule_matched=None)

    dlp.scan.side_effect = _record_dlp
    scanner = MagicMock()
    scanner.scan.return_value = None

    response = json.dumps({"jsonrpc": "2.0", "result": {"status": "ok"}}).encode("utf-8")
    response_frame = struct.pack(">I", len(response)) + response

    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    with patch.object(transport, "_process") as mock_proc:
        mock_proc.stdin.write.side_effect = lambda _: call_order.append("write")
        mock_proc.stdin.drain = AsyncMock()
        mock_proc.stdout.readexactly = AsyncMock(
            side_effect=[response_frame[:4], response_frame[4:]]
        )
        await transport.dispatch("lifecycle.start", {})
    assert call_order.index("dlp") < call_order.index("write"), (
        "DLP must run before subprocess write"
    )


@pytest.mark.asyncio
async def test_broker_substitutes_only_after_dlp_passes(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """Refused DLP → broker.substitute is NEVER called.

    If the DLP refuses the frame, ``dispatch`` short-circuits and raises
    BEFORE any broker substitution can happen. This is part of the
    arch-001 invariant — the substituted values must never reach a
    point where they could be leaked via the refusal audit row.
    """
    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=True, rule_matched="reject_for_test")
    scanner = MagicMock()
    scanner.scan.return_value = None
    fake_broker.substitute = AsyncMock(side_effect=AssertionError("must not call"))

    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    with pytest.raises(DlpOutboundRefusedError):
        await transport.dispatch("web.fetch", {"url": "https://example.com"})
    # The AssertionError side-effect would have fired if substitute ran;
    # the DlpOutboundRefusedError raising here proves it didn't.


@pytest.mark.asyncio
async def test_outbound_dlp_refusal_with_no_rule_matched_falls_back(
    fake_audit_writer: MagicMock,
    fake_broker: MagicMock,
    stub_nonce: object,
) -> None:
    """A refusal result without a ``rule_matched`` value records ``unknown``.

    Defence-in-depth: a misbehaving DLP adapter that returns
    ``refused=True`` but no rule identifier still produces a forensic-
    safe audit row. ``rule_matched`` is closed vocabulary; ``"unknown"``
    is the sentinel for "DLP refused but didn't name the rule".
    """
    dlp = MagicMock()
    dlp.scan.return_value = MagicMock(refused=True, rule_matched=None)
    scanner = MagicMock()
    scanner.scan.return_value = None
    transport = StdioTransport(
        plugin_id="test.plugin",
        executable="/bin/sh",
        args=["-c", "true"],
        audit_writer=fake_audit_writer,
        dlp=dlp,
        scanner=scanner,
        secret_broker=fake_broker,
        inbound_t3_nonce=stub_nonce,
    )
    with pytest.raises(DlpOutboundRefusedError) as excinfo:
        await transport.dispatch("web.fetch", {"url": "https://example.com"})
    assert excinfo.value.rule_matched == "unknown"
    assert fake_audit_writer.calls[0]["subject"]["scan_rule_matched"] == "unknown"
