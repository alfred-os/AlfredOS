"""``OutboundDlp.scan_for_outbound`` — the only constructor for ``ScannedOutboundBody``.

PR-S4-8 round-2 closure #1 (sec-001 CRITICAL + comms-002 HIGH): the comms
``OutboundMessageRequest.body`` field is typed ``ScannedOutboundBody`` — a
``NewType`` over ``tuple[str, OutboundDlpScanResult]`` carrying the
redacted text + ``dlp_redactions_count`` + ``canary_tripped``. The ONLY
way to mint a ``ScannedOutboundBody`` is through this method, so every
outbound construction site is forced through the DLP scan.
"""

from __future__ import annotations

from collections.abc import Mapping

from alfred.security.dlp import (
    OutboundDlp,
    OutboundDlpScanResult,
    ScannedOutboundBody,
)


class _StubBroker:
    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._mapping = dict(sorted((mapping or {}).items(), key=lambda kv: -len(kv[0])))

    def redact(self, text: str) -> str:
        for value, name in self._mapping.items():
            text = text.replace(value, f"[REDACTED:{name}]")
        return text


class _AuditRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, Mapping[str, object]]] = []

    def __call__(self, *, event: str, subject: Mapping[str, object]) -> None:
        self.events.append((event, subject))


def _dlp(mapping: dict[str, str] | None = None) -> OutboundDlp:
    return OutboundDlp(broker=_StubBroker(mapping), audit=_AuditRecorder())


def test_scan_for_outbound_returns_scanned_body() -> None:
    result = _dlp().scan_for_outbound("hello world")
    # NewType is a runtime tuple of (redacted_text, scan_result).
    text, scan = result
    assert text == "hello world"
    assert isinstance(scan, OutboundDlpScanResult)


def test_scan_for_outbound_clean_text_zero_redactions() -> None:
    _text, scan = _dlp().scan_for_outbound("perfectly clean")
    assert scan.dlp_redactions_count == 0
    assert scan.canary_tripped is False


def test_scan_for_outbound_redacts_known_secret() -> None:
    body = _dlp({"super-secret-value": "api_token"}).scan_for_outbound(
        "the key is super-secret-value ok"
    )
    text, scan = body
    assert "super-secret-value" not in text
    assert "[REDACTED:api_token]" in text
    assert scan.dlp_redactions_count >= 1


def test_scan_for_outbound_redacts_api_key_shape() -> None:
    text, scan = _dlp().scan_for_outbound("token sk-ABCDEFGHIJKLMNOPQRSTUV done")
    assert "sk-ABCDEFGHIJKLMNOPQRSTUV" not in text
    assert scan.dlp_redactions_count >= 1


def test_scanned_outbound_body_is_newtype_over_tuple() -> None:
    # ScannedOutboundBody.__supertype__ is the underlying tuple alias.
    assert ScannedOutboundBody.__supertype__ is not None


def test_scan_result_is_frozen() -> None:
    import pytest as _pytest
    from pydantic import ValidationError

    scan = OutboundDlpScanResult(dlp_redactions_count=0, canary_tripped=False)
    with _pytest.raises(ValidationError):
        scan.canary_tripped = True  # type: ignore[misc]
