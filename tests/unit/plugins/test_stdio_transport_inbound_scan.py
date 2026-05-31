"""InboundContentScanner — PR-S3-3a Task 4 (spec §4.5).

Distinct from :class:`alfred.security.dlp.OutboundDlp` because the threat
models are inverted:

* **Outbound** (host → subprocess) — prevent host secrets being
  exfiltrated to a plugin. Disposition: redact-and-continue.
* **Inbound** (subprocess → host) — detect injected instructions and
  canary tokens in T3 content flowing back toward the orchestrator.
  Disposition: SECURITY EVENT (no redact-and-continue path; canary trip
  triggers quarantine).

scan() is synchronous; call sites wrap in ``asyncio.to_thread()`` to keep
the event loop responsive on regex-heavy frames.
"""

from __future__ import annotations

import inspect

import pytest

from alfred.plugins.inbound_scanner import CanaryTrip, InboundContentScanner
from alfred.security.dlp import OutboundDlp

# ---------------------------------------------------------------------------
# Clean / matching behaviour.
# ---------------------------------------------------------------------------


def test_clean_frame_passes_with_none() -> None:
    scanner = InboundContentScanner()
    assert scanner.scan(b'{"result": "ok"}') is None


def test_canary_trip_returns_canary_trip_event() -> None:
    # Plant a canary token; the scanner returns a SECURITY EVENT, not a
    # boolean — callers must dispatch on the typed result.
    scanner = InboundContentScanner(canary_tokens=frozenset({"ALFRED_CANARY_TEST"}))
    result = scanner.scan(b'{"result": "ALFRED_CANARY_TEST was found"}')
    assert isinstance(result, CanaryTrip)
    assert result.matched_token == "ALFRED_CANARY_TEST"  # noqa: S105 -- canary token, not a credential


def test_canary_trip_records_byte_offset() -> None:
    scanner = InboundContentScanner(canary_tokens=frozenset({"CANARY"}))
    result = scanner.scan(b"prefix-bytes-CANARY-suffix")
    assert isinstance(result, CanaryTrip)
    # The match starts at byte 13 (length of b"prefix-bytes-").
    assert result.frame_offset == len(b"prefix-bytes-")


def test_canary_trip_frame_offset_is_byte_not_char_offset() -> None:
    """A multi-byte UTF-8 prefix must produce a *byte* offset, not a char index.

    CR on PR #140 caught the prior char-mode implementation: the
    ``CanaryTrip.frame_offset`` field is documented as a byte offset
    (used for forensic correlation across replays of the same frame),
    but a string-mode ``match.start()`` returns a character index that
    diverges from the bytes-into-the-frame position whenever the
    preceding bytes include a multi-byte UTF-8 character. T3 frames are
    routinely non-ASCII (web content, attachments), so this divergence
    was guaranteed to surface in production. The prefix ``"héllo-"``
    has ``len("héllo-") == 6`` characters but encodes to
    ``len(b"héllo-".encode("utf-8")) == 7`` bytes — the assertion only
    holds when the scanner operates on raw bytes.
    """
    scanner = InboundContentScanner(canary_tokens=frozenset({"CANARY"}))
    prefix = "héllo-".encode()
    result = scanner.scan(prefix + b"CANARY-suffix")
    assert isinstance(result, CanaryTrip)
    assert result.frame_offset == len(prefix)
    # Belt-and-braces: confirm the divergence is real (the char-mode
    # offset would have been 6, not 7).
    assert len("héllo-") != len(prefix), (
        "test premise broken — prefix must have distinct char/byte lengths"
    )


def test_first_match_wins_when_multiple_canaries_present() -> None:
    # The scanner returns on the first match — it does not enumerate all
    # canaries. The canary trip itself is enough to quarantine the plugin.
    scanner = InboundContentScanner(canary_tokens=frozenset({"ONE", "TWO"}))
    result = scanner.scan(b"ONE then TWO")
    assert isinstance(result, CanaryTrip)
    assert result.matched_token in {"ONE", "TWO"}


def test_no_canaries_configured_means_clean_frame() -> None:
    # An empty canary set is the "scanner is wired but no canaries
    # registered" state. Frames pass through regardless of content.
    scanner = InboundContentScanner()
    assert scanner.scan(b"arbitrary content") is None


def test_canary_set_non_empty_but_no_match_returns_none() -> None:
    # Covers the loop-continuation branch when a canary is registered but
    # absent from the frame — distinct from the empty-canaries fast path.
    scanner = InboundContentScanner(canary_tokens=frozenset({"NEVER_PRESENT"}))
    assert scanner.scan(b"this frame is clean") is None


def test_scanner_handles_non_utf8_bytes() -> None:
    # T3 content may be binary (e.g. a fetched image); the scanner must
    # not throw on undecodable bytes.
    scanner = InboundContentScanner(canary_tokens=frozenset({"X"}))
    result = scanner.scan(b"\xff\xfe\x00\x01X-found")
    assert isinstance(result, CanaryTrip)


# ---------------------------------------------------------------------------
# Disposition / class identity.
# ---------------------------------------------------------------------------


def test_inbound_scanner_is_not_outbound_dlp_subclass() -> None:
    # spec §4.5: different threat models, different dispositions.
    # Reuse of OutboundDlp here would silently subject inbound frames to
    # the "redact-and-continue" disposition, breaking the security model.
    assert not issubclass(InboundContentScanner, OutboundDlp)


def test_canary_trip_is_frozen_dataclass() -> None:
    # Frozen so audit-emission cannot mutate the matched token / offset.
    # FrozenInstanceError is the documented exception for frozen
    # dataclasses; using it concretely rather than catch-all Exception so
    # the test asserts the precise contract.
    import dataclasses

    trip = CanaryTrip(matched_token="X", frame_offset=0)  # noqa: S106 -- canary token, not a credential
    with pytest.raises(dataclasses.FrozenInstanceError):
        trip.matched_token = "Y"  # type: ignore[misc]  # noqa: S105 -- canary token, not a credential


# ---------------------------------------------------------------------------
# Synchrony — call sites must wrap in ``asyncio.to_thread`` so the
# scanner cannot be mistakenly awaited inside an event loop.
# ---------------------------------------------------------------------------


def test_scan_is_synchronous() -> None:
    scanner = InboundContentScanner()
    assert not inspect.iscoroutinefunction(scanner.scan)
