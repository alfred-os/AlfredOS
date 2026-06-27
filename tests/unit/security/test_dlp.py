"""Per-file 100%-coverage gate target. PR D1 ``src/alfred/security/dlp.py``.

Every branch of every stage covered. The canary-stub identity test is a
deliberate regression guard: if a future contributor accidentally
deletes the no-op, this test fails with a clear pointer back to the
docstring.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.dlp import OutboundCanaryTripped, OutboundDlp

# ----- Doubles --------------------------------------------------------------


class _StubBroker:
    """Deterministic broker stub. Replaces literal secret values."""

    def __init__(self, mapping: dict[str, str]) -> None:
        # ``mapping`` maps secret-value -> name. Longer first to avoid the
        # shorter-suffix-eats-longer-tail bug (PRD §7.1 ordering).
        self._mapping = dict(sorted(mapping.items(), key=lambda kv: -len(kv[0])))

    def redact(self, text: str) -> str:
        for value, name in self._mapping.items():
            text = text.replace(value, f"[REDACTED:{name}]")
        return text


class _AuditRecorder:
    """Appends every audit event into a list. Tests assert against the list."""

    def __init__(self) -> None:
        self.events: list[tuple[str, Mapping[str, object]]] = []

    def __call__(self, *, event: str, subject: Mapping[str, object]) -> None:
        self.events.append((event, subject))


class _RaisingAudit:
    """Audit sink that raises. Used to verify that DLP propagates."""

    def __call__(self, *, event: str, subject: Mapping[str, object]) -> None:
        raise RuntimeError("simulated audit-write failure")


def _dlp(broker_mapping: dict[str, str] | None = None) -> tuple[OutboundDlp, _AuditRecorder]:
    audit = _AuditRecorder()
    broker = _StubBroker(broker_mapping or {})
    return OutboundDlp(broker=broker, audit=audit), audit


# ----- Stage 1: broker redaction ------------------------------------------


def test_stage_1_known_secret_replaced() -> None:
    dlp, audit = _dlp({"hunter2": "deepseek_api_key"})
    out = dlp.scan("debug: hunter2 in the logs")
    assert out == "debug: [REDACTED:deepseek_api_key] in the logs"
    assert len(audit.events) == 1
    event, subject = audit.events[0]
    assert event == "dlp.outbound_redacted"
    assert subject["stages_triggered"] == ("broker",)


def test_stage_1_clean_input_untouched() -> None:
    dlp, audit = _dlp({"hunter2": "deepseek_api_key"})
    assert dlp.scan("nothing to see here") == "nothing to see here"
    assert audit.events == []


# ----- Stage 2: generic API-key regex --------------------------------------


@pytest.mark.parametrize(
    "shape",
    [
        "sk-AAAAAAAAAAAAAAAAAAAA",
        "sk_AAAAAAAAAAAAAAAAAAAA",
        "pk-AAAAAAAAAAAAAAAAAAAA",
        "pk_AAAAAAAAAAAAAAAAAAAA",
        "tok-AAAAAAAAAAAAAAAAAAAA",
        "tok_AAAAAAAAAAAAAAAAAAAA",
        "key-AAAAAAAAAAAAAAAAAAAA",
        "key_AAAAAAAAAAAAAAAAAAAA",
    ],
)
def test_stage_2_prefix_matches(shape: str) -> None:
    dlp, audit = _dlp()
    assert dlp.scan(shape) == "[REDACTED:api-key-shape]"
    assert audit.events[0][1]["stages_triggered"] == ("api_key_shape",)


def test_stage_2_too_short_does_not_match() -> None:
    """19 alnum chars is below the threshold; must NOT match."""
    dlp, audit = _dlp()
    text = "sk-AAAAAAAAAAAAAAAAAAA"  # 19 A's
    assert dlp.scan(text) == text
    assert audit.events == []


def test_stage_2_capital_prefix_does_not_match() -> None:
    """Case-sensitive by design — lowercase prefixes match real SDK formats."""
    dlp, audit = _dlp()
    text = "Sk-AAAAAAAAAAAAAAAAAAAA"
    assert dlp.scan(text) == text
    assert audit.events == []


def test_stage_2_word_boundary_anchoring() -> None:
    """Prefix attached to another word still matches via the ``-`` boundary."""
    dlp, _audit = _dlp()
    # The hyphen-separated ``-sk-...`` form is still bounded by ``\b`` at
    # the hyphen, so the API-key shape is caught.
    text = "prefix-sk-AAAAAAAAAAAAAAAAAAAA"
    out = dlp.scan(text)
    assert "[REDACTED:api-key-shape]" in out


# ----- Stage 3: the real outbound canary scan (G7-2b) ----------------------


class _RaisingMatcher:
    """A canary matcher whose ``first_match`` raises — proves fail-LOUD."""

    def first_match(self, text: str) -> str | None:
        raise RuntimeError("simulated matcher internal error")


def test_canary_trip_raises_and_audits_after_the_row() -> None:
    """A registered canary in the outbound body fails LOUD: the trip audit row is
    written, THEN OutboundCanaryTripped raises (never fail-open). HARD rule #7."""
    audit = _AuditRecorder()
    dlp = OutboundDlp(
        broker=_StubBroker({}),
        audit=audit,
        canary=CanaryMatcher(tokens=[CanaryToken("CANARY-OUT-12345")]),
    )
    with pytest.raises(OutboundCanaryTripped) as exc_info:
        dlp.scan("exfil attempt carrying CANARY-OUT-12345 outbound")
    assert exc_info.value.token == "CANARY-OUT-12345"  # noqa: S105 -- canary sentinel, not a secret
    assert exc_info.value.reason == "outbound_canary_tripped"
    # The trip audit row fired (loud), distinct from the redaction row.
    canary_rows = [e for e in audit.events if e[0] == "dlp.outbound_canary_tripped"]
    assert len(canary_rows) == 1
    assert canary_rows[0][1]["token"] == "CANARY-OUT-12345"  # noqa: S105 -- canary sentinel


def test_redaction_audit_is_preserved_when_canary_trips() -> None:
    """A body that BOTH carries a redactable secret AND trips a canary records the
    redaction row BEFORE the canary-trip row (the redaction audit is not lost to the
    canary raise) — and the canary exception still propagates. (CR review.)"""
    audit = _AuditRecorder()
    dlp = OutboundDlp(
        broker=_StubBroker({}),
        audit=audit,
        canary=CanaryMatcher(tokens=[CanaryToken("CANARY-OUT-12345")]),
    )
    with pytest.raises(OutboundCanaryTripped):
        dlp.scan("leak sk-AAAAAAAAAAAAAAAAAAAA and CANARY-OUT-12345")
    assert [event for event, _subject in audit.events] == [
        "dlp.outbound_redacted",
        "dlp.outbound_canary_tripped",
    ]
    assert audit.events[0][1]["stages_triggered"] == ("api_key_shape",)


def test_canary_that_is_also_api_key_shaped_still_trips() -> None:
    """A canary token that ALSO matches the stage-2 redaction regex must STILL trip —
    the canary scan runs on the original text, so redaction cannot silently erase it
    (CR review, fail-LOUD / HARD rule #7)."""
    dlp = OutboundDlp(
        broker=_StubBroker({}),
        audit=_AuditRecorder(),
        # The canary value is itself an api-key shape (would be redacted by stage 2).
        canary=CanaryMatcher(tokens=[CanaryToken("sk-AAAAAAAAAAAAAAAAAAAA")]),
    )
    with pytest.raises(OutboundCanaryTripped):
        dlp.scan("exfil sk-AAAAAAAAAAAAAAAAAAAA now")


def test_clean_body_with_canary_matcher_returns_redacted_text() -> None:
    """When no canary is present the stage is transparent; redaction still runs."""
    audit = _AuditRecorder()
    dlp = OutboundDlp(
        broker=_StubBroker({}),
        audit=audit,
        canary=CanaryMatcher(tokens=[CanaryToken("CANARY-OUT-12345")]),
    )
    assert dlp.scan("clean body sk-AAAAAAAAAAAAAAAAAAAA") == "clean body [REDACTED:api-key-shape]"
    assert not any(e[0] == "dlp.outbound_canary_tripped" for e in audit.events)


def test_no_canary_matcher_is_a_no_op_stage() -> None:
    """When ``canary`` is None (today's core default) stage 3 does nothing."""
    audit = _AuditRecorder()
    dlp = OutboundDlp(broker=_StubBroker({}), audit=audit, canary=None)
    assert dlp.scan("CANARY-OUT-12345 passes when no matcher is wired") == (
        "CANARY-OUT-12345 passes when no matcher is wired"
    )
    assert audit.events == []


def test_canary_matcher_internal_error_fails_loud_not_open() -> None:
    """An internal matcher error must PROPAGATE — never swallow + fall through (a
    swallowed error would silently let the canary'd body egress)."""
    dlp = OutboundDlp(broker=_StubBroker({}), audit=_AuditRecorder(), canary=_RaisingMatcher())  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="simulated matcher internal error"):
        dlp.scan("any body at all")


def test_canary_trips_on_scan_for_outbound_too() -> None:
    """The chokepoint minting path also fails loud (B4 calls scan_for_outbound)."""
    dlp = OutboundDlp(
        broker=_StubBroker({}),
        audit=_AuditRecorder(),
        canary=CanaryMatcher(tokens=[CanaryToken("CANARY-OUT-12345")]),
    )
    with pytest.raises(OutboundCanaryTripped):
        dlp.scan_for_outbound("body with CANARY-OUT-12345")


# ----- Broker-optional (gateway side: stages 2+3 only) ---------------------


def test_broker_none_skips_stage_1_but_runs_stage_2() -> None:
    """The gateway holds no vault (ADR-0036), so it builds OutboundDlp(broker=None):
    a broker-only-detectable value passes (no stage 1), but an API-key-shaped value
    is still redacted by stage 2 — one code path, no fork."""
    audit = _AuditRecorder()
    dlp = OutboundDlp(broker=None, audit=audit)
    # A value only the broker would know is NOT redacted (no stage 1).
    assert dlp.scan("known-only-to-broker-value") == "known-only-to-broker-value"
    # An API-key-shaped value is still caught by stage 2.
    out = dlp.scan("leak sk-AAAAAAAAAAAAAAAAAAAA")
    assert "[REDACTED:api-key-shape]" in out
    # The stage-2 row never lists ``broker`` (it was skipped).
    stage2_rows = [e for e in audit.events if e[0] == "dlp.outbound_redacted"]
    assert stage2_rows[0][1]["stages_triggered"] == ("api_key_shape",)


def test_broker_none_still_trips_canary_at_stage_3() -> None:
    """broker=None + a canary matcher: stage 3 still fails loud (gateway 2nd pass)."""
    dlp = OutboundDlp(
        broker=None,
        audit=_AuditRecorder(),
        canary=CanaryMatcher(tokens=[CanaryToken("CANARY-OUT-12345")]),
    )
    with pytest.raises(OutboundCanaryTripped):
        dlp.scan_for_outbound("redacted body still carrying CANARY-OUT-12345")


# ----- Multi-secret ordering -----------------------------------------------


def test_multi_secret_longer_first_ordering() -> None:
    """Longer secret redacted first so a shared prefix doesn't leak the tail."""
    dlp, _audit = _dlp({"abc": "short", "abcdef": "long"})
    out = dlp.scan("token: abcdef ends here")
    assert "[REDACTED:long]" in out
    # ``abc`` should NOT appear bare anywhere in the output.
    assert " abc " not in out


def test_both_backends_feed_redactor() -> None:
    """File-source + env-source secrets both flow through the same redactor."""
    dlp, _audit = _dlp({"file-secret": "discord_bot_token", "env-secret": "deepseek_api_key"})
    out = dlp.scan("debug: file-secret AND env-secret")
    assert "[REDACTED:discord_bot_token]" in out
    assert "[REDACTED:deepseek_api_key]" in out


# ----- Multi-stage interaction --------------------------------------------


def test_both_stages_trigger_records_both_in_audit() -> None:
    dlp, audit = _dlp({"hunter2": "deepseek_api_key"})
    text = "debug: hunter2 AND sk-AAAAAAAAAAAAAAAAAAAA"
    out = dlp.scan(text)
    assert "[REDACTED:deepseek_api_key]" in out
    assert "[REDACTED:api-key-shape]" in out
    assert audit.events[0][1]["stages_triggered"] == ("broker", "api_key_shape")


# ----- Audit semantics -----------------------------------------------------


def test_audit_records_byte_counts() -> None:
    dlp, audit = _dlp()
    pre = "header sk-AAAAAAAAAAAAAAAAAAAA trailer"
    out = dlp.scan(pre)
    subject = audit.events[0][1]
    # Bytes, not characters. For an all-ASCII pre/post the two are equal;
    # the non-ASCII case below pins the encoding choice.
    assert subject["pre_bytes"] == len(pre.encode("utf-8"))
    assert subject["post_bytes"] == len(out.encode("utf-8"))
    # The sentinel and matched key happen to have different lengths.
    # Whatever the direction, post != pre is what we care about.
    assert subject["post_bytes"] != subject["pre_bytes"]


def test_audit_byte_counts_are_utf8_not_chars_for_non_ascii() -> None:
    """Non-ASCII pin: forensic audit consumers reason in bytes.

    ``len("é") == 1`` (chars) but ``len("é".encode("utf-8")) == 2`` (bytes).
    The audit row records the latter so a 4-byte emoji and an ASCII
    character don't both report as length 1.
    """
    dlp, audit = _dlp()
    pre = "café sk-AAAAAAAAAAAAAAAAAAAA 🚀"
    out = dlp.scan(pre)
    subject = audit.events[0][1]
    # The ASCII character count is shorter than the UTF-8 byte count for
    # both pre and post — char counts would have been wrong.
    assert subject["pre_bytes"] == len(pre.encode("utf-8"))
    assert subject["post_bytes"] == len(out.encode("utf-8"))
    assert subject["pre_bytes"] > len(pre), (
        "test setup bug: chosen input must contain multibyte UTF-8 chars"
    )


def test_no_audit_on_clean_input() -> None:
    dlp, audit = _dlp({"hunter2": "deepseek_api_key"})
    dlp.scan("nothing sensitive at all")
    assert audit.events == []


def test_audit_write_failure_propagates() -> None:
    """CLAUDE.md hard rule #7 — failed audit writes raise, never silently swallow."""
    broker_mapping: dict[str, Any] = {"hunter2": "deepseek_api_key"}

    class _Broker:
        def redact(self, text: str) -> str:
            for value, name in broker_mapping.items():
                text = text.replace(value, f"[REDACTED:{name}]")
            return text

    dlp = OutboundDlp(broker=_Broker(), audit=_RaisingAudit())
    with pytest.raises(RuntimeError, match="simulated audit-write failure"):
        dlp.scan("debug: hunter2 leaks")
