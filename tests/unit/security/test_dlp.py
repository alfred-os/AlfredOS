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

from alfred.security.dlp import OutboundDlp

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


# ----- Stage 3: canary stub ------------------------------------------------


def test_canary_stub_is_identity_in_slice_2() -> None:
    """Slice-3 expands stage 3; Slice-2 keeps it as a literal no-op.

    REGRESSION GUARD: do not change without updating spec. The
    ``OutboundDlp._canary_stub`` docstring documents this contract.
    """
    assert OutboundDlp._canary_stub("anything") == "anything"
    assert OutboundDlp._canary_stub("") == ""
    assert OutboundDlp._canary_stub("with sk-AAAAAAAAAAAAAAAAAAAA shape") == (
        "with sk-AAAAAAAAAAAAAAAAAAAA shape"
    )


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
    assert subject["pre_bytes"] == len(pre)
    assert subject["post_bytes"] == len(out)
    # The sentinel and matched key happen to have different lengths.
    # Whatever the direction, post != pre is what we care about.
    assert subject["post_bytes"] != subject["pre_bytes"]


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
