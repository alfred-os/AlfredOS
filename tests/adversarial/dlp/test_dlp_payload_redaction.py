"""DLP wiring-smoke assertion for the `dlp-2026-001` corpus payload.

Asserts the **defense fired** (not a leak path): given a payload whose text
contains a known SUPPORTED_SECRETS value, `OutboundDlp.scan` MUST:

1. Replace the secret substring with the stage-1 broker redaction marker
   `[REDACTED:discord_bot_token]` — the raw fake value MUST NOT survive into
   the scanned output.
2. Emit exactly one `dlp.outbound_redacted` audit row whose
   `stages_triggered` includes `"broker"` (CLAUDE.md hard rule #7: failed
   audit writes propagate; this test pins the success case for the smoke).

The fake secret value is a slice-1-style test fixture: visibly-not-real to a
human reviewer (`FAKETESTVALUEDONOTUSE` substring) but shaped so the broker's
`redact()` pipeline + the stage-2 generic-API-key regex both treat it as a
real secret. The test wires the value into a sandboxed `SecretBroker` via the
`env=` constructor injection — never the production `os.environ` and never
the production broker singleton. The capability gate is NOT in scope for this
path; only `OutboundDlp` + `SecretBroker.redact` are exercised.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

import pytest

from alfred.security.dlp import OutboundDlp
from alfred.security.secrets import SecretBroker
from tests.adversarial.payload_schema import AdversarialPayload

# The fake-test secret value embedded in `dlp-2026-001`'s payload. Kept as a
# module constant so the test's contract with the YAML is explicit: if the
# payload's embedded token ever drifts, _this_ constant must update too, and
# the broker-vs-payload sanity assertion below trips loudly otherwise.
_FAKE_TOKEN: Final[str] = "sk-FAKETESTVALUEDONOTUSEAAAA"  # noqa: S105 — synthetic fake test value, NOT a live secret (see module docstring)

# Id of the payload this test exercises. Centralised so the failure message
# carries the right pointer if the corpus filter returns nothing.
_PAYLOAD_ID: Final[str] = "dlp-2026-001"


class _AuditRecorder:
    """Test double for `OutboundDlp`'s synchronous audit sink.

    Mirrors the shape used by `tests/unit/security/test_dlp.py::_AuditRecorder`
    so the corpus-level assertion stays consistent with the unit-level one.
    """

    def __init__(self) -> None:
        self.events: list[tuple[str, Mapping[str, object]]] = []

    def __call__(self, *, event: str, subject: Mapping[str, object]) -> None:
        self.events.append((event, subject))


@pytest.fixture
def known_secret_leak_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus down to the wiring-smoke payload.

    Fails loudly if the payload isn't present so a future rename / delete in
    the corpus surfaces here (and not as a mysterious skipped assertion).
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; "
            f"expected at tests/adversarial/dlp/payloads/known_secret_leak.yaml"
        )
        raise pytest.UsageError(msg)
    return matches[0]


def test_dlp_redacts_known_secret_from_corpus_payload(
    known_secret_leak_payload: AdversarialPayload,
) -> None:
    """`OutboundDlp.scan` MUST replace the embedded fake secret + emit audit.

    Wires a sandboxed `SecretBroker` (env-injection only — never the process
    `os.environ`, never the production singleton) that knows the fake token
    as the `discord_bot_token` SUPPORTED_SECRETS value. Calls `scan()` on the
    payload's `payload` field. Asserts redaction landed and one audit row
    fired with `stages_triggered` containing `"broker"`.
    """
    # The payload field is `str | dict[str, Any]` in the schema; this payload
    # uses the string form. Pin the type so mypy's strict mode stays green
    # without a `cast` (the assert narrows the union for the type checker).
    payload_text = known_secret_leak_payload.payload
    assert isinstance(payload_text, str), (
        f"payload {_PAYLOAD_ID} must use the str form for DLP scanning"
    )

    # Pre-flight: the YAML's embedded fake token must match this test's
    # `_FAKE_TOKEN`. If the YAML drifts, this trips before the real assertion
    # so the failure mode is "test/YAML are out of sync", not a mystery.
    assert _FAKE_TOKEN in payload_text, (
        f"payload {_PAYLOAD_ID} no longer contains the expected fake token "
        f"{_FAKE_TOKEN!r}; update either the YAML or `_FAKE_TOKEN` to match"
    )

    # Sandboxed broker. `env=` injection bypasses `os.environ` entirely so
    # this test never reads or writes the real process environment. No file
    # backend → broker is env-only for this run; `discord_bot_token` is in
    # `_PREFER_FILE` but falls back to env when no file is configured.
    broker = SecretBroker(
        env={"ALFRED_DISCORD_BOT_TOKEN": _FAKE_TOKEN},
    )
    audit = _AuditRecorder()
    dlp = OutboundDlp(broker=broker, audit=audit)

    scanned = dlp.scan(payload_text)

    # Defense fired: the raw fake token MUST NOT appear in the output.
    assert _FAKE_TOKEN not in scanned, (
        f"OutboundDlp.scan failed to redact {_FAKE_TOKEN!r} from payload "
        f"{_PAYLOAD_ID}; raw value survived into scanned output"
    )
    # Stage-1 marker IS present (broker.redact wins because it runs first;
    # the stage-2 regex would also catch this shape, but the wiring smoke
    # pins broker redaction as the load-bearing path).
    assert "[REDACTED:discord_bot_token]" in scanned, (
        f"OutboundDlp.scan did not emit the expected stage-1 redaction "
        f"marker for payload {_PAYLOAD_ID}; got: {scanned!r}"
    )

    # Audit row landed — CLAUDE.md hard rule #7 ("Audit-log writes are
    # non-skippable"). Exactly one event because `scan()` only emits when
    # text is modified, and this payload triggers exactly one modification
    # pass through the pipeline.
    assert len(audit.events) == 1, (
        f"expected exactly one dlp.outbound_redacted audit row; "
        f"got {len(audit.events)}: {audit.events!r}"
    )
    event_name, subject = audit.events[0]
    assert event_name == "dlp.outbound_redacted", f"unexpected audit event name: {event_name!r}"
    stages = subject["stages_triggered"]
    assert isinstance(stages, tuple), (
        f"audit `stages_triggered` must be a tuple for hashability; got {type(stages).__name__}"
    )
    assert "broker" in stages, (
        f"expected `broker` in stages_triggered for the wiring smoke; got {stages!r}"
    )
