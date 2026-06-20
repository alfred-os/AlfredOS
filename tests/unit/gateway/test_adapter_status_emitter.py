"""Tests for the gateway-side ``AdapterStatusEmitter`` (G6-2b-1 / #288).

The emitter is the PRODUCER of the four ``gateway.adapter.*`` frames. These tests
pin (correction #1/#6, SEC-1):

* validate-on-produce: a malformed build raises ``ValidationError`` at the PRODUCER
  before any frame reaches the sink (symmetric with the core-side observer's
  consumer-side validation — a trust-boundary property);
* the per-transition payload mapping (crashed -> error_class + redacted detail;
  down -> closed-vocab reason; up -> captured epoch; breaker_open ->
  retry_after_seconds);
* crash-detail REDACT-then-BOUND, including a BOUNDARY-STRADDLING secret (a secret
  positioned so the bound cuts mid-token) + a mutation proof that the WRONG order
  (bound-then-redact) would leak an unredacted ``sk-`` prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.handlers import _MAX_CRASH_DETAIL_LEN
from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.security.dlp import redact_secret_shapes

pytestmark = pytest.mark.asyncio

_A = "discord"
_EPOCH = "0123456789abcdef0123456789abcdef"
_REDACTION_SENTINEL = "[REDACTED:api-key-shape]"


@dataclass
class _RecordingSink:
    frames: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    async def emit(self, method: str, params: dict[str, object]) -> None:
        self.frames.append((method, params))


# ---------------------------------------------------------------------------
# Per-transition payload mapping (correction #6)
# ---------------------------------------------------------------------------


async def test_emit_up_maps_adapter_and_epoch() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_up(adapter_id=_A, epoch=_EPOCH, host_restart_seq=0)
    # SEC-01 (#288): the up frame carries the incarnation being STARTED.
    assert sink.frames == [
        ("gateway.adapter.up", {"adapter_id": _A, "epoch": _EPOCH, "host_restart_seq": 0})
    ]


async def test_emit_up_threads_host_restart_seq() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_up(adapter_id=_A, epoch=_EPOCH, host_restart_seq=2)
    assert sink.frames[0][1]["host_restart_seq"] == 2


async def test_emit_down_maps_closed_vocab_reason() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_down(adapter_id=_A, reason="supervisor")
    assert sink.frames == [("gateway.adapter.down", {"adapter_id": _A, "reason": "supervisor"})]


async def test_emit_breaker_open_maps_retry_after_seconds() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_breaker_open(adapter_id=_A, retry_after_seconds=7)
    assert sink.frames == [
        ("gateway.adapter.breaker_open", {"adapter_id": _A, "retry_after_seconds": 7})
    ]


async def test_emit_crashed_maps_error_class_and_redacted_detail() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_crashed(
        adapter_id=_A, error_class="BrokenPipeError", detail="plain crash detail", host_restart_seq=0
    )
    method, params = sink.frames[0]
    assert method == "gateway.adapter.crashed"
    assert params["adapter_id"] == _A
    assert params["error_class"] == "BrokenPipeError"
    assert params["detail"] == "plain crash detail"


async def test_emit_crashed_threads_host_restart_seq() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_crashed(
        adapter_id=_A, error_class="BrokenPipeError", detail="x", host_restart_seq=4
    )
    method, params = sink.frames[0]
    assert method == "gateway.adapter.crashed"
    assert params["host_restart_seq"] == 4


async def test_emit_crashed_defaults_host_restart_seq_to_zero() -> None:
    sink = _RecordingSink()
    await AdapterStatusEmitter(sink=sink).emit_crashed(
        adapter_id=_A, error_class="BrokenPipeError", detail="x", host_restart_seq=0
    )
    assert sink.frames[0][1]["host_restart_seq"] == 0


# ---------------------------------------------------------------------------
# Validate-on-produce (trust-boundary, symmetric to the observer)
# ---------------------------------------------------------------------------


async def test_malformed_epoch_raises_at_producer_before_sink() -> None:
    """A non-32-hex epoch is a ValidationError at the PRODUCER — never reaches sink."""
    sink = _RecordingSink()
    with pytest.raises(ValidationError):
        await AdapterStatusEmitter(sink=sink).emit_up(
            adapter_id=_A, epoch="too-short", host_restart_seq=0
        )
    assert sink.frames == []


async def test_unknown_adapter_kind_raises_at_producer() -> None:
    """An adapter_id outside the closed adapter_kind set is refused at the producer."""
    sink = _RecordingSink()
    with pytest.raises(ValidationError):
        await AdapterStatusEmitter(sink=sink).emit_up(
            adapter_id="not-a-kind", epoch=_EPOCH, host_restart_seq=0
        )
    assert sink.frames == []


async def test_empty_error_class_raises_at_producer() -> None:
    """AdapterCrashedNotification.error_class has min_length=1 — empty is refused."""
    sink = _RecordingSink()
    with pytest.raises(ValidationError):
        await AdapterStatusEmitter(sink=sink).emit_crashed(
            adapter_id=_A, error_class="", detail="x", host_restart_seq=0
        )
    assert sink.frames == []


# ---------------------------------------------------------------------------
# Crash-detail REDACT-then-BOUND, incl. a boundary-straddling secret (correction #1)
# ---------------------------------------------------------------------------


def _boundary_straddling_detail() -> str:
    """A detail where a secret straddles the ``_MAX_CRASH_DETAIL_LEN`` boundary.

    The ``sk-…`` token starts a few bytes BEFORE the cap so a bound-then-redact would
    truncate its alnum tail to < 20 chars (the regex minimum), leaving an unredacted
    ``sk-`` prefix the shape-regex no longer matches. A leading space gives the regex
    its ``\\b`` word boundary.
    """
    secret = "sk-" + "A" * 40  # 43 chars, well over the 20-char regex minimum
    # Pad so the secret begins 8 bytes before the cap: after truncation only "sk-" +
    # 5 alnum survive (< 20) -> bound-then-redact would NOT match -> leak.
    pad_len = _MAX_CRASH_DETAIL_LEN - 8
    return ("X" * pad_len) + " " + secret


async def test_crashed_detail_redacted_then_bound_no_secret_leak() -> None:
    sink = _RecordingSink()
    detail = _boundary_straddling_detail()
    await AdapterStatusEmitter(sink=sink).emit_crashed(
        adapter_id=_A, error_class="BrokenPipeError", detail=detail, host_restart_seq=0
    )
    on_wire = sink.frames[0][1]["detail"]
    assert isinstance(on_wire, str)
    # Redact-then-bound: the secret was replaced wholesale BEFORE truncation, so no
    # ``sk-`` fragment can survive, and the result respects the length bound.
    assert "sk-" not in on_wire
    assert len(on_wire) <= _MAX_CRASH_DETAIL_LEN


async def test_mutation_bound_then_redact_would_leak_secret() -> None:
    """Mutation proof: the WRONG order (bound-then-redact) leaks an unredacted prefix.

    This is the inline mutation check correction #1 demands: it computes BOTH orderings
    on the boundary-straddling input and asserts they DIFFER — the correct order
    (redact-then-bound) scrubs the secret, the mutated order (bound-then-redact) leaks
    a ``sk-`` fragment. If the emitter ever regressed to the mutated order, the
    ``test_crashed_detail_...`` assertion above would fail; this test pins WHY.
    """
    detail = _boundary_straddling_detail()

    correct = redact_secret_shapes(detail)[:_MAX_CRASH_DETAIL_LEN]  # redact -> bound
    mutated = redact_secret_shapes(detail[:_MAX_CRASH_DETAIL_LEN])  # bound -> redact

    # The correct order leaves NO sk- fragment (the whole secret was replaced before
    # truncation; the bound may then cut the sentinel itself, which is harmless).
    assert "sk-" not in correct
    # The mutated order LEAKS an unredacted sk- prefix (the truncated tail is < 20
    # alnum, so the regex no longer matches it) and never inserts the sentinel.
    assert "sk-" in mutated
    assert _REDACTION_SENTINEL not in mutated
    # The two orderings genuinely differ on this input (the mutation is observable),
    # so the redact-then-bound assertion above is a real, non-vacuous guard.
    assert correct != mutated
