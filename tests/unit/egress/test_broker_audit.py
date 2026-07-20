"""Unit tests for ``EgressBrokerAuditor`` (#340 broker-audit pre-gate, Task 2).

Covers: the signed T0 success row (``egress.broker.connected``), the signed T0
failure row (``egress.broker.refused``) carrying the closed-vocab ``reason``, and
the bounded hot-path await (D3 / err-004 / sec-006) — a hung ``append_schema``
must time out loud (structlog error + re-raise), never silently stall the
extraction hot path (HARD #7).

The ``egress.broker.connected`` / ``egress.broker.refused`` hookpoints are not
yet declared anywhere in production (declaration is golive's ``broker_sockets``
wiring, a later task — this auditor ships dormant). So, mirroring
``tests/unit/security/test_sandbox_refusal_audit.py``'s ``_fake_invoke``
fixture, the real dispatch registry's strict-declaration check is sidestepped by
monkeypatching ``alfred.hooks.invoke.invoke`` at its source module rather than
exercising the live ``get_registry()`` singleton — this test proves ``_write``'s
SHAPE (fields, dispatch args), not that a hookpoint is declared, which is out of
scope for this task.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
from typing import Any

import pytest
import structlog

from alfred.egress.broker_audit import EgressBrokerAuditor


class _RecordingAuditWriter:
    """Test double standing in for ``AuditWriter`` — records every ``append_schema`` call."""

    def __init__(self, *, hang: bool = False) -> None:
        self.rows: list[dict[str, Any]] = []
        self._hang = hang

    async def append_schema(self, **kw: Any) -> None:
        if self._hang:
            await asyncio.sleep(3600)
        self.rows.append(kw)


@pytest.fixture
def _fake_invoke(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Monkeypatch ``alfred.hooks.invoke.invoke`` so ``_write`` never touches the
    real dispatch registry (which would refuse an undeclared hookpoint in strict
    mode — see module docstring). Records every call's kwargs.

    Patched at the source submodule (``importlib.import_module``), not via the
    dotted-string form of ``monkeypatch.setattr`` — ``alfred.hooks/__init__.py``
    re-exports ``invoke``, which rebinds the *package* attribute name to the
    already-imported function object, so the dotted-string resolver's
    attribute-walk lands on the function instead of the submodule and silently
    patches the wrong target (same trap documented in the sandbox-refusal-audit
    precedent test).
    """
    invoked: list[dict[str, Any]] = []

    async def _invoke(name: str, ctx: object, **kwargs: Any) -> object:
        invoked.append({"name": name, **kwargs})
        return ctx

    invoke_module = importlib.import_module("alfred.hooks.invoke")
    monkeypatch.setattr(invoke_module, "invoke", _invoke)
    return invoked


async def test_success_row_signed_t0_with_destination_and_egress_id(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    w = _RecordingAuditWriter()
    await EgressBrokerAuditor(w).record_broker_success(
        destination="gateway:8889", extraction_id="ext-1", socket_ordinal=0
    )
    row = w.rows[-1]
    assert row["event"] == "egress.broker.connected"
    assert row["trust_tier_of_trigger"] == "T0"
    assert row["result"] == "success"
    assert row["actor_user_id"] is None
    assert row["cost_estimate_usd"] == 0.0
    assert set(row["subject"]) == row["fields"]  # symmetric key validation
    assert row["subject"]["destination"] == "gateway:8889"
    assert len(row["subject"]["egress_id"]) == 64  # sha256 hex, non-secret
    # The fail-closed hookpoint dispatched exactly once, for the right event.
    assert len(_fake_invoke) == 1
    assert _fake_invoke[0]["name"] == "egress.broker.connected"
    assert _fake_invoke[0]["fail_closed"] is True
    assert _fake_invoke[0]["kind"] == "post"


async def test_egress_id_is_deterministic_sha256_of_destination_and_salt(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    """Still a deterministic, non-secret sha256 — now over destination AND the socket salt."""
    w = _RecordingAuditWriter()
    await EgressBrokerAuditor(w).record_broker_success(
        destination="gateway:8889", extraction_id="ext-1", socket_ordinal=0
    )
    expected = hashlib.sha256(b"gateway:8889|ext-1:0").hexdigest()
    assert w.rows[-1]["subject"]["egress_id"] == expected


async def test_sockets_of_one_extraction_get_distinct_egress_ids(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    """rev-464-03: N sockets per extraction must NOT collapse to ONE egress_id.

    ``dispatch`` brokers BROKER_SOCKET_COUNT sockets per extraction and wrote a
    ``record_broker_success`` row for each. All N share one proxy destination, so the
    sha256-of-destination id was IDENTICAL across them: an audit consumer could not tell
    1 extraction x 3 sockets from 3 extractions x 1 socket, and the ADR-0040 residual (vii)
    egress counts inflated 3x.

    A single row carrying a socket count would need ``socket_count`` added to
    ``EGRESS_BROKER_SUCCESS_FIELDS`` — a schema change, deliberately out of scope — so each
    socket is salted instead.
    """
    w = _RecordingAuditWriter()
    auditor = EgressBrokerAuditor(w)
    for ordinal in range(3):
        await auditor.record_broker_success(
            destination="gateway:8889", extraction_id="ext-1", socket_ordinal=ordinal
        )
    ids = [row["subject"]["egress_id"] for row in w.rows]
    assert len(set(ids)) == 3, "the three sockets of one extraction collided onto one egress_id"


async def test_rows_of_one_extraction_share_a_trace_id(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    """The N rows must still be CORRELATABLE as one extraction after the salt.

    Salting alone would only trade one ambiguity for another — 3 unrelated-looking rows. The
    shared ``trace_id`` is what lets a consumer group them and count extractions correctly.
    ``trace_id`` is a top-level ``append_schema`` parameter, NOT a member of the fieldset, so
    this grouping costs no schema change.
    """
    w = _RecordingAuditWriter()
    auditor = EgressBrokerAuditor(w)
    for ordinal in range(3):
        await auditor.record_broker_success(
            destination="gateway:8889", extraction_id="ext-1", socket_ordinal=ordinal
        )
    await auditor.record_broker_success(
        destination="gateway:8889", extraction_id="ext-2", socket_ordinal=0
    )
    traces = [row["trace_id"] for row in w.rows]
    assert traces[:3] == ["ext-1"] * 3  # one extraction, three sockets
    assert traces[3] == "ext-2"  # a different extraction is distinguishable
    assert len({r["subject"]["egress_id"] for r in w.rows}) == 4  # all four sockets distinct


async def test_failure_row_carries_closed_vocab_reason(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    w = _RecordingAuditWriter()
    await EgressBrokerAuditor(w).record_broker_failure(
        destination="gateway:8889", reason="gateway_unreachable", extraction_id="ext-1"
    )
    row = w.rows[-1]
    assert row["event"] == "egress.broker.refused"
    assert row["trust_tier_of_trigger"] == "T0"
    assert row["result"] == "refused"
    assert set(row["subject"]) == row["fields"]  # symmetric key validation
    assert row["subject"]["reason"] == "gateway_unreachable"
    assert row["subject"]["destination"] == "gateway:8889"
    assert len(_fake_invoke) == 1
    assert _fake_invoke[0]["name"] == "egress.broker.refused"
    assert _fake_invoke[0]["fail_closed"] is True


async def test_bounded_await_fails_loud_not_silent(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    # A hung append_schema must not hang the extraction hot path forever (D3).
    # The timeout fires (and re-raises) before _write ever reaches the
    # invoke(...) dispatch call — the _fake_invoke fixture proves that
    # positively rather than merely by absence of a wired hookpoint.
    w = _RecordingAuditWriter(hang=True)
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises((TimeoutError, asyncio.TimeoutError)),
    ):
        await EgressBrokerAuditor(w, audit_await_timeout_s=0.05).record_broker_success(
            destination="gateway:8889", extraction_id="ext-1", socket_ordinal=0
        )
    timeout_events = [e for e in captured if e["event"] == "egress.broker.audit_write_timeout"]
    assert len(timeout_events) == 1
    assert timeout_events[0]["log_level"] == "error"
    assert timeout_events[0]["audit_event"] == "egress.broker.connected"
    # Never silently swallowed: nothing was ever appended to the writer.
    assert w.rows == []
    # The fail-closed hookpoint must never dispatch when the row was never persisted.
    assert _fake_invoke == []


async def test_bounded_await_applies_to_failure_row_too(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    w = _RecordingAuditWriter(hang=True)
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        await EgressBrokerAuditor(w, audit_await_timeout_s=0.05).record_broker_failure(
            destination="gateway:8889", reason="gateway_unreachable", extraction_id="ext-1"
        )
    assert _fake_invoke == []


async def test_append_schema_failure_propagates_not_swallowed(
    _fake_invoke: list[dict[str, Any]],
) -> None:
    """Fail-loud (HARD #7): a non-timeout ``append_schema`` failure must also
    propagate to the caller, not be caught-and-ignored."""

    class _BoomAudit:
        async def append_schema(self, **kw: Any) -> None:
            raise RuntimeError("db down")

    with pytest.raises(RuntimeError, match="db down"):
        await EgressBrokerAuditor(_BoomAudit()).record_broker_success(
            destination="gateway:8889", extraction_id="ext-1", socket_ordinal=0
        )
    # The hookpoint must never dispatch when the row was never persisted.
    assert _fake_invoke == []
