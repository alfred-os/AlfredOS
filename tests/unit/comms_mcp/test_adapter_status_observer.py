"""G6-2a (#288): core-side adapter-status observer/auditor (Spec B §4/§6).

The observer is the core's consumer of the gateway's ``gateway.adapter.*``
status notifications. It Pydantic-validates each frame, epoch-reconciles ``up``
(the G3 anti-forgery lesson), writes one audit row per ACCEPTED transition, and
records the latest per-adapter status for ``alfred status``. A malformed /
forged-epoch / unknown-method frame is REFUSED LOUDLY — audited as
``gateway.adapter.status_rejected``, never silently dropped (Spec B §6).

These tests drive a FAKE gateway: synthetic frame dicts straight into
``observe``. No root, no launcher, no bwrap — they run on the required non-root
unit job, so the forgery-refusal contract is gated, not skipped (G2/#245
paper-gate lesson). The fake-gateway suite proves the APPLICATION-level
validation only; the carrier-auth of the live status leg (Spec A 0600 +
SO_PEERCRED + per-boot-epoch envelope) is proven by G6-2b's live-leg integration
test + the existing Spec A link-auth tests (correction #5).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.adapter_status_observer import (
    _MAX_CRASH_DETAIL_LEN,
    AdapterStatusAuditWriteError,
    AdapterStatusObserver,
    AdapterStatusSnapshot,
)
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_EPOCH = "a" * 32
_OTHER_EPOCH = "b" * 32
_FIXED_NOW = datetime(2026, 6, 19, 12, 0, 0, tzinfo=UTC)


class _FakeAudit:
    """Captures append_schema calls so tests assert the audited contract."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


def _make_observer(
    audit: _FakeAudit, *, reconciler: CrashIncidentReconciler | None = None
) -> AdapterStatusObserver:
    return AdapterStatusObserver(
        audit=audit,  # structural _AuditWriterLike
        expected_epoch=lambda: _EPOCH,
        now=lambda: _FIXED_NOW,
        reconciler=reconciler if reconciler is not None else CrashIncidentReconciler(),
    )


@pytest.mark.asyncio
async def test_up_with_matching_epoch_is_accepted_and_audited() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.up"
    assert row["schema_name"] == "GATEWAY_ADAPTER_UP_FIELDS"
    assert row["result"] == "success"
    # core-owned control frame → T0 (matches daemon.lifecycle.* rows; correction #3).
    assert row["trust_tier_of_trigger"] == "T0"
    # trace_id is the per-adapter correlation handle, not the timestamp (correction #4).
    assert row["trace_id"] == "discord"
    assert row["subject"] == {
        "adapter_id": "discord",
        "epoch": _EPOCH,
        "occurred_at": _FIXED_NOW.isoformat(),
        # SEC-01 (#288): the up subject records the incarnation being STARTED
        # (defaulted to 0 here — this frame omits the field).
        "host_restart_seq": 0,
    }
    snap = obs.latest("discord")
    assert isinstance(snap, AdapterStatusSnapshot)
    assert snap.state == "up"


@pytest.mark.asyncio
async def test_down_crashed_breaker_open_each_audit_their_family() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.down", {"adapter_id": "discord", "reason": "operator"})
    await obs.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "RuntimeError", "detail": "boom"},
    )
    await obs.observe(
        "gateway.adapter.breaker_open",
        {"adapter_id": "discord", "retry_after_seconds": 30},
    )

    events = [r["event"] for r in audit.rows]
    assert events == [
        "gateway.adapter.down",
        "gateway.adapter.crashed",
        "gateway.adapter.breaker_open",
    ]
    crashed = audit.rows[1]["subject"]
    assert isinstance(crashed, dict)
    assert "detail" not in crashed  # raw wire field never persisted
    assert "detail_redacted" in crashed  # correction #2: detail_redacted, not redacted_detail
    assert obs.latest("discord").state == "breaker_open"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_crashed_subject_carries_host_restart_seq_and_incident_fields() -> None:
    audit = _FakeAudit()
    reconciler = CrashIncidentReconciler()
    obs = _make_observer(audit, reconciler=reconciler)
    await obs.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "boom",
            "host_restart_seq": 2,
        },
    )
    subject = audit.rows[-1]["subject"]
    assert isinstance(subject, dict)
    assert audit.rows[-1]["event"] == "gateway.adapter.crashed"
    assert subject["host_restart_seq"] == 2
    assert subject["crash_signal_source"] == "gateway"
    assert subject["crash_incident_id"]
    assert subject["duplicate"] is False
    # The reconciler now holds one incident at incarnation 2.
    assert len(reconciler.incidents("discord")) == 1
    assert reconciler.incidents("discord")[0].host_restart_seq == 2


@pytest.mark.asyncio
async def test_up_advances_incarnation_for_later_child_crash() -> None:
    audit = _FakeAudit()
    reconciler = CrashIncidentReconciler()
    obs = _make_observer(audit, reconciler=reconciler)
    # An accepted up at incarnation 1 (epoch matches) advances the reconciler — so a
    # subsequent in-child crash (wired in Task 8) would tag to incarnation 1, not 0.
    await obs.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 1},
    )
    # No crash yet -> no incidents, but the reconciler's current incarnation advanced:
    # a child crash now folds at seq 1.
    assert reconciler.incidents("discord") == ()
    child = reconciler.observe_child_crash(adapter_id="discord")
    assert child.host_restart_seq == 1


@pytest.mark.asyncio
async def test_duplicate_gateway_crash_through_observer_still_writes_a_second_row() -> None:
    """TE-1 (HIGH): a DUPLICATE gateway crash through the REAL wired observer STILL audits.

    The reconciler flags the second crash ``duplicate=True`` (one incident), but the
    observer writes a SECOND audit row regardless — hard rule #7: a replayed signal is
    NEVER suppressed, it is marked. A regression that gated the write on
    ``not fold.duplicate`` would silently drop this row and this test would catch it.
    """
    audit = _FakeAudit()
    reconciler = CrashIncidentReconciler()
    obs = _make_observer(audit, reconciler=reconciler)
    frame = {
        "adapter_id": "discord",
        "error_class": "RuntimeError",
        "detail": "boom",
        "host_restart_seq": 0,
    }
    await obs.observe("gateway.adapter.crashed", frame)
    await obs.observe("gateway.adapter.crashed", frame)

    crash_rows = [r for r in audit.rows if r["event"] == "gateway.adapter.crashed"]
    # TWO loud rows (never dropped) ...
    assert len(crash_rows) == 2
    # ... but ONE incident, and the second row is FLAGGED as the replay.
    first_subject = crash_rows[0]["subject"]
    second_subject = crash_rows[1]["subject"]
    assert isinstance(first_subject, dict)
    assert isinstance(second_subject, dict)
    assert first_subject["duplicate"] is False
    assert second_subject["duplicate"] is True
    assert first_subject["crash_incident_id"] == second_subject["crash_incident_id"]
    assert len(reconciler.incidents("discord")) == 1


@pytest.mark.asyncio
async def test_crashed_detail_is_dlp_scrubbed_and_length_bounded() -> None:
    """correction #1: a synthetic secret in ``detail`` does NOT survive into
    the persisted ``detail_redacted``, AND over-long detail is truncated.

    A no-op scrub fails the first assertion; an unbounded copy fails the second.
    The synthetic secret is built from fragments at runtime (push-protection rule)
    so no token-shaped literal lands in source.
    """
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # ``sk-`` + 40 chars is the api-key shape redact_secret_shapes catches.
    secret = "sk-" + ("A" * 40)
    long_detail = secret + (" filler" * 500)

    await obs.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "RuntimeError", "detail": long_detail},
    )

    subject = audit.rows[0]["subject"]
    assert isinstance(subject, dict)
    redacted = subject["detail_redacted"]
    assert isinstance(redacted, str)
    # The secret must NOT survive the scrub (a no-op scrub fails here).
    assert secret not in redacted
    # The persisted value is length-bounded by the existing crash-detail cap.
    assert len(redacted) <= _MAX_CRASH_DETAIL_LEN


@pytest.mark.asyncio
async def test_crashed_detail_secret_straddling_length_bound_does_not_leak() -> None:
    """A secret straddling the _MAX_CRASH_DETAIL_LEN boundary must not leak a prefix.

    REGRESSION GUARD for the redact-order security nuance: with bound-then-redact
    (``redact_secret_shapes(detail[:LEN])``) a secret that begins just before the
    cap is truncated mid-token, leaving an unredacted prefix the shape-regex no
    longer matches — a partial-secret leak. The correct order is redact-then-bound
    (``redact_secret_shapes(detail)[:LEN]``): the whole secret is replaced before
    truncation, so no fragment can survive. This test FAILS under bound-then-redact.
    """
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # ``sk-`` + 40 chars is the api-key shape; place it so it STRADDLES the cap:
    # the 6-char ``sk-AAA`` head lands inside the bound, the tail past it. The filler
    # ends in a space so the shape-regex has the word boundary it needs BEFORE the
    # secret (a realistic delimited crash detail) — isolating the redact-vs-bound
    # ORDER as the property under test. Filler carries no ``sk-`` so any surviving
    # ``sk-`` came from the straddling secret (which bound-then-redact would leave).
    secret = "sk-" + ("A" * 40)
    filler = "x" * (_MAX_CRASH_DETAIL_LEN - 6 - 1) + " "
    straddling_detail = filler + secret

    await obs.observe(
        "gateway.adapter.crashed",
        {"adapter_id": "discord", "error_class": "RuntimeError", "detail": straddling_detail},
    )

    subject = audit.rows[0]["subject"]
    assert isinstance(subject, dict)
    redacted = subject["detail_redacted"]
    assert isinstance(redacted, str)
    # No fragment of the api-key shape survives (bound-then-redact would leave "sk-AAA").
    assert "sk-" not in redacted
    assert len(redacted) <= _MAX_CRASH_DETAIL_LEN


@pytest.mark.asyncio
async def test_malformed_frame_is_refused_and_audited_not_dropped() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # Missing required ``epoch`` for ``up``.
    await obs.observe("gateway.adapter.up", {"adapter_id": "discord"})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    assert row["schema_name"] == "GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS"
    assert row["result"] == "refused"
    assert row["trust_tier_of_trigger"] == "T0"
    subject = row["subject"]
    assert isinstance(subject, dict)
    assert subject["rejection_reason"] == "malformed_frame"
    assert subject["rejected_method"] == "gateway.adapter.up"
    # No accepted state recorded for a refused frame.
    assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_forged_epoch_up_is_refused_and_audited() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # Well-formed frame, but the epoch is a different (stale/foreign) core boot.
    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _OTHER_EPOCH})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    assert row["result"] == "refused"
    subject = row["subject"]
    assert isinstance(subject, dict)
    assert subject["rejection_reason"] == "epoch_mismatch"
    assert subject["adapter_id"] == "discord"
    # trace_id correlates to the parsed adapter on the epoch-mismatch path.
    assert row["trace_id"] == "discord"
    # The forged liveness assertion did NOT mark the adapter up.
    assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_unknown_method_is_refused_and_audited() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.teleport", {"adapter_id": "discord"})

    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["event"] == "gateway.adapter.status_rejected"
    subject = row["subject"]
    assert isinstance(subject, dict)
    assert subject["rejection_reason"] == "unknown_method"
    assert subject["rejected_method"] == "gateway.adapter.teleport"
    # Unparseable adapter kind is recorded as "" — never as a known kind.
    assert subject["adapter_id"] == ""


@pytest.mark.asyncio
async def test_unknown_adapter_kind_in_known_method_is_malformed_refusal() -> None:
    audit = _FakeAudit()
    obs = _make_observer(audit)

    # "telegram" is not in adapter_kind for this build → AdapterId rejects it.
    await obs.observe("gateway.adapter.up", {"adapter_id": "telegram", "epoch": _EPOCH})

    row = audit.rows[0]
    subject = row["subject"]
    assert isinstance(subject, dict)
    assert row["event"] == "gateway.adapter.status_rejected"
    assert subject["rejection_reason"] == "malformed_frame"
    # adapter_id could not be validated → "" in the audit row.
    assert subject["adapter_id"] == ""


@pytest.mark.asyncio
async def test_params_not_a_mapping_is_malformed_refusal() -> None:
    """correction #7(a): params that is not a Mapping (a list / None) → malformed."""
    audit = _FakeAudit()
    obs = _make_observer(audit)

    for bad_params in ([1, 2, 3], None, "string", 42):
        audit.rows.clear()
        await obs.observe("gateway.adapter.up", bad_params)
        row = audit.rows[0]
        subject = row["subject"]
        assert isinstance(subject, dict)
        assert row["event"] == "gateway.adapter.status_rejected"
        assert subject["rejection_reason"] == "malformed_frame"
        assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_epoch_smuggled_onto_non_up_frame_is_malformed_refusal() -> None:
    """correction #7(b): an ``epoch`` smuggled onto a non-``up`` frame is
    rejected by ``extra="forbid"`` → malformed (only ``up`` is epoch-bound)."""
    audit = _FakeAudit()
    obs = _make_observer(audit)

    smuggled = [
        ("gateway.adapter.down", {"adapter_id": "discord", "reason": "operator", "epoch": _EPOCH}),
        (
            "gateway.adapter.crashed",
            {"adapter_id": "discord", "error_class": "X", "detail": "", "epoch": _EPOCH},
        ),
        (
            "gateway.adapter.breaker_open",
            {"adapter_id": "discord", "retry_after_seconds": 1, "epoch": _EPOCH},
        ),
    ]
    for method, params in smuggled:
        audit.rows.clear()
        await obs.observe(method, params)
        row = audit.rows[0]
        subject = row["subject"]
        assert isinstance(subject, dict)
        assert row["event"] == "gateway.adapter.status_rejected"
        assert subject["rejection_reason"] == "malformed_frame"
        assert subject["rejected_method"] == method
        assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_snapshot_overwrite_last_accepted_wins() -> None:
    """correction #7(c): up then down for the same adapter → latest() is down."""
    audit = _FakeAudit()
    obs = _make_observer(audit)

    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH})
    assert obs.latest("discord").state == "up"  # type: ignore[union-attr]

    await obs.observe("gateway.adapter.down", {"adapter_id": "discord", "reason": "operator"})
    snap = obs.latest("discord")
    assert isinstance(snap, AdapterStatusSnapshot)
    assert snap.state == "down"


def test_latest_is_none_for_never_seen_adapter() -> None:
    obs = _make_observer(_FakeAudit())
    assert obs.latest("tui") is None


class _RaisingAudit:
    """An audit writer whose ``append_schema`` always fails.

    Proves the observer propagates a genuine audit-WRITE failure LOUDLY (CLAUDE.md
    hard rule #7) instead of swallowing it — distinct from a bad FRAME, which is
    refused+audited without raising. Guards the documented fail-loud contract that
    ``_FakeAudit`` (always succeeds) cannot exercise.
    """

    async def append_schema(self, **kwargs: object) -> None:
        raise RuntimeError("audit backend down")


def _observer_with_raising_audit() -> AdapterStatusObserver:
    return AdapterStatusObserver(
        audit=_RaisingAudit(),  # structural _AuditWriterLike
        expected_epoch=lambda: _EPOCH,
        now=lambda: _FIXED_NOW,
        reconciler=CrashIncidentReconciler(),
    )


@pytest.mark.asyncio
async def test_audit_write_failure_propagates_on_accept() -> None:
    """An accepted frame whose audit append fails must RAISE (fail-loud, hard rule #7).

    SEC-1 (#288): the raise is the DISTINCT typed
    :class:`AdapterStatusAuditWriteError` (so the live runner can re-raise it past its
    blanket catch-and-continue), with the raw backend error preserved as the cause.
    """
    obs = _observer_with_raising_audit()
    with pytest.raises(AdapterStatusAuditWriteError) as excinfo:
        await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH})
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "audit backend down"
    # The failed write means no snapshot was recorded (append precedes the record).
    assert obs.latest("discord") is None


@pytest.mark.asyncio
async def test_audit_write_failure_propagates_on_reject() -> None:
    """A refused frame whose status_rejected audit append fails must also RAISE typed."""
    obs = _observer_with_raising_audit()
    with pytest.raises(AdapterStatusAuditWriteError) as excinfo:
        await obs.observe("gateway.adapter.teleport", {"adapter_id": "discord"})
    assert isinstance(excinfo.value.__cause__, RuntimeError)


@pytest.mark.asyncio
async def test_refusal_leaves_an_existing_snapshot_untouched() -> None:
    """A forged/refused frame must NOT clobber a previously-accepted snapshot."""
    audit = _FakeAudit()
    obs = _make_observer(audit)
    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _EPOCH})
    accepted = obs.latest("discord")
    assert accepted is not None and accepted.state == "up"
    # A forged-epoch up for the same adapter is refused...
    await obs.observe("gateway.adapter.up", {"adapter_id": "discord", "epoch": _OTHER_EPOCH})
    # ...and the prior accepted snapshot still stands (no downgrade-by-forgery).
    snap = obs.latest("discord")
    assert snap is not None and snap.state == "up"
