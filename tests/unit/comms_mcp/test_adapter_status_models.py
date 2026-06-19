"""G6-2a (#288): gateway.adapter.* status wire models.

These are the gateway -> core adapter-status notifications (Spec B §3). They
mirror the existing comms_mcp wire discipline: frozen, ``extra="forbid"``,
closed-vocab ``adapter_id``, and the ``ReadyNotification`` 32-hex epoch rule on
the liveness-asserting ``up`` frame. A typo'd or smuggled wire field is a loud
``ValidationError`` here, at the boundary — never silent drift.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_BREAKER_OPEN,
    GATEWAY_ADAPTER_CRASHED,
    GATEWAY_ADAPTER_DOWN,
    GATEWAY_ADAPTER_UP,
    AdapterBreakerOpenNotification,
    AdapterCrashedNotification,
    AdapterDownNotification,
    AdapterUpNotification,
)

_EPOCH = "0" * 32  # 32 lowercase hex chars — the ReadyNotification rule.


def test_method_name_constants_are_canonical() -> None:
    assert GATEWAY_ADAPTER_UP == "gateway.adapter.up"
    assert GATEWAY_ADAPTER_DOWN == "gateway.adapter.down"
    assert GATEWAY_ADAPTER_CRASHED == "gateway.adapter.crashed"
    assert GATEWAY_ADAPTER_BREAKER_OPEN == "gateway.adapter.breaker_open"


def test_up_accepts_known_adapter_and_valid_epoch() -> None:
    model = AdapterUpNotification(adapter_id="discord", epoch=_EPOCH)
    assert model.adapter_id == "discord"
    assert model.epoch == _EPOCH


def test_up_rejects_unknown_adapter_kind() -> None:
    with pytest.raises(ValidationError):
        AdapterUpNotification(adapter_id="telegram", epoch=_EPOCH)


def test_up_rejects_malformed_epoch() -> None:
    for bad in ("", "Z" * 32, "0" * 31, "0" * 33, "00FF" + "0" * 28):
        with pytest.raises(ValidationError):
            AdapterUpNotification(adapter_id="discord", epoch=bad)


def test_models_are_frozen_and_forbid_extra() -> None:
    up = AdapterUpNotification(adapter_id="discord", epoch=_EPOCH)
    with pytest.raises(ValidationError):
        up.adapter_id = "tui"  # type: ignore[misc]  # frozen
    with pytest.raises(ValidationError):
        AdapterUpNotification(adapter_id="discord", epoch=_EPOCH, smuggled="x")  # type: ignore[call-arg]


def test_down_carries_closed_reason_vocab() -> None:
    model = AdapterDownNotification(adapter_id="discord", reason="operator")
    assert model.reason == "operator"
    with pytest.raises(ValidationError):
        AdapterDownNotification(adapter_id="discord", reason="meltdown")  # type: ignore[arg-type]


def test_crashed_requires_nonempty_error_class() -> None:
    AdapterCrashedNotification(adapter_id="discord", error_class="RuntimeError", detail="")
    with pytest.raises(ValidationError):
        AdapterCrashedNotification(adapter_id="discord", error_class="", detail="x")


def test_breaker_open_requires_nonnegative_retry() -> None:
    AdapterBreakerOpenNotification(adapter_id="discord", retry_after_seconds=0)
    with pytest.raises(ValidationError):
        AdapterBreakerOpenNotification(adapter_id="discord", retry_after_seconds=-1)


def test_status_audit_field_sets_exist_and_carry_join_keys() -> None:
    from alfred.audit.audit_row_schemas import (
        GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
        GATEWAY_ADAPTER_DOWN_FIELDS,
        GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS,
        GATEWAY_ADAPTER_UP_FIELDS,
    )

    # Every accepted-transition row joins on adapter_id + occurred_at.
    for fields in (
        GATEWAY_ADAPTER_UP_FIELDS,
        GATEWAY_ADAPTER_DOWN_FIELDS,
        GATEWAY_ADAPTER_CRASHED_FIELDS,
        GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS,
    ):
        assert "adapter_id" in fields
        assert "occurred_at" in fields

    assert GATEWAY_ADAPTER_UP_FIELDS == frozenset({"adapter_id", "epoch", "occurred_at"})
    assert GATEWAY_ADAPTER_DOWN_FIELDS == frozenset({"adapter_id", "reason", "occurred_at"})
    # ``detail_redacted`` matches the existing COMMS_ADAPTER_CRASHED_FIELDS
    # convention (correction #2): the scrubbed crash detail field name is
    # ``detail_redacted`` repo-wide.
    assert GATEWAY_ADAPTER_CRASHED_FIELDS == frozenset(
        {"adapter_id", "error_class", "detail_redacted", "occurred_at"}
    )
    assert GATEWAY_ADAPTER_BREAKER_OPEN_FIELDS == frozenset(
        {"adapter_id", "retry_after_seconds", "occurred_at"}
    )
    # The rejection row never carries the raw frame — only a closed-vocab reason
    # + the method that was refused + the observed adapter_id ("" when unparseable).
    assert GATEWAY_ADAPTER_STATUS_REJECTED_FIELDS == frozenset(
        {"adapter_id", "rejected_method", "rejection_reason", "occurred_at"}
    )
