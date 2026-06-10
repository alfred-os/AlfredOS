"""Reference plugin pure handlers + the inject_inbound production gate (Tasks 50-51).

The full-lifecycle reference adapter implements the eight ADR-0024 wire methods
and emits the four host-bound notifications on internal test triggers. The
``inject_inbound`` trigger is the highest-risk surface: it manufactures an
inbound platform message, so it MUST refuse outside ``ALFRED_ENV=test`` — a
``comms.test_injection_refused`` refusal frame + a raised
:class:`TestInjectionRefusedError` (plan §10 risk row / Task 51).

These tests drive the plugin's pure handler functions directly (no subprocess)
so the wire-shape + the production gate are covered without spawning a process.
"""

from __future__ import annotations

import pytest

from plugins.alfred_comms_test import main


def test_lifecycle_start_returns_ok() -> None:
    result = main.handle_lifecycle_start({"adapter_id": "alfred_comms_test"})
    assert result["ok"] is True
    # M2 forward-contract: the reference plugin emits plugin_version (spec §8.1),
    # and the host's LifecycleStartResult schema (extra="forbid") must admit it.
    from alfred.comms_mcp.protocol import LifecycleStartResult

    validated = LifecycleStartResult.model_validate(result)
    assert validated.plugin_version == result["plugin_version"]


def test_lifecycle_stop_reports_flushed_count() -> None:
    main.reset_state()
    result = main.handle_lifecycle_stop({"adapter_id": "alfred_comms_test", "reason": "shutdown"})
    assert result["ok"] is True
    assert result["flushed_messages"] == 0


def test_adapter_health_ok_after_start() -> None:
    main.reset_state()
    main.handle_lifecycle_start({"adapter_id": "alfred_comms_test"})
    health = main.handle_adapter_health({"adapter_id": "alfred_comms_test"})
    assert health["ok"] is True
    assert health["queue_depth"] == 0
    assert health["error_count"] == 0


def test_outbound_message_buffers_and_reports_delivered() -> None:
    main.reset_state()
    result = main.handle_outbound_message(
        {
            "adapter_id": "alfred_comms_test",
            "target_platform_id": "discord:123",
            "body": "hi",
        }
    )
    assert result["outcome"] == "delivered"
    assert main.outbound_buffer_depth() == 1


def test_adapter_health_reports_real_queue_depth_after_sends() -> None:
    # CR #232: ``queue_depth`` must reflect the REAL pending-outbound buffer, not
    # a hardcoded 0 -- otherwise health lies after the first send.
    main.reset_state()
    main.handle_lifecycle_start({"adapter_id": "alfred_comms_test"})
    for i in range(3):
        main.handle_outbound_message(
            {"adapter_id": "alfred_comms_test", "target_platform_id": "discord:1", "body": f"m{i}"}
        )
    health = main.handle_adapter_health({"adapter_id": "alfred_comms_test"})
    assert health["queue_depth"] == 3
    # lifecycle.stop drains the same buffer it reports as flushed_messages.
    stop = main.handle_lifecycle_stop({"adapter_id": "alfred_comms_test"})
    assert stop["flushed_messages"] == 3
    assert main.handle_adapter_health({"adapter_id": "alfred_comms_test"})["queue_depth"] == 0


def test_build_inbound_notification_shape() -> None:
    frame = main.build_inbound_notification({"content": "hello"})
    assert frame["jsonrpc"] == "2.0"
    assert frame["method"] == "inbound.message"
    assert "id" not in frame  # a notification, never a request
    params = frame["params"]
    assert params["adapter_id"] == "alfred_comms_test"
    assert params["body"] == {"content": "hello"}
    assert params["addressing_signal"] == "dm"


def test_inject_inbound_allowed_in_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_ENV", "test")
    frame = main.inject_inbound({"content": "hello"})
    assert frame["method"] == "inbound.message"


def test_inject_inbound_allowed_in_development_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_ENV", "development")
    frame = main.inject_inbound({"content": "hello"})
    assert frame["method"] == "inbound.message"


def test_inject_inbound_refused_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_ENV", "production")
    # The gate also consults ALFRED_ENVIRONMENT (daemon control surface); clear it
    # so a dev/test value in the ambient env cannot open the gate under test.
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    with pytest.raises(main.TestInjectionRefusedError):
        main.inject_inbound({"content": "hello"})


def test_inject_inbound_allowed_via_alfred_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A daemon-spawned adapter is gated on ALFRED_ENVIRONMENT (the scrubbed-env signal).

    The daemon's scrubbed comms-child allowlist drops ALFRED_ENV but keeps
    ALFRED_ENVIRONMENT, so the gate MUST accept a dev/test value from the latter.
    """
    monkeypatch.delenv("ALFRED_ENV", raising=False)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    frame = main.inject_inbound({"content": "hello"})
    assert frame["method"] == "inbound.message"


def test_inject_inbound_refused_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset env (the common production default) MUST fail closed.

    A missing var must never be read as "permitted" — the gate fabricates
    inbound platform traffic, so the absence of an explicit dev/test signal on
    EVERY consulted var is a refusal, not a default-allow.
    """
    monkeypatch.delenv("ALFRED_ENV", raising=False)
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    with pytest.raises(main.TestInjectionRefusedError):
        main.inject_inbound({"content": "hello"})


def test_inject_inbound_refused_when_env_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty signal on every var is indistinguishable from unset and must refuse."""
    monkeypatch.setenv("ALFRED_ENV", "")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "")
    with pytest.raises(main.TestInjectionRefusedError):
        main.inject_inbound({"content": "hello"})


def test_test_injection_refused_carries_event_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """The refusal names the ``comms.test_injection_refused`` event for the host."""
    monkeypatch.setenv("ALFRED_ENV", "production")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    try:
        main.inject_inbound({"content": "hello"})
    except main.TestInjectionRefusedError as exc:
        assert exc.event == "comms.test_injection_refused"
    else:  # pragma: no cover - the raise above is asserted
        pytest.fail("expected TestInjectionRefusedError")
