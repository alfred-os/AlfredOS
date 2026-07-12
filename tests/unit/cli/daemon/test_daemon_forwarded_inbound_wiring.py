"""The daemon wires the fail-closed forwarded-inbound registry onto the gateway leg.

Spec B G6-7-4 Task 5 (#309). The HOST runner over the GATEWAY leg builds a
per-kind collaborator REGISTRY + the per-boot ``GatewayForwardedInboundReceiver``,
injects the receiver into the gateway-leg runner's disposition, and binds the
PER-CONNECTION ack tracker onto it (the SAME instance the inbound handler + ack-emit
timer use).

Invariants under proof (hermetic — NO real Redis / subprocess / socket):

* the per-kind registry builder yields a NON-None ``SubPayloadPromoter`` for the
  classifier-bearing ``discord`` kind and ONE long-lived ``pre_resolution_limiter`` per
  kind (the SAME instance across two ``receive()``-driven dispatches — sec-003);
* a ``discord`` entry that would get a None promoter REFUSES BOOT (the registry builder
  raises; the call site refuses with the audited ``comms_promoter_misconfigured``
  reason), never deferring to a per-message ``PromoterRequiredError``;
* the GATEWAY-leg runner (the ``with_credential_resolver=True`` socket carrier) is built
  WITH the receiver; the daemon-spawned stdio path is NOT;
* at accept, the receiver's ``set_ack_tracker`` is bound with the SAME
  ``BoundedSeqAckTracker`` instance bound to the inbound handler (identity);
* the default / ``alfred_comms_test`` boot path stays unchanged (the existing daemon
  boot tests stay green — pinned here by a focused stdio-receiver-None assert).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._comms_boot import (
    _build_forwarded_inbound_registry,
    _ForwardedInboundRegistryMisconfiguredError,
)
from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND
from alfred.comms_mcp.forwarded_inbound_receiver import GatewayForwardedInboundReceiver
from alfred.comms_mcp.inbound import _PreResolutionLimiter
from alfred.comms_mcp.sub_payload_promotion import SubPayloadPromoter
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.hooks.registry import HookRegistry

from .conftest import FakeAuditWriter, FakeSupervisor
from .test_daemon_comms_socket import _CapturingSupervisor, _ClosingTransport
from .test_daemon_comms_spawn import _ENABLED_ADAPTER, _patch_comms_seams, quarantine_registry

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint

_TUI_ADAPTER = "alfred_tui"


class _Store:
    """A loose content-store double (the promoter only needs ``write``)."""

    async def write(  # pragma: no cover - the registry-builder unit never promotes a body
        self, *, handle_id: str, body: bytes, source_url: str
    ) -> object:
        raise AssertionError("the registry-builder unit never promotes a body")


class _NeverCommittedStore:
    """A G0 idempotency store double: the dispatched edge only reads + commits once."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        return True

    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        return False


class _StubAttemptStore:
    """A forwarded-dispatch attempt ledger double (G6-7-5).

    The wiring tests inject a fake ``dispatch`` so the ceiling never engages; this
    only satisfies the receiver's required ``attempt_store`` collaborator shape.
    """

    async def increment(self, *, adapter_id: str, inbound_id: str) -> int:
        return 1

    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int:
        return 0


def _build_registry() -> Any:
    return _build_forwarded_inbound_registry(
        graph_content_store=_Store(),
        resolver_bridge=object(),
        inbound_orchestrator=object(),
        burst_limiter=object(),
        secret_broker=object(),
    )


# --- registry builder: promoter + long-lived limiter ------------------------------


def test_registry_discord_entry_has_promoter_and_limiter() -> None:
    """The ``discord`` entry carries a real promoter + a ``_PreResolutionLimiter``."""
    assert REQUIRED_CLASSIFIERS_BY_KIND.get("discord")  # premise: classifier-bearing
    registry = _build_registry()

    collab = registry["discord"]
    assert isinstance(collab.sub_payload_promoter, SubPayloadPromoter)
    assert isinstance(collab.pre_resolution_limiter, _PreResolutionLimiter)


@pytest.mark.asyncio
async def test_pre_resolution_limiter_is_long_lived_across_dispatches() -> None:
    """The SAME limiter instance reaches the dispatch on two ``receive()`` calls (sec-003).

    A per-call limiter would silently reset the sliding window every message and
    disable the DoS gate. Drive the REAL receiver over the built registry with a fake
    dispatch that captures the ``pre_resolution_limiter`` it was handed, and assert the
    two captures are the SAME object.
    """
    registry = _build_registry()
    seen_limiters: list[object] = []

    async def _capture_dispatch(_notification: object, **kwargs: object) -> None:
        seen_limiters.append(kwargs["pre_resolution_limiter"])

    receiver = GatewayForwardedInboundReceiver(
        registry=registry,
        idempotency_store=_NeverCommittedStore(),
        attempt_store=_StubAttemptStore(),
        audit_writer=FakeAuditWriter(),  # type: ignore[arg-type]
        dispatch=_capture_dispatch,
    )
    # A well-formed discord notification body the gateway forwards (the canonical
    # comms-MCP test helper builds every required field; adapter_id matches the
    # envelope routing key so re-parse's F3 equality holds).
    from tests.unit.comms_mcp._inbound_spies import make_notification

    body = make_notification(adapter_id="discord", body={"content": "hi"}).model_dump_json()
    params = {"adapter_id": "discord", "body": body}

    await receiver.receive(params=params, wire_seq=0)
    await receiver.receive(params=params, wire_seq=1)

    assert len(seen_limiters) == 2
    assert seen_limiters[0] is seen_limiters[1]
    assert seen_limiters[0] is registry["discord"].pre_resolution_limiter


def test_registry_builder_refuses_none_promoter_for_classifier_bearing_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``discord`` entry that gets a None promoter RAISES (boot fail-close), not defer."""

    def _none_factory(*, adapter_kind: str, content_store: object) -> None:
        return None

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._build_sub_payload_promoter", _none_factory)

    with pytest.raises(_ForwardedInboundRegistryMisconfiguredError) as excinfo:
        _build_registry()
    assert excinfo.value.adapter_kind == "discord"


# --- boot wiring: gateway leg gets the receiver; the registry fail-close refuses boot --


class _ReceiverCapturingRunner:
    """A socket-carrier ``CommsPluginRunner`` double that records its receiver kwarg."""

    instances: ClassVar[list[_ReceiverCapturingRunner]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.forwarded_inbound_receiver = kwargs.get("forwarded_inbound_receiver")
        _ReceiverCapturingRunner.instances.append(self)

    async def start_and_handshake(self) -> None:
        return None

    async def pump(self) -> None:  # pragma: no cover - not driven in these cases
        return None

    async def send_notification(self, method: str, params: Any) -> None:  # pragma: no cover
        return None

    async def send_request(self, method: str, params: Any) -> Any:  # pragma: no cover
        return {}


class _ImmediateAcceptListener:
    """Listener whose ``accept()`` resolves at once with a closeable transport."""

    instances: ClassVar[list[_ImmediateAcceptListener]] = []

    def __init__(self, *, adapter_id: str, on_peer_rejected: Any = None) -> None:
        self.adapter_id = adapter_id
        self.on_peer_rejected = on_peer_rejected
        self.transport = _ClosingTransport()
        self.aclose_calls = 0
        _ImmediateAcceptListener.instances.append(self)

    async def bind(self) -> None:
        return None

    async def accept(self) -> Any:
        return self.transport

    async def aclose(self) -> None:
        self.aclose_calls += 1


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.O_NOFOLLOW (not exposed by CPython on Windows)",
)
def test_gateway_leg_runner_built_with_forwarded_receiver(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """Driving ``_accept_and_pump`` builds the gateway-leg runner WITH the receiver,
    and binds the SAME ack tracker onto the receiver as the inbound handler (identity).
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    _ReceiverCapturingRunner.instances.clear()
    _ImmediateAcceptListener.instances.clear()
    _CapturingSupervisor.captured.clear()
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.CommsSocketListener", _ImmediateAcceptListener
    )
    monkeypatch.setattr("alfred.cli.daemon._comms_boot.CommsPluginRunner", _ReceiverCapturingRunner)
    monkeypatch.setattr("alfred.cli.daemon._commands.Supervisor", _CapturingSupervisor)

    # Capture both ack-tracker bindings so the identity invariant can be asserted.
    from alfred.comms_mcp.forwarded_inbound_receiver import GatewayForwardedInboundReceiver as _Recv
    from alfred.comms_mcp.handlers import InboundMessageHandler

    receiver_trackers: list[object] = []
    handler_trackers: list[object] = []
    orig_recv_set = _Recv.set_ack_tracker
    orig_handler_set = InboundMessageHandler.set_ack_tracker

    def _spy_recv(self: Any, ack_tracker: Any) -> None:
        receiver_trackers.append(ack_tracker)
        orig_recv_set(self, ack_tracker)

    def _spy_handler(self: Any, ack_tracker: Any) -> None:
        handler_trackers.append(ack_tracker)
        orig_handler_set(self, ack_tracker)

    monkeypatch.setattr(_Recv, "set_ack_tracker", _spy_recv)
    monkeypatch.setattr(InboundMessageHandler, "set_ack_tracker", _spy_handler)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Boot captured exactly one supervised accept-task; drive it to build the runner.
    assert len(_CapturingSupervisor.captured) == 1
    accept_coro = _CapturingSupervisor.captured[0]

    async def _drive() -> None:
        await asyncio.wait_for(asyncio.ensure_future(accept_coro), timeout=1.0)

    asyncio.run(_drive())

    # The gateway-leg runner was built WITH the per-boot receiver.
    assert len(_ReceiverCapturingRunner.instances) == 1
    runner = _ReceiverCapturingRunner.instances[0]
    assert isinstance(runner.forwarded_inbound_receiver, _Recv)

    # G6-7-5 Task 7 (#309): the boot graph threaded a REAL durable attempt ledger into
    # the receiver — the Postgres-backed ADR-0039 item-4b poison-ceiling store, NOT a
    # fake. Its constructor only captures the ``session_scope`` callable (no DB at build
    # time), so the Postgres-less boot harness still constructs it. The store is a
    # builder-local threaded into the receiver, never a ``_CommsBootGraph`` field — so
    # ``aclose`` cannot reach (and so never disposes) it; the shared DSN-cached engine is
    # reaped only at process exit (pinned by the promoter-wiring module's
    # ``test_graph_aclose_skips_close_for_non_content_store``).
    from alfred.memory.forwarded_dispatch_attempts import PostgresForwardedDispatchAttemptStore

    assert isinstance(
        runner.forwarded_inbound_receiver._attempt_store, PostgresForwardedDispatchAttemptStore
    )

    # The receiver's ack tracker is the SAME instance bound to the inbound handler.
    assert len(receiver_trackers) == 1
    assert len(handler_trackers) == 1
    assert isinstance(receiver_trackers[0], BoundedSeqAckTracker)
    assert receiver_trackers[0] is handler_trackers[0]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.O_NOFOLLOW (not exposed by CPython on Windows)",
)
def test_arm_time_preview_warning_emitted_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """devex HIGH-1 (#309): ONE operator-facing preview-status warning at arm-time.

    The gateway-leg socket listener is one-shot per boot, so the
    ``comms.gateway.forwarded_inbound_preview`` warning must fire EXACTLY once when the
    forwarded-inbound receiver is armed (NOT per-frame / per-connection). The message is
    ``t()``-routed (i18n hard rule #1) — it carries the resolved preview-status string,
    never a bare key.
    """
    import structlog.testing

    from alfred.i18n import t

    del quarantine_registry
    del patch_quarantine_child_spawn
    _ReceiverCapturingRunner.instances.clear()
    _ImmediateAcceptListener.instances.clear()
    _CapturingSupervisor.captured.clear()
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.CommsSocketListener", _ImmediateAcceptListener
    )
    monkeypatch.setattr("alfred.cli.daemon._comms_boot.CommsPluginRunner", _ReceiverCapturingRunner)
    monkeypatch.setattr("alfred.cli.daemon._commands.Supervisor", _CapturingSupervisor)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output
    assert len(_CapturingSupervisor.captured) == 1
    accept_coro = _CapturingSupervisor.captured[0]

    with structlog.testing.capture_logs() as logs:

        async def _drive() -> None:
            await asyncio.wait_for(asyncio.ensure_future(accept_coro), timeout=1.0)

        asyncio.run(_drive())

    preview = [e for e in logs if e.get("event") == "comms.gateway.forwarded_inbound_preview"]
    # Fires EXACTLY once at arm-time — never per-frame / per-connection.
    assert len(preview) == 1
    assert preview[0]["log_level"] == "warning"
    # ``t()``-routed: the resolved preview string, never a bare key.
    expected = t("gateway.adapter.forwarded_inbound.preview")
    assert preview[0]["message"] == expected
    assert preview[0]["message"] != "gateway.adapter.forwarded_inbound.preview"
    assert "PREVIEW" in preview[0]["message"]


def test_boot_refuses_when_forwarded_registry_promoter_misconfigured(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A None promoter for the ``discord`` forwarded kind REFUSES boot (exit 2).

    The registry build happens inside the comms-graph build, so a misconfig there must
    refuse the boot fail-closed (audited ``comms_promoter_misconfigured``), never park a
    graph that would trip a per-message ``PromoterRequiredError``. Force the
    (deterministic) factory to return None so the forwarded registry's classifier-bearing
    ``discord`` kind hits the fail-close.
    """
    del quarantine_registry
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    def _none_factory(*, adapter_kind: str, content_store: object) -> None:
        return None

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._build_sub_payload_promoter", _none_factory)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2, result.output

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # Fail-closed: no pump registered (the refusal fired in the graph build).
    assert sup.registered_tasks == []
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "comms_promoter_misconfigured" in reasons
    # No (lying) completion row — the refusal happened before the completion signal.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The live quarantine child was reaped despite the build failing (CR #255 posture).
    assert patch_quarantine_child_spawn == [] or patch_quarantine_child_spawn[0].aclose_calls >= 1
