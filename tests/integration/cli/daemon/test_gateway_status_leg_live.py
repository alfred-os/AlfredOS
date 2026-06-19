"""Spec B G6-2b-2a (#288) — the LIVE forged-status-refusal leg, NON-ROOT in-process.

Drives a synthetic gateway->core ``gateway.adapter.*`` frame through the WIRED leg
(gateway core-link transport ``send`` -> core HOST ``CommsPluginRunner``-equivalent pump
-> real ``AlfredPluginSession._on_post_handshake_method`` -> real
``AdapterStatusObserver``) and asserts the accept + reject (forged-epoch / malformed /
unknown-method) paths AND the SEC-1 audit-failure-is-loud case. This is the producer the
G6-2a paper-gate concern lacked: the security boundary now runs LIVE on the required
non-root gate (no launcher hop -> no root skip), mirroring
``test_gateway_core_link_socket_id_match.py``.

The carrier (core/HOST side) binds the socket + answers the gateway's ``lifecycle.start``
handshake, then runs a faithful HOST pump that reads each post-handshake frame and routes
it through the REAL session arm + observer — so the Task-4 prefix-routing arm + the
observer's validate/epoch-reconcile/audit/refuse are exercised end-to-end over the live
wire. The gateway (PEER side) is a REAL ``GatewayCoreLink``; it sends status frames via
the REAL ``send_status_frame`` seam.
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.bootstrap.lifecycle_epoch import (
    current_boot_epoch,
    mint_boot_epoch,
    reset_boot_epoch_for_tests,
)
from alfred.comms_mcp.adapter_status_observer import (
    AdapterStatusAuditWriteError,
    AdapterStatusObserver,
)
from alfred.comms_mcp.handlers import (
    BindingHandler,
    CrashHandler,
    InboundHandler,
    RateLimitHandler,
)
from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_UP
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.link_state import GatewayLinkState
from alfred.plugins.comms_seq_codec import SEQ_VERSION
from alfred.plugins.comms_socket_transport import (
    CommsProtocolError,
    CommsSocketListener,
    CommsSocketTransport,
)
from alfred.plugins.session import AlfredPluginSession

# AF_UNIX is the carrier; only a platform genuinely without it (Windows) cannot run this.
# Explicitly NOT a non-root skip (the paper-gate hazard this test exists to close), so the
# required non-root ``Integration`` job collects + runs it.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not hasattr(socket, "AF_UNIX"),
        reason="AF_UNIX unavailable (Windows); the gateway<->core carrier requires it",
    ),
]

_TRANSPORT_READ_EXCEPTIONS: tuple[type[BaseException], ...] = (
    BrokenPipeError,
    ConnectionResetError,
    asyncio.IncompleteReadError,
    EOFError,
    CommsProtocolError,
)

_BOUND_ADAPTER_KIND = "tui"
_DIAL_ADAPTER_ID = "tui"
_ENABLED_ADAPTER_ID = "alfred_tui"
_LIFECYCLE_START_ID = 0
_TIMEOUT_S = 10.0

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""


class _RecordingAudit:
    """Captures observer audit rows (accept + refusal) — the assertion surface."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


class _FailingAudit:
    """An audit writer whose append_schema fails — drives the SEC-1 fail-loud case."""

    async def append_schema(self, **kwargs: object) -> None:
        raise OSError("audit backend unreachable")


class _RecordingSupervisor:
    def __init__(self) -> None:
        self.restart_requests: list[dict[str, str]] = []

    async def trip_breaker(
        self, *, component_id: str, reason: str
    ) -> None:  # pragma: no cover - unused
        raise AssertionError("trip_breaker not expected on the status arm")

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None:
        self.restart_requests.append({"adapter_id": adapter_id, "reason": reason})


async def _make_observer_session(
    *, audit: object, supervisor: _RecordingSupervisor
) -> tuple[AlfredPluginSession, AdapterStatusObserver]:
    """A REAL comms session wired with a REAL AdapterStatusObserver over the given audit.

    The observer's ``expected_epoch`` narrows ``current_boot_epoch() -> str | None`` to a
    ``Callable[[], str]`` (correction #3) — the epoch is minted in the test before this is
    built, so it is non-None.
    """

    def _expected_epoch() -> str:
        epoch = current_boot_epoch()
        assert epoch is not None  # minted in the test setup
        return epoch

    observer = AdapterStatusObserver(
        audit=audit,  # type: ignore[arg-type]
        expected_epoch=_expected_epoch,
        now=lambda: datetime.now(UTC),
    )
    session = await AlfredPluginSession.for_comms_adapter(
        adapter_id="alfred_comms_test",
        manifest_raw=_MANIFEST,
        audit_writer=MagicMock(),
        gate=MagicMock(),
        supervisor=supervisor,  # type: ignore[arg-type]
        inbound_handler=MagicMock(spec=InboundHandler),
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
        status_observer=observer,
    )
    return session, observer


@pytest.fixture
def runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the socket runtime dir at a SHORT tmp ``$HOME`` so the test never touches ~/.run."""
    with tempfile.TemporaryDirectory(prefix="alfgw-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


async def _wait_for(predicate: Any, timeout: float) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise TimeoutError("status-leg condition never became true")


@asynccontextmanager
async def _faithful_core_carrier(
    *,
    epoch: str,
    session: AlfredPluginSession,
    routing_error_box: list[BaseException],
) -> AsyncIterator[CommsSocketListener]:
    """Bind ``comms-tui.sock``, answer the handshake, then route status frames live.

    The HOST (core) side: SEND ``lifecycle.start`` first, READ the gateway's ack, flip
    seq/ack, then PUMP — read each post-handshake method-bearing frame and route it
    through the REAL ``session._on_post_handshake_method`` (the Task-4 arm) so the real
    observer validates/epoch-reconciles/audits/refuses. A routing exception (the SEC-1
    audit-write-failure case) is captured so the test can assert it surfaced LOUD rather
    than being silently swallowed by the pump.
    """
    listener = CommsSocketListener(adapter_id=_BOUND_ADAPTER_KIND)
    await listener.bind()
    accepted: list[CommsSocketTransport] = []

    async def _accept_and_pump() -> None:
        transport: CommsSocketTransport = await listener.accept()
        accepted.append(transport)
        await transport.send(
            {
                "jsonrpc": "2.0",
                "id": _LIFECYCLE_START_ID,
                "method": "lifecycle.start",
                "params": {
                    "adapter_id": _ENABLED_ADAPTER_ID,
                    "epoch": epoch,
                    "seq_ack": {"version": SEQ_VERSION},
                },
            }
        )
        ack = await transport.read_frame()
        assert ack is not None, "gateway closed the core leg before its handshake ack"
        result = ack.get("result")
        assert isinstance(result, dict) and result.get("ok"), ack
        seq_ack = result.get("seq_ack")
        if isinstance(seq_ack, dict) and seq_ack.get("version") == SEQ_VERSION:
            transport.enable_seq_ack()
        # The live HOST pump: read each status frame the gateway sends and route it
        # through the REAL session arm + observer. A routing raise (SEC-1) is captured
        # and re-raised here so the carrier task ends LOUD (proving it is not swallowed).
        with suppress(*_TRANSPORT_READ_EXCEPTIONS):
            while True:
                frame = await transport.read_frame()
                if frame is None:
                    return
                method = frame.get("method")
                if method is None:
                    continue
                params = frame.get("params")
                params_mapping = params if isinstance(params, dict) else None
                try:
                    await session._on_post_handshake_method(str(method), params_mapping)
                except BaseException as exc:
                    routing_error_box.append(exc)
                    raise

    pump_task = asyncio.ensure_future(_accept_and_pump())
    try:
        yield listener
    finally:
        for transport in accepted:
            with suppress(Exception):
                await transport.close()
        pump_task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(pump_task, timeout=_TIMEOUT_S)
        await asyncio.wait_for(listener.aclose(), timeout=_TIMEOUT_S)


@asynccontextmanager
async def _live_leg(
    *, audit: object, runtime_dir: Path
) -> AsyncIterator[
    tuple[GatewayCoreLink, AdapterStatusObserver, _RecordingSupervisor, list[BaseException]]
]:
    """Bring up the wired gateway->core status leg; yield (core_link, observer, supervisor, errbox).

    Mints the boot epoch, binds the carrier, dials the REAL ``GatewayCoreLink``, waits for
    the leg to reach UP (so ``_current_core_transport`` is bound), then yields. Reaps the
    gateway + carrier on exit.
    """
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    reset_boot_epoch_for_tests()
    epoch = mint_boot_epoch()
    supervisor = _RecordingSupervisor()
    session, observer = await _make_observer_session(audit=audit, supervisor=supervisor)
    routing_error_box: list[BaseException] = []
    gateway_shutdown = asyncio.Event()
    core_link_task: asyncio.Task[None] | None = None

    async def _instant_sleep(_delay: float) -> None:
        await asyncio.sleep(0)

    try:
        async with _faithful_core_carrier(
            epoch=epoch, session=session, routing_error_box=routing_error_box
        ):
            core_link = GatewayCoreLink(
                client_listener=GatewayClientListener(),
                dial_adapter_id=_DIAL_ADAPTER_ID,
                sleep=_instant_sleep,
                jitter=lambda hi: hi,
                shutdown_event=gateway_shutdown,
            )
            core_link_task = asyncio.ensure_future(core_link.run())
            try:
                await _wait_for(
                    lambda: (
                        core_link._machine.state is GatewayLinkState.UP
                        and core_link._current_core_transport is not None
                    ),
                    _TIMEOUT_S,
                )
                yield core_link, observer, supervisor, routing_error_box
            finally:
                gateway_shutdown.set()
                if core_link_task is not None:
                    with suppress(asyncio.CancelledError, Exception):
                        await asyncio.wait_for(core_link_task, timeout=_TIMEOUT_S)
    finally:
        reset_boot_epoch_for_tests()


async def test_valid_up_frame_is_accepted_on_the_live_leg(runtime_dir: Path) -> None:
    """A valid ``gateway.adapter.up`` (matching epoch) is accepted + audited success."""
    audit = _RecordingAudit()
    async with _live_leg(audit=audit, runtime_dir=runtime_dir) as (link, observer, _sup, _err):
        await link.send_status_frame(
            GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": current_boot_epoch()}
        )
        await _wait_for(lambda: observer.latest("discord") is not None, _TIMEOUT_S)
    snapshot = observer.latest("discord")
    assert snapshot is not None and snapshot.state == "up"
    rows = [r for r in audit.rows if r.get("event") == "gateway.adapter.up"]
    assert len(rows) == 1
    assert rows[0]["result"] == "success"


async def test_forged_epoch_up_is_refused_on_the_live_leg(runtime_dir: Path) -> None:
    """A ``gateway.adapter.up`` with a non-matching epoch is REFUSED + audited."""
    audit = _RecordingAudit()
    async with _live_leg(audit=audit, runtime_dir=runtime_dir) as (link, observer, _sup, _err):
        await link.send_status_frame(
            GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "f" * 32}
        )
        await _wait_for(
            lambda: any(r.get("event") == "gateway.adapter.status_rejected" for r in audit.rows),
            _TIMEOUT_S,
        )
    rejected = [r for r in audit.rows if r.get("event") == "gateway.adapter.status_rejected"]
    assert len(rejected) == 1
    subject = rejected[0]["subject"]
    assert isinstance(subject, dict) and subject["rejection_reason"] == "epoch_mismatch"
    # A forged up records NO snapshot.
    assert observer.latest("discord") is None


async def test_malformed_frame_is_refused_on_the_live_leg(runtime_dir: Path) -> None:
    """A ``gateway.adapter.up`` missing required fields is REFUSED (malformed)."""
    audit = _RecordingAudit()
    async with _live_leg(audit=audit, runtime_dir=runtime_dir) as (link, _obs, _sup, _err):
        await link.send_status_frame(GATEWAY_ADAPTER_UP, {"adapter_id": "discord"})  # no epoch
        await _wait_for(
            lambda: any(r.get("event") == "gateway.adapter.status_rejected" for r in audit.rows),
            _TIMEOUT_S,
        )
    rejected = [r for r in audit.rows if r.get("event") == "gateway.adapter.status_rejected"]
    assert len(rejected) == 1
    subject = rejected[0]["subject"]
    assert isinstance(subject, dict) and subject["rejection_reason"] == "malformed_frame"


async def test_unknown_status_method_is_refused_on_the_live_leg(runtime_dir: Path) -> None:
    """An unknown ``gateway.adapter.*`` method reaches the observer's unknown_method refusal.

    Correction #2: prefix routing means a forged ``gateway.adapter.bogus`` is observed +
    refused (audited ``status_rejected``, reason ``unknown_method``) by the SOLE authority
    over the namespace — NOT the generic unknown-method handler that would restart the leg.
    """
    audit = _RecordingAudit()
    async with _live_leg(audit=audit, runtime_dir=runtime_dir) as (link, _obs, supervisor, _err):
        await link.send_status_frame("gateway.adapter.bogus", {"adapter_id": "discord"})
        await _wait_for(
            lambda: any(r.get("event") == "gateway.adapter.status_rejected" for r in audit.rows),
            _TIMEOUT_S,
        )
    rejected = [r for r in audit.rows if r.get("event") == "gateway.adapter.status_rejected"]
    assert len(rejected) == 1
    subject = rejected[0]["subject"]
    assert isinstance(subject, dict) and subject["rejection_reason"] == "unknown_method"
    # The observer absorbed it — the generic unknown-method restart path did NOT fire.
    assert supervisor.restart_requests == []


async def test_audit_write_failure_is_loud_on_the_live_leg(runtime_dir: Path) -> None:
    """SEC-1 LIVE: an observer audit-write failure surfaces LOUD (NOT swallowed) on the leg.

    The carrier pump routes through the REAL session arm + an observer whose audit append
    raises. The arm raises ``AdapterStatusAuditWriteError``; the carrier captures it and
    re-raises — proving the failure is not silently downgraded on the wired path.
    """
    async with _live_leg(audit=_FailingAudit(), runtime_dir=runtime_dir) as (
        link,
        _obs,
        _sup,
        errbox,
    ):
        await link.send_status_frame(
            GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": current_boot_epoch()}
        )
        await _wait_for(lambda: len(errbox) > 0, _TIMEOUT_S)
    assert any(isinstance(exc, AdapterStatusAuditWriteError) for exc in errbox)
