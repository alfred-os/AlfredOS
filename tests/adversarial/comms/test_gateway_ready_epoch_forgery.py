"""Adversarial: a forged ``daemon.lifecycle.ready`` epoch must be rejected.

**Threat model** (Spec A G3-3b / ADR-0032 — gateway core-leg false-liveness): a
peer on the core leg that slipped past ``SO_PEERCRED`` (a same-uid impostor, a
stale-socket race that re-bound the core path) sends a SHAPE-VALID
``daemon.lifecycle.ready`` carrying an epoch that is NOT the one captured at the
gateway's ``lifecycle.start`` handshake. If the gateway fed that to its link-state
machine it would emit a ``link.restored`` to the client — a FALSE all-clear that
paints the reconnect banner away while the real core is still down (or while an
impostor holds the leg). The epoch-reconcile is the defense: a ``ready`` whose
epoch != the captured handshake epoch is dropped with NO feed, NO control frame,
and a loud ``gateway.core_link.ready_epoch_mismatch`` warning.

This is a standalone adversarial module (not a corpus YAML payload — the corpus
covers prompt/tier/DLP content payloads; this is a wire-protocol forgery). It
mirrors the unit forgery test in
``tests/unit/gateway/test_core_link.py::test_consume_ready_with_forged_epoch_is_rejected_loud``
so the forgery attempt is test-observable in the release-blocking adversarial suite
now; the durable, signed audit row for the rejection is deferred to G4.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import structlog.testing

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LinkReconnectingNotification,
    LinkRestoredNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.link_state import GatewayLinkState
from alfred.gateway.metrics import CORE_LINK_UP


class _RecordingClientListener:
    """Records every ``send_control`` so the test can assert NO frame reached the client."""

    def __init__(self) -> None:
        self.controls: list[LinkControlNotification] = []

    async def send_control(self, notification: LinkControlNotification) -> None:
        self.controls.append(notification)


@pytest.mark.asyncio
async def test_forged_ready_epoch_is_rejected_no_false_restored() -> None:
    captured_epoch = uuid4().hex
    forged_epoch = uuid4().hex
    assert forged_epoch != captured_epoch

    recorder = _RecordingClientListener()
    link = GatewayCoreLink(client_listener=recorder)  # type: ignore[arg-type]
    # The epoch the gateway captured at the genuine lifecycle.start handshake.
    link._core_epoch = captured_epoch

    with structlog.testing.capture_logs() as captured:
        await link._consume_frame(
            {"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged_epoch}}
        )

    # No false ``restored``: the client saw NOTHING and the machine never transitioned.
    assert recorder.controls == []
    assert link._machine.state is GatewayLinkState.UP
    # The forgery is LOUD (CLAUDE.md hard rule #7) — test-observable in the adversarial
    # suite. The durable signed audit row is deferred to G4.
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert mismatch[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_forged_ready_while_gapped_never_paints_false_all_clear() -> None:
    """The LOAD-BEARING forgery: a forged ``ready`` arriving while the gap is OPEN.

    The UP-state case above passes even with the epoch guard removed (from UP a
    ``ready`` — forged or matching — emits nothing). The attack that the guard
    actually stops is a forged ``ready`` arriving WHILE GAPPED: without the guard,
    ``CORE_READY`` would feed the machine and emit a real ``link.restored`` — painting
    the reconnect banner away while the real core is still down (or an impostor holds
    the leg). With the guard, the gap STAYS open: the client's last control is
    ``reconnecting`` (NO ``restored``), the machine is still NOT UP, the gauge is 0,
    and ``ready_epoch_mismatch`` fired. Deleting the guard MUST fail this test.
    """
    captured_epoch = uuid4().hex
    forged_epoch = uuid4().hex
    assert forged_epoch != captured_epoch

    recorder = _RecordingClientListener()
    link = GatewayCoreLink(client_listener=recorder)  # type: ignore[arg-type]
    link._core_epoch = captured_epoch

    # Open the gap first: a genuine going_down -> reconnecting reaches the client.
    await link._consume_frame(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
    )
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]
    assert link._machine.state is not GatewayLinkState.UP

    # THEN the forged ready arrives while gapped — it must be rejected with no feed.
    with structlog.testing.capture_logs() as captured:
        await link._consume_frame(
            {"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged_epoch}}
        )

    # No false all-clear: the client's controls END at [reconnecting] — never restored.
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]
    assert not any(isinstance(c, LinkRestoredNotification) for c in recorder.controls)
    assert link._machine.state is not GatewayLinkState.UP
    assert CORE_LINK_UP._value.get() == 0
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert mismatch[0].get("log_level") == "warning"
