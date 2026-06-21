"""RELEASE-BLOCKING (keystone K7): per-leg restart-survival over the gateway (Spec B G6-4).

The Spec-B G6-4 per-leg analog of the Spec-A G5 client-leg proof
(:mod:`tests.integration.test_gateway_restart_survival`). It drives the SAME REAL stack —
a REAL chat leg over a REAL AF_UNIX socket into the REAL :class:`GatewayProcess`, with the
core a CONTROLLABLE fake — across a REAL core restart (going_down -> gap -> reconnect at a
fresh epoch). What K7 mandates this prove AT G6-4 (with a fake leg / fake core; the real
Discord child is G6-5):

#. **per-leg un-acked replay EXACTLY-ONCE via a GENUINE double-delivery** — the SAME
   ``(adapter_id, inbound_id)`` is delivered to the core TWICE (once un-acked on epoch 1,
   then re-sent by the gateway's resume on epoch 2). A faithful core-side G0
   :class:`alfred.memory.inbound_idempotency.InboundIdempotencyStore` model commits it ONCE
   and records ONE replay-observed DROP — never "send once, see one arrival" (which never
   exercises G0 dedup).
#. **cross-leg same-``inbound_id`` isolation** — adapter-minted ids are not globally unique;
   two DIFFERENT legs sending the SAME ``inbound_id`` BOTH commit, because the ledger keys on
   the COMPOSITE ``(adapter_id, inbound_id)``.
#. **the two-phase determinism barrier (NOT a sleep)** — replay STAYS refused (zero received
   on the new core) while the new core is PRE-``ready`` (half-booted), then is ACCEPTED once
   ``release_ready()`` fires. Driven by an OBSERVABLE seam
   (:class:`_HalfBootedCoreTransport`), asserted with :func:`stays` / :func:`settle`.
#. **per-adapter metrics across the bounce** — counters (``gateway_ingress_throttled_total``)
   do NOT reset; gauges (``gateway_core_link_up``, ``gateway_adapter_buffer_depth_*``) move.

**Lane honesty (K7 / the #245 paper-gate hazard).** This module carries ONLY
``pytest.mark.integration`` — NO ``skipif(root/bwrap/Linux)`` — so it is collected AND run in
the REQUIRED non-root ``integration`` CI job (``ci.yml`` ~:652, ``uv run pytest
tests/integration``), never relocated to the slower privileged lane.
:func:`test_k7_lane_canary_collected_and_run_in_non_root_integration` is a deliberate
collected-and-run CANARY: if a future change adds a root/bwrap skip to this module, that
canary turns from a pass into a SKIP and the lane regression is loud.

**The REAL AF_UNIX wire is preserved** (not an in-memory transport pair): the held-across-
restart multiplexed wire — ``adapter_id``-keyed routing across a genuine reconnect — is the
property under test, exactly as the Spec-A proof keeps it.
"""

from __future__ import annotations

import os

import pytest
from prometheus_client import REGISTRY

from alfred.comms_mcp.protocol import LINK_RECONNECTING, LINK_RESTORED
from tests.integration._gateway_restart_harness import (
    _GatewayCoreG0Model,
    _GoDownCoreTransport,
    _HalfBootedCoreTransport,
    _payload_inbound_identity,
    fresh_epoch,
    gateway_stack,
    settle,
    stays,
)

pytestmark = pytest.mark.integration

# The TUI dial-in leg is the FIRST (and, at G6-4, only production-wired) ``GatewayLeg``; its
# in-body ``adapter_id`` is the ``adapter_kind`` member ``"tui"`` (the core's G0 composite-key
# half) and its per-adapter metric label.
_TUI_ADAPTER = "tui"


def _gauge(name: str, labels: dict[str, str] | None = None) -> float:
    """Read a gauge/counter sample value (``0.0`` when the series is not yet materialised)."""
    return REGISTRY.get_sample_value(name, labels) or 0.0


# ---------------------------------------------------------------------------
# K7 (i) — per-leg un-acked replay EXACTLY ONCE via a GENUINE double-delivery.
# ---------------------------------------------------------------------------


async def test_unacked_inbound_replays_exactly_once_across_a_core_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuinely double-delivered ``(adapter_id, inbound_id)`` G0-dedups to ONE commit (K7).

    The exactly-once proof. An operator turn is sent on epoch 1 and the core RECEIVES it but
    WITHHOLDS its ack — so it stays genuinely un-acked in the gateway leg's ReplayBuffer. The
    restart (``go_down`` -> gap -> reconnect) makes the gateway's resume RE-SEND that same
    payload (SAME ``inbound_id``, SAME bytes) on epoch 2 — a GENUINE second delivery of the
    same composite key. A faithful core-side G0 model commits the key ONCE (epoch 1) and
    records ONE replay-observed DROP (epoch 2). Assert ONE commit + ONE replay — never two
    commits (a double-dispatch) and never zero replays ("send once, see one arrival", which
    never exercises G0 dedup).

    NON-VACUITY: a control turn IS acked before the gap, so it is trimmed and does NOT replay
    — proving the replay set is the un-acked remainder, not a blind re-send of the stream.
    """
    epoch1, epoch2 = fresh_epoch(), fresh_epoch()
    first = _GoDownCoreTransport(epoch1)
    # ``second``'s relay pump parks on its empty on-demand queue after the handshake (its
    # ``read_payload_unit`` awaits ``_relay_q.get()`` forever), so the restored leg holds
    # steady — its captured-replay arrivals stay observable — until teardown.
    second = _GoDownCoreTransport(epoch2)

    # The ONE faithful G0 accept-once store both core legs commit through (the durable ledger
    # is core-global, not per-connection — the composite key is the only isolation).
    g0 = _GatewayCoreG0Model()

    async with gateway_stack(
        monkeypatch=monkeypatch, core_outcomes=[lambda: first, lambda: second]
    ) as stack:
        assert await settle(lambda: bool(first.sent)), "epoch-1 handshake never completed"

        await stack.send_operator_input("acked-turn")  # trimmed before the gap
        await stack.send_operator_input("unacked-turn")  # stays un-acked -> replays
        assert await settle(lambda: len(first.sent_units) == 2), (
            f"both turns never reached epoch-1 core: {len(first.sent_units)}"
        )
        # Commit each epoch-1 arrival through the core G0 store (the durable-intake step the
        # real core runs BEFORE side effects).
        for payload, _seq, _ack in first.sent_units:
            assert g0.observe_payload(_TUI_ADAPTER, payload) is True  # both fresh on epoch 1
        acked_id = _payload_inbound_identity(first.sent_units[0][0])[1]
        unacked_id = _payload_inbound_identity(first.sent_units[1][0])[1]

        # Ack ONLY the first turn (cumulative_ack=0 covers seq 0): it is trimmed from the leg
        # buffer BEFORE the gap, so it is NOT un-acked at restart and must NOT replay.
        first.deliver_ack(0, seq=10)
        first.go_down()
        assert await settle(lambda: bool(second.sent)), "reconnect never handshaked epoch 2"

        # The resume re-sends ONLY the un-acked remainder on epoch 2 — the GENUINE second
        # delivery of ``unacked_id``.
        assert await settle(lambda: len(second.sent_units) == 1), (
            f"un-acked turn did not replay exactly once on the wire: {second.sent_units}"
        )
        replayed_payload = second.sent_units[0][0]
        assert _payload_inbound_identity(replayed_payload)[1] == unacked_id
        # G0 dedup: the re-delivered key loses the commit-once (replay-observed), the acked key
        # never reappears.
        assert g0.observe_payload(_TUI_ADAPTER, replayed_payload) is False

        # EXACTLY-ONCE oracle: ONE commit + ONE replay for the un-acked key; the acked key
        # committed once and never replayed (non-vacuity).
        assert g0.commits_for(_TUI_ADAPTER, unacked_id) == 1
        assert g0.replays_for(_TUI_ADAPTER, unacked_id) == 1
        assert g0.commits_for(_TUI_ADAPTER, acked_id) == 1
        assert g0.replays_for(_TUI_ADAPTER, acked_id) == 0
        # One gap then a clean restore (the control frames crossed the REAL socket to chat).
        assert await settle(lambda: len(stack.link_states) >= 2), "restored never emitted"
        assert stack.link_states == [LINK_RECONNECTING, LINK_RESTORED]


# ---------------------------------------------------------------------------
# K7 (ii) — cross-leg same-``inbound_id`` isolation (the COMPOSITE key isolates legs).
# ---------------------------------------------------------------------------


def test_same_inbound_id_on_two_legs_both_commit() -> None:
    """Two DIFFERENT legs reusing the SAME ``inbound_id`` BOTH commit (composite key, K7).

    Adapter-minted ``inbound_id``s are opaque adapter-supplied metadata and are NOT globally
    unique — two adapters may independently mint ``"msg-1"``. The durable G0 ledger keys on
    the COMPOSITE ``(adapter_id, inbound_id)``, so one adapter's id reuse can never drop
    another adapter's distinct message. Drive the SAME id through TWO distinct adapter ids and
    assert BOTH win the commit-once (and a THIRD same-key delivery on one leg replays) — the
    isolation that lets N legs safely multiplex one core ledger at G6-4.
    """
    g0 = _GatewayCoreG0Model()
    shared_inbound_id = "msg-1"

    assert g0.commit_once("tui", shared_inbound_id) is True
    assert g0.commit_once("discord", shared_inbound_id) is True
    # A genuine same-leg re-delivery still dedups (the composite key isolates legs, not the
    # within-leg accept-once).
    assert g0.commit_once("tui", shared_inbound_id) is False

    assert g0.commits_for("tui", shared_inbound_id) == 1
    assert g0.commits_for("discord", shared_inbound_id) == 1
    assert g0.replays_for("tui", shared_inbound_id) == 1
    assert g0.replays_for("discord", shared_inbound_id) == 0


# ---------------------------------------------------------------------------
# K7 (iii) — the two-phase determinism barrier (replay refused pre-ready, accepted post).
# ---------------------------------------------------------------------------


async def test_replay_refused_while_half_booted_then_accepted_once_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replay STAYS refused while the new core is PRE-``ready``; ACCEPTED after ``release_ready``.

    The determinism barrier, via an OBSERVABLE seam (NOT a sleep). The reconnect target is a
    :class:`_HalfBootedCoreTransport` whose handshake read PARKS until ``release_ready()`` — so
    after the gap the gateway dials the fresh leg but BLOCKS in the peer handshake, unable to
    flush the captured replay. Assert with :func:`stays` that the new core receives ZERO units
    across the whole stability window while half-booted; then ``release_ready()`` lets the
    handshake complete and :func:`settle` proves the un-acked remainder is THEN delivered. The
    barrier is the parked handshake, never an ``asyncio.sleep`` standing in for one.
    """
    epoch1, epoch2 = fresh_epoch(), fresh_epoch()
    first = _GoDownCoreTransport(epoch1)
    second = _HalfBootedCoreTransport(epoch2)

    async with gateway_stack(
        monkeypatch=monkeypatch, core_outcomes=[lambda: first, lambda: second]
    ) as stack:
        assert await settle(lambda: bool(first.sent)), "epoch-1 handshake never completed"

        await stack.send_operator_input("survive-the-bounce")  # un-acked -> must replay
        assert await settle(lambda: len(first.sent_units) == 1), "turn never reached epoch-1"
        unacked_id = _payload_inbound_identity(first.sent_units[0][0])[1]

        # Open the gap; the gateway reconnects to the HALF-BOOTED core and blocks in the
        # handshake (no start frame until release_ready).
        first.go_down()
        assert await settle(lambda: stack.dial.calls == 2), "reconnect never dialed epoch 2"

        # PHASE 1 (refused): while pre-``ready`` the new leg never handshakes (no ack written
        # back) and the replay STAYS unsent — zero units across the whole window.
        assert await stays(lambda: not second.sent and not second.sent_units), (
            "a half-booted (pre-ready) core received traffic before release_ready"
        )

        # PHASE 2 (accepted): boot to ready -> the handshake completes and the resume flushes
        # the un-acked remainder onto the now-ready leg.
        second.release_ready()
        assert await settle(lambda: len(second.sent_units) == 1), (
            "the un-acked remainder was not replayed once the core became ready"
        )
        assert _payload_inbound_identity(second.sent_units[0][0])[1] == unacked_id
        assert await settle(lambda: len(stack.link_states) >= 2), "restored never emitted"
        assert stack.link_states == [LINK_RECONNECTING, LINK_RESTORED]


# ---------------------------------------------------------------------------
# K7 (iv) — per-adapter metrics across the bounce (counters hold; gauges move).
# ---------------------------------------------------------------------------


async def test_per_adapter_metrics_track_the_leg_across_the_bounce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Across the restart: the ``up`` gauge moves, buffer-depth gauges move, the throttle
    COUNTER does NOT reset (K7 (iv)).

    The per-adapter observability survives the bounce. The TUI leg's ingress gate is
    NON-BINDING (interactive path never throttled), so ``gateway_ingress_throttled_total`` for
    it never increments — but it is a COUNTER, so it must be the SAME value after the bounce as
    before (a reset to 0 would be the bug). ``gateway_core_link_up`` is a GAUGE that goes
    1 -> (gap) -> 1, and the per-adapter ``gateway_adapter_buffer_depth_*`` gauges rise with an
    un-acked frame and are re-populated by the resume — they MOVE, they do not stick.
    """
    epoch1, epoch2 = fresh_epoch(), fresh_epoch()
    first = _GoDownCoreTransport(epoch1)
    # ``second``'s relay pump parks on its empty on-demand queue post-handshake (holds the
    # restored leg steady until teardown).
    second = _GoDownCoreTransport(epoch2)

    throttled_before = _gauge("gateway_ingress_throttled_total", {"adapter": _TUI_ADAPTER})

    async with gateway_stack(
        monkeypatch=monkeypatch, core_outcomes=[lambda: first, lambda: second]
    ) as stack:
        assert await settle(lambda: bool(first.sent)), "epoch-1 handshake never completed"
        # UP after the first handshake.
        assert await settle(lambda: _gauge("gateway_core_link_up") == 1.0)

        await stack.send_operator_input("metric-turn")  # un-acked -> buffered
        assert await settle(lambda: len(first.sent_units) == 1), "turn never reached epoch-1"
        # The per-adapter depth gauges rose for the un-acked frame on the TUI leg.
        assert await settle(
            lambda: _gauge("gateway_adapter_buffer_depth_frames", {"adapter": _TUI_ADAPTER}) >= 1.0
        ), "the un-acked frame did not raise the per-adapter buffer-depth gauge"
        assert _gauge("gateway_adapter_buffer_depth_bytes", {"adapter": _TUI_ADAPTER}) > 0.0

        first.go_down()
        # The gap drops the up gauge, then the reconnect restores it (the gauge MOVES).
        assert await settle(lambda: _gauge("gateway_core_link_up") == 0.0), "gap did not drop up"
        assert await settle(lambda: bool(second.sent)), "reconnect never handshaked epoch 2"
        assert await settle(lambda: _gauge("gateway_core_link_up") == 1.0), (
            "restore did not lift it"
        )
        # The resume re-populated the leg buffer on the fresh epoch (the depth gauge moved
        # again, not stuck at zero through the bounce).
        assert await settle(lambda: len(second.sent_units) == 1), "remainder did not replay"

        # The throttle COUNTER did not reset across the bounce (a counter is monotone; the
        # non-binding TUI gate never trips, so it equals the pre-bounce value).
        throttled_after = _gauge("gateway_ingress_throttled_total", {"adapter": _TUI_ADAPTER})
        assert throttled_after == throttled_before
        # The per-adapter depth series resolves with EXACTLY the single ``adapter`` label
        # (cardinality guard) — querying any other label yields no sample.
        assert (
            REGISTRY.get_sample_value(
                "gateway_adapter_buffer_depth_frames", {"adapter": _TUI_ADAPTER, "extra": "x"}
            )
            is None
        )


# ---------------------------------------------------------------------------
# K7 — lane-honesty CANARY (the #245 paper-gate guard).
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason=(
        "K7 lane canary: this assertion proves the proof RUNS in the required NON-root "
        "integration lane. The privileged (root) lane ALSO collects tests/integration, so "
        "skip there — the canary's anti-#245 intent is preserved because it still RUNS + "
        "asserts in the non-root lane (a future relocation of this module behind a "
        "root/bwrap skip would turn THAT non-root run from a pass into a skip, loud)."
    ),
)
def test_k7_lane_canary_collected_and_run_in_non_root_integration() -> None:
    """This release-blocking module is COLLECTED AND RUN in the required non-root lane (K7).

    A deliberate canary against the #245 paper-gate hazard: the K7 per-leg restart-survival
    proof MUST execute in the REQUIRED non-root ``integration`` CI job, never be relocated to
    the slower privileged lane by an accidental ``skipif(root/bwrap/Linux)``. This test
    asserts the conditions that keep it there:

    * it carries ONLY ``pytest.mark.integration`` (asserted on this module's marker) — so
      ``uv run pytest tests/integration`` collects it with no root gate;
    * it is RUNNING as a NON-root, NON-privileged process — the ``skipif(geteuid()==0)`` above
      means this canary is SKIPPED in the privileged (root) lane that ALSO collects
      ``tests/integration`` and RUN (asserting non-root) in the required non-root lane.

    The OTHER K7 proofs in this module carry NO skip of their own, so they run in BOTH lanes;
    a future edit that adds a ``skipif(root/bwrap/Linux)`` to the MODULE would turn this
    canary's non-root run from a PASS into a SKIP — a loud, visible lane regression, exactly
    the signal the #245 lesson demands. (The canary's OWN ``skipif`` is scoped strictly to
    ``geteuid()==0`` so it never masks a module-wide relocation in the non-root lane.)
    """
    marks = {m.name for m in pytestmark} if isinstance(pytestmark, list) else {pytestmark.name}
    assert marks == {"integration"}, f"K7 module must carry ONLY the integration marker: {marks}"
    # Reached only in the non-root lane (the skipif guards the root lane). geteuid()==0 here
    # would mean the skip was bypassed — the lane the K7 lesson forbids for this proof.
    assert os.geteuid() != 0, "the K7 restart-survival proof must run in the NON-root lane"
