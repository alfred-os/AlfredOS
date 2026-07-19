"""Task 16 (#340 golive / spec §21.5 / R.1 D1 / ADR-0052): the gateway per-listener
handshake idle timeout must nest INSIDE the child-side timeout hierarchy.

The gateway CONNECT forward-proxy idle-reaps a handshake after its per-instance timeout.
The Discord/adapter plane keeps the tight 10s slow-loris guard (the module default), but
the PROVIDER plane raises it to 22s: a pre-brokered one-shot socket used on a LATE retry
(attempt 3 ~ t=17.5s, still inside the 20s child budget) would otherwise be dead-on-arrival
(reaped by the 10s idle timeout) the moment the child dials it.

This is the ORDERING-INVARIANT guard for the full 5-term nesting

    action_deadline(30) > host_read(25) > gateway_handshake(22) > child_budget(20) > SDK_read(8)

drawn from the LIVE constants in their real modules (NEVER literals) so a cross-module
drift in ANY term trips the guard. Task 15's ``test_quarantine_timeout_hierarchy`` pins the
child-side terms; this file adds the gateway term (22) and pins it relative to the child
budget (20) and the host read-frame bound (25). It ALSO pins that ONLY the provider plane
got the bump — the adapter plane must keep the 10s default, so a regression that raised the
slow-loris guard everywhere fails here.
"""

from __future__ import annotations

from alfred.gateway.adapter_egress_listener import build_adapter_egress_proxy
from alfred.gateway.egress_proxy import (
    _HANDSHAKE_TIMEOUT_S,
    _PROVIDER_HANDSHAKE_TIMEOUT_S,
)
from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
from alfred.security.quarantine_child.brokered_egress import _CHILD_SDK_READ_TIMEOUT
from alfred.security.quarantine_child.provider_dispatch import _MAX_TOTAL_WALL_CLOCK_SECONDS
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S

# The design gap between the child wall-clock budget (20s) and the provider-plane gateway
# handshake idle timeout (22s): the gateway must NOT reap a pre-brokered socket dialed on a
# late retry that is still inside the child budget. 22 = 20 + 2 (spec §21.5 / §4-P1e).
_BUDGET_HANDSHAKE_MARGIN_S = 2.0


def _sdk_read_seconds() -> float:
    """The child's socket-level SDK read ceiling (``httpx.Timeout.read``), narrowed non-None.

    Mirrors Task 15's helper: ``httpx.Timeout(read=8.0)`` always sets ``.read``; the assert
    narrows ``float | None`` for mypy AND fails loud if a future retune drops it to ``None``.
    """
    read = _CHILD_SDK_READ_TIMEOUT.read
    assert read is not None
    return read


def test_five_term_timeout_nesting_is_strictly_monotone() -> None:
    """The full 5-term nesting is strictly monotone, from LIVE constants (not literals).

    ``action_deadline(30) > host_read(25) > gateway_handshake(22) > child_budget(20) >
    SDK_read(8)``. The gateway term (22) is the one Task 16 lands; the outer/inner terms are
    the same live constants Task 15 pins, so a drift in EITHER direction trips this guard.
    """
    action_deadline = float(_DEFAULT_ACTION_DEADLINE_SECONDS)
    assert (
        action_deadline  # 30
        > _READ_FRAME_TIMEOUT_S  # 25
        > _PROVIDER_HANDSHAKE_TIMEOUT_S  # 22
        > _MAX_TOTAL_WALL_CLOCK_SECONDS  # 20
        > _sdk_read_seconds()  # 8
    )


def test_provider_handshake_dominates_child_budget_with_margin() -> None:
    """§4-P1e: the provider-plane handshake exceeds the child budget by a real margin AND
    stays under the host read-frame bound.

    ``gateway_handshake >= child_budget + margin`` is what keeps a late-retry pre-brokered
    socket alive (the whole point of raising the timeout); ``gateway_handshake < host_read``
    keeps the HOST (not the gateway) the owner of the outer tear-down.
    """
    assert (
        _PROVIDER_HANDSHAKE_TIMEOUT_S >= _MAX_TOTAL_WALL_CLOCK_SECONDS + _BUDGET_HANDSHAKE_MARGIN_S
    )
    assert _PROVIDER_HANDSHAKE_TIMEOUT_S < _READ_FRAME_TIMEOUT_S


def test_provider_plane_handshake_is_22_exactly() -> None:
    """ADR-0052 (Task 12) records 22.0 EXACTLY as the merge-gate; the nesting depends on it."""
    assert _PROVIDER_HANDSHAKE_TIMEOUT_S == 22.0


def test_module_default_stays_the_10s_slow_loris_guard() -> None:
    """The module default (every non-provider caller) is UNCHANGED at 10s."""
    assert _HANDSHAKE_TIMEOUT_S == 10.0


def test_adapter_plane_keeps_the_tight_10s_default() -> None:
    """The Discord AF_UNIX adapter plane must NOT inherit the provider-plane bump.

    ``build_adapter_egress_proxy`` constructs its ``EgressForwardProxy`` WITHOUT passing
    ``handshake_timeout_s``, so it keeps the 10s default — a regression that raised the
    slow-loris guard everywhere (e.g. by bumping the module default or passing 22 here too)
    fails this assertion. Construction does no I/O (the bind happens inside ``serve``), so
    calling the real factory is a pure, side-effect-free construction check.
    """
    adapter_proxy = build_adapter_egress_proxy()
    assert adapter_proxy._handshake_timeout_s == _HANDSHAKE_TIMEOUT_S == 10.0
