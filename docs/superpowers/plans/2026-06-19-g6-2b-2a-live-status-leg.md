# G6-2b-2a — Live Status Leg Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the G6-2b-1 `GatewayAdapterSupervisor` + `AdapterStatusEmitter` + core-side `AdapterStatusObserver` LIVE — a real (separate-from-T3) status seam carries `gateway.adapter.*` frames from the gateway to the core, where the observer Pydantic-validates, epoch-reconciles, audits, and refuses forged frames — proven by a non-root in-process test.

**Architecture:** Add a NEW `status_frame_sink` channel on `GatewayCoreLink` that is SEPARATE from the opaque T3 `_payload_relay`. The gateway sends `gateway.adapter.*` as method-bearing JSON-RPC frames via the core-link transport's `send()` (the same primitive the handshake ack uses — distinct from the opaque `send_payload_unit` relay). On the core, those method-bearing frames already arrive in `CommsPluginRunner._pump` → `AlfredPluginSession._on_post_handshake_method`; a NEW arm there routes the four `gateway.adapter.*` methods to the daemon-constructed `AdapterStatusObserver` (NOT the comms-notification handler fan-out, NOT the T3 inbound pipeline). The `GatewayAdapterSupervisor` is wired into `GatewayProcess` boot with the live emitter sink + the captured core boot epoch, given an EMPTY adapter set (plumbing live, no real spawn until G6-3).

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2, structlog, pytest. No new datastores. No `src/alfred/security/` edits.

---

## Background — verified architecture (read before starting)

The gateway↔core leg is ONE dialed unix socket. The **core is HOST** (`alfred.plugins.comms_runner.CommsPluginRunner`); the **gateway is PEER** (`alfred.gateway.core_link.GatewayCoreLink`). The transport (`alfred.plugins.comms_socket_transport.CommsSocketTransport`) multiplexes two send shapes over that one wire:

- `send(frame)` — a method-bearing JSON-RPC frame (`json.dumps` body, `a=0` placeholder ack). The core reads these with `read_frame()` (JSON parse) → `_pump` routes by `method`.
- `send_payload_unit(payload, seq, ack)` — an OPAQUE relay unit carrying a real seq/ack. This is the **T3 payload channel** (`_payload_relay`); the gateway never parses these. **Forbidden for control frames.**

Both deframe through the shared `_read_seq_frame`, so a `send()`-shaped frame round-trips cleanly to the core's `read_frame()` even with seq/ack negotiated. **This is why the status seam is a separate `send()`-based channel, not a reuse of `_payload_relay`.**

On the core, `CommsPluginRunner._pump` (`src/alfred/plugins/comms_runner.py:481`) reads a frame, and for a method-bearing notification calls `_route_notification` → `AlfredPluginSession._on_post_handshake_method` (`src/alfred/plugins/session.py:575`). Today an unknown method on a comms session emits `COMMS_UNKNOWN_NOTIFICATION_FIELDS` + requests a restart. The four `gateway.adapter.*` methods must be intercepted in that router BEFORE the unknown-method tail and routed to the observer.

The 2b-1 components already exist and are unit-tested but dormant:

- `src/alfred/gateway/adapter_supervisor.py` — `GatewayAdapterSupervisor` (ctor takes `child_factory`, `cred_seam`, `emitter`, `epoch`, determinism seams). `supervise_all(adapter_ids)` boots a fleet under a bounded `TaskGroup`; an empty list is a clean no-op (the `TaskGroup` body never iterates).
- `src/alfred/gateway/adapter_status_emitter.py` — `AdapterStatusEmitter(sink=...)`; sink protocol is `async def emit(method: str, params: dict) -> None`.
- `src/alfred/comms_mcp/adapter_status_observer.py` — `AdapterStatusObserver(audit=, expected_epoch=, now=)`; `async def observe(method, params)`; never raises on a bad frame (loud audited refusal), only raises on a genuine audit-write failure.

---

## File structure

**New files:**

- `src/alfred/gateway/status_leg.py` — the live sink object (`GatewayCoreLinkStatusSink`) adapting `AdapterStatusEmitter`'s `emit(method, params)` to `GatewayCoreLink.send_status_frame`. Small, single-responsibility, owns the emitter→core-link bind.
- `tests/unit/gateway/test_status_leg.py` — unit tests for the sink + the new `GatewayCoreLink` status seam.
- `tests/integration/cli/daemon/test_gateway_status_leg_live.py` — the NON-ROOT in-process live-leg test: drives a synthetic gateway→core `gateway.adapter.*` frame through the wired leg into the observer; asserts accept + reject (forged-epoch / malformed / unknown) paths. Mirrors the G6-0b `test_gateway_core_link_socket_id_match.py` non-root pattern.

**Modified files:**

- `src/alfred/gateway/core_link.py` — add a `status_frame_sink` ctor seam + `send_status_frame(method, params)` that sends a method-bearing frame via the live core transport's `send()` (NOT `send_payload_unit`); loud-drop on a gapped/None transport (mirrors `relay_to_core`).
- `src/alfred/gateway/process.py` — construct + wire the `GatewayAdapterSupervisor` (live emitter sink + captured epoch + empty adapter set) into the boot sequence as a supervised task alongside the relay.
- `src/alfred/plugins/session.py` — add the `gateway.adapter.*` routing arm in `_on_post_handshake_method` (before the unknown-method tail) that calls the injected observer; add an optional `status_observer` ctor param on `for_comms_adapter`.
- `src/alfred/cli/daemon/_commands.py` — construct the `AdapterStatusObserver` in `_build_comms_boot_graph`, thread it onto `_CommsBootGraph`, and inject it into the session via `_build_comms_adapter_wiring`.

---

## Precursor-gap decisions (verified against main — see the Precursor-gaps section at the end for evidence)

- **(a) Gateway-LOCAL audit append+reconcile does NOT exist on main.** There is no gateway-local audit-append/reconcile mechanism in `src/alfred/audit/` or the gateway modules; the gateway has no DB and no signing key, and `core_link.py` writes back-pressure rows only as structlog breadcrumbs (`gateway.comms.breaker_tripped`) with the signed-log reconcile marked an explicit follow-up. **Decision: DEFER the gateway-LOCAL per-transition row to a later slice. In 2b-2a the per-transition AUDIT of record is the CORE-side observer's `audit.append_schema` per accepted/refused frame** (the observer already does this). The emitter's structlog breadcrumbs on the gateway side stay as-is. This is faithful to spec §6 ("status notifications reconcile into the signed core audit log; the gateway holds no signing key") for the 2b-2a slice — the core-side row IS the signed reconcile.
- **(b) The supervisor takes an `adapter_ids: list[str]` to `supervise_all`.** In 2b-2a wire the supervisor LIVE but pass an **empty configured adapter set** (`[]`) so it is live-wired but spawns nothing — `supervise_all([])` is a clean no-op (its `TaskGroup` body never iterates). No real credential or child factory is constructed in 2b-2a; the real per-adapter `CommsPluginRunner`/`CommsStdioTransport` child factory + cred client land in G6-3, and Discord enablement in G6-5. This wires the PLUMBING (the live status seam + the supervisor object + the boot task) without forcing a real spawn.
- **(c) The gateway captures the core boot epoch via `GatewayCoreLink._core_epoch`,** set during `_peer_handshake` (`core_link.py:780`). It is `None` until the first successful handshake. **Decision: the supervisor/emitter must read the epoch at EMIT time, not construction time** (the handshake may not have completed at boot). Since 2b-2a passes an empty adapter set, no `up` frame is actually emitted live; but the wiring is shaped so G6-3 reads `core_link.current_core_epoch()` (a NEW read-only accessor added in Task 2) lazily. The supervisor ctor's `epoch: str` is satisfied for the empty-set boot by a callable-or-snapshot bridge documented in Task 6.

---

## Task 1: A read-only `current_core_epoch()` accessor on `GatewayCoreLink`

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (add accessor near the `replay_pending_gate` property, ~L296)
- Test: `tests/unit/gateway/test_status_leg.py`

- [ ] **Step 1: Write the failing test**

```python
"""G6-2b-2a (#288): the live status leg — sink + GatewayCoreLink status seam."""

from __future__ import annotations

import asyncio

import pytest

from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink


def _make_core_link() -> GatewayCoreLink:
    return GatewayCoreLink(client_listener=GatewayClientListener())


def test_current_core_epoch_is_none_before_handshake() -> None:
    link = _make_core_link()
    assert link.current_core_epoch() is None


def test_current_core_epoch_reflects_captured_epoch() -> None:
    link = _make_core_link()
    link._core_epoch = "a" * 32  # set as the peer handshake would
    assert link.current_core_epoch() == "a" * 32
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_status_leg.py::test_current_core_epoch_is_none_before_handshake -v`
Expected: FAIL with `AttributeError: 'GatewayCoreLink' object has no attribute 'current_core_epoch'`

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/gateway/core_link.py`, add directly after the `replay_pending_gate` property (~L301):

```python
    def current_core_epoch(self) -> str | None:
        """The most recently captured core boot epoch (32-hex), or ``None``.

        ``None`` until the first successful peer handshake captures it (Spec B
        §3 / G6-2b-2a). The status leg reads this LAZILY at emit time (not at
        construction) so an ``up`` frame stamps the epoch the live handshake
        captured — a forged/stale epoch is what the core-side observer refuses.
        """
        return self._core_epoch
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_status_leg.py -v`
Expected: PASS (both epoch tests)

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_status_leg.py
git commit -m "feat(gateway): expose current_core_epoch() on GatewayCoreLink for the status leg (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: `GatewayCoreLink.send_status_frame` — the separate status channel

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (add `status_frame_sink` ctor param ~L209, add `send_status_frame` method after `relay_to_core` ~L1029)
- Test: `tests/unit/gateway/test_status_leg.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/gateway/test_status_leg.py`:

```python
class _FakeTransport:
    """Records frames sent via send() (the method-bearing path) vs send_payload_unit()."""

    def __init__(self) -> None:
        self.sent_frames: list[dict[str, object]] = []
        self.sent_payload_units: list[bytes] = []

    async def send(self, frame: dict[str, object]) -> None:
        self.sent_frames.append(frame)

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        self.sent_payload_units.append(payload)


async def test_send_status_frame_uses_send_not_payload_unit() -> None:
    link = _make_core_link()
    transport = _FakeTransport()
    link._current_core_transport = transport  # bound as run() would after handshake
    await link.send_status_frame("gateway.adapter.up", {"adapter_id": "discord", "epoch": "a" * 32})
    assert transport.sent_frames == [
        {
            "jsonrpc": "2.0",
            "method": "gateway.adapter.up",
            "params": {"adapter_id": "discord", "epoch": "a" * 32},
        }
    ]
    # Payload-blindness: the status frame NEVER rides the opaque T3 relay channel.
    assert transport.sent_payload_units == []


async def test_send_status_frame_loud_drops_on_no_transport(
    caplog: pytest.LogCaptureFixture,
) -> None:
    link = _make_core_link()  # _current_core_transport is None (no UP leg)
    # No raise: a gapped leg is an operational edge, loud-dropped like relay_to_core.
    await link.send_status_frame("gateway.adapter.down", {"adapter_id": "discord", "reason": "operator"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_status_leg.py::test_send_status_frame_uses_send_not_payload_unit -v`
Expected: FAIL with `AttributeError: 'GatewayCoreLink' object has no attribute 'send_status_frame'`

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/gateway/core_link.py`, the `send_status_frame` is self-contained and needs no ctor change (it reads `_current_core_transport` directly). Add after `relay_to_core` (~L1029):

```python
    async def send_status_frame(self, method: str, params: Mapping[str, object]) -> None:
        """Send a ``gateway.adapter.*`` status frame over the SEPARATE status channel.

        Spec B §3 / G6-2b-2a (#288). The status seam is DISTINCT from the opaque
        T3 ``_payload_relay`` (payload-blindness, CLAUDE.md hard rule #5): a status
        frame is a method-bearing JSON-RPC notification sent via the transport's
        :meth:`send` (the same primitive the handshake ack uses), so it lands in the
        core HOST's :meth:`CommsPluginRunner._pump` as a routed notification — NEVER
        via :meth:`send_payload_unit` (the opaque relay carrier). The gateway does
        not parse any T3 body to build this frame; ``params`` is supervision metadata.

        **Loud drop, NO buffering (CLAUDE.md hard rule #7).** A ``None`` current
        transport (the reconnect-race / pre-UP window) or any send-path fault is a
        LOUD drop, never raised, never buffered — mirroring :meth:`relay_to_core`.
        A dropped status frame is re-derivable from the next live transition; the
        status leg is observability, not durable-intake.
        """
        local = self._current_core_transport
        if local is None:
            log.warning("gateway.status.send_dropped", reason="no_core_transport", method=method)
            return
        frame: dict[str, object] = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        try:
            await local.send(frame)
        except (BrokenPipeError, ConnectionResetError, RuntimeError, CommsProtocolError) as exc:
            log.warning("gateway.status.send_dropped", error=repr(exc), method=method)
```

Add `send` to the `_CommsTransportLike` Protocol if not present — it already declares `async def send(self, frame: Mapping[str, object]) -> None` at L176, so no Protocol change is needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_status_leg.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_status_leg.py
git commit -m "feat(gateway): add send_status_frame separate-channel status seam to GatewayCoreLink (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: `GatewayCoreLinkStatusSink` — the live emitter→core-link adapter

**Files:**

- Create: `src/alfred/gateway/status_leg.py`
- Test: `tests/unit/gateway/test_status_leg.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/gateway/test_status_leg.py`:

```python
from alfred.gateway.status_leg import GatewayCoreLinkStatusSink


async def test_status_sink_emits_through_core_link_status_frame() -> None:
    link = _make_core_link()
    transport = _FakeTransport()
    link._current_core_transport = transport
    sink = GatewayCoreLinkStatusSink(core_link=link)
    await sink.emit("gateway.adapter.crashed", {"adapter_id": "discord", "error_class": "X", "detail": ""})
    assert transport.sent_frames == [
        {
            "jsonrpc": "2.0",
            "method": "gateway.adapter.crashed",
            "params": {"adapter_id": "discord", "error_class": "X", "detail": ""},
        }
    ]
    assert transport.sent_payload_units == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_status_leg.py::test_status_sink_emits_through_core_link_status_frame -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'alfred.gateway.status_leg'`

- [ ] **Step 3: Write minimal implementation**

Create `src/alfred/gateway/status_leg.py`:

```python
"""``GatewayCoreLinkStatusSink`` — the live status-frame sink (G6-2b-2a / #288).

Adapts the :class:`alfred.gateway.adapter_status_emitter.AdapterStatusEmitter`
sink interface (``async def emit(method: str, params: dict) -> None``) to the
SEPARATE status channel on the gateway's core link
(:meth:`alfred.gateway.core_link.GatewayCoreLink.send_status_frame`) — replacing
the 2b-1 fake/recording sink with the live gateway->core leg.

**Payload-blind (CLAUDE.md hard rule #5).** Status frames ride
``send_status_frame`` (a method-bearing JSON-RPC frame over the transport's
``send``), NEVER the opaque T3 ``_payload_relay`` / ``send_payload_unit`` channel.
This sink does no body parse; it forwards the emitter's already-validated
``(method, params)`` straight to the core link.
"""

from __future__ import annotations

from collections.abc import Mapping

from alfred.gateway.core_link import GatewayCoreLink


class GatewayCoreLinkStatusSink:
    """The live ``AdapterStatusEmitter`` sink: forward each frame to the core link."""

    def __init__(self, *, core_link: GatewayCoreLink) -> None:
        self._core_link = core_link

    async def emit(self, method: str, params: Mapping[str, object]) -> None:
        """Forward one built+validated ``gateway.adapter.*`` frame to the core link.

        Loud-drop on a gapped leg is the core link's contract
        (:meth:`GatewayCoreLink.send_status_frame`) — this sink adds no buffering.
        """
        await self._core_link.send_status_frame(method, params)


__all__ = ["GatewayCoreLinkStatusSink"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_status_leg.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/status_leg.py tests/unit/gateway/test_status_leg.py
git commit -m "feat(gateway): add GatewayCoreLinkStatusSink live emitter->core-link adapter (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Core-side `_on_post_handshake_method` routes `gateway.adapter.*` to the observer

**Files:**

- Modify: `src/alfred/plugins/session.py` (add `status_observer` param to `for_comms_adapter` + `__init__`; add the routing arm in `_on_post_handshake_method` before the unknown-method tail)
- Test: `tests/unit/plugins/test_session_status_observer_arm.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/plugins/test_session_status_observer_arm.py`:

```python
"""G6-2b-2a (#288): the core-side session arm routing gateway.adapter.* to the observer."""

from __future__ import annotations

import pytest

from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_UP


class _RecordingObserver:
    def __init__(self) -> None:
        self.observed: list[tuple[object, object]] = []

    async def observe(self, method: object, params: object) -> None:
        self.observed.append((method, params))


@pytest.fixture
def comms_session_factory():
    """Build a minimal comms-wired AlfredPluginSession with a recording observer.

    Reuse the existing comms-session construction helper from the session unit
    suite (tests/unit/plugins/test_session*.py) — the production
    ``AlfredPluginSession.for_comms_adapter`` with fakes for gate/supervisor/
    handlers, plus the NEW ``status_observer`` kwarg.
    """
    # Implementer: import the existing session test helpers (e.g.
    # `_build_comms_session(...)`) used by tests/unit/plugins/test_session_dispatch.py
    # and thread `status_observer=` through. If no shared helper exists, construct
    # via `AlfredPluginSession.for_comms_adapter` with the same fakes that suite uses.
    ...


async def test_gateway_adapter_method_routes_to_observer(comms_session_factory) -> None:
    observer = _RecordingObserver()
    session = comms_session_factory(status_observer=observer)
    params = {"adapter_id": "discord", "epoch": "a" * 32}
    await session._on_post_handshake_method(GATEWAY_ADAPTER_UP, params)
    assert observer.observed == [(GATEWAY_ADAPTER_UP, params)]


async def test_gateway_adapter_method_does_not_request_restart(comms_session_factory) -> None:
    """A gateway.adapter.* method is NOT an unknown method — no restart request."""
    observer = _RecordingObserver()
    session = comms_session_factory(status_observer=observer)
    await session._on_post_handshake_method(GATEWAY_ADAPTER_UP, {"adapter_id": "discord", "epoch": "a" * 32})
    # The supervisor fake records request_plugin_restart calls; assert none fired.
    assert session._supervisor.restart_requests == []  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/plugins/test_session_status_observer_arm.py -v`
Expected: FAIL — `for_comms_adapter` does not accept `status_observer` (TypeError), or the method routes to the unknown-method tail (observer never called).

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/plugins/session.py`:

1. Add a module-level constant near `_COMMS_NOTIFICATION_METHODS`:

```python
from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_BREAKER_OPEN,
    GATEWAY_ADAPTER_CRASHED,
    GATEWAY_ADAPTER_DOWN,
    GATEWAY_ADAPTER_UP,
)

# Gateway->core adapter-status methods (Spec B G6-2b-2a / #288). These are NOT
# comms-notification handler methods and NOT T3 payloads — they are routed to the
# core-side AdapterStatusObserver, which validates/epoch-reconciles/audits/refuses.
_GATEWAY_ADAPTER_STATUS_METHODS: Final[frozenset[str]] = frozenset(
    {
        GATEWAY_ADAPTER_UP,
        GATEWAY_ADAPTER_DOWN,
        GATEWAY_ADAPTER_CRASHED,
        GATEWAY_ADAPTER_BREAKER_OPEN,
    }
)
```

2. Add a `status_observer` parameter to both `__init__` and `for_comms_adapter` (default `None`), stored as `self._status_observer`. Match the existing optional-collaborator pattern used for `inbound_handler` etc. The observer's structural type is `async def observe(self, method: object, params: object) -> None` — declare a local `_StatusObserverLike` Protocol mirroring the others in the module.

3. In `_on_post_handshake_method`, insert the new arm AFTER the `_is_comms_session` guard and BEFORE the `_COMMS_NOTIFICATION_METHODS` check:

```python
        if method in _GATEWAY_ADAPTER_STATUS_METHODS:
            # Spec B G6-2b-2a (#288): a gateway-reported adapter-status frame. Routed
            # to the AdapterStatusObserver (validate -> epoch-reconcile -> audit ->
            # refuse forged), NOT the comms-notification handler fan-out and NOT the
            # T3 inbound pipeline. The observer NEVER raises on a bad frame (it audits
            # a loud refusal), so a forged/malformed status frame cannot tear the leg.
            if self._status_observer is not None:
                await self._status_observer.observe(method, params)
            else:
                # No observer wired (a non-gateway leg / a Slice-3 session that
                # somehow received the method): treat as unknown — loud, audited,
                # restart-requested — never silently dropped (CLAUDE.md hard rule #7).
                await self._emit_unknown_notification(method, params)
                if self._supervisor is not None:
                    await self._supervisor.request_plugin_restart(
                        adapter_id=self._effective_adapter_id, reason="unknown_notification"
                    )
            return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/plugins/test_session_status_observer_arm.py -v`
Expected: PASS

- [ ] **Step 5: Run the existing session suite to confirm no regression**

Run: `uv run pytest tests/unit/plugins/test_session_dispatch.py tests/unit/plugins/test_session.py -q`
Expected: PASS (the new arm is gated on the four new method constants; existing methods are untouched)

- [ ] **Step 6: Commit**

```bash
git add src/alfred/plugins/session.py tests/unit/plugins/test_session_status_observer_arm.py
git commit -m "feat(comms): route gateway.adapter.* frames to AdapterStatusObserver in session dispatch (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Construct + register the observer in the daemon boot graph

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (`_CommsBootGraph` dataclass; `_build_comms_boot_graph` constructs the observer; `_build_comms_adapter_wiring` injects it into the session)
- Test: `tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py`:

```python
"""G6-2b-2a (#288): the daemon boot graph builds + registers the AdapterStatusObserver."""

from __future__ import annotations

from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver


async def test_boot_graph_exposes_a_status_observer(comms_boot_graph) -> None:
    """`_build_comms_boot_graph` constructs an AdapterStatusObserver on the graph.

    `comms_boot_graph` is the existing daemon-boot-graph fixture used by the other
    `_build_comms_boot_graph` unit tests (it provides settings/audit/dlp/nonce/
    policies + the boot epoch). The implementer reuses that fixture.
    """
    assert isinstance(comms_boot_graph.status_observer, AdapterStatusObserver)


async def test_observer_expected_epoch_reads_live_boot_epoch(comms_boot_graph) -> None:
    """The observer's expected_epoch callable returns the daemon's per-boot epoch."""
    from alfred.bootstrap.lifecycle_epoch import current_boot_epoch

    assert comms_boot_graph.status_observer._expected_epoch() == current_boot_epoch()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py -v`
Expected: FAIL with `AttributeError: '_CommsBootGraph' object has no attribute 'status_observer'`

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/cli/daemon/_commands.py`:

1. Add the field to `_CommsBootGraph` (the frozen dataclass, near `idempotency_store`):

```python
    # Spec B G6-2b-2a (#288): the core-side observer/auditor for gateway-reported
    # adapter status. Built ONCE here, injected into every per-adapter session so a
    # gateway.adapter.* frame is validated/epoch-reconciled/audited/refused core-side.
    status_observer: AdapterStatusObserver
```

2. In `_build_comms_boot_graph`, construct it (inside the existing post-spawn `try`, before the `return _CommsBootGraph(...)`):

```python
    from alfred.bootstrap.lifecycle_epoch import current_boot_epoch
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver

    def _expected_epoch() -> str:
        # The daemon's per-boot epoch (the SAME value threaded into the runner's
        # lifecycle.start handshake). Set by mint_boot_epoch at boot; non-None by
        # the time the comms graph is built. The observer refuses an `up` whose
        # epoch != this — the forged-liveness defense (Spec B §3/§6f).
        epoch = current_boot_epoch()
        if epoch is None:  # pragma: no cover - boot epoch is minted before the graph
            raise RuntimeError("boot epoch unset when building the status observer")
        return epoch

    status_observer = AdapterStatusObserver(
        audit=audit,
        expected_epoch=_expected_epoch,
        now=lambda: datetime.now(UTC),
    )
```

Add `from datetime import UTC, datetime` to the imports if absent. Thread `status_observer=status_observer` into the `_CommsBootGraph(...)` constructor call.

3. In `_build_comms_adapter_wiring`, pass the observer into the session:

```python
    session = await AlfredPluginSession.for_comms_adapter(
        ...
        crash_handler=crash_handler,
        status_observer=graph.status_observer,
        transport=None,
        max_in_flight_notifications=settings.comms_max_in_flight_notifications,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py -v`
Expected: PASS

- [ ] **Step 5: Run the boot-graph + aclose suites for regression**

Run: `uv run pytest tests/unit/cli/daemon -q -k "boot_graph or comms"`
Expected: PASS (the `aclose` reap behaviour is unchanged — the observer holds no resource to reap)

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_comms_boot_graph_status_observer.py
git commit -m "feat(daemon): construct + register AdapterStatusObserver in the comms boot graph (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: Wire the `GatewayAdapterSupervisor` live into `GatewayProcess` (empty adapter set)

**Files:**

- Modify: `src/alfred/gateway/process.py` (construct the supervisor with the live status sink + lazy epoch; run `supervise_all([])` as a supervised task alongside the relay)
- Test: `tests/unit/gateway/test_process_supervisor_wiring.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/gateway/test_process_supervisor_wiring.py`:

```python
"""G6-2b-2a (#288): GatewayProcess wires the supervisor live with an empty adapter set."""

from __future__ import annotations

import asyncio

from alfred.gateway.process import GatewayProcess


def test_process_builds_status_sink_and_supervisor_for_core_link() -> None:
    """The process exposes a builder that binds a live status sink to a core link.

    Unit-level: assert the helper `_build_adapter_supervisor(core_link)` returns a
    GatewayAdapterSupervisor whose emitter sink forwards to the given core link's
    send_status_frame (the live leg), constructed with the configured (empty in
    2b-2a) adapter set.
    """
    from alfred.gateway.adapter_supervisor import GatewayAdapterSupervisor
    from alfred.gateway.client_listener import GatewayClientListener
    from alfred.gateway.core_link import GatewayCoreLink

    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = GatewayCoreLink(client_listener=GatewayClientListener())
    supervisor = process._build_adapter_supervisor(core_link)
    assert isinstance(supervisor, GatewayAdapterSupervisor)
    assert process._adapter_ids == []  # 2b-2a wires the plumbing, spawns nothing


async def test_supervise_empty_set_is_a_clean_noop() -> None:
    """supervise_all([]) returns immediately — live-wired, spawns nothing (gap b)."""
    from alfred.gateway.client_listener import GatewayClientListener
    from alfred.gateway.core_link import GatewayCoreLink

    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = GatewayCoreLink(client_listener=GatewayClientListener())
    supervisor = process._build_adapter_supervisor(core_link)
    await asyncio.wait_for(supervisor.supervise_all(process._adapter_ids), timeout=1.0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_process_supervisor_wiring.py -v`
Expected: FAIL with `AttributeError: 'GatewayProcess' object has no attribute '_build_adapter_supervisor'`

- [ ] **Step 3: Write minimal implementation**

In `src/alfred/gateway/process.py`:

1. Add an `adapter_ids` ctor param (default `None` → `[]`) and store `self._adapter_ids: list[str] = list(adapter_ids or [])`. Document: 2b-2a passes the empty/configured set; G6-3 provides real ids + creds.

2. Add the builder helper:

```python
    def _build_adapter_supervisor(self, core_link: GatewayCoreLink) -> GatewayAdapterSupervisor:
        """Build the live-wired adapter supervisor for this gateway process (#288).

        Spec B G6-2b-2a: bind the supervisor's status emitter to the LIVE
        gateway->core status leg (:class:`GatewayCoreLinkStatusSink` over
        ``core_link.send_status_frame``), replacing 2b-1's fake sink. The adapter
        set is EMPTY in 2b-2a (gap b) — the plumbing is live but no child is spawned
        until G6-3 supplies a real credential client + child factory. The epoch is
        read LAZILY from the core link at emit time (gap c): the supervisor ctor's
        ``epoch`` snapshot is unused for the empty set (no ``up`` is emitted), and
        G6-3 reads ``core_link.current_core_epoch()`` per spawn.
        """
        sink = GatewayCoreLinkStatusSink(core_link=core_link)
        emitter = AdapterStatusEmitter(sink=sink)
        return GatewayAdapterSupervisor(
            child_factory=_UnspawnedAdapterChildFactory(),
            cred_seam=_UnavailableCredSeam(),
            emitter=emitter,
            # Empty-set boot: no `up` emits, so a placeholder epoch is never put on the
            # wire. G6-3 reads the live `core_link.current_core_epoch()` per spawn.
            epoch=core_link.current_core_epoch() or "0" * 32,
            sleep=self._sleep,
            jitter=None,
            monotonic=None,
        )
```

3. Add the two fail-closed placeholder collaborators (2b-2a spawns nothing; these MUST never be reached with an empty adapter set — they raise loud if a future edit passes a non-empty set without G6-3):

```python
class _UnspawnedAdapterChildFactory:
    """G6-2b-2a placeholder: refuses to spawn (no real launcher until G6-3).

    With the 2b-2a empty adapter set this is NEVER called. It raises
    :class:`GatewayAdapterSpawnError` loud (fail-closed, CLAUDE.md hard rule #7)
    rather than fabricating a child, so a premature non-empty adapter set fails
    audibly instead of running a credential-less/child-less adapter.
    """

    async def spawn_and_handshake(self, *, adapter_id: str, epoch: str) -> object:
        raise GatewayAdapterSpawnError(
            f"adapter child spawn is not wired until G6-3 (adapter_id={adapter_id!r})"
        )


class _UnavailableCredSeam:
    """G6-2b-2a placeholder cred seam: always unavailable (real cred is G6-3)."""

    async def is_available(self, *, adapter_id: str) -> bool:
        return False
```

4. In `run()`, after `relay = GatewayRelay(...)`, run the supervisor concurrently with the relay under a `TaskGroup` so the empty-set no-op completes and a future non-empty set is supervised alongside the relay:

```python
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
            )
            supervisor = self._build_adapter_supervisor(core_link)
            async with asyncio.TaskGroup() as group:
                group.create_task(relay.run())
                # 2b-2a: supervise_all([]) returns immediately (gap b). Wired live so
                # G6-3 flips the adapter set on without re-touching the boot sequence.
                group.create_task(supervisor.supervise_all(self._adapter_ids))
```

Add imports: `GatewayAdapterSupervisor`, `GatewayAdapterSpawnError` from `alfred.gateway.adapter_supervisor`; `AdapterStatusEmitter` from `alfred.gateway.adapter_status_emitter`; `GatewayCoreLinkStatusSink` from `alfred.gateway.status_leg`; `GatewayCoreLink` is already imported.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_process_supervisor_wiring.py -v`
Expected: PASS

- [ ] **Step 5: Run the existing process suite for regression**

Run: `uv run pytest tests/unit/gateway/test_process.py tests/unit/gateway/test_process_e2e.py -q`
Expected: PASS (the empty-set supervisor task is a clean no-op; the relay path is unchanged)

- [ ] **Step 6: Commit**

```bash
git add src/alfred/gateway/process.py tests/unit/gateway/test_process_supervisor_wiring.py
git commit -m "feat(gateway): wire GatewayAdapterSupervisor live into GatewayProcess (empty adapter set) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: The forged-status-refusal LIVE — non-root in-process integration test

**Files:**

- Create: `tests/integration/cli/daemon/test_gateway_status_leg_live.py`

This is the security boundary of 2b-2a: the observer must accept a valid frame and refuse forged-epoch / malformed / unknown frames **on the real wired leg, driven by a real producer** (the gateway core-link transport's `send` → the core HOST runner's pump → the session arm → the observer). It mirrors the G6-0b non-root pattern (`test_gateway_core_link_socket_id_match.py`): a faithful in-process carrier, NO daemon graph, NO Postgres, NO launcher, so the required non-root `Integration` job runs it (paper-gate concern G6-2a deferred is RESOLVED here — there is now a producer).

- [ ] **Step 1: Write the failing test**

```python
"""Spec B G6-2b-2a (#288) — the LIVE forged-status-refusal leg, NON-ROOT in-process.

Drives a synthetic gateway->core ``gateway.adapter.*`` frame through the WIRED leg
(gateway core-link transport ``send`` -> core HOST ``CommsPluginRunner`` pump ->
``AlfredPluginSession._on_post_handshake_method`` -> ``AdapterStatusObserver``) and
asserts the accept + reject (forged-epoch / malformed / unknown) paths. This is the
producer the G6-2a paper-gate concern lacked: the security boundary now runs LIVE on
the required non-root gate (no launcher hop -> no root skip), mirroring
``test_gateway_core_link_socket_id_match.py``.
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import pytest

from alfred.bootstrap.lifecycle_epoch import (
    current_boot_epoch,
    mint_boot_epoch,
    reset_boot_epoch_for_tests,
)
from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_UP

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not hasattr(socket, "AF_UNIX"),
        reason="AF_UNIX unavailable (Windows); the gateway<->core carrier requires it",
    ),
]

_TIMEOUT_S = 10.0


class _RecordingAudit:
    """Captures observer audit rows (accept + refusal) — the assertion surface."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


async def _wait_for(predicate, timeout: float) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise TimeoutError("status-leg condition never became true")
```

The body builds: (1) a real `CommsSocketListener`-backed core carrier that performs the host `lifecycle.start` handshake AND, after the handshake, runs a real `CommsPluginRunner`-equivalent pump that reads frames and routes `gateway.adapter.*` to a real `AdapterStatusObserver` (constructed with `_RecordingAudit`, `expected_epoch=current_boot_epoch`, `now=...`); (2) a real `GatewayCoreLink` dialing it; (3) the gateway side sends status frames via `core_link.send_status_frame` (the live seam). Reuse the `runtime_dir` fixture + `_faithful_core_carrier` scaffolding from `test_gateway_core_link_socket_id_match.py` (copy the fixture; do not import test internals).

```python
async def test_valid_up_frame_is_accepted_on_the_live_leg(runtime_dir: Path) -> None:
    """A valid ``gateway.adapter.up`` (matching epoch) is accepted + audited success."""
    # Build the carrier + observer + core link; wait for the leg UP; then:
    #   await core_link.send_status_frame(GATEWAY_ADAPTER_UP,
    #       {"adapter_id": "discord", "epoch": current_boot_epoch()})
    # Assert: exactly one observer audit row with event == "gateway.adapter.up" and
    #   result == "success"; observer.latest("discord").state == "up".
    ...


async def test_forged_epoch_up_is_refused_on_the_live_leg(runtime_dir: Path) -> None:
    """A ``gateway.adapter.up`` with a non-matching epoch is REFUSED + audited."""
    #   await core_link.send_status_frame(GATEWAY_ADAPTER_UP,
    #       {"adapter_id": "discord", "epoch": "f" * 32})  # wrong epoch
    # Assert: a status_rejected row with rejection_reason == "epoch_mismatch";
    #   observer.latest("discord") is None (no snapshot recorded for a forged up).
    ...


async def test_malformed_frame_is_refused_on_the_live_leg(runtime_dir: Path) -> None:
    """A ``gateway.adapter.up`` missing required fields is REFUSED (malformed)."""
    #   await core_link.send_status_frame(GATEWAY_ADAPTER_UP, {"adapter_id": "discord"})
    # Assert: a status_rejected row with rejection_reason == "malformed_frame".
    ...


async def test_unknown_status_method_is_refused_on_the_live_leg(runtime_dir: Path) -> None:
    """An unknown ``gateway.adapter.*``-shaped method is refused (unknown_method).

    Send a method NOT in the four constants but routed via the same send() seam, e.g.
    "gateway.adapter.bogus". The session arm only intercepts the four known methods,
    so this lands in the unknown-method tail UNLESS the observer is consulted; assert
    the precise live behaviour: the observer is NOT consulted (it only sees the four),
    so the core requests a restart. (Document this boundary; it proves the arm is
    scoped to the four methods, not a catch-all.)
    """
    ...
```

Implementer note: the carrier-side pump that routes to the observer can be the real `AlfredPluginSession._on_post_handshake_method` wired with a recording observer + fake supervisor, OR a thin faithful router that calls `observer.observe(method, params)` for the four constants — prefer driving the REAL `_on_post_handshake_method` so the Task-4 arm is exercised end-to-end. Use the real `current_boot_epoch()` after `mint_boot_epoch()` so the accept path's epoch genuinely matches.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/cli/daemon/test_gateway_status_leg_live.py -v`
Expected: FAIL (test bodies are stubs / the leg/assertions not yet complete)

- [ ] **Step 3: Complete the test bodies**

Fill in the carrier + core-link wiring (copy the `runtime_dir` fixture, `_faithful_core_carrier` accept/handshake, and `_reap_gateway` helpers from `test_gateway_core_link_socket_id_match.py`; extend the post-handshake hold-open read to route method-bearing frames through the real `_on_post_handshake_method` + observer). Assert the four behaviours above.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/integration/cli/daemon/test_gateway_status_leg_live.py -v`
Expected: PASS (accept + the three refusal paths, all on the live wired leg, non-root)

- [ ] **Step 5: Run the full gateway + comms unit suites + this integration file together**

Run: `uv run pytest tests/unit/gateway tests/unit/comms_mcp/test_adapter_status_observer.py tests/integration/cli/daemon/test_gateway_status_leg_live.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tests/integration/cli/daemon/test_gateway_status_leg_live.py
git commit -m "test(gateway): prove the forged-status-refusal LIVE on the wired leg, non-root (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 8: Quality gates + i18n catalog check

**Files:** none (verification only)

- [ ] **Step 1: Run lint + format + type-check**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/`
Expected: clean. (No new operator-facing `t()` strings are introduced — the status seam emits structlog keys only; the observer's audit reasons are already-catalogued from G6-2a. Confirm no hardcoded English crept in.)

- [ ] **Step 2: Run the i18n catalog drift check**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/g6-2b-2a.pot src/alfred && uv run pybabel update -i /tmp/g6-2b-2a.pot -d src/alfred/locale -l en --no-fuzzy-matching --check 2>&1 | tail -5`
Expected: no drift (no new catalog keys). If a key was added, fix the catalog per the project i18n rules (never `--omit-header`).

- [ ] **Step 3: Run the full affected test surface once**

Run: `uv run pytest tests/unit/gateway tests/unit/comms_mcp tests/unit/cli/daemon tests/unit/plugins/test_session_status_observer_arm.py tests/integration/cli/daemon/test_gateway_status_leg_live.py -q`
Expected: PASS

- [ ] **Step 4: Commit any catalog/lint fixups (if needed)**

```bash
git add -A
git commit -m "chore(gateway): lint/i18n fixups for the live status leg (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Plan-review corrections (MUST apply — architect + security + core-engineer + test-engineer, 2026-06-19)

The fleet verified the status-seam transport is architecturally correct (single core `_pump`→`read_frame` demuxes by method; control frame + T3 relay multiplex cleanly on one socket; payload-blindness holds; epoch chain has no degenerate None window). Apply these corrections — they OVERRIDE conflicting earlier text:

1. **SEC-1 (HIGH / BLOCKING — the load-bearing fix): the observer's audit-write failure must stay LOUD + trip quarantine on the live leg.** The merged `AdapterStatusObserver` correctly RAISES on a failed signed-audit write (fail-loud, hard rules #5/#7). But on the live core leg the observer is invoked from `CommsPluginRunner._route_notification` (`src/alfred/plugins/comms_runner.py` ~L746-768), whose **blanket `except Exception: <log + continue>`** would SWALLOW that raise — silently downgrading a non-skippable signed-audit-write failure to a structlog warning with no quarantine. This DEFEATS the whole point of the observer. Fix (the implementer must choose + verify, with a test): make the audit-write failure survive the runner's catch — EITHER (a) wire the `gateway.adapter.*` routing so a failed audit write goes through the daemon's existing fail-loud/quarantine path (mirror the `_emit_or_quarantine` pattern in `cli/daemon/_commands.py`) rather than the runner's catch-and-continue, OR (b) have the observer raise a DISTINCT typed exception (e.g. an audit-write-failure marker) that `_route_notification` explicitly RE-RAISES (does not swallow) so it trips the runner's loud/quarantine path. Add a LIVE test: the observer's `audit.append_schema` raises on the wired leg → the failure is loud + quarantines (NOT swallowed/continued). This is the #1 must-fix; do not ship 2b-2a without it.

2. **ARCH-2 + SEC-2: route the WHOLE `gateway.adapter.*` PREFIX to the observer, placed so the loud-refusal branch is live (not dead).** Route by prefix (`method.startswith("gateway.adapter.")`) → observer, NOT only the four exact constants — so a forged `gateway.adapter.bogus` reaches the observer's `unknown_method` refusal (audited `status_rejected`) instead of falling through to the generic unknown-method handler that restarts the gateway leg. AND place the routing arm so its loud-refusal else-branch is NOT dead code: SEC-2 found that placing it AFTER the `not _is_comms_session` early-return (`session.py` `_on_post_handshake_method` ~L575-646) makes the refusal unreachable on Slice-3 sessions — place it correctly so every `gateway.adapter.*` frame is observed+validated regardless of session type. This makes the observer the SOLE authority over the whole `gateway.adapter.*` namespace and exercises its `unknown_method` path live.

3. **Core HIGH: epoch typing — wrap `current_boot_epoch()` (`str | None`) into `Callable[[], str]`.** The observer requires `expected_epoch: Callable[[], str]`, but `current_boot_epoch() -> str | None`. Task 5 already wraps it with a None-raising `_expected_epoch()`; **Task 7's live test MUST do the same** (mint the boot epoch in setup, narrow to `str`) — passing `current_boot_epoch` directly fails mypy-strict AND makes the accept-path epoch match unreliable.

4. **Core key correction: NO new `_route_unit` arm on `GatewayCoreLink`.** The gateway→core status frames reach the observer via the **socket carrier's `CommsPluginRunner._pump` → `_on_post_handshake_method`** (the core's gateway-facing receive path), NOT via a new `core_link.py` `_route_unit` arm (that router is the OTHER direction, core→gateway). Update any task that adds a `_route_unit` arm to instead wire the `_on_post_handshake_method` routing (per correction #2). `send_status_frame` (the gateway→core SEND) correctly mirrors `relay_to_core`'s loud-drop — keep that.

5. **Core MED: add supervisor shutdown-cancellation now.** `supervise_all([])` runs in the relay TaskGroup with no shutdown cancellation. Harmless for the empty set today, but this is presented as the live supervised wiring G6-3 flips on — a NON-empty supervisor would block the outer TaskGroup forever on shutdown. Wire the supervisor task so it is cancelled/reaped on gateway-process shutdown (mirror how the relay's other supervised tasks are reaped). Add a test that the supervisor task is cancelled on shutdown.

6. **TE-1 (HIGH): coverage gates.** Add the new `src/alfred/gateway/status_leg.py` (and any other new gateway-kernel src file) to the gateway-kernel per-file `--fail-under=100` coverage gate in `.github/workflows/ci.yml` (BOTH the python-job step ~L204 and the coverage-gates step ~L1248 — the two-gates pattern, as done for the 2b-1 adapter_* files). The empty-set fail-closed placeholders (`_UnspawnedAdapterChildFactory`/`_UnavailableCredSeam`) are never reached on `[]` → they will RED `process.py`'s existing 100% gate: either directly test them (assert they raise `GatewayAdapterSpawnError` if invoked — preferred, proves fail-closed) or `# pragma: no cover` with a documented rationale.

7. **SEC-3 + TE: the live test must drive the REAL wired path (no thin shim).** Task 7's integration test must route a synthetic `gateway.adapter.*` frame through the genuinely-wired seam (`core_link.send_status_frame` → core `_pump` → real `_on_post_handshake_method` → real `AdapterStatusObserver`) and assert accept (audited) + all three refusals (forged-epoch / malformed / unknown-method, each `status_rejected`) + the SEC-1 audit-failure-is-loud case. A "thin shim router" that bypasses the real path would be a paper gate. Non-root, AF_UNIX-only skipif (mirror `test_gateway_core_link_socket_id_match.py`).

8. **Core MED2 / TE: document + de-vacuum.** The observer is injected into ALL comms sessions (stdio adapters too, via the shared socket-carrier runner), so a "no-observer" else-branch is dead in production — document it (or scope appropriately). Task-4's fixture MUST set `adapter_id` (else vacuous). Task 6 must not regress the TaskGroup exception-shape.

9. **Doc: annotate the Spec §6 over-claim.** Spec §6 calls the gateway-local audit append+reconcile "Spec A's mechanism reused", but it does NOT exist on main (only structlog breadcrumbs). 2b-2a correctly relies on the CORE-side observer's `audit.append_schema` as the audit-of-record and defers the gateway-local row. Add a one-line note to ADR-0036 (or the spec) recording that the gateway-local signed reconcile is a later-slice component, so the over-claim doesn't mislead.

## Self-review

**Spec coverage (§3, §4, §6 of the design + the IN list):**

1. NEW `status_frame_sink`/`send_status_frame` separate channel on `GatewayCoreLink`, distinct from `_payload_relay` — Task 2. (Spec §3 "status frames ride the gateway↔core link", §6 payload-blindness.)
2. The live sink adapting `AdapterStatusEmitter`'s `emit(method, params)` to the core link — Task 3 (`GatewayCoreLinkStatusSink`), replacing the 2b-1 fake.
3. `GatewayAdapterSupervisor` wired into `GatewayProcess` boot with the live emitter sink + captured core epoch — Task 6.
4. Core-side: construct + register the merged `AdapterStatusObserver` in the daemon `_build_comms_boot_graph` (Task 5) + route incoming `gateway.adapter.*` frames to it on the core's gateway-facing receive path via a NEW arm in `_on_post_handshake_method` (Task 4) — NOT the payload relay.
5. The forged-status-refusal runs LIVE (accept + epoch-mismatch/malformed/unknown refusal) proven by a non-root in-process test — Task 7.

**Type consistency:** `send_status_frame(method: str, params: Mapping)` (Task 2) is called by `GatewayCoreLinkStatusSink.emit(method: str, params: Mapping)` (Task 3), invoked by `AdapterStatusEmitter`'s `_AdapterStatusSink.emit(method: str, params: dict)` (existing). `observe(method, params)` (existing observer) is called from `_on_post_handshake_method` (Task 4) with the four `GATEWAY_ADAPTER_*` constants (existing in `protocol.py`). `_CommsBootGraph.status_observer: AdapterStatusObserver` (Task 5) is read in `_build_comms_adapter_wiring` (Task 5) and passed to `for_comms_adapter(status_observer=...)` (Task 4). `current_core_epoch()` (Task 1) is read in `_build_adapter_supervisor` (Task 6). Consistent.

**Placeholder scan:** No "TODO"/"add appropriate handling"/"similar to" — every code step shows the code. The integration test (Task 7) has stubbed bodies in Step 1 but Step 3 explicitly completes them with the named helpers to copy; this is staged TDD, not a placeholder deliverable.

## Scope-boundary note

**IN (this slice):** the separate status channel on the core link; the live sink; the supervisor wired into `GatewayProcess` with an EMPTY adapter set; the observer constructed in the daemon boot graph + the core-side routing arm; the live forged-status-refusal non-root test.

**OUT (deferred, per the brief):** crash de-dup join + `host_restart_seq` field + observer snapshot query endpoint (2b-2b); `alfred status` render (2b-2c); real credential spawn + real child factory + real `adapter_ids` (G6-3); ingress gate / leg scheduler / per-leg ReplayBuffer / replay (G6-4); Discord flag-day (G6-5); the seven-entry adversarial corpus (G6-6). The gateway-LOCAL per-transition audit row is DEFERRED (precursor (a)); the CORE-side observer audit is the 2b-2a audit of record.

**Trust boundary:** this wires a forged-status-refusal path LIVE → it requires a SECURITY plan-review before implementation. The observer's audit fires on the real leg (proven in Task 7). No `src/alfred/security/` file is edited (the emitter/observer/sink are pure CALLERS of `redact_secret_shapes`; the change set is gateway + comms_mcp routing + daemon boot wiring + session dispatch).

## Precursor-gaps — verified findings

**(a) Gateway-LOCAL audit append + reconcile — DOES NOT EXIST on main.**
Evidence: `grep gateway src/alfred/audit/` returns only the `gateway.adapter.*` audit-row *schema field-sets* (`audit_row_schemas.py:752+`), written by the CORE-side observer — not a gateway-local append/reconcile mechanism. A repo-wide `grep reconcile|gateway_local|local_append` finds no gateway-local audit module. The gateway holds no DB and no signing key: `core_link.py` writes back-pressure/breaker events as **structlog breadcrumbs only** (`gateway.comms.breaker_tripped`, L1010), with the code comment explicitly calling the signed-log reconcile a "tracked 2b/design-§6 follow-up". Spec §6 says the gateway-local append+reconcile is "Spec A's mechanism reused" — but Spec A never shipped it as a reusable component (it shipped structlog breadcrumbs). **Decision: DEFER the gateway-LOCAL per-transition row; rely on the CORE-side observer's `audit.append_schema` (one row per accepted transition + one `status_rejected` row per refusal) as the per-transition audit of record for 2b-2a.** This is spec-faithful for the slice — the signed reconcile target IS the core audit log, and the observer writes there. Flag for plan-review: confirm the security reviewer accepts the gateway-side structlog breadcrumb (no signed local row) for 2b-2a, with the gateway-local signed-reconcile component tracked to a later slice.

**(b) The supervisor's adapter set — `supervise_all(adapter_ids: list[str])`; wire it EMPTY in 2b-2a.**
Evidence: `GatewayAdapterSupervisor.supervise_all` (`adapter_supervisor.py:256`) takes `adapter_ids: list[str]` and iterates them inside a `TaskGroup`; an empty list never enters the loop body, so `supervise_all([])` is a clean immediate return. The ctor takes a `child_factory` + `cred_seam` (both FAKE in 2b-1; real in G6-3). **Decision: 2b-2a constructs the supervisor LIVE (live status sink + lazy epoch) but passes `[]`, with fail-closed placeholder `_UnspawnedAdapterChildFactory` (raises `GatewayAdapterSpawnError`) + `_UnavailableCredSeam` (always `False`) that are NEVER reached on the empty set and fail LOUD if a future non-empty set is passed before G6-3.** No real Discord credential or child is constructed. This wires the plumbing without forcing a spawn — exactly the brief's intent. G6-3 supplies the real `adapter_ids` (Discord) + the real cred client + child factory.

**(c) Epoch capture — `GatewayCoreLink._core_epoch`, set in `_peer_handshake`; read LAZILY.**
Evidence: `_core_epoch` is captured during the peer handshake (`core_link.py:780`, `self._core_epoch = self._validate_epoch(epoch)`) and is `None` until the first successful handshake. The supervisor's emitter needs the epoch only when emitting an `up` frame. **Decision: add a read-only `current_core_epoch()` accessor (Task 1) and read it LAZILY at emit time in G6-3, not at supervisor construction.** In 2b-2a the empty adapter set means no `up` is emitted, so the ctor's `epoch=` is satisfied by `core_link.current_core_epoch() or "0"*32` (a placeholder never put on the wire). The core-side observer's `expected_epoch` reads the daemon's `current_boot_epoch()` (Task 5) — the SAME per-boot epoch threaded into the runner's `lifecycle.start` handshake (`_commands.py:934`), which is what the gateway captures as `_core_epoch`. So a genuine live `up` (G6-3) stamps the captured handshake epoch and the observer accepts it; a forged epoch is refused — proven against synthetic frames in Task 7.

## Spec / code mismatches found

1. **Spec §6 over-claims a reusable Spec A gateway-local audit append+reconcile component** — it does not exist on main (only structlog breadcrumbs). Recorded in precursor (a); the plan defers the gateway-local signed row and relies on the core-side observer audit. The design doc should be annotated (or an ADR-0036 note added) that the gateway-local signed reconcile is a later-slice component, not a Spec A reuse.
2. **Status seam transport mechanism is unstated in the spec** — the spec says "status frames ride the gateway↔core link" but not *how* without violating payload-blindness. Verified resolution: a method-bearing frame via the transport's `send()` (the handshake-ack primitive), distinct from the opaque `send_payload_unit` T3 relay; the core's existing `_pump`→`_on_post_handshake_method` routes it by method. This is the load-bearing design choice in Tasks 2 + 4 and should be highlighted in plan-review.
