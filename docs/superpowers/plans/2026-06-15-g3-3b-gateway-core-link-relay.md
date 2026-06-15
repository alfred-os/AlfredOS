# G3-3b — Gateway Core-Link + Relay + Process Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. This is the second half of G3-3 (parent: `2026-06-15-g3-3-alfred-gateway-process.md`; **G3-3a / #271 is MERGED** — the pure `LinkStateMachine` + the three `link.*` control-frame models + `GatewayClientListener` are on `main`). Because the core-facing half + the runnable process is large, **G3-3b is split into two PRs**: **G3-3b-1** (the core-link manager — detailed below, full TDD) and **G3-3b-2** (the opaque relay + the `alfred gateway` process — scope-fixed, detailed against G3-3b-1's merged reality). Both are trust-boundary PRs (always-up T1 carrier).

**Goal:** Build the core-facing half of the `alfred-gateway`: a reconnect-capable, epoch-validating link to the core that drives the merged G3-3a link-state machine + reconnect banner (G3-3b-1), then the payload-blind opaque relay + the runnable `alfred gateway` process (G3-3b-2).

**Architecture:** The gateway is **PEER** on its core leg (it dials the core's socket; the core's `CommsPluginRunner` is HOST and sends `lifecycle.start` — confirmed in `src/alfred/cli/daemon/_commands.py:826` `_build_comms_runner` + `comms_runner.py:384` `_handshake`) and **HOST** on its client leg (it binds `comms-gateway.sock`, the TUI dials in, the gateway sends `lifecycle.start`). It is the **first real `AlfredSeqAck/1` peer**: it negotiates + terminates seq/ack independently on each leg, so the client-leg seq counter stays monotonic across a core restart (the across-restart resume invariant G4 builds on). Core-liveness is reconciled from the **handshake epoch** (the boot-`ready` broadcast reaches zero senders in the normal case — the socket peer connects on-demand later, per `comms_runner.py:170`), with a received `ready` frame epoch-checked as corroboration. T3 stays in the core — the gateway is a **T1 carrier** and relays the opaque payload **byte-for-byte**, parsing only the `method` to route.

**Tech Stack:** Python 3.12+, asyncio, AF_UNIX, Pydantic v2 wire models, structlog, prometheus_client, pytest + hypothesis, mypy --strict + pyright.

---

## G3-3b sub-epic decomposition

| PR | Scope | Trust-boundary? |
|----|-------|-----------------|
| **G3-3b-1** | The **core-link manager**: `GatewayCoreLink` (`src/alfred/gateway/core_link.py`) — dial the core via `dial_comms_socket`; **dial-side `SO_PEERCRED`** (the both-direction dial side G3-1 deferred); a lean **peer-side** handshake (respond to the core's `lifecycle.start`: validate, capture + validate the `epoch`, echo `AlfredSeqAck/1`, enable core-leg seq/ack); lifecycle-frame **validation + epoch-reconcile** (parse via merged `ReadyNotification`/`GoingDownNotification`; a forged/mismatched-epoch `ready` is rejected + logged loud, never fed as `core_ready`); drive the merged `LinkStateMachine.feed(...)` → `GatewayClientListener.send_control(...)`; a **fake-clock reconnect/backoff** loop. NO payload relay (non-lifecycle frames are dropped + counted). Three of the four metrics. | Yes — core-facing socket + wire-trust. |
| **G3-3b-2** | The **opaque relay + the process**: a codec-level opaque-payload seam on the transport (`read_payload_unit`/`send_payload_unit`); the relay loop (`src/alfred/gateway/relay.py`) — two pumped directions, payload byte-for-byte, `id` preserved, per-leg reseq, **no buffering**; the lean **client-leg host** handshake (gateway → TUI `lifecycle.start`); the `GatewayProcess` wiring (`src/alfred/gateway/process.py`); the `alfred gateway` CLI (`src/alfred/cli/gateway/`) + `src/alfred/gateway/__main__.py`; the fourth metric (`gateway_peer_auth_rejected_total`); the **non-root in-process wire-contract test** (#245 paper-gate hazard); the **payload-blindness canary test** (spec §6 corpus (a)). | Yes — always-up T1 carrier. |

**Deferred (NOT G3-3b):** `ReplayBuffer`/resume/cap/TTL/breaker/back-pressure/zeroing + the durable signed gateway-local audit reconcile (G4 — 3b logs link transitions + epoch rejects loud via structlog; the gateway has no audit sink until G4); the Compose service + long-running core daemon + shared-volume socket relocation (G3-4); re-pointing `alfred chat` from `comms-tui.sock` → `comms-gateway.sock` + the PTY smoke (G5); egress proxy (Spec C).

---

## Design notes (read before any task)

### Topology + role (confirmed against merged code)

- The core (daemon) **binds + accepts** its socket and runs `CommsPluginRunner` as **HOST** (`_commands.py:826`, `_listen_socket_comms_adapter`). The HOST sends `lifecycle.start` first (`comms_runner.py:408`). The gateway **dials** the core's socket, so on the **core leg the gateway is the PEER** — it RESPONDS to `lifecycle.start`. This peer-side handshake **does not exist yet** (the runner is host-only); G3-3b-1 builds it.
- The gateway **binds** `comms-gateway.sock` (merged `GatewayClientListener`, `adapter_id="gateway"`) and the TUI dials in, so on the **client leg the gateway is the HOST** — it sends `lifecycle.start` to the TUI. That client-leg host handshake is only needed to negotiate client-leg seq/ack for the **relay**, so it is **G3-3b-2** (G3-3b-1 emits `link.*` control frames on a non-negotiated client leg as plain ADR-0025 frames — the client reads either form).
- Dial target: the gateway dials the core's socket via `dial_comms_socket("tui")` (the existing socket-backed adapter the core binds). The dial `adapter_id` is a `GatewayCoreLink` constructor parameter (default `"tui"`) so G3-4's shared-volume relocation is a one-line change. The client socket id stays `"gateway"`.

### The handshake epoch IS the liveness signal (the crux)

- The core's runner threads its non-secret per-boot `epoch` into the `lifecycle.start` **params** (`comms_runner.py:406`). In the normal boot the core emits its `daemon.lifecycle.ready` **broadcast before the gateway has dialed in** (zero senders — `comms_runner.py:170`), so the gateway **never receives a `ready` frame on first connect**. Therefore: **a successful core-leg handshake (with a valid 32-hex epoch captured) is itself the `core_ready` signal.** `GatewayCoreLink` feeds `CORE_READY` on handshake success — NOT on a separate `ready` frame.
- A `daemon.lifecycle.ready` frame that DOES arrive mid-connection is corroboration: parse via the merged `ReadyNotification` (epoch pinned 32-hex), **reconcile its epoch against the captured handshake epoch**. A match → `feed(CORE_READY)` (idempotent: `UP + core_ready → UP`, emits nothing). A **mismatch** → a stale/forged `ready` (a false `restored` is an attack surface, parent plan line 138) → log loud (`gateway.core_link.ready_epoch_mismatch`) + DROP, never `feed(core_ready)`. The epoch CHECK ships here even though the buffer-flush it guards is G4.
- `feed()` takes TYPED events only (security M4, merged in 3a): the frame is `ReadyNotification`/`GoingDownNotification`-parsed + epoch-checked BEFORE the typed `feed(core_ready)` call. The pure machine is structurally incapable of being driven by raw bytes.

### Link-event sourcing (the four merged `GatewayLinkEvent`s)

| Wire observation on the core leg | Typed event fed |
|----|----|
| `lifecycle.start` handshake completes (valid epoch captured) | `CORE_READY` (startup: `UP + core_ready → UP`, no spurious restored; post-gap: `REDIALING + core_ready → UP`, emit `restored`) |
| `daemon.lifecycle.ready` frame, epoch matches handshake | `CORE_READY` (idempotent corroboration) |
| `daemon.lifecycle.ready` frame, epoch MISMATCH | *(none — reject + log loud; forgery defense)* |
| `daemon.lifecycle.going_down` frame (valid `GoingDownNotification`) | `CORE_GOING_DOWN` (emit `reconnecting`) |
| Core-leg EOF / `CommsProtocolError` / broken pipe | `CORE_CRASH_EOF` (emit `reconnecting` if first in gap; idempotent after `going_down`) |
| Reconnect attempt begins | `REDIAL_STARTED` |

The merged machine tolerates `DOWN_* + core_ready` directly (architect H2), so a ready-before-`redial_started` race is safe; G3-3b-1 still feeds `REDIAL_STARTED` before each dial attempt where it can.

### Reconnect/backoff (fake-clock injectable)

- The loop is driven by two injected seams so it is deterministic under test: `sleep: Callable[[float], Awaitable[None]]` (default `asyncio.sleep`) and `jitter: Callable[[float], float]` (default a `random.Random`-backed `lambda hi: rng.uniform(0, hi)`; an injected deterministic callable in tests). **Never a 0-delay first retry**: the first backoff is `INITIAL_BACKOFF_SECONDS` (0.25 s) with full jitter applied to `[INITIAL, ...]`, exponential ×2 to `MAX_BACKOFF_SECONDS` (5.0 s) ceiling. Each attempt: `feed(REDIAL_STARTED)` → `sleep(backoff_with_jitter)` → dial → on success re-handshake; on `(FileNotFoundError, ConnectionRefusedError, OSError)` increment `gateway_reconnect_attempts_total`, grow the backoff, loop.

### Dial-side peer-auth (the both-direction `SO_PEERCRED` G3-1 deferred)

- `dial_comms_socket` is extended to verify the **listener** it dialed is the same uid, reusing the merged `_resolve_peer_uid` / `_peer_uid_authorized` (same `(OSError, struct.error)` + length-guard + degrade-open-on-`None` discipline). A different-uid listener is always an impostor (a stale-socket race / wider-perm misconfig) → raise loud `CommsPeerAuthError` (a new `CommsProtocolError` subclass, so the existing malformed/crash arms catch it uniformly) → the gateway routes it as a failed dial + retries. This strictly improves the TUI's existing dial too (it should verify the daemon is same-uid). No T3 on the exception.
- **Dial-side degrade-open is strictly WEAKER than accept-side (security SEC-2 — load-bearing).** On the ACCEPT side, `SO_PEERCRED`-absent degrade-open (`reported_uid is None → authorized`) is backstopped by the FS-perms-of-record: the listener itself *bound* the 0600 socket under a 0700 dir, so the only connector is same-uid. The DIAL side does NOT own the inode — it dials a path some other process bound — so on a no-`SO_PEERCRED` host (a macOS dev host) a different-uid process that won a stale-socket race could be dialed and trusted, which would dissolve the handshake-epoch trust gate below. Two mitigations ship in Task 1: (a) a **pre-dial `lstat` FS guard** — the dialed path must be a SOCKET owned by `os.getuid()` (cheap, restores an owner backstop on the degrade-open platform; reuses the merged `_unlink_stale` lstat-not-stat / no-symlink-follow discipline); (b) the ADR + the dial docstring state explicitly that the post-connect `SO_PEERCRED` check is **enforcing only where `SO_PEERCRED` answers (Linux)** — the dial-side degrade-open trusts an FS layout it does not own, which the pre-dial `lstat` then re-backstops. The Linux path's mismatched-uid reject is the adversarial test; the degrade-open platform's `lstat` owner check is the documented backstop.

### Opaque relay (G3-3b-2 — stated here so 3b-1's drop-path is forward-compatible)

- The relay forwards the **opaque ADR-0025 payload bytes byte-for-byte** (the codec docstring's invariant: the codec NEVER `json.loads` the payload, so the `id` the core correlates on survives end-to-end). To ROUTE (distinguish a `daemon.lifecycle.*` control frame the gateway consumes from a payload frame it relays), the gateway parses a COPY to read **only** `method` — it never reads/acts on the body — and relays the **original** payload bytes with the other leg's own `seq` + real `cumulative_ack()`. This needs a codec-level seam on the transport: `read_payload_unit() -> bytes | None` (returns `SeqFrame.payload` — the opaque inner bytes — without `json.loads`) and `send_payload_unit(payload: bytes, *, ack: int)` (reseq-frames the bytes with this leg's `_send_seq` + the **real** `ack` the relay threads in — the merged `send()` hard-codes the `a=0` placeholder, so the seam MUST take `ack` explicitly; architect Medium). The existing `read_frame`/`send` (parsed) stay for the handshake + the lifecycle-frame consume.
- **Fail TOWARD relay on a routing-parse failure (security SEC-3 — hard rule #7).** The routing `json.loads(payload)` runs on attacker-controlled T3 bytes (already size-bounded by `_MAX_COMMS_LINE_BYTES`, but not nesting-depth-bounded). Wrap it in `try/except (json.JSONDecodeError, ValueError, RecursionError)`; on ANY parse failure, **relay the frame as opaque** (forward the original bytes), NEVER drop it and NEVER treat it as a control frame to consume. A frame the gateway cannot route is the *core's* parser's problem, not the gateway's — silently dropping it would be an availability hole the core can't see. A frame with **no `method`** (a JSON-RPC RESPONSE, `id`-only — core→client) is ALSO relayed, not dropped (architect Low): only an explicit `daemon.lifecycle.*` method is consumed; everything else forwards.
- **`SeqDedupWindow` retention (security SEC-5).** G3-3b is the FIRST long-lived process to wire `SeqDedupWindow`; its `_seen` set grows one int per frame unbounded (the codec docstring defers bounded retention to G4's ReplayBuffer). The relay only needs `cumulative_ack()` (the contiguous high-water), NOT the full `_seen` history — so G3-3b's per-leg window is a slow OOM on an always-up gateway. **G3-3b-2 caps it:** either reset the window's `_seen` once a `seq` is acked-and-relayed past, or compute the ack from a bounded recent window. State which in 3b-2; do NOT defer the unbounded-`_seen`-in-a-long-lived-process question to G4 (it bites here, before G4 exists).

---

## PR G3-3b-1 — The core-link manager (TDD)

**Goal:** A complete, tested `GatewayCoreLink` that dials the core, runs the peer-side handshake, reconciles the epoch, drives the merged link-state machine + reconnect banner, and reconnects with backoff — with NO payload relay. Independently testable with an in-process loopback fake-core.

### Files

- Create: `src/alfred/gateway/core_link.py` — `GatewayCoreLink` + `GatewayCoreLinkError`.
- Create: `src/alfred/gateway/metrics.py` — the three core-link Prometheus metrics.
- Modify: `src/alfred/plugins/comms_socket_transport.py` — export `_resolve_peer_uid`/`_peer_uid_authorized` for reuse + add dial-side peer-auth to `dial_comms_socket` (new `CommsPeerAuthError`).
- Modify: `src/alfred/plugins/comms_wire.py` — `CommsPeerAuthError(CommsProtocolError)` (so it lives next to the wire-error family the codec/transport already import).
- Modify: `src/alfred/gateway/__init__.py` — export `GatewayCoreLink`, `GatewayCoreLinkError`.
- Modify: `docs/adr/0032-gateway-comms-resume-transport.md` — record the core-link contract (peer-handshake, handshake-epoch-as-liveness, epoch-reconcile forgery defense, reconnect/backoff, dial-side peer-auth).
- Test: `tests/unit/gateway/test_core_link.py`.
- Test: `tests/unit/plugins/test_comms_socket_transport.py` (extend: dial-side peer-auth).
- (NO i18n change: `CommsPeerAuthError` / the loud structlog keys are operator-log breadcrumbs on a wire-trust path, not `t()` user strings; the reconnect banner is the **client's** `t()` call in G5. The new error messages carry no operator-facing localizable text — they are closed-vocab log keys + a non-T3 exception string, matching the merged `CommsProtocolError` precedent.)

### Design constants

```python
# src/alfred/gateway/core_link.py
INITIAL_BACKOFF_SECONDS: Final[float] = 0.25  # never a 0-delay first retry (spec §4)
MAX_BACKOFF_SECONDS: Final[float] = 5.0        # exponential ceiling
_BACKOFF_FACTOR: Final[float] = 2.0
_DEFAULT_DIAL_ADAPTER_ID: Final[str] = "tui"   # the core's socket; G3-4 relocates
GATEWAY_PLUGIN_VERSION: Final[str] = "alfred-gateway/0"  # self-reported in the peer ack
```

### Tasks

- [ ] **Task 1: `CommsPeerAuthError` + dial-side peer-auth on `dial_comms_socket` (TDD)**

**Files:** `src/alfred/plugins/comms_wire.py`, `src/alfred/plugins/comms_socket_transport.py`; Test: `tests/unit/plugins/test_comms_socket_transport.py`.

- [ ] Step 1 — failing tests:
  - a loopback `CommsSocketListener` bound by the current uid is dialed by `dial_comms_socket`; the dial SUCCEEDS (same uid / `None` on a no-`SO_PEERCRED` host both authorized);
  - `_resolve_peer_uid` monkeypatched to a DIFFERENT uid → the dial raises `CommsPeerAuthError` (a `CommsProtocolError` subclass) and the dialed writer is closed (no leak);
  - **SEC-2b — the resolved uid is the PEER's, not ours:** with a real same-uid loopback listener, assert the dial-side `_resolve_peer_uid` was called on the CONNECTED socket (`writer.get_extra_info("socket")`), not the listener — mirror the accept-side warning at `comms_socket_transport.py:502` that reading creds off the wrong socket returns our own uid and always passes;
  - **SEC-2 — the pre-dial `lstat` FS guard:** a path that is NOT a socket, or a socket NOT owned by `os.getuid()`, raises `CommsPeerAuthError` BEFORE `open_unix_connection` (the degrade-open-platform backstop).

```python
def test_dial_rejects_mismatched_listener_uid(monkeypatch, tmp_path):
    # ... bind a listener, then force a uid mismatch on the dial side:
    monkeypatch.setattr(transport_mod, "_resolve_peer_uid", lambda _sock: os.getuid() + 1)
    with pytest.raises(CommsPeerAuthError):
        await dial_comms_socket("tui")
```

- [ ] Step 2 — run, expect FAIL. `uv run pytest tests/unit/plugins/test_comms_socket_transport.py -k peer_auth -v`
- [ ] Step 3 — implement: add `class CommsPeerAuthError(CommsProtocolError)` to `comms_wire.py` (docstring: a dialed/accepted peer's uid mismatched ours — a stale-socket race / wider-perm misconfig; carries NO T3). In `comms_socket_transport.py`, in `dial_comms_socket`: (a) **pre-dial** `lstat` the resolved path (reuse the `_unlink_stale` lstat-not-stat / no-symlink-follow discipline) — if it is not `S_ISSOCK` or `st.st_uid != os.getuid()`, raise `CommsPeerAuthError` (the degrade-open backstop the gateway needs because it does not own the inode — SEC-2); (b) **post-connect**, read the dialed socket's peer creds via `_resolve_peer_uid(writer.get_extra_info("socket"))` and, if `not _peer_uid_authorized(reported_uid=...)`, close the writer + raise `CommsPeerAuthError` (loud `comms.socket.dial_peer_uid_rejected` warning with `peer_uid` + `expected_uid`). Add `_resolve_peer_uid`, `_peer_uid_authorized`, `CommsPeerAuthError` to `__all__`. Degrade-open on `None` (no `SO_PEERCRED`) like the accept side, **but** with the docstring stating the post-connect check is Linux-enforcing-only and the pre-dial `lstat` is the degrade-open backstop (SEC-2).
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(comms): dial-side SO_PEERCRED peer-auth on dial_comms_socket (Spec A G3-3b / ADR-0031) (#237)` + trailer).

- [ ] **Task 2: core-link Prometheus metrics (TDD)**

**Files:** `src/alfred/gateway/metrics.py`; Test: `tests/unit/gateway/test_core_link.py` (metric-presence assertions, or a dedicated `test_metrics.py`).

- [ ] Step 1 — failing test: importing `alfred.gateway.metrics` exposes a `Gauge` `gateway_core_link_up`, a `Counter` `gateway_reconnect_attempts_total`, and a `Counter` (seconds-total) or `Gauge` `gateway_core_unavailable_seconds`, each registered on the default registry (a duplicate-name import would raise loudly).
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement `metrics.py` mirroring `comms_mcp/observability.py` (module-level construction on the default `CollectorRegistry`, no per-user labels): `CORE_LINK_UP = Gauge("gateway_core_link_up", "1 when the gateway's core link is UP, 0 during a gap.")`; `RECONNECT_ATTEMPTS = Counter("gateway_reconnect_attempts_total", "Count of core-leg dial attempts after a gap.")`; `CORE_UNAVAILABLE_SECONDS = Counter("gateway_core_unavailable_seconds_total", "Cumulative seconds the core link spent not-UP.")`. `gateway_peer_auth_rejected_total` lands in G3-3b-2 with the client-leg/relay reject sink. Export in `__all__`.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): core-link Prometheus metrics (Spec A G3-3b) (#237)` + trailer).

- [ ] **Task 3: `GatewayCoreLink` peer-handshake + epoch capture (TDD)**

**Files:** `src/alfred/gateway/core_link.py`; Test: `tests/unit/gateway/test_core_link.py`.

- [ ] Step 1 — failing test: drive `GatewayCoreLink._peer_handshake(transport)` against an in-process fake-core transport that sends `{"jsonrpc":"2.0","id":0,"method":"lifecycle.start","params":{"adapter_id":"tui","seq_ack":{"version":"1"},"epoch":"<32hex>"}}`. Assert: (a) the link RESPONDS with `{"jsonrpc":"2.0","id":0,"result":{"ok":true,"plugin_version":GATEWAY_PLUGIN_VERSION,"seq_ack":{"version":"1"}}}`; (b) `transport.enable_seq_ack()` was called (both peers advertised); (c) the captured epoch equals the sent 32-hex. A SECOND test: the core OMITS `seq_ack` → the response omits `seq_ack` AND `enable_seq_ack()` is NOT called (plain-wire fallback). A THIRD: a `lifecycle.start` whose `epoch` is malformed (not 32-hex) or ABSENT raises `GatewayCoreLinkError` (fail-loud — a core that cannot prove its epoch is not a liveness signal).

```python
class _FakeCoreTransport:
    """In-process _CommsTransportLike fake: a deque of inbound frames + a sent-list."""
    def __init__(self, inbound): self._inbound = deque(inbound); self.sent = []; self.seq_ack_enabled = False
    async def spawn(self): ...
    async def send(self, frame): self.sent.append(dict(frame))
    async def read_frame(self): return self._inbound.popleft() if self._inbound else None
    async def close(self): ...
    def enable_seq_ack(self): self.seq_ack_enabled = True
```

- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement `_peer_handshake`: read frames until `method == "lifecycle.start"` (warn-and-drop any pre-handshake frame, mirroring `comms_runner.py:450`; a `None`/EOF before the handshake raises `GatewayCoreLinkError`). Extract `params["epoch"]`, validate it via the merged `ReadyNotification`-style guard — reuse the model's field constraint by validating `ReadyNotification(epoch=epoch)` inside a `try/except ValidationError → GatewayCoreLinkError` (DRY: the 32-hex rule lives in ONE place, the merged model). Build the result: `{"ok": True, "plugin_version": GATEWAY_PLUGIN_VERSION}` and, IFF `params.get("seq_ack", {}).get("version") == SEQ_VERSION`, add `"seq_ack": {"version": SEQ_VERSION}` + call `transport.enable_seq_ack()`. Send `{"jsonrpc":"2.0","id":<the start id>,"result":<result>}`. Store `self._core_epoch = epoch`. Return `True`.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): GatewayCoreLink peer-side lifecycle.start handshake + epoch capture (Spec A G3-3b / ADR-0032) (#237)` + trailer).

- [ ] **Task 4: lifecycle-frame consume + epoch-reconcile forgery defense (TDD)**

**Files:** `src/alfred/gateway/core_link.py`; Test: `tests/unit/gateway/test_core_link.py`.

- [ ] Step 1 — failing tests, driving `GatewayCoreLink._consume_frame(frame)` (the per-frame router that maps a parsed frame → an optional `GatewayLinkEvent` and feeds the machine + emits the control frame via a captured `GatewayClientListener` fake):
  - a valid `{"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}` → feeds `CORE_GOING_DOWN` → the fake listener observes `LinkReconnectingNotification`;
  - a `{"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": <the handshake epoch>}}` → feeds `CORE_READY` (idempotent — from `UP` emits nothing);
  - **the forgery defense (security SEC-4 — make it an adversarial-corpus entry, not just a unit test)**: a `ready` frame whose `epoch` is a DIFFERENT valid 32-hex → NO `feed`, NO control frame, a loud `gateway.core_link.ready_epoch_mismatch` log (assert via `structlog` capture), and the machine stays `UP`. An epoch-mismatch `ready` is an *attempted forgery against the trust boundary* (a same-uid peer past `SO_PEERCRED` injecting a false liveness signal — distinct from benign malformed-frame noise), so this test lives in / is mirrored into the adversarial corpus (spec §6) and asserts the loud key fires — making the forgery attempt **test-observable NOW**, before G4's durable sink exists. G4 owes a DEDICATED durable `ready_epoch_mismatch` audit row (NOT bundled with generic link transitions — note this in the ADR amendment);
  - a malformed `going_down` (`reason` not in the closed `Literal`) → `ValidationError`-rejected → loud `gateway.core_link.malformed_lifecycle_frame` log, NO feed (a malformed control frame is not a state transition);
  - a non-lifecycle payload frame (`{"method": "inbound.message", ...}`) → DROPPED + the `_dropped_payload_frames` counter increments (relay is G3-3b-2), NO feed.
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement `_consume_frame`: read `method = frame.get("method")`. On `DAEMON_LIFECYCLE_GOING_DOWN`: `GoingDownNotification.model_validate(frame.get("params") or {})` inside `try/except ValidationError` (loud + return on malformed) → `self._feed(GatewayLinkEvent.CORE_GOING_DOWN)`. On `DAEMON_LIFECYCLE_READY`: validate `ReadyNotification.model_validate(...)`; if `parsed.epoch != self._core_epoch` → loud `ready_epoch_mismatch` + return (forgery defense); else `self._feed(GatewayLinkEvent.CORE_READY)`. Otherwise (any other / `None` method): `self._dropped_payload_frames += 1` + `log.debug` (relay is 3b-2). `_feed(event)` calls `emitted = self._machine.feed(event)`; if `emitted is not None` maps it via the merged `LinkControl → Link*Notification` table (lift the `_CONTROL_MODEL` map from the 3a machine→wire test into a shared helper — see Task 4b) and `await self._client_listener.send_control(model())`, and updates `CORE_LINK_UP`/`CORE_UNAVAILABLE_SECONDS` from the resulting `machine.state`.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): core lifecycle-frame consume + epoch-reconcile forgery defense (Spec A G3-3b / ADR-0032) (#237)` + trailer).

- [ ] **Task 4b: shared `LinkControl → Link*Notification` map (DRY) (TDD)**

**Files:** `src/alfred/gateway/link_state.py` (or a small `_control_frames.py`); Test: `tests/unit/gateway/test_link_state.py`.

- [ ] Step 1 — failing test: a `control_notification(LinkControl.RECONNECTING)` helper returns a `LinkReconnectingNotification` instance (and `RESTORED → LinkRestoredNotification`, `UNAVAILABLE → LinkUnavailableNotification`); an exhaustive test asserts every `LinkControl` member maps (no `KeyError` possible — a future member without a mapping is a loud test failure).
- [ ] Step 2 — run, expect FAIL. Step 3 — implement the map + a `control_notification(control) -> LinkControlNotification` helper, exported from the gateway package, so both `GatewayCoreLink._feed` and the existing 3a `test_client_listener.py` machine→wire test consume ONE table (today the table is duplicated in the test — collapse it). Step 4 — PASS. (Folds into Task 4's commit.)

- [ ] **Task 5: reconnect/backoff loop (fake-clock) (TDD)**

**Files:** `src/alfred/gateway/core_link.py`; Test: `tests/unit/gateway/test_core_link.py`.

- [ ] Step 1 — failing tests with an injected `sleep` (records the delays) + an injected `jitter` (`lambda hi: hi`, identity, so delays are deterministic) + a `dial` seam (a `Callable[[], Awaitable[_CommsTransportLike]]` the test controls):
  - the FIRST retry delay is `INITIAL_BACKOFF_SECONDS` (never 0) and subsequent delays are `0.25, 0.5, 1.0, 2.0, 4.0, 5.0, 5.0` (×2 capped at `MAX_BACKOFF_SECONDS`);
  - each attempt feeds `REDIAL_STARTED` (assert via the machine/listener fake) and increments `RECONNECT_ATTEMPTS`;
  - a dial that raises `(FileNotFoundError, ConnectionRefusedError, CommsPeerAuthError)` is retried; a dial that SUCCEEDS then completes the peer-handshake → feeds `CORE_READY` → from `REDIALING` emits `restored` → the loop exits with the live transport.
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement `_reconnect() -> _CommsTransportLike`: `backoff = INITIAL_BACKOFF_SECONDS`; loop: `self._feed(REDIAL_STARTED)`; `RECONNECT_ATTEMPTS.inc()`; `await self._sleep(self._jitter(backoff))`; `try: transport = await self._dial(); await self._peer_handshake(transport)` → `self._feed(CORE_READY)` → `return transport`; `except (FileNotFoundError, ConnectionRefusedError, OSError, CommsProtocolError) as exc:` (loud `gateway.core_link.reconnect_failed`) → `backoff = min(backoff * _BACKOFF_FACTOR, MAX_BACKOFF_SECONDS)` → continue. Full jitter is `self._jitter(backoff)` (default `uniform(0, backoff)`; the test's identity jitter gives the bare schedule). Guard: a successful dial whose handshake then raises closes the transport before retrying (no leak).
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): fake-clock reconnect/backoff loop with full jitter (Spec A G3-3b) (#237)` + trailer).

- [ ] **Task 6: `GatewayCoreLink.run()` — the supervised lifecycle (TDD)**

**Files:** `src/alfred/gateway/core_link.py`; Test: `tests/unit/gateway/test_core_link.py`.

- [ ] Step 1 — failing test: an end-to-end in-process drive — `run()` dials (initial), handshakes (feeds `CORE_READY`, startup `UP→UP` no banner), pumps frames, observes a `going_down` then EOF (feeds `CORE_GOING_DOWN` → `reconnecting`, then `CORE_CRASH_EOF` idempotent), reconnects (the fake `dial` returns a fresh transport with a NEW epoch handshake), feeds `CORE_READY` → `restored`. Assert the fake client listener observed EXACTLY `[reconnecting, restored]` (the §9 invariant end-to-end across a real gap+reconnect — the integration proof for 3b). A SECOND test: a `shutdown_event` set mid-pump ends `run()` promptly without a spurious `reconnecting`.
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement `run()`: dial + `_peer_handshake` + `_feed(CORE_READY)` for the initial connection (a failed initial dial — `(FileNotFoundError, ConnectionRefusedError, OSError, CommsProtocolError)`, which INCLUDES `CommsPeerAuthError` since it subclasses `CommsProtocolError` — enters `_reconnect()`, NEVER crashes `run()`; architect Low); then a pump loop: `frame = await transport.read_frame()`; `None`/EOF or a transport-crash exception → `self._feed(CORE_CRASH_EOF)` → `transport = await self._reconnect()` → continue; else `self._consume_frame(frame)`. Race the read against `self._shutdown_event` by **mirroring** (re-implementing — it is a private method on a different class, NOT importable; architect Low) the merged `comms_runner._read_frame_or_shutdown` / `_commands._accept_and_pump` `FIRST_COMPLETED`-race template: cancel the loser, return promptly on shutdown. On shutdown: close the transport, return (NO `reconnecting` — we are shutting down, not gapping). `finally`: close the live transport (no subprocess, but the socket FD must not leak).
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): GatewayCoreLink.run — supervised dial/handshake/pump/reconnect lifecycle (Spec A G3-3b) (#237)` + trailer).

- [ ] **Task 7: ADR-0032 amendment + CI coverage gate + full gate + open PR**

- [ ] ADR-0032: add a "Core-link manager (G3-3b-1)" subsection — the peer-handshake direction (gateway is PEER on the core leg), **handshake-epoch-as-liveness** (the normal-boot zero-senders `ready` reality, *proven* by the boot ordering: the core's socket only becomes dialable AFTER `supervisor.start()` succeeds — `_commands.py` `mint_boot_epoch` → `supervisor.start()` → `listener.bind()` — so a successful handshake genuinely implies a healthy core and the banner cannot clear prematurely; cite this ordering, architect point 2), the **epoch-reconcile forgery defense** (a mismatched-epoch `ready` is rejected, never `feed(core_ready)` — a false `restored` is an attack surface; G4 owes a DEDICATED durable `ready_epoch_mismatch` audit row, SEC-4), the reconnect/backoff schedule (never-0 first retry, ×2 to 5 s, full jitter), and the audit deferral (link transitions + epoch rejects are loud via structlog; the durable signed reconcilable row is G4 — spec §6, NOT a gap). MD032-clean. **The dial-side `SO_PEERCRED` peer-auth is recorded under ADR-0031** (the socket-transport ADR that owns the accept-side peer-auth — architect Low), noting it is Linux-enforcing with the pre-dial `lstat` owner-backstop on degrade-open hosts (SEC-2).
- [ ] **Add the per-file 100%-line+branch CI coverage gate** for `src/alfred/gateway/core_link.py` + `src/alfred/gateway/metrics.py` in `ci.yml` (the python-job per-file gate AND the combined coverage-gates job AND both arm64 legs' equivalents if they carry per-file gates), mirroring the merged `link_state.py`/`client_listener.py` entries (architect L2 — a new trust-boundary file needs its gate wired, not assumed). `metrics.py` is module-level construction (100% trivially); `core_link.py` is the trust-boundary 100%-branch target.
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/gateway tests/unit/plugins/test_comms_socket_transport.py -q && npx markdownlint-cli2@0.14.0 docs/adr/0032-gateway-comms-resume-transport.md docs/superpowers/plans/2026-06-15-g3-3b-gateway-core-link-relay.md`
- [ ] `make check` (NOT piped through `tail`). On the arm64 mac, ignore ONLY a known-local docker/`/lib64` artifact if one surfaces; the gateway code is pure-asyncio + loopback sockets, so it must be green locally.
- [ ] Commit the plan + ADR; open the PR; run the FULL `/review-pr` fleet (security ALWAYS — this is a wire-trust PR; plus error, test, performance, docs, i18n, devex, architect; conditional: comms-engineer for the transport change) + CodeRabbit; **resolve every addressed CR thread** (the merge-unblock discipline — `resolveReviewThread`, NOT waiting for a re-review); merge `gh pr merge <n> --rebase --delete-branch`.

### G3-3b-1 acceptance

- **PR-description note (architect Low):** G3-3b-1 ships the core-link KERNEL — a tested `GatewayCoreLink` library with NO `alfred gateway` command and NO client-leg seq/ack, so it is not yet operator-reachable; the runnable process + relay is G3-3b-2. State this in the PR body so the absent CLI reads as the deliberate split, not a gap (mirrors how 3a shipped a library, not a process). The `plugin_version` the peer-handshake emits honours spec §8.1 but is NOT enforced by the core leg (the merged `comms_runner._handshake` checks only `ok` + `seq_ack`, `comms_runner.py:426`) — the Task 3 test asserts the gateway's OWN output contract, not a core requirement.
- `GatewayCoreLink` dials, runs the peer-handshake, captures + validates the epoch, and drives the §9 invariant end-to-end across a real gap+reconnect (Task 6 observes exactly `[reconnecting, restored]`).
- A mismatched-epoch `ready` is rejected (forgery defense) — no false `restored`.
- The reconnect loop never 0-delays the first retry, caps at 5 s, full jitter; deterministic under the injected clock.
- Dial-side `SO_PEERCRED` rejects a mismatched-uid listener.
- New `src/alfred/gateway/core_link.py` + `metrics.py` at 100% branch; `make check` green.

---

## PR G3-3b-2 — Opaque relay + the `alfred gateway` process (scope-fixed; detailed against G3-3b-1's merged reality)

**Goal:** Make the gateway a runnable, payload-blind relay process.

**Key tasks (each captured from the design notes above; detailed with real code when 3b-2 is written against 3b-1's merged kernel):**

- **Opaque-payload transport seam** (`comms_socket_transport.py`): `read_payload_unit() -> bytes | None` (returns the `decode_seq_frame` `SeqFrame.payload` — the opaque inner bytes — WITHOUT `json.loads`; `None` on clean EOF; the SAME over-bound/malformed loud-failure discipline as `read_frame`) and `send_payload_unit(payload: bytes)` (reseq-frames the bytes with this leg's `_send_seq` + the real `cumulative_ack()` the relay supplies, under the existing `_send_lock`). The handshake + lifecycle-consume keep using `read_frame`/`send` (parsed); the relay uses the raw seam. Per-file gate already covers the file.
- **Client-leg host handshake** (`src/alfred/gateway/client_link.py` or a method on the process): the gateway sends `lifecycle.start` to the dialed-in TUI (HOST role — mirror `comms_runner._handshake`'s SEND side WITHOUT the session/gate: read the TUI's `ok` + `seq_ack` echo, `enable_seq_ack()` on the client transport **iff echoed** — a half-negotiated leg, one side framing the other plain, is a wire-corruption surface, so the `iff echoed` gate ships with a negative test: client omits `seq_ack` → gateway stays plain on that leg, SEC-6b). **CRITICAL — send `adapter_id="tui"`, NOT `"gateway"` (architect HIGH).** The merged TUI server does `LifecycleStartRequest.model_validate(params)` (`plugins/alfred_tui/src/alfred_tui/server.py:120`) and `AdapterId` validates against the `adapter_kind` frozenset `{"alfred_comms_test","discord","tui"}` (`protocol.py:56,85`) — `"gateway"` is NOT a member, so a `{adapter_id:"gateway"}` handshake fails `ValidationError` and the relay never comes up. The gateway transparently stands in for the daemon toward an unmodified TUI that only knows the kind `"tui"`; G5 re-points the TUI's DIAL TARGET (`comms-tui.sock`→`comms-gateway.sock`) but does NOT change the kind it speaks. So the client-leg handshake `adapter_id` is `"tui"`, matching the core-leg dial default. (Do NOT add `"gateway"` to the frozenset — these `link.*` frames carry no `adapter_id`, and widening the kind set would also need a `BODY_FIELD_BY_KIND` entry + classifier wiring for a kind that has no inbound body.) This negotiates client-leg seq/ack so the relay can reframe with a monotonic client-leg counter that survives a core restart.
- **The relay loop** (`src/alfred/gateway/relay.py`): two pumped directions — `client→core` and `core→client` — each: `payload = await src.read_payload_unit()`; on `None`/EOF end that direction; parse a COPY for `method` ONLY (`json.loads(payload)`); if it is a `daemon.lifecycle.*` control frame, route it to `GatewayCoreLink._consume_frame` (the gateway consumes, does NOT relay it); else `await dst.send_payload_unit(payload)` (the ORIGINAL bytes, byte-for-byte; the `id` inside survives). Per-leg `SeqDedupWindow` supplies the real `cumulative_ack()` (NOT the `a=0` placeholder — the gateway is the first real ack source). **No buffering** — a frame in flight across a core gap is dropped (G4 adds the `ReplayBuffer`); the relay re-establishes on reconnect via `GatewayCoreLink`.
- **`GatewayProcess`** (`src/alfred/gateway/process.py`): binds the client listener, accepts the TUI, runs the client-leg handshake, constructs `GatewayCoreLink(client_listener=..., ...)`, and supervises `GatewayCoreLink.run()` + the two relay directions in an `asyncio.TaskGroup` with a shared `shutdown_event`; reaps every transport + the listener on EVERY exit path (mirror `_CommsBootGraph.aclose`).
- **`gateway_peer_auth_rejected_total`** metric + wire the client listener's `on_peer_rejected` to increment it + a loud structlog row (the durable signed audit row is still G4 — no audit sink yet).
- **`alfred gateway` CLI** (`src/alfred/cli/gateway/__init__.py`, a `gateway_app` typer group registered in `main.py` via `app.add_typer(gateway_app, name="gateway")`) + **`src/alfred/gateway/__main__.py`** (so `python -m alfred.gateway` runs it, mirroring how the daemon is launched). Lazy heavy imports inside the callback (perf-001). `gateway start`/`status` minimum; long-running `start` builds + runs `GatewayProcess`.
- **Non-root in-process wire-contract test** (#245 paper-gate hazard — the explicit G2 lesson: a launcher/root-only test that proves a wire contract is NOT a real gate): an in-process gateway ↔ fake-core + fake-client over loopback sockets exercising the FULL deframe/reframe relay + a reconnect, with NO root-only launcher gate. This is the gate that proves the seq/ack peer contract on the required non-root CI leg. It MUST cover, beyond the happy relay (SEC-6a): (a) the **client-leg `seq` keeps climbing monotonically across a core-leg reconnect** — the across-restart invariant, load-bearing because the client transport is single-accept-for-life and never replaced while the core transport is (architect Low); (b) an interleaved `going_down` consumed mid-payload-stream does NOT create a client-leg `seq` gap (SEC-3b); (c) the forgery-defense (epoch-mismatch `ready`) and dial-reject paths fire on the non-root leg too, not just the happy path (SEC-6a).
- **Payload-blindness canary test** (spec §6 corpus (a)): a payload bearing a canary-T3 token is relayed client→core byte-for-byte; assert the bytes the fake-core receives are IDENTICAL to what the fake-client sent (proving no re-serialization), and that the gateway never `json.loads`'d the body (the canary trips only in the core, which is out of the gateway's scope).

**Coverage:** `core_link`/relay-orchestration 100% branch where trust-bearing; ≥80% relay/process glue; the opaque-payload seam 100% (it is on the transport's per-file gate).

---

## Self-review (G3-3b)

- **Spec coverage:** §3 stable-kernel-above (core-link sits above the 3a kernel) → 3b-1; §4 lifecycle-consume → `_consume_frame`; §4 reconnect → the backoff loop; §6 payload-blind T1 carrier + canary → 3b-2 opaque relay + canary test; §7 seq/ack first-real-peer → per-leg negotiation (3b-1 core leg, 3b-2 client leg + relay reframe); §9 invariant end-to-end across a gap → Task 6. ✓
- **Grounded in merged constants (architect M2):** `DAEMON_LIFECYCLE_READY`/`DAEMON_LIFECYCLE_GOING_DOWN`, `ReadyNotification`/`GoingDownNotification`, `SEQ_VERSION`, `_LIFECYCLE_START_ID=0`, the host `_handshake` shape (`comms_runner.py:384`), `dial_comms_socket`/`_resolve_peer_uid`/`_peer_uid_authorized` (`comms_socket_transport.py`), `LinkStateMachine`/`GatewayLinkEvent`/`LinkControl`/`GatewayClientListener` (merged 3a) — all cited by file:line, not prose. ✓
- **Placeholders:** none in 3b-1 — every task has real code/signatures/commands. 3b-2 is scope-fixed, each item grounded in a merged seam. ✓
- **Type consistency:** `GatewayCoreLink.run()`/`_peer_handshake(transport)`/`_consume_frame(frame)`/`_reconnect() -> _CommsTransportLike`/`_feed(event: GatewayLinkEvent)`; `control_notification(LinkControl) -> LinkControlNotification`; `CommsPeerAuthError(CommsProtocolError)` — names consistent across tasks 1–6 and forward into 3b-2. ✓
- **CR discipline:** Task 7 explicitly resolves addressed CR threads (the merge-unblock discipline), not waiting for a re-review. ✓
- **Security posture:** typed-event boundary preserved (forged `ready` cannot reach `feed`); epoch-reconcile forgery defense; dial-side peer-auth; T1 carrier (opaque byte-for-byte relay, method-only peek); no audit sink → loud structlog, durable row deferred to G4 (stated, not a gap). ✓
